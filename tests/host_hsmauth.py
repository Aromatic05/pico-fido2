#!/usr/bin/env python3
"""Drive the native emulator through stock yubikit YubiHSM Auth APIs."""

from __future__ import annotations

import os
import signal
import socket
import struct
import subprocess
import tempfile
from pathlib import Path

from yubikit.core import TRANSPORT
from yubikit.core.smartcard import ApduError, SmartCardConnection, SW
from yubikit.core.smartcard.scp import (
    StaticKeys,
    _CARD_CRYPTOGRAM,
    _derive,
)
from yubikit.hsmauth import ALGORITHM, HsmAuthSession
from yubikit.core import InvalidPinError

CCID_PORT = 35963
HID_PORT = 35962
DEFAULT_MANAGEMENT_KEY = bytes(16)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError(f"EOF while reading {size} bytes")
        data += chunk
    return bytes(data)


def send_frame(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack("!H", len(data)) + data)


def recv_frame(sock: socket.socket) -> bytes:
    size = struct.unpack("!H", recv_exact(sock, 2))[0]
    return recv_exact(sock, size)


class TcpSmartCardConnection(SmartCardConnection):
    transport = TRANSPORT.USB

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def send_and_receive(self, apdu: bytes) -> tuple[bytes, int]:
        send_frame(self.sock, apdu)
        response = recv_frame(self.sock)
        if len(response) < 2:
            raise RuntimeError("short APDU response")
        return response[:-2], int.from_bytes(response[-2:], "big")

    def close(self) -> None:
        self.sock.close()


class Emulator:
    def __init__(self, binary: Path, run_dir: Path):
        self.binary = binary.resolve()
        self.run_dir = run_dir
        self.listener: socket.socket | None = None
        self.ccid: socket.socket | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.log_path = run_dir / "emulator.log"

    def start(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", CCID_PORT))
        self.listener.listen(1)
        self.listener.settimeout(5)

        log = self.log_path.open("ab")
        try:
            self.process = subprocess.Popen(
                [str(self.binary)],
                cwd=self.run_dir,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        finally:
            log.close()

        self.ccid, _ = self.listener.accept()
        self.ccid.settimeout(5)
        self._wait_hid()

    def _wait_hid(self) -> None:
        import time

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                raise RuntimeError(
                    f"emulator exited {self.process.returncode}:\n{self.log_tail()}"
                )
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.settimeout(0.05)
            try:
                probe.connect(("127.0.0.1", HID_PORT))
                return
            except OSError:
                time.sleep(0.01)
            finally:
                probe.close()
        raise RuntimeError("HID emulator did not become ready")

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.kill(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=2)
        self._close_sockets()

    def hard_kill(self) -> None:
        if self.process is not None and self.process.poll() is None:
            os.kill(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=2)
        self._close_sockets()

    def _close_sockets(self) -> None:
        if self.ccid is not None:
            self.ccid.close()
            self.ccid = None
        if self.listener is not None:
            self.listener.close()
            self.listener = None

    def log_tail(self) -> str:
        if not self.log_path.exists():
            return ""
        return "\n".join(self.log_path.read_text(errors="replace").splitlines()[-40:])


def expect_invalid_pin(call, retries: int) -> None:
    try:
        call()
    except InvalidPinError as exc:
        if exc.attempts_remaining != retries:
            raise AssertionError(
                f"expected {retries} retries, got {exc.attempts_remaining}"
            ) from exc
    else:
        raise AssertionError("operation unexpectedly accepted wrong key/password")


def run(binary: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="pico-fido2-hsmauth-") as tmp:
        run_dir = Path(tmp)
        emulator = Emulator(binary, run_dir)
        emulator.start()
        try:
            assert emulator.ccid is not None
            connection = TcpSmartCardConnection(emulator.ccid)
            session = HsmAuthSession(connection)

            if tuple(session.version) != (5, 7, 0):
                raise AssertionError(f"unexpected HSM Auth version: {session.version}")

            session.reset()
            if session.list_credentials():
                raise AssertionError("HSM Auth reset did not remove credentials")
            if session.get_management_key_retries() != 8:
                raise AssertionError("unexpected initial management retry count")

            wrong_management_key = b"X" * 16
            key_enc = bytes(range(16))
            key_mac = bytes(range(16, 32))
            password = b"credential-pass!"
            if len(password) != 16:
                raise AssertionError("test credential password must be 16 bytes")
            label = "sym-main"

            expect_invalid_pin(
                lambda: session.put_credential_symmetric(
                    wrong_management_key,
                    "wrong-mgmt",
                    key_enc,
                    key_mac,
                    password,
                ),
                7,
            )
            if session.get_management_key_retries() != 7:
                raise AssertionError("wrong management key retry was not persisted")

            credential = session.put_credential_symmetric(
                DEFAULT_MANAGEMENT_KEY,
                label,
                key_enc,
                key_mac,
                password,
            )
            if credential.algorithm != ALGORITHM.AES128_YUBICO_AUTHENTICATION:
                raise AssertionError("wrong algorithm returned after PUT")
            if session.get_management_key_retries() != 8:
                raise AssertionError("successful management auth did not reset retries")

            emulator.hard_kill()
            emulator = Emulator(binary, run_dir)
            emulator.start()
            assert emulator.ccid is not None
            session = HsmAuthSession(TcpSmartCardConnection(emulator.ccid))

            listed = session.list_credentials()
            if len(listed) != 1 or listed[0].label != label or listed[0].counter != 8:
                raise AssertionError(f"unexpected LIST result: {listed!r}")

            challenge = session.get_challenge(label)
            if len(challenge) != 8:
                raise AssertionError(f"unexpected challenge length: {len(challenge)}")

            context = bytes.fromhex("00112233445566778899aabbccddeeff")
            expected = StaticKeys(key_enc, key_mac).derive(context)
            actual = session.calculate_session_keys_symmetric(label, context, password)
            if actual[:3] != expected[:3]:
                raise AssertionError(
                    "SCP03 session keys differ from stock yubikit reference"
                )

            card_crypto = _derive(
                expected.key_smac,
                _CARD_CRYPTOGRAM,
                context,
                0x40,
            )
            with_card_crypto = session.calculate_session_keys_symmetric(
                label,
                context,
                password,
                card_crypto,
            )
            if with_card_crypto[:3] != expected[:3]:
                raise AssertionError("card cryptogram path changed session keys")

            try:
                session.calculate_session_keys_symmetric(
                    label,
                    context,
                    password,
                    b"\xff" * 8,
                )
            except ApduError as exc:
                if exc.sw != SW.SECURITY_CONDITION_NOT_SATISFIED:
                    raise AssertionError(f"unexpected bad card crypto SW: {exc.sw:04x}") from exc
            else:
                raise AssertionError("bad card cryptogram was accepted")

            expect_invalid_pin(
                lambda: session.calculate_session_keys_symmetric(
                    label,
                    context,
                    b"wrong-password!!",
                ),
                7,
            )
            listed = session.list_credentials()
            if listed[0].counter != 7:
                raise AssertionError("credential retry counter did not decrement")

            emulator.hard_kill()
            emulator = Emulator(binary, run_dir)
            emulator.start()
            assert emulator.ccid is not None
            session = HsmAuthSession(TcpSmartCardConnection(emulator.ccid))
            if session.list_credentials()[0].counter != 7:
                raise AssertionError("credential retry counter was not durable")

            session.calculate_session_keys_symmetric(label, context, password)
            if session.list_credentials()[0].counter != 8:
                raise AssertionError("successful credential auth did not reset retries")

            new_management_key = b"new-management!!"
            if len(new_management_key) != 16:
                raise AssertionError("test management key must be 16 bytes")
            session.put_management_key(DEFAULT_MANAGEMENT_KEY, new_management_key)

            emulator.hard_kill()
            emulator = Emulator(binary, run_dir)
            emulator.start()
            assert emulator.ccid is not None
            session = HsmAuthSession(TcpSmartCardConnection(emulator.ccid))
            expect_invalid_pin(
                lambda: session.delete_credential(DEFAULT_MANAGEMENT_KEY, label),
                7,
            )
            session.delete_credential(new_management_key, label)
            if session.list_credentials():
                raise AssertionError("credential DELETE did not persist in live state")

            session.reset()
            if session.get_management_key_retries() != 8:
                raise AssertionError("reset did not restore management retries")
            session.put_credential_symmetric(
                DEFAULT_MANAGEMENT_KEY,
                "post-reset",
                key_enc,
                key_mac,
                password,
            )
            session.delete_credential(DEFAULT_MANAGEMENT_KEY, "post-reset")
        finally:
            emulator.stop()

    print("stock yubikit YubiHSM Auth symmetric lifecycle: PASS")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    run(args.binary)
