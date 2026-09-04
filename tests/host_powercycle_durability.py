#!/usr/bin/env python3
"""Verify that a successful command response implies durable host-emulator state.

The test deliberately SIGKILLs the emulator immediately after a successful
mutating command, then restarts it against the same memory.flash image.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import signal
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

try:
    import fido2.hid as fido_hid
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.pin import ClientPin
    from fido2.hid import CtapHidDevice
    from fido2.hid import emulation as fido_hid_emulation
except ImportError as exc:
    raise SystemExit("python-fido2 is required for the HID durability test") from exc

# Select the TCP HID backend explicitly. Do not depend on a patched site-package
# or on the host OS HID backend chosen by python-fido2.
fido_hid.list_descriptors = fido_hid_emulation.list_descriptors
fido_hid.get_descriptor = fido_hid_emulation.get_descriptor
fido_hid.open_connection = fido_hid_emulation.open_connection

CCID_PORT = 35963
HID_PORT = 35962
OATH_AID = bytes.fromhex("A0000005272101")
OATH_SET_CODE = 0x03
OATH_LIST = 0xA1
TAG_KEY = 0x73
TAG_CHALLENGE = 0x74
TAG_RESPONSE = 0x75
ALG_SHA1_TOTP = 0x21


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


def apdu(ins: int, p1: int = 0, p2: int = 0, data: bytes = b"") -> bytes:
    if not data:
        return bytes([0x00, ins, p1, p2])
    if len(data) <= 0xFF:
        return bytes([0x00, ins, p1, p2, len(data)]) + data
    return bytes([0x00, ins, p1, p2, 0x00]) + len(data).to_bytes(2, "big") + data


def transmit(sock: socket.socket, command: bytes) -> tuple[bytes, int]:
    send_frame(sock, command)
    response = recv_frame(sock)
    if len(response) < 2:
        raise RuntimeError("short APDU response")
    return response[:-2], int.from_bytes(response[-2:], "big")


class Emulator:
    def __init__(self, binary: Path, run_dir: Path):
        self.binary = binary
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

    def hard_kill(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            os.kill(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=2)
        self._close_sockets()

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
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


def select_oath(sock: socket.socket) -> bytes:
    body, sw = transmit(sock, apdu(0xA4, 0x04, 0x00, OATH_AID))
    if sw != 0x9000:
        raise RuntimeError(f"OATH SELECT failed: {sw:04x}")
    return body


def run_oath_cycle(binary: Path, run_dir: Path) -> None:
    key = b"kaka blahonga"
    challenge = bytes(range(1, 9))
    response = hmac.digest(key, challenge, "sha1")
    payload = (
        bytes([TAG_KEY, len(key) + 1, ALG_SHA1_TOTP])
        + key
        + bytes([TAG_CHALLENGE, len(challenge)])
        + challenge
        + bytes([TAG_RESPONSE, len(response)])
        + response
    )

    first = Emulator(binary, run_dir)
    first.start()
    try:
        assert first.ccid is not None
        select_oath(first.ccid)
        _, sw = transmit(first.ccid, apdu(OATH_SET_CODE, data=payload))
        if sw != 0x9000:
            raise RuntimeError(f"OATH SET_CODE failed: {sw:04x}")
        # No grace period: once 9000 is visible, power loss is immediate.
        first.hard_kill()
    finally:
        first.stop()

    second = Emulator(binary, run_dir)
    second.start()
    try:
        assert second.ccid is not None
        selected = select_oath(second.ccid)
        if bytes([TAG_CHALLENGE, 8]) not in selected:
            raise RuntimeError("OATH access code did not survive hard power loss")
        _, sw = transmit(second.ccid, apdu(OATH_LIST))
        if sw != 0x6982:
            raise RuntimeError(f"OATH LIST bypassed access code after reboot: {sw:04x}")
    finally:
        second.stop()


def open_fido() -> tuple[CtapHidDevice, Ctap2]:
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is None:
        raise RuntimeError("FIDO HID emulator not found")
    return dev, Ctap2(dev)


def run_fido_pin_cycle(binary: Path, run_dir: Path) -> None:
    pin = "Durable42"
    first = Emulator(binary, run_dir)
    first.start()
    dev: CtapHidDevice | None = None
    try:
        dev, ctap2 = open_fido()
        ClientPin(ctap2).set_pin(pin)
        # No socket close and no delay before the simulated power cut.
        first.hard_kill()
    finally:
        if dev is not None:
            try:
                dev.close()
            except OSError:
                pass
        first.stop()

    second = Emulator(binary, run_dir)
    second.start()
    dev = None
    try:
        dev, ctap2 = open_fido()
        info = ctap2.get_info()
        if not info.options.get("clientPin", False):
            raise RuntimeError("FIDO PIN state did not survive hard power loss")
        token = ClientPin(ctap2).get_pin_token(pin)
        if not token:
            raise RuntimeError("persisted FIDO PIN cannot be used after reboot")
    finally:
        if dev is not None:
            dev.close()
        second.stop()


def run(binary: Path, iterations: int) -> None:
    for i in range(iterations):
        with tempfile.TemporaryDirectory(prefix="pico-oath-durable-") as tmp:
            run_oath_cycle(binary, Path(tmp))
        with tempfile.TemporaryDirectory(prefix="pico-fido-pin-durable-") as tmp:
            run_fido_pin_cycle(binary, Path(tmp))
        print(f"power-cycle durability iteration {i + 1}/{iterations}: PASS")

    print(f"OATH SET_CODE response durability: PASS x{iterations}")
    print(f"FIDO ClientPin response durability: PASS x{iterations}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", type=Path, default=Path("build-host/pico_fido2"))
    parser.add_argument("--iterations", type=int, default=5)
    args = parser.parse_args()
    if args.iterations < 1:
        raise SystemExit("--iterations must be >= 1")
    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"emulator binary not found: {binary}")
    run(binary, args.iterations)


if __name__ == "__main__":
    main()
