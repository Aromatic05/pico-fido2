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
    from fido2.ctap import CtapError
    from fido2.ctap2 import Config, Ctap2, CredentialManagement
    from fido2.ctap2.pin import ClientPin, PinProtocolV2
    from fido2.hid import CtapHidDevice
    from fido2.hid.base import CtapHidConnection, HidDescriptor
except ImportError as exc:
    raise SystemExit("python-fido2 is required for the HID durability test") from exc

CCID_PORT = 35963
HID_PORT = 35962
OATH_AID = bytes.fromhex("A0000005272101")
OATH_PUT = 0x01
OATH_SET_CODE = 0x03
OATH_LIST = 0xA1
OATH_CALCULATE = 0xA2
TAG_NAME = 0x71
TAG_KEY = 0x73
TAG_CHALLENGE = 0x74
TAG_RESPONSE = 0x75
TAG_IMF = 0x7A
ALG_SHA1_TOTP = 0x21
ALG_SHA1_HOTP = 0x11


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


class TcpHidConnection(CtapHidConnection):
    def __init__(self) -> None:
        self.sock = socket.create_connection(("127.0.0.1", HID_PORT), timeout=5)
        self.sock.settimeout(5)

    def read_packet(self) -> bytes:
        packet = recv_frame(self.sock)
        if len(packet) != 64:
            raise RuntimeError(f"unexpected emulator HID packet size: {len(packet)}")
        return packet

    def write_packet(self, data: bytes) -> None:
        if len(data) != 64:
            raise ValueError(f"unexpected CTAPHID packet size: {len(data)}")
        send_frame(self.sock, data)

    def close(self) -> None:
        self.sock.close()


def tcp_hid_descriptors():
    yield HidDescriptor(
        path="tcp://127.0.0.1:35962",
        vid=0x1050,
        pid=0x0407,
        report_size_in=64,
        report_size_out=64,
        product_name="YubiKey 5",
        serial_number=None,
    )


def tcp_hid_open_connection(descriptor: HidDescriptor) -> CtapHidConnection:
    del descriptor
    return TcpHidConnection()


# Select the product emulator explicitly. This keeps the durability gate on
# stock python-fido2 while avoiding any host HID backend or patched site-package.
fido_hid.list_descriptors = tcp_hid_descriptors
fido_hid.open_connection = tcp_hid_open_connection


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
    def __init__(self, binary: Path, run_dir: Path, extra_env: dict[str, str] | None = None):
        self.binary = binary
        self.run_dir = run_dir
        self.extra_env = extra_env or {}
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
                env={**os.environ, **self.extra_env},
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


def run_oath_storage_fault_cycles(binary: Path) -> None:
    # OATH SET_CODE persistent-write failure must be fail-closed.
    # OATH PUT persistent-write failure must not leave a ghost credential.
    # OATH HOTP counter write failure must not advance durable state.
    key = b"fault-oath-key"
    challenge = bytes(range(1, 9))
    response = hmac.digest(key, challenge, "sha1")
    set_code_payload = (
        bytes([TAG_KEY, len(key) + 1, ALG_SHA1_TOTP])
        + key
        + bytes([TAG_CHALLENGE, len(challenge)])
        + challenge
        + bytes([TAG_RESPONSE, len(response)])
        + response
    )

    with tempfile.TemporaryDirectory(prefix="pico-oath-fault-code-") as tmp:
        run_dir = Path(tmp)
        first = Emulator(binary, run_dir, {"PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": "0xBAFF"})
        first.start()
        try:
            assert first.ccid is not None
            select_oath(first.ccid)
            _, sw = transmit(first.ccid, apdu(OATH_SET_CODE, data=set_code_payload))
            if sw == 0x9000:
                raise RuntimeError("OATH SET_CODE falsely succeeded after persistent write failure")
            first.hard_kill()
        finally:
            first.stop()

        second = Emulator(binary, run_dir); second.start()
        try:
            assert second.ccid is not None
            selected = select_oath(second.ccid)
            if bytes([TAG_CHALLENGE, 8]) in selected:
                raise RuntimeError("failed OATH SET_CODE became persistent after restart")
            _, sw = transmit(second.ccid, apdu(OATH_LIST))
            if sw != 0x9000:
                raise RuntimeError(f"failed OATH SET_CODE left access control active: {sw:04x}")
        finally:
            second.stop()

    name = b"fault-oath"
    secret = bytes([0x0B]) * 20
    put_payload = (
        bytes([TAG_NAME, len(name)]) + name
        + bytes([TAG_KEY, len(secret) + 2, ALG_SHA1_TOTP, 6]) + secret
    )
    with tempfile.TemporaryDirectory(prefix="pico-oath-fault-cred-") as tmp:
        run_dir = Path(tmp)
        first = Emulator(binary, run_dir, {"PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": "0xBA00"})
        first.start()
        try:
            assert first.ccid is not None
            select_oath(first.ccid)
            _, sw = transmit(first.ccid, apdu(OATH_PUT, data=put_payload))
            if sw == 0x9000:
                raise RuntimeError("OATH PUT falsely succeeded after persistent write failure")
            first.hard_kill()
        finally:
            first.stop()

        second = Emulator(binary, run_dir); second.start()
        try:
            assert second.ccid is not None
            select_oath(second.ccid)
            body, sw = transmit(second.ccid, apdu(OATH_LIST))
            if sw != 0x9000 or body != b"":
                raise RuntimeError("failed OATH PUT left a ghost credential after restart")
        finally:
            second.stop()

    hotp_name = b"fault-hotp"
    hotp_secret = bytes([0x0C]) * 20
    hotp_payload = (
        bytes([TAG_NAME, len(hotp_name)]) + hotp_name
        + bytes([TAG_KEY, len(hotp_secret) + 2, ALG_SHA1_HOTP, 6]) + hotp_secret
        + bytes([TAG_IMF, 8]) + bytes(8)
    )
    calculate_payload = (
        bytes([TAG_NAME, len(hotp_name)]) + hotp_name
        + bytes([TAG_CHALLENGE, 8]) + bytes(8)
    )
    with tempfile.TemporaryDirectory(prefix="pico-oath-fault-hotp-") as tmp:
        run_dir = Path(tmp)
        first = Emulator(binary, run_dir, {
            "PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": "0xBA00",
            "PICO_KEYS_EMU_FAIL_FILE_PUT_NTH": "2",
        })
        first.start()
        failed_response = b""
        try:
            assert first.ccid is not None
            select_oath(first.ccid)
            _, sw = transmit(first.ccid, apdu(OATH_PUT, data=hotp_payload))
            if sw != 0x9000:
                raise RuntimeError(f"OATH HOTP PUT failed: {sw:04x}")
            failed_response, sw = transmit(
                first.ccid, apdu(OATH_CALCULATE, 0x00, 0x01, calculate_payload)
            )
            if sw == 0x9000:
                raise RuntimeError("OATH HOTP CALCULATE falsely succeeded after counter write failure")
            first.hard_kill()
        finally:
            first.stop()

        second = Emulator(binary, run_dir)
        second.start()
        try:
            assert second.ccid is not None
            select_oath(second.ccid)
            retry_response, sw = transmit(
                second.ccid, apdu(OATH_CALCULATE, 0x00, 0x01, calculate_payload)
            )
            if sw != 0x9000:
                raise RuntimeError(f"OATH HOTP retry failed after reboot: {sw:04x}")
            if failed_response and retry_response != failed_response:
                raise RuntimeError("failed OATH HOTP calculation advanced the persistent counter")
        finally:
            second.stop()


def run_openpgp_init_fault_cycle(binary: Path) -> None:
    """a failed required default write must not expose a half-ready applet."""
    import re

    source_root = Path(__file__).resolve().parents[1] / "pico-openpgp" / "src" / "openpgp"
    pw1_fid: str | None = None
    pattern = re.compile(r"^#define\s+EF_PW1\s+(0x[0-9A-Fa-f]+|\d+)")
    for header in source_root.rglob("*.[ch]"):
        for line in header.read_text(errors="ignore").splitlines():
            match = pattern.match(line.strip())
            if match:
                pw1_fid = match.group(1)
                break
        if pw1_fid is not None:
            break
    if pw1_fid is None:
        raise RuntimeError("could not resolve EF_PW1 for OpenPGP init fault test")

    aid = bytes.fromhex("D27600012401")
    with tempfile.TemporaryDirectory(prefix="pico-openpgp-init-fault-") as tmp:
        run_dir = Path(tmp)
        first = Emulator(binary, run_dir, {
            "PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": pw1_fid,
        })
        first.start()
        try:
            assert first.ccid is not None
            _, sw = transmit(first.ccid, apdu(0xA4, 0x04, 0x00, aid))
            if sw == 0x9000:
                raise RuntimeError("OpenPGP selected despite required init write failure")
            first.hard_kill()
        finally:
            first.stop()

        second = Emulator(binary, run_dir)
        second.start()
        try:
            assert second.ccid is not None
            _, sw = transmit(second.ccid, apdu(0xA4, 0x04, 0x00, aid))
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP did not self-heal after init fault: {sw:04x}")
            _, sw = transmit(second.ccid, apdu(0x20, 0x00, 0x81, b"123456"))
            if sw != 0x9000:
                raise RuntimeError(f"repaired OpenPGP default PW1 unusable: {sw:04x}")
        finally:
            second.stop()
    print("OpenPGP fresh-init fail-closed/retry recovery: PASS")


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


def run_fido_resident_ssh_cycle(binary: Path, run_dir: Path, alg: int, label: str) -> None:
    """exercise the OpenSSH-style resident credential persistence path."""
    pin = "Resident42"
    rp = {"id": "ssh:", "name": "OpenSSH"}
    user = {
        "id": b"aromatic-resident-user",
        "name": "aromatic",
        "displayName": "Aromatic SSH",
    }
    key_params = [{"type": "public-key", "alg": alg}]

    first = Emulator(binary, run_dir)
    first.start()
    dev: CtapHidDevice | None = None
    credential_id = b""
    created_public_key: dict[int, object] = {}
    created_counter = 0
    try:
        dev, ctap2 = open_fido()
        client_pin = ClientPin(ctap2)
        client_pin.set_pin(pin)
        protocol = PinProtocolV2()
        client_data_hash = os.urandom(32)
        token = client_pin.get_pin_token(
            pin,
            permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
            permissions_rpid=rp["id"],
        )
        result = ctap2.make_credential(
            client_data_hash=client_data_hash,
            rp=rp,
            user=user,
            key_params=key_params,
            options={"rk": True},
            pin_uv_param=protocol.authenticate(token, client_data_hash),
            pin_uv_protocol=protocol.VERSION,
        )
        credential_id = result.auth_data.credential_data.credential_id
        created_public_key = dict(result.auth_data.credential_data.public_key)
        created_counter = result.auth_data.counter
        if not credential_id:
            raise RuntimeError("resident SSH makeCredential returned no credential id")
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
        client_pin = ClientPin(ctap2)
        protocol = PinProtocolV2()

        mgmt_token = client_pin.get_pin_token(
            pin,
            permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT,
        )
        cred_mgmt = CredentialManagement(ctap2, protocol, mgmt_token)
        rps = cred_mgmt.enumerate_rps()
        ssh_rps = [
            entry for entry in rps
            if entry[CredentialManagement.RESULT.RP]["id"] == rp["id"]
        ]
        if len(ssh_rps) != 1:
            raise RuntimeError(f"resident SSH RP missing after hard power loss: {rps!r}")

        rp_hash = hashlib.sha256(rp["id"].encode()).digest()
        creds = cred_mgmt.enumerate_creds(rp_hash)
        matching = [
            entry for entry in creds
            if entry[CredentialManagement.RESULT.CREDENTIAL_ID]["id"] == credential_id
        ]
        if len(matching) != 1:
            raise RuntimeError("resident SSH credential id missing after hard power loss")
        returned_user = matching[0][CredentialManagement.RESULT.USER]
        if returned_user.get("id") != user["id"]:
            raise RuntimeError("resident SSH user id changed across hard power loss")
        returned_public_key = dict(matching[0][CredentialManagement.RESULT.PUBLIC_KEY])
        if returned_public_key != created_public_key:
            raise RuntimeError(
                f"resident SSH {label} public key changed during credential enumeration"
            )
        if returned_public_key.get(3) != alg:
            raise RuntimeError(
                f"resident SSH {label} COSE alg mismatch: {returned_public_key!r}"
            )
        if alg == -8:
            if (returned_public_key.get(1), returned_public_key.get(-1)) != (1, 6):
                raise RuntimeError(
                    f"resident SSH Ed25519 COSE kty/crv malformed: {returned_public_key!r}"
                )
            if len(returned_public_key.get(-2, b"")) != 32:
                raise RuntimeError("resident SSH Ed25519 public key is not 32 bytes")

        assertion_hash = os.urandom(32)
        assertion_token = client_pin.get_pin_token(
            pin,
            permissions=ClientPin.PERMISSION.GET_ASSERTION,
            permissions_rpid=rp["id"],
        )
        assertion = ctap2.get_assertion(
            rp_id=rp["id"],
            client_data_hash=assertion_hash,
            pin_uv_param=protocol.authenticate(assertion_token, assertion_hash),
            pin_uv_protocol=protocol.VERSION,
        )
        if assertion.credential["id"] != credential_id:
            raise RuntimeError(
                "resident SSH credential cannot authenticate without allowList after reboot"
            )
        if assertion.auth_data.counter <= created_counter:
            raise RuntimeError(
                f"resident SSH sign counter went backwards across reboot: "
                f"{created_counter} -> {assertion.auth_data.counter}"
            )
        if assertion.auth_data.counter - created_counter > 128:
            raise RuntimeError(
                f"resident SSH sign counter jumped beyond one reserved window: "
                f"{created_counter} -> {assertion.auth_data.counter}"
            )
    finally:
        if dev is not None:
            dev.close()
        second.stop()


def expect_ctap_error(action, expected: CtapError.ERR, label: str) -> None:
    try:
        action()
    except CtapError as exc:
        if exc.code != expected:
            raise RuntimeError(f"{label}: expected {expected}, got {exc.code}") from exc
        return
    raise RuntimeError(f"{label}: command falsely returned success")


def run_fido_storage_fault_cycles(binary: Path) -> None:
    # required fresh-init device-root write failure.
    # setPIN verifier/device-root transaction failure.
    # changePIN rollback must preserve the old resident identity.
    # retry counters and pinUvAuthToken persistence must fail closed.
    # resident credential and RP metadata must remain consistent.
    # authenticator config writes must not publish uncommitted state.
    pin = "FaultPin42"

    # A required factory-record write failure must not leave a partially
    # initialized authenticator accepting credential operations. Keep GetInfo
    # and authenticatorReset available as diagnosis/recovery surfaces.
    with tempfile.TemporaryDirectory(prefix="pico-fido-fault-init-") as tmp:
        run_dir = Path(tmp)
        first = Emulator(binary, run_dir, {
            "PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": "0xCC00",
            "PICO_KEYS_EMU_FAIL_FILE_PUT_NTH": "1",
        })
        first.start(); dev = None
        try:
            dev, ctap2 = open_fido()
            ctap2.get_info()
            expect_ctap_error(
                lambda: ctap2.make_credential(
                    os.urandom(32),
                    {"id": "startup.example", "name": "Startup"},
                    {"id": b"startup-user", "name": "startup", "displayName": "Startup"},
                    [{"type": "public-key", "alg": -7}],
                ),
                CtapError.ERR.PROCESSING,
                "half-initialized FIDO makeCredential",
            )
            ctap2.reset()
            recovered = ctap2.make_credential(
                os.urandom(32),
                {"id": "startup.example", "name": "Startup"},
                {"id": b"startup-user", "name": "startup", "displayName": "Startup"},
                [{"type": "public-key", "alg": -7}],
            )
            if not recovered.auth_data.credential_data.credential_id:
                raise RuntimeError("authenticatorReset did not recover failed FIDO initialization")
        finally:
            if dev is not None:
                dev.close()
            first.stop()

    for fid, label, nth in (
        ("0x1080", "PIN verifier", "1"),
        ("0xCC00", "device-root rewrap", "2"),
    ):
        with tempfile.TemporaryDirectory(prefix="pico-fido-fault-pin-") as tmp:
            run_dir = Path(tmp)
            first = Emulator(binary, run_dir, {
                "PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": fid,
                "PICO_KEYS_EMU_FAIL_FILE_PUT_NTH": nth,
            })
            first.start(); dev = None
            try:
                dev, ctap2 = open_fido()
                expect_ctap_error(
                    lambda: ClientPin(ctap2).set_pin(pin),
                    CtapError.ERR.PROCESSING,
                    f"setPIN {label} storage fault",
                )
                first.hard_kill()
            finally:
                if dev is not None:
                    try: dev.close()
                    except OSError: pass
                first.stop()
            second = Emulator(binary, run_dir); second.start(); dev = None
            try:
                dev, ctap2 = open_fido()
                if ctap2.get_info().options.get("clientPin") is not False:
                    raise RuntimeError(f"failed setPIN {label} became persistent after restart")
            finally:
                if dev is not None: dev.close()
                second.stop()

    # Before changePIN this scenario creates one resident key, and obtaining
    # its MAKE_CREDENTIAL token performs the normal retry decrement/restore.
    # EF_PIN matches are therefore: setPIN #1, token #2/#3, changePIN retry
    # decrement/restore #4/#5, and the final new verifier #6.
    with tempfile.TemporaryDirectory(prefix="pico-fido-fault-change-pin-") as tmp:
        run_dir = Path(tmp)
        first = Emulator(binary, run_dir, {
            "PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": "0x1080",
            "PICO_KEYS_EMU_FAIL_FILE_PUT_NTH": "6",
        })
        first.start(); dev = None
        old_pin = "OldPin42"
        new_pin = "NewPin84"
        old_credential_id = b""
        try:
            dev, ctap2 = open_fido(); client_pin = ClientPin(ctap2)
            client_pin.set_pin(old_pin)
            protocol = PinProtocolV2(); client_hash = os.urandom(32)
            token = client_pin.get_pin_token(
                old_pin,
                permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
                permissions_rpid="ssh:",
            )
            resident = ctap2.make_credential(
                client_data_hash=client_hash,
                rp={"id": "ssh:", "name": "OpenSSH"},
                user={"id": b"change-pin-user", "name": "change", "displayName": "Change"},
                key_params=[{"type": "public-key", "alg": -7}],
                options={"rk": True},
                pin_uv_param=protocol.authenticate(token, client_hash),
                pin_uv_protocol=protocol.VERSION,
            )
            old_credential_id = resident.auth_data.credential_data.credential_id
            expect_ctap_error(
                lambda: client_pin.change_pin(old_pin, new_pin),
                CtapError.ERR.PROCESSING,
                "changePIN final verifier storage fault",
            )
            first.hard_kill()
        finally:
            if dev is not None:
                try: dev.close()
                except OSError: pass
            first.stop()
        second = Emulator(binary, run_dir); second.start(); dev = None
        try:
            dev, ctap2 = open_fido(); client_pin = ClientPin(ctap2)
            protocol = PinProtocolV2(); assertion_hash = os.urandom(32)
            token = client_pin.get_pin_token(
                old_pin,
                permissions=ClientPin.PERMISSION.GET_ASSERTION,
                permissions_rpid="ssh:",
            )
            assertion = ctap2.get_assertion(
                rp_id="ssh:",
                client_data_hash=assertion_hash,
                pin_uv_param=protocol.authenticate(token, assertion_hash),
                pin_uv_protocol=protocol.VERSION,
            )
            if assertion.credential["id"] != old_credential_id:
                raise RuntimeError("failed changePIN made the old resident credential unusable")
            expect_ctap_error(
                lambda: client_pin.get_pin_token(new_pin),
                CtapError.ERR.PIN_INVALID,
                "failed changePIN unexpectedly activated new PIN",
            )
        finally:
            if dev is not None: dev.close()
            second.stop()

    # getPinUvAuthTokenUsingPin persists the retry decrement before checking
    # the PIN and restores the retry counter after a correct PIN. Either write
    # failing must suppress token issuance rather than weaken retry policy.
    for nth, label in (("2", "retry decrement"), ("3", "retry restore")):
        with tempfile.TemporaryDirectory(prefix="pico-fido-fault-pin-token-") as tmp:
            run_dir = Path(tmp)
            first = Emulator(binary, run_dir, {
                "PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": "0x1080",
                "PICO_KEYS_EMU_FAIL_FILE_PUT_NTH": nth,
            })
            first.start(); dev = None
            try:
                dev, ctap2 = open_fido(); client_pin = ClientPin(ctap2)
                client_pin.set_pin(pin)
                expect_ctap_error(
                    lambda: client_pin.get_pin_token(pin),
                    CtapError.ERR.PROCESSING,
                    f"PIN token {label} storage fault",
                )
                first.hard_kill()
            finally:
                if dev is not None:
                    try: dev.close()
                    except OSError: pass
                first.stop()
            second = Emulator(binary, run_dir); second.start(); dev = None
            try:
                dev, ctap2 = open_fido()
                ClientPin(ctap2).get_pin_token(pin)
            finally:
                if dev is not None: dev.close()
                second.stop()

    # The first ClientPIN operation initializes key agreement and rotates the
    # token once. That persistent write is match #2 after factory init and
    # must fail the command rather than be ignored.
    with tempfile.TemporaryDirectory(prefix="pico-fido-fault-clientpin-init-") as tmp:
        run_dir = Path(tmp)
        first = Emulator(binary, run_dir, {
            "PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": "0x1090",
            "PICO_KEYS_EMU_FAIL_FILE_PUT_NTH": "2",
        })
        first.start(); dev = None
        try:
            dev, ctap2 = open_fido(); client_pin = ClientPin(ctap2)
            expect_ctap_error(
                lambda: client_pin.set_pin(pin),
                CtapError.ERR.PROCESSING,
                "ClientPIN initialization token storage fault",
            )
            first.hard_kill()
        finally:
            if dev is not None:
                try: dev.close()
                except OSError: pass
            first.stop()
        second = Emulator(binary, run_dir); second.start(); dev = None
        try:
            dev, ctap2 = open_fido()
            if ctap2.get_info().options.get("clientPin") is not False:
                raise RuntimeError("failed ClientPIN initialization left a configured PIN")
        finally:
            if dev is not None: dev.close()
            second.stop()

    # Token material itself is persistent. After setPIN, issuing a token is
    # match #3 (factory init #1, ClientPIN initialize #2). A failed rotation
    # must suppress issuance rather than return the previous token bytes.
    with tempfile.TemporaryDirectory(prefix="pico-fido-fault-auth-token-") as tmp:
        run_dir = Path(tmp)
        first = Emulator(binary, run_dir, {
            "PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": "0x1090",
            "PICO_KEYS_EMU_FAIL_FILE_PUT_NTH": "3",
        })
        first.start(); dev = None
        try:
            dev, ctap2 = open_fido(); client_pin = ClientPin(ctap2)
            client_pin.set_pin(pin)
            expect_ctap_error(
                lambda: client_pin.get_pin_token(pin),
                CtapError.ERR.PROCESSING,
                "pinUvAuthToken rotation storage fault",
            )
            first.hard_kill()
        finally:
            if dev is not None:
                try: dev.close()
                except OSError: pass
            first.stop()
        second = Emulator(binary, run_dir); second.start(); dev = None
        try:
            dev, ctap2 = open_fido()
            ClientPin(ctap2).get_pin_token(pin)
        finally:
            if dev is not None: dev.close()
            second.stop()

    for fid, label in (("0xCF00", "credential"), ("0xD000", "RP metadata")):
        with tempfile.TemporaryDirectory(prefix="pico-fido-fault-rk-") as tmp:
            run_dir = Path(tmp)
            first = Emulator(binary, run_dir, {"PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": fid})
            first.start(); dev = None
            try:
                dev, ctap2 = open_fido(); client_pin = ClientPin(ctap2); client_pin.set_pin(pin)
                protocol = PinProtocolV2(); client_hash = os.urandom(32)
                token = client_pin.get_pin_token(pin, permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL, permissions_rpid="ssh:")
                expect_ctap_error(
                    lambda: ctap2.make_credential(
                        client_data_hash=client_hash,
                        rp={"id": "ssh:", "name": "OpenSSH"},
                        user={"id": b"fault-user", "name": "fault", "displayName": "Fault"},
                        key_params=[{"type": "public-key", "alg": -7}],
                        options={"rk": True},
                        pin_uv_param=protocol.authenticate(token, client_hash),
                        pin_uv_protocol=protocol.VERSION,
                    ),
                    CtapError.ERR.KEY_STORE_FULL,
                    f"resident {label} storage fault",
                )
                first.hard_kill()
            finally:
                if dev is not None:
                    try: dev.close()
                    except OSError: pass
                first.stop()
            second = Emulator(binary, run_dir); second.start(); dev = None
            try:
                dev, ctap2 = open_fido(); client_pin = ClientPin(ctap2); protocol = PinProtocolV2()
                token = client_pin.get_pin_token(pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
                metadata = CredentialManagement(ctap2, protocol, token).get_metadata()
                if metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT] != 0:
                    raise RuntimeError(f"failed resident {label} write left a ghost credential")
            finally:
                if dev is not None: dev.close()
                second.stop()

    with tempfile.TemporaryDirectory(prefix="pico-fido-fault-config-") as tmp:
        # ENABLE_ENTERPRISE_ATT has no sub-parameter map.  The
        # pinUvAuth payload builder must not call memcpy(NULL, ..., 0); this
        # scenario is also run under UBSAN by the complete local gate.
        run_dir = Path(tmp)
        first = Emulator(binary, run_dir, {
            "PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": "0xC001",
        })
        first.start(); dev = None
        try:
            dev, ctap2 = open_fido(); client_pin = ClientPin(ctap2); client_pin.set_pin(pin)
            protocol = PinProtocolV2()
            token = client_pin.get_pin_token(
                pin, permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG
            )
            config = Config(ctap2, protocol, token)
            expect_ctap_error(
                config.enable_enterprise_attestation,
                CtapError.ERR.PROCESSING,
                "enableEnterpriseAttestation options storage fault",
            )
            if ctap2.get_info().options.get("ep") is not False:
                raise RuntimeError("failed enterprise-attestation config changed ep state")
        finally:
            if dev is not None: dev.close()
            first.stop()


def run_fido_sector_power_cut_cycles(binary: Path) -> None:
    """cut power at sector/journal boundaries of an aged resident write.

    Ten existing RPs are enough to place the next resident credential and its
    RP index on different flash sectors.  Each case must reboot into a
    self-consistent old (10 credentials) or new (11 credentials) state.
    """
    cases: tuple[tuple[str | None, int], ...] = (
        (None, 1),
        (None, 2),
        ("after-erase", 1),
        ("after-erase", 2),
        ("mid-program", 1),
        ("mid-program", 2),
        ("journal-mid-data", 1),
        ("journal-mid-data", 2),
        ("journal-before-commit", 1),
        ("journal-before-commit", 2),
        ("journal-after-meta", 1),
        ("journal-after-meta", 2),
    )
    pin = "SectorCut42"
    protocol = PinProtocolV2()

    for phase, cut_page in cases:
        label = phase or "after-page"
        with tempfile.TemporaryDirectory(prefix=f"pico-fido-sector-cut-{label}-{cut_page}-") as tmp:
            run_dir = Path(tmp)
            arm = run_dir / "commit-cut.arm"
            env = {
                "PICO_KEYS_EMU_COMMIT_CUT_ARM_FILE": str(arm),
                "PICO_KEYS_EMU_COMMIT_CUT_AFTER_PAGES": str(cut_page),
            }
            if phase is not None:
                env["PICO_KEYS_EMU_COMMIT_CUT_PHASE"] = phase
            if phase in ("mid-program", "journal-mid-data"):
                env["PICO_KEYS_EMU_COMMIT_CUT_PROGRAM_BYTES"] = "256"

            first = Emulator(binary, run_dir, env)
            first.start()
            dev = None
            try:
                dev, ctap2 = open_fido()
                client_pin = ClientPin(ctap2)
                client_pin.set_pin(pin)
                for i in range(10):
                    rp_id = f"sector-cut-{i:03}.example"
                    client_data_hash = os.urandom(32)
                    token = client_pin.get_pin_token(
                        pin,
                        permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
                        permissions_rpid=rp_id,
                    )
                    ctap2.make_credential(
                        client_data_hash,
                        {"id": rp_id, "name": rp_id},
                        {
                            "id": f"user-{i:03}".encode(),
                            "name": f"user-{i:03}",
                            "displayName": f"User {i:03}",
                        },
                        [{"type": "public-key", "alg": -7}],
                        options={"rk": True},
                        pin_uv_param=protocol.authenticate(token, client_data_hash),
                        pin_uv_protocol=protocol.VERSION,
                    )

                rp_id = "sector-cut-010.example"
                client_data_hash = os.urandom(32)
                token = client_pin.get_pin_token(
                    pin,
                    permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
                    permissions_rpid=rp_id,
                )
                arm.touch()
                try:
                    ctap2.make_credential(
                        client_data_hash,
                        {"id": rp_id, "name": rp_id},
                        {"id": b"user-010", "name": "user-010", "displayName": "User 010"},
                        [{"type": "public-key", "alg": -7}],
                        options={"rk": True},
                        pin_uv_param=protocol.authenticate(token, client_data_hash),
                        pin_uv_protocol=protocol.VERSION,
                    )
                    raise RuntimeError(f"{label} page {cut_page}: power cut did not trigger")
                except (OSError, RuntimeError):
                    pass
                for _ in range(100):
                    if first.process is not None and first.process.poll() is not None:
                        break
                    time.sleep(0.01)
                if first.process is None or first.process.poll() != 97:
                    raise RuntimeError(
                        f"{label} page {cut_page}: expected emulator power-cut exit 97, "
                        f"got {None if first.process is None else first.process.poll()}"
                    )
            finally:
                if dev is not None:
                    try:
                        dev.close()
                    except OSError:
                        pass
                first.stop()
                arm.unlink(missing_ok=True)

            second = Emulator(binary, run_dir)
            second.start()
            dev = None
            try:
                dev, ctap2 = open_fido()
                client_pin = ClientPin(ctap2)
                token = client_pin.get_pin_token(
                    pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT
                )
                cred_mgmt = CredentialManagement(ctap2, protocol, token)
                metadata = cred_mgmt.get_metadata()
                rps = cred_mgmt.enumerate_rps()
                total = 0
                for rp in rps:
                    total += len(
                        cred_mgmt.enumerate_creds(
                            rp[CredentialManagement.RESULT.RP_ID_HASH]
                        )
                    )
                existing = metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
                if existing != total or len(rps) != total or total not in (10, 11):
                    raise RuntimeError(
                        f"{label} page {cut_page}: torn resident database "
                        f"metadata={existing} rps={len(rps)} credentials={total}"
                    )
            finally:
                if dev is not None:
                    dev.close()
                second.stop()

    print(f"FIDO sector/journal power-cut recovery: PASS x{len(cases)}")


def run(binary: Path, iterations: int, eddsa: bool) -> None:
    run_openpgp_init_fault_cycle(binary)
    run_oath_storage_fault_cycles(binary)
    run_fido_storage_fault_cycles(binary)
    run_fido_sector_power_cut_cycles(binary)
    for i in range(iterations):
        with tempfile.TemporaryDirectory(prefix="pico-oath-durable-") as tmp:
            run_oath_cycle(binary, Path(tmp))
        with tempfile.TemporaryDirectory(prefix="pico-fido-pin-durable-") as tmp:
            run_fido_pin_cycle(binary, Path(tmp))
        with tempfile.TemporaryDirectory(prefix="pico-fido-resident-ssh-es256-durable-") as tmp:
            run_fido_resident_ssh_cycle(binary, Path(tmp), -7, "ES256")
        if eddsa:
            with tempfile.TemporaryDirectory(prefix="pico-fido-resident-ssh-ed25519-durable-") as tmp:
                run_fido_resident_ssh_cycle(binary, Path(tmp), -8, "Ed25519")
        print(f"power-cycle durability iteration {i + 1}/{iterations}: PASS")

    print(f"OATH SET_CODE response durability: PASS x{iterations}")
    print("OATH persistent-write fail-closed behavior: PASS")
    print(f"FIDO ClientPin response durability: PASS x{iterations}")
    print(f"FIDO resident SSH credential durability: PASS x{iterations}")
    print("FIDO persistent-write fail-closed behavior: PASS")
    if eddsa:
        print(f"FIDO resident SSH Ed25519 credential durability: PASS x{iterations}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", type=Path, default=Path("build-host/pico_fido2"))
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--eddsa", action="store_true")
    args = parser.parse_args()
    if args.iterations < 1:
        raise SystemExit("--iterations must be >= 1")
    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"emulator binary not found: {binary}")
    run(binary, args.iterations, args.eddsa)


if __name__ == "__main__":
    main()
