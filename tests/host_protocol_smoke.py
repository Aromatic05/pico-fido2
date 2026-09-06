#!/usr/bin/env python3
"""Smoke-test the native emulator through its HID and raw APDU TCP transports."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CCID_PORT = 35963
HID_PORT = 35962
CTAPHID_INIT = 0x86
CTAPHID_MSG = 0x83
CTAPHID_OTP = 0xF0
CTAPHID_CBOR = 0x90
CTAPHID_KEEPALIVE = 0xBB
CTAPHID_ERROR = 0xBF


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


def hid_init_packet(cid: bytes, command: int, payload: bytes) -> bytes:
    if len(payload) > 57:
        raise ValueError("initial HID payload is too large")
    return (cid + bytes([command]) + struct.pack("!H", len(payload)) + payload).ljust(64, b"\0")


def parse_hid_init(packet: bytes) -> tuple[bytes, int, bytes]:
    if len(packet) != 64:
        raise RuntimeError(f"unexpected HID packet length: {len(packet)}")
    length = struct.unpack("!H", packet[5:7])[0]
    return packet[:4], packet[4], packet[7:7 + length]


def recv_hid_message(sock: socket.socket, expected_cid: bytes, expected_command: int) -> bytes:
    while True:
        packet = recv_frame(sock)
        cid, command, first = parse_hid_init(packet)
        if cid != expected_cid:
            raise RuntimeError(f"unexpected CID: {cid.hex()}")
        if command == CTAPHID_KEEPALIVE:
            continue
        if command == CTAPHID_ERROR:
            raise RuntimeError(f"CTAPHID_ERROR: {first.hex()}")
        if command != expected_command:
            raise RuntimeError(f"unexpected HID command: {command:#x}")

        total = struct.unpack("!H", packet[5:7])[0]
        data = bytearray(first)
        sequence = 0
        while len(data) < total:
            continuation = recv_frame(sock)
            if len(continuation) != 64 or continuation[:4] != expected_cid:
                raise RuntimeError("invalid HID continuation packet")
            if continuation[4] != sequence:
                raise RuntimeError("invalid HID continuation sequence")
            chunk = min(59, total - len(data))
            data += continuation[5:5 + chunk]
            sequence += 1
        return bytes(data[:total])


def fido_get_info(hid: socket.socket, cid: bytes) -> bytes:
    send_frame(hid, hid_init_packet(cid, CTAPHID_CBOR, b"\x04"))
    response = recv_hid_message(hid, cid, CTAPHID_CBOR)
    if not response or response[0] != 0x00:
        raise RuntimeError("CTAP2 authenticatorGetInfo failed")
    if len(response) < 2 or not 0xA0 <= response[1] <= 0xBF:
        raise RuntimeError("CTAP2 authenticatorGetInfo did not return a CBOR map")
    return response


def fido_get_pin_retries(hid: socket.socket, cid: bytes) -> bytes:
    request = bytes.fromhex("06a201010201")
    send_frame(hid, hid_init_packet(cid, CTAPHID_CBOR, request))
    response = recv_hid_message(hid, cid, CTAPHID_CBOR)
    if response != bytes.fromhex("00a10308"):
        raise RuntimeError(f"CTAP2 getPINRetries failed: {response.hex()}")
    return response


def hid_oath_apdu(hid: socket.socket, cid: bytes, apdu: bytes) -> bytes:
    send_frame(hid, hid_init_packet(cid, CTAPHID_OTP, apdu))
    return recv_hid_message(hid, cid, CTAPHID_OTP)


def hid_oath_list(hid: socket.socket, cid: bytes) -> bytes:
    response = hid_oath_apdu(hid, cid, bytes.fromhex("00A10000"))
    if not response.startswith(b"\x90\x00"):
        raise RuntimeError(f"HID OATH LIST failed: {response.hex()}")
    return response


def raw_apdu(sock: socket.socket, command: bytes) -> tuple[bytes, int]:
    send_frame(sock, command)
    response = recv_frame(sock)
    if len(response) < 2:
        raise RuntimeError("short APDU response")
    return response[:-2], int.from_bytes(response[-2:], "big")


def tlv_value(data: bytes, tag: int) -> bytes:
    pos = 0
    while pos + 2 <= len(data):
        current = data[pos]
        length = data[pos + 1]
        pos += 2
        if pos + length > len(data):
            break
        value = data[pos:pos + length]
        if current == tag:
            return value
        pos += length
    raise RuntimeError(f"TLV tag {tag:#x} not found in {data.hex()}")


def openpgp_get_data(ccid: socket.socket, tag: int, interleave=None) -> bytes:
    command = bytes([0x00, 0xCA, tag >> 8, tag & 0xFF, 0xFE])
    send_frame(ccid, command)
    response = recv_frame(ccid)
    data = bytearray()
    interleaved = False

    while True:
        if len(response) < 2:
            raise RuntimeError("short OpenPGP APDU response")
        sw1, sw2 = response[-2:]
        data += response[:-2]
        if (sw1, sw2) == (0x90, 0x00):
            return bytes(data)
        if sw1 != 0x61:
            raise RuntimeError(f"OpenPGP GET DATA failed: {sw1:02x}{sw2:02x}")
        if interleave is not None and not interleaved:
            interleave()
            interleaved = True
        send_frame(ccid, bytes([0x00, 0xC0, 0x00, 0x00, sw2]))
        response = recv_frame(ccid)


def run_smoke(binary: Path) -> None:
    ccid_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ccid_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ccid_server.bind(("127.0.0.1", CCID_PORT))
    ccid_server.listen(1)
    ccid_server.settimeout(5)

    with tempfile.TemporaryDirectory(prefix="pico-fido2-emulation-") as run_dir:
        log_path = Path(run_dir) / "emulator.log"
        with log_path.open("wb") as log:
            process = subprocess.Popen([str(binary)], cwd=run_dir, stdout=log, stderr=subprocess.STDOUT)

        hid = None
        ccid = None
        try:
            ccid, _ = ccid_server.accept()
            ccid.settimeout(5)

            for _ in range(100):
                try:
                    hid = socket.create_connection(("127.0.0.1", HID_PORT), timeout=0.2)
                    hid.settimeout(5)
                    break
                except OSError:
                    time.sleep(0.05)
            if hid is None:
                raise RuntimeError("HID emulator did not start")

            piv_select = bytes.fromhex("00A4040005A000000308")
            send_frame(ccid, piv_select)
            piv_select_response = recv_frame(ccid)
            if len(piv_select_response) < 2 or piv_select_response[-2] not in (0x61, 0x90):
                raise RuntimeError(f"PIV SELECT failed: {piv_select_response.hex()}")

            piv_version = bytes.fromhex("00FD0000")
            send_frame(ccid, piv_version)
            version_before = recv_frame(ccid)
            if not version_before.endswith(b"\x90\x00"):
                raise RuntimeError(f"PIV VERSION before HID failed: {version_before.hex()}")

            nonce = bytes.fromhex("0011223344556677")
            send_frame(hid, hid_init_packet(b"\xff" * 4, CTAPHID_INIT, nonce))
            _, command, init_payload = parse_hid_init(recv_frame(hid))
            if command != CTAPHID_INIT or init_payload[:8] != nonce or len(init_payload) < 17:
                raise RuntimeError("CTAPHID_INIT failed")
            if init_payload[13:16] != bytes([5, 7, 0]):
                raise RuntimeError(
                    f"CTAPHID_INIT advertised inconsistent firmware version: {init_payload[13:16].hex()}"
                )
            assigned_cid = init_payload[8:12]
            if assigned_cid in (b"\0" * 4, b"\xff" * 4):
                raise RuntimeError("invalid assigned CTAPHID CID")

            send_frame(ccid, piv_version)
            version_after_init = recv_frame(ccid)
            if version_after_init != version_before:
                raise RuntimeError(
                    "HID INIT changed the CCID application session: "
                    f"before={version_before.hex()} after={version_after_init.hex()}"
                )

            get_info = fido_get_info(hid, assigned_cid)
            print(f"FIDO2 GetInfo: PASS ({len(get_info) - 1} CBOR bytes)")

            fido_get_pin_retries(hid, assigned_cid)
            print("FIDO2 getPINRetries without configured PIN: PASS")

            send_frame(ccid, piv_version)
            version_after = recv_frame(ccid)
            if version_after != version_before:
                raise RuntimeError(
                    "HID CTAP2 changed the CCID application session: "
                    f"before={version_before.hex()} after={version_after.hex()}"
                )

            u2f_version = bytes.fromhex("0003000000")
            send_frame(hid, hid_init_packet(assigned_cid, CTAPHID_MSG, u2f_version))
            u2f_response = recv_hid_message(hid, assigned_cid, CTAPHID_MSG)
            if u2f_response != b"U2F_V2\x90\x00":
                raise RuntimeError(f"U2F VERSION failed: {u2f_response.hex()}")

            send_frame(ccid, piv_version)
            version_after_u2f = recv_frame(ccid)
            if version_after_u2f != version_before:
                raise RuntimeError(
                    "HID U2F changed the CCID application session: "
                    f"before={version_before.hex()} after={version_after_u2f.hex()}"
                )
            print("CCID PIV selection survives HID INIT/CTAP2/U2F: PASS")

            select = bytes.fromhex("00A4040006D27600012401")
            send_frame(ccid, select)
            select_response = recv_frame(ccid)
            if not select_response.endswith(b"\x90\x00"):
                raise RuntimeError("OpenPGP SELECT failed")

            def interleave_hid() -> None:
                fido_get_info(hid, assigned_cid)
                hid_oath_list(hid, assigned_cid)

            application_data = openpgp_get_data(ccid, 0x006E, interleave=interleave_hid)
            if not application_data.startswith(b"\x4f"):
                raise RuntimeError("unexpected OpenPGP application-related data")
            print(f"OpenPGP GET RESPONSE survives HID CTAP2/OATH: PASS ({len(application_data)} bytes)")

            # OATH access-code authentication belongs to the transport session.
            oath_aid = bytes.fromhex("A0000005272101")
            select_oath = bytes([0x00, 0xA4, 0x04, 0x00, len(oath_aid)]) + oath_aid
            _, sw = raw_apdu(ccid, select_oath)
            if sw != 0x9000:
                raise RuntimeError(f"CCID OATH SELECT failed: {sw:04x}")

            oath_key = b"kaka blahonga"
            setup_challenge = bytes(range(1, 9))
            setup_response = hmac.new(oath_key, setup_challenge, hashlib.sha1).digest()
            set_code_data = (
                bytes([0x73, len(oath_key) + 1, 0x21]) + oath_key
                + bytes([0x74, len(setup_challenge)]) + setup_challenge
                + bytes([0x75, len(setup_response)]) + setup_response
            )
            _, sw = raw_apdu(ccid, bytes([0x00, 0x03, 0x00, 0x00, len(set_code_data)]) + set_code_data)
            if sw != 0x9000:
                raise RuntimeError(f"CCID OATH SET CODE failed: {sw:04x}")

            select_data, sw = raw_apdu(ccid, select_oath)
            if sw != 0x9000:
                raise RuntimeError(f"CCID OATH reselect failed: {sw:04x}")
            device_challenge = tlv_value(select_data, 0x74)
            validate_response = hmac.new(oath_key, device_challenge, hashlib.sha1).digest()
            host_challenge = b"12345678"
            validate_data = (
                bytes([0x75, len(validate_response)]) + validate_response
                + bytes([0x74, len(host_challenge)]) + host_challenge
            )
            _, sw = raw_apdu(ccid, bytes([0x00, 0xA3, 0x00, 0x00, len(validate_data)]) + validate_data)
            if sw != 0x9000:
                raise RuntimeError(f"CCID OATH VALIDATE failed: {sw:04x}")
            _, sw = raw_apdu(ccid, bytes.fromhex("00A10000"))
            if sw != 0x9000:
                raise RuntimeError(f"CCID OATH LIST after validate failed: {sw:04x}")

            hid_oath = hid_oath_apdu(hid, assigned_cid, bytes.fromhex("00A10000"))
            if not hid_oath.endswith(b"\x69\x82"):
                raise RuntimeError(f"unvalidated HID OATH unexpectedly authorized: {hid_oath.hex()}")
            _, sw = raw_apdu(ccid, bytes.fromhex("00A10000"))
            if sw != 0x9000:
                raise RuntimeError(
                    "HID OATH changed the authenticated CCID OATH session: "
                    f"CCID LIST returned {sw:04x}"
                )
            print("CCID OATH authentication survives unvalidated HID OATH: PASS")

            hid_select = hid_oath_apdu(hid, assigned_cid, select_oath)
            if not hid_select.startswith(b"\x90\x00"):
                raise RuntimeError(f"HID OATH SELECT failed: {hid_select.hex()}")
            hid_challenge = tlv_value(hid_select[2:], 0x74)
            hid_validate_response = hmac.new(oath_key, hid_challenge, hashlib.sha1).digest()
            hid_validate_data = (
                bytes([0x75, len(hid_validate_response)]) + hid_validate_response
                + bytes([0x74, len(host_challenge)]) + host_challenge
            )
            hid_validate_apdu = bytes([0x00, 0xA3, 0x00, 0x00, len(hid_validate_data)]) + hid_validate_data
            hid_validate = hid_oath_apdu(hid, assigned_cid, hid_validate_apdu)
            if not hid_validate.startswith(b"\x90\x00"):
                raise RuntimeError(
                    "HID OATH validation did not survive transport dispatch selection: "
                    f"{hid_validate.hex()}"
                )
            hid_oath_list(hid, assigned_cid)
            _, sw = raw_apdu(ccid, bytes.fromhex("00A10000"))
            if sw != 0x9000:
                raise RuntimeError(f"HID OATH authentication changed CCID OATH: {sw:04x}")
            print("CCID and HID OATH authentication sessions are independent: PASS")
        except Exception:
            if log_path.exists():
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
                if log_text:
                    print("--- emulator log ---", file=sys.stderr)
                    print(log_text, file=sys.stderr, end="" if log_text.endswith("\n") else "\n")
            raise
        finally:
            if hid is not None:
                hid.close()
            if ccid is not None:
                ccid.close()
            ccid_server.close()
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", type=Path, default=Path("build-host/pico_fido2"))
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"emulator binary not found: {binary}")
    run_smoke(binary)


if __name__ == "__main__":
    main()
