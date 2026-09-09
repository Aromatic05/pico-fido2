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


def u2f_apdu(hid: socket.socket, cid: bytes, ins: int, p1: int = 0, p2: int = 0, data: bytes = b"") -> tuple[bytes, int]:
    apdu = struct.pack(">BBBBBH", 0, ins, p1, p2, 0, len(data)) + data + b"\0\0"
    send_frame(
        hid,
        (cid + bytes([CTAPHID_MSG]) + struct.pack("!H", len(apdu)) + apdu[:57]).ljust(64, b"\0"),
    )
    if len(apdu) > 57:
        remaining = apdu[57:]
        sequence = 0
        while remaining:
            chunk = remaining[:59]
            remaining = remaining[59:]
            send_frame(hid, (cid + bytes([sequence]) + chunk).ljust(64, b"\0"))
            sequence += 1
    response = recv_hid_message(hid, cid, CTAPHID_MSG)
    if len(response) < 2:
        raise RuntimeError("short U2F APDU response")
    return response[:-2], int.from_bytes(response[-2:], "big")


def u2f_register(hid: socket.socket, cid: bytes) -> tuple[bytes, bytes, bytes]:
    client = hashlib.sha256(b"reset-isolation-client").digest()
    app = hashlib.sha256(b"https://reset-isolation.invalid").digest()
    response, sw = u2f_apdu(hid, cid, 0x01, data=client + app)
    if sw != 0x9000:
        raise RuntimeError(f"U2F REGISTER failed: {sw:04x}")
    if len(response) < 67 or response[0] != 0x05 or response[1] != 0x04:
        raise RuntimeError(f"malformed U2F REGISTER response: {response[:80].hex()}")
    key_handle_len = response[66]
    if key_handle_len == 0 or len(response) < 67 + key_handle_len:
        raise RuntimeError("malformed U2F key handle")
    return client, app, response[67:67 + key_handle_len]


def u2f_check_key_handle(hid: socket.socket, cid: bytes, client: bytes, app: bytes, key_handle: bytes) -> int:
    _, sw = u2f_apdu(
        hid,
        cid,
        0x02,
        p1=0x07,
        data=client + app + bytes([len(key_handle)]) + key_handle,
    )
    return sw


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


def fido_reset(hid: socket.socket, cid: bytes) -> None:
    send_frame(hid, hid_init_packet(cid, CTAPHID_CBOR, b"\x07"))
    response = recv_hid_message(hid, cid, CTAPHID_CBOR)
    if response != b"\x00":
        raise RuntimeError(f"CTAP2 authenticatorReset failed: {response.hex()}")


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

            for ref, label in ((0x80, "PIN"), (0x81, "PUK")):
                metadata, sw = raw_apdu(ccid, bytes([0x00, 0xF7, 0x00, ref]))
                if sw != 0x9000:
                    raise RuntimeError(f"PIV {label} GET_METADATA failed: {sw:04x}")
                if tlv_value(metadata, 0x05) != b"\x01":
                    raise RuntimeError(f"PIV {label} default metadata is inconsistent: {metadata.hex()}")
                if tlv_value(metadata, 0x06) != b"\x03\x03":
                    raise RuntimeError(f"PIV {label} retry metadata is inconsistent: {metadata.hex()}")
            print("PIV PIN/PUK GET_METADATA: PASS")

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

            # OpenPGP and PIV share DEK storage but must never share an
            # authenticated session. Switching AIDs must unload the previous
            # applet so a stale wrapper selector cannot affect the new applet.
            pw3_switch = b"12345678"
            piv_pin_switch = b"123456\xff\xff"
            _, sw = raw_apdu(ccid, select)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP select before applet-switch test failed: {sw:04x}")
            _, sw = raw_apdu(
                ccid,
                bytes([0x00, 0x20, 0x00, 0x83, len(pw3_switch)]) + pw3_switch,
            )
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP PW3 verify before applet switch failed: {sw:04x}")
            _, sw = raw_apdu(ccid, piv_select)
            if sw not in (0x6100, 0x9000) and (sw >> 8) != 0x61:
                raise RuntimeError(f"PIV select during applet-switch test failed: {sw:04x}")
            _, sw = raw_apdu(ccid, select)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP reselect during applet-switch test failed: {sw:04x}")
            _, sw = raw_apdu(ccid, bytes.fromhex("00200083"))
            if sw == 0x9000:
                raise RuntimeError("OpenPGP PW3 authentication survived an applet switch")

            _, sw = raw_apdu(ccid, piv_select)
            if sw not in (0x6100, 0x9000) and (sw >> 8) != 0x61:
                raise RuntimeError(f"PIV reselect during applet-switch test failed: {sw:04x}")
            _, sw = raw_apdu(
                ccid,
                bytes([0x00, 0x20, 0x00, 0x80, len(piv_pin_switch)]) + piv_pin_switch,
            )
            if sw != 0x9000:
                raise RuntimeError(f"PIV PIN verify before applet switch failed: {sw:04x}")
            _, sw = raw_apdu(ccid, select)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP select after PIV verify failed: {sw:04x}")
            _, sw = raw_apdu(ccid, piv_select)
            if sw not in (0x6100, 0x9000) and (sw >> 8) != 0x61:
                raise RuntimeError(f"PIV select after OpenPGP switch failed: {sw:04x}")
            _, sw = raw_apdu(ccid, bytes.fromhex("00200080"))
            if sw == 0x9000:
                raise RuntimeError("PIV PIN authentication survived an applet switch")
            print("OpenPGP/PIV applet switches clear cross-applet authentication: PASS")

            # Cross-applet factory-reset isolation. A valid non-resident U2F
            # handle is the closest emulator analogue to the GitHub/Google
            # security-key registrations that were invalidated by a global
            # flash reset.
            client_hash, app_hash, key_handle = u2f_register(hid, assigned_cid)
            if u2f_check_key_handle(hid, assigned_cid, client_hash, app_hash, key_handle) != 0x6985:
                raise RuntimeError("new U2F key handle failed CHECK_ONLY before reset")

            # Give PIV a non-default PIN so OpenPGP reset must preserve PIV
            # state, not merely leave the applet selectable.
            _, sw = raw_apdu(ccid, piv_select)
            if sw not in (0x6100, 0x9000) and (sw >> 8) != 0x61:
                raise RuntimeError(f"PIV reselect failed: {sw:04x}")
            default_piv_pin = b"123456\xff\xff"
            changed_piv_pin = b"654321\xff\xff"
            _, sw = raw_apdu(
                ccid,
                bytes([0x00, 0x24, 0x00, 0x80, 16]) + default_piv_pin + changed_piv_pin,
            )
            if sw != 0x9000:
                raise RuntimeError(f"PIV PIN change failed: {sw:04x}")

            # Mirror ykman openpgp reset: select, authenticate PW3,
            # TERMINATE DF, ACTIVATE FILE.
            _, sw = raw_apdu(ccid, select)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP reselect failed: {sw:04x}")
            pw3 = b"12345678"
            _, sw = raw_apdu(ccid, bytes([0x00, 0x20, 0x00, 0x83, len(pw3)]) + pw3)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP PW3 verify failed: {sw:04x}")
            _, sw = raw_apdu(ccid, bytes.fromhex("00E60000"))
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP TERMINATE DF failed: {sw:04x}")
            _, sw = raw_apdu(ccid, bytes.fromhex("00440000"))
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP ACTIVATE FILE failed: {sw:04x}")

            u2f_after_openpgp = u2f_check_key_handle(hid, assigned_cid, client_hash, app_hash, key_handle)
            if u2f_after_openpgp != 0x6985:
                raise RuntimeError(
                    f"OpenPGP reset invalidated FIDO key handle: {u2f_after_openpgp:04x}"
                )
            _, sw = raw_apdu(ccid, piv_select)
            if sw not in (0x6100, 0x9000) and (sw >> 8) != 0x61:
                raise RuntimeError(f"PIV select after OpenPGP reset failed: {sw:04x}")
            _, sw = raw_apdu(
                ccid,
                bytes([0x00, 0x20, 0x00, 0x80, len(changed_piv_pin)]) + changed_piv_pin,
            )
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP reset changed PIV PIN: {sw:04x}")
            print("OpenPGP factory reset preserves FIDO identity and PIV PIN: PASS")

            # Store an OpenPGP-owned data object, then factory-reset PIV and
            # prove the OpenPGP object and FIDO root both survive.
            _, sw = raw_apdu(ccid, select)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP select before PIV reset failed: {sw:04x}")
            _, sw = raw_apdu(ccid, bytes([0x00, 0x20, 0x00, 0x83, len(pw3)]) + pw3)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP PW3 verify after reset failed: {sw:04x}")
            marker = b"reset-isolation"
            _, sw = raw_apdu(ccid, bytes([0x00, 0xDA, 0x00, 0x5B, len(marker)]) + marker)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP cardholder-name write failed: {sw:04x}")

            _, sw = raw_apdu(ccid, piv_select)
            if sw not in (0x6100, 0x9000) and (sw >> 8) != 0x61:
                raise RuntimeError(f"PIV select before factory reset failed: {sw:04x}")
            wrong = b"000000\xff\xff"
            for _ in range(3):
                raw_apdu(ccid, bytes([0x00, 0x20, 0x00, 0x80, len(wrong)]) + wrong)
            wrong_puk = b"00000000"
            replacement_pin = b"111111\xff\xff"
            for _ in range(3):
                raw_apdu(
                    ccid,
                    bytes([0x00, 0x24, 0x00, 0x81, 16]) + wrong_puk + replacement_pin,
                )
            _, sw = raw_apdu(ccid, bytes.fromhex("00FB0000"))
            if sw != 0x9000:
                raise RuntimeError(f"PIV factory reset failed: {sw:04x}")

            u2f_after_piv = u2f_check_key_handle(hid, assigned_cid, client_hash, app_hash, key_handle)
            if u2f_after_piv != 0x6985:
                raise RuntimeError(f"PIV reset invalidated FIDO key handle: {u2f_after_piv:04x}")
            _, sw = raw_apdu(ccid, select)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP select after PIV reset failed: {sw:04x}")
            name_after_piv = openpgp_get_data(ccid, 0x005B)
            if name_after_piv != marker:
                raise RuntimeError(
                    f"PIV reset changed OpenPGP cardholder data: {name_after_piv!r}"
                )
            print("PIV factory reset preserves FIDO identity and OpenPGP data: PASS")

            # authenticatorReset rotates FIDO state but must preserve the
            # sibling CCID applets that share the same physical flash store.
            _, sw = raw_apdu(ccid, piv_select)
            if sw not in (0x6100, 0x9000) and (sw >> 8) != 0x61:
                raise RuntimeError(f"PIV select before FIDO reset failed: {sw:04x}")
            post_reset_piv_pin = b"765432\xff\xff"
            _, sw = raw_apdu(
                ccid,
                bytes([0x00, 0x24, 0x00, 0x80, 16]) + default_piv_pin + post_reset_piv_pin,
            )
            if sw != 0x9000:
                raise RuntimeError(f"PIV PIN change before FIDO reset failed: {sw:04x}")

            fido_reset(hid, assigned_cid)
            if u2f_check_key_handle(hid, assigned_cid, client_hash, app_hash, key_handle) == 0x6985:
                raise RuntimeError("FIDO reset failed to invalidate the old FIDO key handle")

            _, sw = raw_apdu(ccid, select)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP select after FIDO reset failed: {sw:04x}")
            name_after_fido = openpgp_get_data(ccid, 0x005B)
            if name_after_fido != marker:
                raise RuntimeError(
                    f"FIDO reset changed OpenPGP cardholder data: {name_after_fido!r}"
                )

            _, sw = raw_apdu(ccid, piv_select)
            if sw not in (0x6100, 0x9000) and (sw >> 8) != 0x61:
                raise RuntimeError(f"PIV select after FIDO reset failed: {sw:04x}")
            _, sw = raw_apdu(
                ccid,
                bytes([0x00, 0x20, 0x00, 0x80, len(post_reset_piv_pin)]) + post_reset_piv_pin,
            )
            if sw != 0x9000:
                raise RuntimeError(f"FIDO reset changed PIV PIN: {sw:04x}")

            oath_after_fido, sw = raw_apdu(ccid, select_oath)
            if sw != 0x9000:
                raise RuntimeError(f"OATH select after FIDO reset failed: {sw:04x}")
            try:
                tlv_value(oath_after_fido, 0x74)
            except RuntimeError as exc:
                raise RuntimeError("FIDO reset erased the OATH access-code record") from exc
            _, sw = raw_apdu(ccid, bytes.fromhex("00A10000"))
            if sw != 0x6982:
                raise RuntimeError(
                    f"OATH access code was not enforced after FIDO reset: {sw:04x}"
                )
            print("FIDO factory reset rotates FIDO identity and preserves OpenPGP/PIV/OATH: PASS")

            # OATH reset is application-local. It must remove the OATH access
            # code while leaving FIDO, PIV and OpenPGP untouched.
            client_after_fido, app_after_fido, handle_after_fido = u2f_register(hid, assigned_cid)
            _, sw = raw_apdu(ccid, select_oath)
            if sw != 0x9000:
                raise RuntimeError(f"OATH select before reset failed: {sw:04x}")
            _, sw = raw_apdu(ccid, bytes.fromhex("0004DEAD"))
            if sw != 0x9000:
                raise RuntimeError(f"OATH factory reset failed: {sw:04x}")
            if u2f_check_key_handle(hid, assigned_cid, client_after_fido, app_after_fido, handle_after_fido) != 0x6985:
                raise RuntimeError("OATH reset invalidated FIDO key handle")
            _, sw = raw_apdu(ccid, piv_select)
            if sw not in (0x6100, 0x9000) and (sw >> 8) != 0x61:
                raise RuntimeError(f"PIV select after OATH reset failed: {sw:04x}")
            _, sw = raw_apdu(
                ccid,
                bytes([0x00, 0x20, 0x00, 0x80, len(post_reset_piv_pin)]) + post_reset_piv_pin,
            )
            if sw != 0x9000:
                raise RuntimeError(f"OATH reset changed PIV PIN: {sw:04x}")
            _, sw = raw_apdu(ccid, select)
            if sw != 0x9000 or openpgp_get_data(ccid, 0x005B) != marker:
                raise RuntimeError("OATH reset changed OpenPGP cardholder data")
            oath_after_reset, sw = raw_apdu(ccid, select_oath)
            if sw != 0x9000:
                raise RuntimeError(f"OATH reselect after reset failed: {sw:04x}")
            try:
                tlv_value(oath_after_reset, 0x74)
                raise RuntimeError("OATH reset left the access-code challenge active")
            except RuntimeError as exc:
                if "left the access-code" in str(exc):
                    raise
            _, sw = raw_apdu(ccid, bytes.fromhex("00A10000"))
            if sw != 0x9000:
                raise RuntimeError(f"OATH reset did not restore unlocked empty state: {sw:04x}")
            print("OATH factory reset preserves FIDO/PIV/OpenPGP: PASS")

            # HSM Auth reset must likewise be local. Change its management key,
            # reset it, then prove the default key works again and siblings survive.
            hsmauth_aid = bytes.fromhex("A000000527210701")
            select_hsmauth = bytes([0x00, 0xA4, 0x04, 0x00, len(hsmauth_aid)]) + hsmauth_aid
            _, sw = raw_apdu(ccid, select_hsmauth)
            if sw != 0x9000:
                raise RuntimeError(f"HSM Auth select failed: {sw:04x}")
            hsm_default = bytes(16)
            hsm_key_a = bytes(range(1, 17))
            hsm_key_b = bytes(range(17, 33))

            def hsm_change_key(old: bytes, new: bytes) -> int:
                data = bytes([0x7B, 16]) + old + bytes([0x7B, 16]) + new
                _, status = raw_apdu(ccid, bytes([0x00, 0x08, 0x00, 0x00, len(data)]) + data)
                return status

            if hsm_change_key(hsm_default, hsm_key_a) != 0x9000:
                raise RuntimeError("HSM Auth management-key setup failed")
            _, sw = raw_apdu(ccid, bytes.fromhex("0006DEAD"))
            if sw != 0x9000:
                raise RuntimeError(f"HSM Auth reset failed: {sw:04x}")
            if hsm_change_key(hsm_default, hsm_key_b) != 0x9000:
                raise RuntimeError("HSM Auth reset did not restore default management key")
            if u2f_check_key_handle(hid, assigned_cid, client_after_fido, app_after_fido, handle_after_fido) != 0x6985:
                raise RuntimeError("HSM Auth reset invalidated FIDO key handle")
            _, sw = raw_apdu(ccid, piv_select)
            if sw not in (0x6100, 0x9000) and (sw >> 8) != 0x61:
                raise RuntimeError(f"PIV select after HSM Auth reset failed: {sw:04x}")
            _, sw = raw_apdu(
                ccid,
                bytes([0x00, 0x20, 0x00, 0x80, len(post_reset_piv_pin)]) + post_reset_piv_pin,
            )
            if sw != 0x9000:
                raise RuntimeError(f"HSM Auth reset changed PIV PIN: {sw:04x}")
            _, sw = raw_apdu(ccid, select)
            if sw != 0x9000 or openpgp_get_data(ccid, 0x005B) != marker:
                raise RuntimeError("HSM Auth reset changed OpenPGP cardholder data")
            print("HSM Auth factory reset preserves FIDO/PIV/OpenPGP: PASS")

            # OpenPGP Reset Code owns a distinct DEK wrapper. Verify the
            # recovery path can use RC alone to replace PW1.
            _, sw = raw_apdu(ccid, select)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP select before Reset Code test failed: {sw:04x}")
            _, sw = raw_apdu(ccid, bytes([0x00, 0x20, 0x00, 0x83, len(pw3)]) + pw3)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP PW3 verify before Reset Code test failed: {sw:04x}")
            reset_code = b"87654321"
            _, sw = raw_apdu(ccid, bytes([0x00, 0xDA, 0x00, 0xD3, len(reset_code)]) + reset_code)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP Reset Code setup failed: {sw:04x}")
            new_pw1 = b"246810"
            reset_retry_data = reset_code + new_pw1
            _, sw = raw_apdu(
                ccid,
                bytes([0x00, 0x2C, 0x00, 0x81, len(reset_retry_data)]) + reset_retry_data,
            )
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP Reset Code recovery failed: {sw:04x}")
            _, sw = raw_apdu(ccid, bytes([0x00, 0x20, 0x00, 0x81, len(new_pw1)]) + new_pw1)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP PW1 did not change via Reset Code: {sw:04x}")
            print("OpenPGP Reset Code recovery: PASS")

            # Re-seed OATH so a management-level device reset has state in
            # every major applet to destroy.
            _, sw = raw_apdu(ccid, select_oath)
            if sw != 0x9000:
                raise RuntimeError(f"OATH select before device reset failed: {sw:04x}")
            reset_challenge = bytes(range(9, 17))
            reset_response = hmac.new(oath_key, reset_challenge, hashlib.sha1).digest()
            reset_code_data = (
                bytes([0x73, len(oath_key) + 1, 0x21]) + oath_key
                + bytes([0x74, len(reset_challenge)]) + reset_challenge
                + bytes([0x75, len(reset_response)]) + reset_response
            )
            _, sw = raw_apdu(
                ccid,
                bytes([0x00, 0x03, 0x00, 0x00, len(reset_code_data)]) + reset_code_data,
            )
            if sw != 0x9000:
                raise RuntimeError(f"OATH setup before device reset failed: {sw:04x}")

            full_client, full_app, full_handle = u2f_register(hid, assigned_cid)
            management_aid = bytes.fromhex("D2760000850101")
            select_management = bytes([0x00, 0xA4, 0x04, 0x00, len(management_aid)]) + management_aid
            _, sw = raw_apdu(ccid, select_management)
            if sw != 0x9000:
                raise RuntimeError(f"Management select failed: {sw:04x}")
            _, sw = raw_apdu(ccid, bytes.fromhex("001E0000"))
            if sw != 0x9000:
                raise RuntimeError(f"Management full-device reset failed: {sw:04x}")

            if u2f_check_key_handle(hid, assigned_cid, full_client, full_app, full_handle) == 0x6985:
                raise RuntimeError("Management device reset failed to rotate FIDO identity")
            _, sw = raw_apdu(ccid, piv_select)
            if sw not in (0x6100, 0x9000) and (sw >> 8) != 0x61:
                raise RuntimeError(f"PIV select after device reset failed: {sw:04x}")
            _, sw = raw_apdu(ccid, bytes([0x00, 0x20, 0x00, 0x80, len(default_piv_pin)]) + default_piv_pin)
            if sw != 0x9000:
                raise RuntimeError(f"Management device reset did not restore default PIV PIN: {sw:04x}")
            _, sw = raw_apdu(ccid, select)
            if sw != 0x9000:
                raise RuntimeError(f"OpenPGP select after device reset failed: {sw:04x}")
            if openpgp_get_data(ccid, 0x005B) != b"":
                raise RuntimeError("Management device reset preserved OpenPGP cardholder data")
            pw_status = openpgp_get_data(ccid, 0x00C4)
            if len(pw_status) < 7 or pw_status[5] != 0:
                raise RuntimeError(
                    f"OpenPGP factory state exposed RC retries: {pw_status.hex()}"
                )
            default_rc = b"12345678"
            forbidden_new_pw1 = b"135791"
            forbidden_reset = default_rc + forbidden_new_pw1
            _, sw = raw_apdu(
                ccid,
                bytes([0x00, 0x2C, 0x00, 0x81, len(forbidden_reset)]) + forbidden_reset,
            )
            if sw == 0x9000:
                raise RuntimeError("OpenPGP factory state exposed a default Reset Code")
            oath_after_device_reset, sw = raw_apdu(ccid, select_oath)
            if sw != 0x9000:
                raise RuntimeError(f"OATH select after device reset failed: {sw:04x}")
            try:
                tlv_value(oath_after_device_reset, 0x74)
                raise RuntimeError("Management device reset preserved OATH access code")
            except RuntimeError as exc:
                if "preserved OATH" in str(exc):
                    raise
            _, sw = raw_apdu(ccid, select_hsmauth)
            if sw != 0x9000:
                raise RuntimeError(f"HSM Auth select after device reset failed: {sw:04x}")
            if hsm_change_key(hsm_default, hsm_key_a) != 0x9000:
                raise RuntimeError("Management device reset preserved HSM Auth management key")
            print("Management device reset wipes FIDO/PIV/OpenPGP/OATH/HSM Auth: PASS")
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
