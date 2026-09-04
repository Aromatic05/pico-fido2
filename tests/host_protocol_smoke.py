#!/usr/bin/env python3
"""Smoke-test the native emulator through its HID and raw APDU TCP transports."""

from __future__ import annotations

import argparse
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

CCID_PORT = 35963
HID_PORT = 35962
CTAPHID_INIT = 0x86
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


def openpgp_get_data(ccid: socket.socket, tag: int) -> bytes:
    command = bytes([0x00, 0xCA, tag >> 8, tag & 0xFF, 0xFE])
    send_frame(ccid, command)
    response = recv_frame(ccid)
    data = bytearray()

    while True:
        if len(response) < 2:
            raise RuntimeError("short OpenPGP APDU response")
        sw1, sw2 = response[-2:]
        data += response[:-2]
        if (sw1, sw2) == (0x90, 0x00):
            return bytes(data)
        if sw1 != 0x61:
            raise RuntimeError(f"OpenPGP GET DATA failed: {sw1:02x}{sw2:02x}")
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

            nonce = bytes.fromhex("0011223344556677")
            send_frame(hid, hid_init_packet(b"\xff" * 4, CTAPHID_INIT, nonce))
            _, command, init_payload = parse_hid_init(recv_frame(hid))
            if command != CTAPHID_INIT or init_payload[:8] != nonce or len(init_payload) < 17:
                raise RuntimeError("CTAPHID_INIT failed")
            assigned_cid = init_payload[8:12]
            if assigned_cid in (b"\0" * 4, b"\xff" * 4):
                raise RuntimeError("invalid assigned CTAPHID CID")

            send_frame(hid, hid_init_packet(assigned_cid, CTAPHID_CBOR, b"\x04"))
            get_info = recv_hid_message(hid, assigned_cid, CTAPHID_CBOR)
            if not get_info or get_info[0] != 0x00:
                raise RuntimeError("CTAP2 authenticatorGetInfo failed")
            if len(get_info) < 2 or not 0xA0 <= get_info[1] <= 0xBF:
                raise RuntimeError("CTAP2 authenticatorGetInfo did not return a CBOR map")
            print(f"FIDO2 GetInfo: PASS ({len(get_info) - 1} CBOR bytes)")

            select = bytes.fromhex("00A4040006D27600012401")
            send_frame(ccid, select)
            select_response = recv_frame(ccid)
            if not select_response.endswith(b"\x90\x00"):
                raise RuntimeError("OpenPGP SELECT failed")

            application_data = openpgp_get_data(ccid, 0x006E)
            if not application_data.startswith(b"\x4f"):
                raise RuntimeError("unexpected OpenPGP application-related data")
            print(f"OpenPGP SELECT/GET DATA: PASS ({len(application_data)} bytes)")
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
