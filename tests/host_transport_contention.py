#!/usr/bin/env python3
"""Stress the shared command arbiter with concurrent HID and CCID traffic."""

from __future__ import annotations

import argparse
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from host_protocol_smoke import (
    CCID_PORT,
    HID_PORT,
    CTAPHID_CBOR,
    CTAPHID_ERROR,
    CTAPHID_INIT,
    CTAPHID_KEEPALIVE,
    hid_init_packet,
    parse_hid_init,
    recv_frame,
    send_frame,
)

CTAP1_ERR_CHANNEL_BUSY = 0x06


def hid_get_info_attempt(hid: socket.socket, cid: bytes) -> tuple[bool, int | None]:
    send_frame(hid, hid_init_packet(cid, CTAPHID_CBOR, b"\x04"))
    while True:
        packet = recv_frame(hid)
        response_cid, command, payload = parse_hid_init(packet)
        if response_cid != cid:
            raise RuntimeError(f"unexpected HID CID: {response_cid.hex()}")
        if command == CTAPHID_KEEPALIVE:
            continue
        if command == CTAPHID_ERROR:
            if len(payload) != 1:
                raise RuntimeError(f"invalid CTAPHID_ERROR payload: {payload.hex()}")
            return False, payload[0]
        if command != CTAPHID_CBOR:
            raise RuntimeError(f"unexpected HID command: {command:#x}")

        total = int.from_bytes(packet[5:7], "big")
        data = bytearray(payload)
        sequence = 0
        while len(data) < total:
            continuation = recv_frame(hid)
            if len(continuation) != 64 or continuation[:4] != cid:
                raise RuntimeError("invalid HID continuation packet")
            if continuation[4] != sequence:
                raise RuntimeError(
                    f"stale/invalid HID sequence: expected={sequence} got={continuation[4]}"
                )
            chunk = min(59, total - len(data))
            data += continuation[5 : 5 + chunk]
            sequence += 1
        if not data or data[0] != 0:
            raise RuntimeError(f"GetInfo CTAP status failed: {data[:8].hex()}")
        if len(data) < 2 or not 0xA0 <= data[1] <= 0xBF:
            raise RuntimeError(f"GetInfo response missing CBOR map: {data[:16].hex()}")
        return True, None


def raw_apdu(ccid: socket.socket, command: bytes) -> bytes:
    send_frame(ccid, command)
    response = recv_frame(ccid)
    if len(response) < 2:
        raise RuntimeError(f"short APDU response: {response.hex()}")
    return response


def run(binary: Path, iterations: int) -> None:
    ccid_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ccid_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ccid_server.bind(("127.0.0.1", CCID_PORT))
    ccid_server.listen(1)
    ccid_server.settimeout(5)

    with tempfile.TemporaryDirectory(prefix="pico-fido2-contention-") as run_dir:
        log_path = Path(run_dir) / "emulator.log"
        with log_path.open("wb") as log:
            process = subprocess.Popen(
                [str(binary)], cwd=run_dir, stdout=log, stderr=subprocess.STDOUT
            )

        ccid = None
        hid = None
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

            nonce = bytes.fromhex("1032547698badcfe")
            send_frame(hid, hid_init_packet(b"\xff" * 4, CTAPHID_INIT, nonce))
            _, command, init_payload = parse_hid_init(recv_frame(hid))
            if command != CTAPHID_INIT or init_payload[:8] != nonce or len(init_payload) < 17:
                raise RuntimeError("CTAPHID_INIT failed")
            cid = init_payload[8:12]

            # Select PIV with Le=0 so this path has an immediate, complete response.
            select = raw_apdu(ccid, bytes.fromhex("00A4040005A00000030800"))
            if not select.endswith(b"\x90\x00"):
                raise RuntimeError(f"PIV SELECT failed: {select.hex()}")

            start = threading.Barrier(3)
            errors: list[BaseException] = []
            hid_busy = 0
            hid_success = 0
            lock = threading.Lock()

            def hid_loop() -> None:
                nonlocal hid_busy, hid_success
                try:
                    start.wait()
                    for _ in range(iterations):
                        while True:
                            ok, error = hid_get_info_attempt(hid, cid)
                            if ok:
                                with lock:
                                    hid_success += 1
                                break
                            if error != CTAP1_ERR_CHANNEL_BUSY:
                                raise RuntimeError(
                                    f"HID contention returned non-BUSY error {error:#x}; "
                                    "stale INVALID_SEQ is forbidden"
                                )
                            with lock:
                                hid_busy += 1
                except BaseException as exc:  # preserve worker failure for main thread
                    errors.append(exc)

            def ccid_loop() -> None:
                try:
                    start.wait()
                    for _ in range(iterations):
                        response = raw_apdu(ccid, bytes.fromhex("00FD0000"))
                        if not response.endswith(b"\x90\x00"):
                            raise RuntimeError(f"PIV VERSION failed: {response.hex()}")
                except BaseException as exc:
                    errors.append(exc)

            hid_thread = threading.Thread(target=hid_loop, name="hid-contention")
            ccid_thread = threading.Thread(target=ccid_loop, name="ccid-contention")
            hid_thread.start()
            ccid_thread.start()
            start.wait()
            hid_thread.join(timeout=30)
            ccid_thread.join(timeout=30)

            if hid_thread.is_alive() or ccid_thread.is_alive():
                raise RuntimeError("contention stress deadlocked")
            if errors:
                raise errors[0]
            if hid_success != iterations:
                raise RuntimeError(f"HID completed {hid_success}/{iterations} requests")

            # Immediate post-contention retries prove neither transport inherited stale state.
            ok, error = hid_get_info_attempt(hid, cid)
            if not ok:
                raise RuntimeError(f"post-contention HID retry failed: {error:#x}")
            response = raw_apdu(ccid, bytes.fromhex("00FD0000"))
            if not response.endswith(b"\x90\x00"):
                raise RuntimeError(f"post-contention PIV VERSION failed: {response.hex()}")

            print(
                f"transport contention: PASS "
                f"(HID={hid_success}, CCID={iterations}, HID_BUSY={hid_busy})"
            )
        except Exception:
            if log_path.exists():
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
                if log_text:
                    print("--- emulator log ---")
                    print(log_text, end="" if log_text.endswith("\n") else "\n")
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
                process.wait(timeout=2)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--iterations", type=int, default=250)
    args = parser.parse_args()
    run(args.binary.resolve(), args.iterations)


if __name__ == "__main__":
    main()
