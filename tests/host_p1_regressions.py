#!/usr/bin/env python3
"""P1 regressions against the product Host emulator, never physical devices."""

import argparse
from contextlib import contextmanager
from pathlib import Path
import tempfile

from host_powercycle_durability import Emulator, apdu, transmit, open_fido
from fido2 import cbor
from fido2.hid import CTAPHID


OPENPGP_AID = bytes.fromhex("D27600012401")
P256_SIG = bytes.fromhex("132A8648CE3D030107")
P256_IMPORT = bytes.fromhex("4D2AB6007F480292205F4820") + (1).to_bytes(32, "big")


@contextmanager
def running(binary, directory, env=None):
    emulator = Emulator(binary, directory, env)
    emulator.start()
    try:
        yield emulator
        assert emulator.process.poll() is None, emulator.log_tail()
        log = emulator.log_path.read_text(errors="replace")
        assert "AddressSanitizer" not in log, log
        assert "runtime error:" not in log, log
    finally:
        emulator.stop()


def command(emulator, ins, p1=0, p2=0, data=b"", expected=0x9000):
    body, sw = transmit(emulator.ccid, apdu(ins, p1, p2, data))
    result = bytearray(body)
    while sw >> 8 == 0x61:
        body, sw = transmit(emulator.ccid, bytes((0, 0xC0, 0, 0, sw & 0xFF)))
        result.extend(body)
    assert sw == expected, (hex(ins), hex(sw), hex(expected), bytes(result).hex())
    return bytes(result)


def openpgp(emulator, pin_ref=0x83):
    command(emulator, 0xA4, 4, data=OPENPGP_AID)
    pins = {0x81: b"123456", 0x83: b"12345678"}
    command(emulator, 0x20, p2=pin_ref, data=pins[pin_ref])


def r2_02(binary):
    with tempfile.TemporaryDirectory(prefix="p1-openpgp-admin-") as tmp:
        directory = Path(tmp)
        with running(binary, directory) as emulator:
            openpgp(emulator)
            command(emulator, 0xDA, p2=0xC1, data=P256_SIG)
        with running(binary, directory) as emulator:
            openpgp(emulator, 0x81)
            command(emulator, 0xDB, 0x3F, 0xFF, P256_IMPORT, 0x6982)
            command(emulator, 0xDA, p2=0xC1, data=bytes.fromhex("010800002000"), expected=0x6982)
            command(emulator, 0xDA, p2=0x5B, data=b"unauthorized", expected=0x6982)
            assert command(emulator, 0xCA, p2=0xC1) == P256_SIG
            assert command(emulator, 0xCA, p2=0x5B) == b""
            command(emulator, 0x20, p2=0x83, data=b"12345678")
            command(emulator, 0xDB, 0x3F, 0xFF, P256_IMPORT)
            assert len(command(emulator, 0x47, 0x81, data=b"\xB6\x00")) > 64


def r2_03(binary):
    for attributes in (P256_SIG, bytes.fromhex("010800002000")):
        with tempfile.TemporaryDirectory(prefix="p1-sign-counter-") as tmp:
            directory = Path(tmp)
            with running(binary, directory) as emulator:
                openpgp(emulator)
                command(emulator, 0xDA, p2=0xC1, data=attributes)
                command(emulator, 0x47, 0x80, data=b"\xB6\x00")
            fault = {"PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": "0x0093"}
            with running(binary, directory, fault) as emulator:
                openpgp(emulator, 0x81)
                assert command(emulator, 0x2A, 0x9E, 0x9A, bytes(32), 0x6400) == b""
                assert "PICO_KEYS_EMU_FILE_PUT_FAULT fid=0x0093" in emulator.log_path.read_text()
                assert command(emulator, 0xCA, p2=0x93) == bytes(3)
            with running(binary, directory) as emulator:
                openpgp(emulator, 0x81)
                assert len(command(emulator, 0x2A, 0x9E, 0x9A, bytes(32))) >= 64
                assert command(emulator, 0xCA, p2=0x93) == b"\x00\x00\x01"
            with running(binary, directory, fault) as emulator:
                openpgp(emulator)
                assert command(emulator, 0x47, 0x80, data=b"\xB6\x00", expected=0x6400) == b""
    with tempfile.TemporaryDirectory(prefix="p1-import-counter-") as tmp:
        directory = Path(tmp)
        with running(binary, directory) as emulator:
            openpgp(emulator)
            command(emulator, 0xDA, p2=0xC1, data=P256_SIG)
        with running(binary, directory, fault) as emulator:
            openpgp(emulator)
            assert command(emulator, 0xDB, 0x3F, 0xFF, P256_IMPORT, 0x6400) == b""


def flash_record(image, fid):
    root = len(image) - 16 - 4 * 4096 - 12
    address = int.from_bytes(image[root:root + 8], "little")
    visited = set()
    while address:
        assert 16 * 4096 <= address < root and address not in visited
        visited.add(address)
        if int.from_bytes(image[address + 16:address + 18], "little") == fid:
            return address
        address = int.from_bytes(image[address:address + 8], "little")
    raise AssertionError(f"missing flash record {fid:#x}")


def r2_04(binary):
    with tempfile.TemporaryDirectory(prefix="p1-root-key-") as tmp:
        directory = Path(tmp)
        with running(binary, directory):
            with open_fido()[0] as device:
                request = b"\x01" + cbor.encode({
                    1: bytes(32), 2: {"id": "root-key.invalid"},
                    3: {"id": b"user"}, 4: [{"type": "public-key", "alg": -7}],
                })
                assert device.call(CTAPHID.CBOR, request)[0] == 0
        flash = directory / "memory.flash"
        original = flash.read_bytes()
        record = flash_record(original, 0xCC00)
        assert int.from_bytes(original[record + 18:record + 20], "little") == 33
        for length, marker in ((1, 1), (31, 1), (33, 0xFF), (33, 2)):
            image = bytearray(original)
            image[record + 18:record + 20] = length.to_bytes(2, "little")
            image[record + 20] = marker
            flash.write_bytes(image)
            with running(binary, directory):
                with open_fido()[0] as device:
                    assert device.call(CTAPHID.CBOR, request)[0] == 0x7F, (length, marker)


CASES = {"R2-02": r2_02, "R2-03": r2_03, "R2-04": r2_04}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("case", choices=[*CASES, "all"])
    args = parser.parse_args()
    selected = CASES if args.case == "all" else {args.case: CASES[args.case]}
    for name, run in selected.items():
        run(args.binary.resolve())
        print(f"{name}: PASS", flush=True)


if __name__ == "__main__":
    main()
