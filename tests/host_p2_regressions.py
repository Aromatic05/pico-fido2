#!/usr/bin/env python3
"""P2 regressions against the product Host emulator, never physical devices."""

import argparse
from pathlib import Path
from tempfile import TemporaryDirectory

from host_p1_regressions import command, running
from host_protocol_smoke import tlv_value


def r5_07(binary):
    from host_hsmauth import TcpSmartCardConnection
    from yubikit.piv import DEFAULT_MANAGEMENT_KEY, MANAGEMENT_KEY_TYPE, PivSession

    with TemporaryDirectory(prefix="p2-piv-metadata-") as tmp:
        directory = Path(tmp)
        key = DEFAULT_MANAGEMENT_KEY + bytes(8)
        with running(binary, directory) as emulator:
            piv = PivSession(TcpSmartCardConnection(emulator.ccid))
            assert tlv_value(command(emulator, 0xF7, p2=0x9B), 5) == b"\x01"
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.set_management_key(MANAGEMENT_KEY_TYPE.AES256, key)
            metadata = command(emulator, 0xF7, p2=0x9B)
            assert tlv_value(metadata, 1) == b"\x0c"
            assert tlv_value(metadata, 5) == b"\x00"
        with running(binary, directory) as emulator:
            piv = PivSession(TcpSmartCardConnection(emulator.ccid))
            piv.authenticate(key)
            assert tlv_value(command(emulator, 0xF7, p2=0x9B), 5) == b"\x00"


def r5_06(binary):
    from unittest import TestCase
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from host_hsmauth import TcpSmartCardConnection
    from yubikit.core.smartcard import ApduError
    from yubikit.piv import DEFAULT_MANAGEMENT_KEY, KEY_TYPE, PIN_POLICY, SLOT, TOUCH_POLICY, PivSession

    with TemporaryDirectory(prefix="p2-piv-verify-") as tmp, running(binary, Path(tmp)) as emulator:
        piv = PivSession(TcpSmartCardConnection(emulator.ccid))
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        slot, key_type = SLOT.AUTHENTICATION, KEY_TYPE.ECCP256
        public = piv.generate_key(slot, key_type, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        message = b"PIV VERIFY reset"
        piv.verify_pin("123456")
        public.verify(piv.sign(slot, key_type, message, hashes.SHA256()), message, ec.ECDSA(hashes.SHA256()))
        command(emulator, 0x20, 0xFF, 0x80)
        command(emulator, 0x20, 0x00, 0x80, expected=0x63C3)
        with TestCase().assertRaises(ApduError) as rejected:
            piv.sign(slot, key_type, message, hashes.SHA256())
        assert rejected.exception.sw == 0x6982
        piv.verify_pin("123456")
        public.verify(piv.sign(slot, key_type, message, hashes.SHA256()), message, ec.ECDSA(hashes.SHA256()))


def r6_03(binary):
    with TemporaryDirectory(prefix="p2-piv-pin-length-") as tmp:
        directory = Path(tmp)
        pin = b"123456\xff\xff"
        puk = b"12345678"
        new_pin = b"654321\xff\xff"
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=bytes.fromhex("A000000308"))
            for length in (256, 264):
                new_value = b"1" * length
                command(emulator, 0x24, p2=0x80, data=pin + new_value, expected=0x6700)
                command(emulator, 0x24, p2=0x81, data=puk + new_value, expected=0x6700)
                command(emulator, 0x2C, p2=0x80, data=puk + new_value, expected=0x6700)
            command(emulator, 0x20, p2=0x80, data=pin)
            command(emulator, 0x24, p2=0x80, data=pin + new_pin)
            command(emulator, 0x20, p2=0x80, data=new_pin)
            command(emulator, 0x2C, p2=0x80, data=puk + pin)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=bytes.fromhex("A000000308"))
            command(emulator, 0x20, p2=0x80, data=pin)


CASES = {
    "r5-07": r5_07,
    "r5-06": r5_06,
    "r6-03": r6_03,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("case", choices=[*CASES, "all"])
    args = parser.parse_args()
    cases = CASES if args.case == "all" else (args.case,)
    for case in cases:
        CASES[case](args.binary.resolve())
        print(f"PASS {case}")


if __name__ == "__main__":
    main()
