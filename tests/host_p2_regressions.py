#!/usr/bin/env python3
"""P2 regressions against the product Host emulator, never physical devices."""

import argparse
from pathlib import Path
from tempfile import TemporaryDirectory

from host_p1_regressions import OPENPGP_AID, P256_IMPORT, P256_SIG, command, openpgp, running
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


def r6_02(binary):
    with TemporaryDirectory(prefix="p2-openpgp-pin-length-") as tmp:
        directory = Path(tmp)
        pw1, pw3, rc = b"123456", b"12345678", b"87654321"
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=OPENPGP_AID)
            for length in (128, 256):
                new_value = b"1" * length
                command(emulator, 0x24, p2=0x81, data=pw1 + new_value, expected=0x6700)
                command(emulator, 0x24, p2=0x83, data=pw3 + new_value, expected=0x6700)
                command(emulator, 0x20, p2=0x83, data=pw3)
                command(emulator, 0x2C, 2, 0x81, new_value, expected=0x6700)
                command(emulator, 0xDA, p2=0xD3, data=new_value, expected=0x6700)
            command(emulator, 0xDA, p2=0xD3, data=rc)
            command(emulator, 0x2C, p2=0x81, data=rc + b"1" * 256, expected=0x6700)
            command(emulator, 0x24, p2=0x81, data=pw1 + b"2" * 127)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=OPENPGP_AID)
            command(emulator, 0x20, p2=0x81, data=b"2" * 127)
            command(emulator, 0x20, p2=0x83, data=pw3)


def verify_openpgp_signature(emulator, public):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    digest = bytes(range(32))
    signature = command(emulator, 0x2A, 0x9E, 0x9A, digest)
    assert len(signature) == 64
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    public.verify(utils.encode_dss_signature(r, s), digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def r5_05(binary):
    from cryptography.hazmat.primitives.asymmetric import ec

    with TemporaryDirectory(prefix="p2-openpgp-reset-code-") as tmp:
        directory = Path(tmp)
        old_rc, new_rc, new_pw1 = b"87654321", b"765432109", b"654321"
        public = ec.derive_private_key(1, ec.SECP256R1()).public_key()
        with running(binary, directory) as emulator:
            openpgp(emulator)
            command(emulator, 0xDA, p2=0xC1, data=P256_SIG)
            command(emulator, 0xDB, 0x3F, 0xFF, P256_IMPORT)
            command(emulator, 0xDA, p2=0xD3, data=old_rc)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=OPENPGP_AID)
            command(emulator, 0x24, p2=0x82, data=old_rc + new_rc)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=OPENPGP_AID)
            command(emulator, 0x2C, p2=0x81, data=new_rc + new_pw1)
            command(emulator, 0x20, p2=0x81, data=new_pw1)
            verify_openpgp_signature(emulator, public)


CASES = {
    "r5-07": r5_07,
    "r5-06": r5_06,
    "r6-03": r6_03,
    "r6-02": r6_02,
    "r5-05": r5_05,
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
