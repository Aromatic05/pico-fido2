#!/usr/bin/env python3
"""P2 regressions against the product Host emulator, never physical devices."""

import argparse
import hmac
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from yubikit.core import Tlv

from host_p1_regressions import OPENPGP_AID, P256_IMPORT, P256_SIG, command, flash_record, openpgp, running
from host_powercycle_durability import OATH_AID
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


def r6_04(binary):
    from cryptography.hazmat.primitives.asymmetric import ec

    new_import = P256_IMPORT[:-32] + (2).to_bytes(32, "big")
    old_public = ec.derive_private_key(1, ec.SECP256R1()).public_key()
    new_public = ec.derive_private_key(2, ec.SECP256R1()).public_key()
    with TemporaryDirectory(prefix="p2-openpgp-first-import-") as tmp:
        directory = Path(tmp)
        with running(binary, directory) as emulator:
            openpgp(emulator)
            command(emulator, 0xDA, p2=0xC1, data=P256_SIG)
        with running(binary, directory, {"PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": "0x10d4"}) as emulator:
            openpgp(emulator)
            assert command(emulator, 0xDB, 0x3F, 0xFF, P256_IMPORT, 0x6400) == b""
            assert "PICO_KEYS_EMU_FILE_PUT_FAULT fid=0x10d4" in emulator.log_path.read_text()
        with running(binary, directory) as emulator:
            openpgp(emulator, 0x81)
            command(emulator, 0x47, 0x81, data=b"\xb6\x00", expected=0x6A88)
            with TestCase().assertRaisesRegex(AssertionError, "missing flash record 0x10d1"):
                flash_record((directory / "memory.flash").read_bytes(), 0x10D1)
    for fid in ("0x10d4", "0x0093", "0x10d1"):
        with TemporaryDirectory(prefix="p2-openpgp-import-") as tmp:
            directory = Path(tmp)
            with running(binary, directory) as emulator:
                openpgp(emulator)
                command(emulator, 0xDA, p2=0xC1, data=P256_SIG)
                command(emulator, 0xDB, 0x3F, 0xFF, P256_IMPORT)
                stored_public = command(emulator, 0x47, 0x81, data=b"\xb6\x00")
                command(emulator, 0x20, p2=0x81, data=b"123456")
                verify_openpgp_signature(emulator, old_public)
            with running(binary, directory, {"PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": fid}) as emulator:
                openpgp(emulator)
                assert command(emulator, 0xDB, 0x3F, 0xFF, new_import, 0x6400) == b""
                assert f"PICO_KEYS_EMU_FILE_PUT_FAULT fid={fid}" in emulator.log_path.read_text()
                assert command(emulator, 0x47, 0x81, data=b"\xb6\x00") == stored_public
                assert command(emulator, 0xCA, p2=0x93) == b"\x00\x00\x01"
            with running(binary, directory) as emulator:
                openpgp(emulator, 0x81)
                assert command(emulator, 0x47, 0x81, data=b"\xb6\x00") == stored_public
                assert command(emulator, 0xCA, p2=0x93) == b"\x00\x00\x01"
                verify_openpgp_signature(emulator, old_public)
                command(emulator, 0x20, p2=0x83, data=b"12345678")
                command(emulator, 0xDB, 0x3F, 0xFF, new_import)
                assert command(emulator, 0xCA, p2=0x93) == bytes(3)
                command(emulator, 0x20, p2=0x81, data=b"123456")
                verify_openpgp_signature(emulator, new_public)


OATH_SECRET = b"p2-test-oath-secret!"
OATH_CHALLENGE = bytes(range(8))


def oath_put(emulator, name):
    command(emulator, 1, data=Tlv(0x71, name) + Tlv(0x73, b"\x21\x06" + OATH_SECRET))


def oath_calculate(emulator, name, expected=0x9000):
    return command(emulator, 0xA2, data=Tlv(0x71, name) + Tlv(0x74, OATH_CHALLENGE), expected=expected)


def r6_05(binary):
    with TemporaryDirectory(prefix="p2-oath-rename-prefix-") as tmp:
        directory = Path(tmp)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=OATH_AID)
            oath_put(emulator, b"foo")
            command(emulator, 5, data=Tlv(0x71, b"foo") * 2, expected=0x6700)
            command(emulator, 5, data=Tlv(0x71, b"foo") + Tlv(0x71, b"foobar"))
            assert command(emulator, 0xA1) == Tlv(0x72, b"\x21foobar")
            oath_calculate(emulator, b"foo", expected=0x6984)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=OATH_AID)
            assert oath_calculate(emulator, b"foobar") == Tlv(
                0x75, b"\x06" + hmac.digest(OATH_SECRET, OATH_CHALLENGE, "sha1")
            )


def r4_05(binary):
    with TemporaryDirectory(prefix="p2-oath-rename-tlv-") as tmp:
        directory = Path(tmp)
        old_name, long_name, longest = b"old", b"n" * 128, b"x" * 253
        calculated = Tlv(0x75, b"\x06" + hmac.digest(OATH_SECRET, OATH_CHALLENGE, "sha1"))
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=OATH_AID)
            # A name is not necessarily the first tag in the stored record.
            command(emulator, 1, data=Tlv(0x73, b"\x21\x06" + OATH_SECRET) + Tlv(0x71, old_name))
            command(emulator, 5, data=Tlv(0x71, old_name) + Tlv(0x71, long_name))
            assert command(emulator, 0xA1) == bytes((0x72, 129, 0x21)) + long_name
            assert oath_calculate(emulator, long_name) == calculated
            oath_calculate(emulator, old_name, expected=0x6984)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=OATH_AID)
            assert oath_calculate(emulator, long_name) == calculated
            command(emulator, 5, data=Tlv(0x71, long_name) + Tlv(0x71, longest))
            assert command(emulator, 0xA1, data=b"\x01") == bytes((0x72, 255, 0x21)) + longest + b"\x00"
            command(emulator, 5, data=Tlv(0x71, longest) + Tlv(0x71, b"z" * 254), expected=0x6700)
            assert oath_calculate(emulator, longest) == calculated
            command(emulator, 5, data=Tlv(0x71, longest) + Tlv(0x71, old_name))
            assert oath_calculate(emulator, old_name) == calculated


def r5_08(binary):
    with TemporaryDirectory(prefix="p2-oath-delete-") as tmp:
        directory = Path(tmp)
        name = b"delete-fault"
        fault = {"PICO_KEYS_EMU_FAIL_FLASH_CLEAR_FID_ONCE": "0xba00"}
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=OATH_AID)
            oath_put(emulator, name)
        with running(binary, directory, fault) as emulator:
            command(emulator, 0xA4, 4, data=OATH_AID)
            command(emulator, 2, data=Tlv(0x71, name), expected=0x6400)
            assert "PICO_KEYS_EMU_FLASH_CLEAR_FAULT fid=0xba00" in emulator.log_path.read_text()
            assert command(emulator, 0xA1) == Tlv(0x72, b"\x21" + name)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=OATH_AID)
            assert command(emulator, 0xA1) == Tlv(0x72, b"\x21" + name)
            command(emulator, 2, data=Tlv(0x71, name))
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=OATH_AID)
            assert command(emulator, 0xA1) == b""

    def authenticate(emulator):
        selected = command(emulator, 0xA4, 4, data=OATH_AID)
        challenge = tlv_value(selected, 0x74)
        command(emulator, 0xA1, expected=0x6982)
        response = hmac.digest(OATH_SECRET, challenge, "sha1")
        command(emulator, 0xA3, data=Tlv(0x75, response) + Tlv(0x74, OATH_CHALLENGE))

    for payload in (b"", Tlv(0x73, b"")):
        with TemporaryDirectory(prefix="p2-oath-clear-code-") as tmp:
            directory = Path(tmp)
            fault = {"PICO_KEYS_EMU_FAIL_FLASH_CLEAR_FID_ONCE": "0xbaff"}
            response = hmac.digest(OATH_SECRET, OATH_CHALLENGE, "sha1")
            setup = Tlv(0x73, b"\x21" + OATH_SECRET) + Tlv(0x74, OATH_CHALLENGE) + Tlv(0x75, response)
            with running(binary, directory) as emulator:
                command(emulator, 0xA4, 4, data=OATH_AID)
                command(emulator, 3, data=setup)
            with running(binary, directory, fault) as emulator:
                authenticate(emulator)
                command(emulator, 3, data=payload, expected=0x6400)
                assert "PICO_KEYS_EMU_FLASH_CLEAR_FAULT fid=0xbaff" in emulator.log_path.read_text()
                command(emulator, 0xA4, 4, data=OATH_AID)
                command(emulator, 0xA1, expected=0x6982)
            with running(binary, directory) as emulator:
                authenticate(emulator)
                command(emulator, 3, data=payload)
            with running(binary, directory) as emulator:
                command(emulator, 0xA4, 4, data=OATH_AID)
                assert command(emulator, 0xA1) == b""


CASES = {
    "r5-07": r5_07,
    "r5-06": r5_06,
    "r6-03": r6_03,
    "r6-02": r6_02,
    "r5-05": r5_05,
    "r6-04": r6_04,
    "r6-05": r6_05,
    "r4-05": r4_05,
    "r5-08": r5_08,
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
