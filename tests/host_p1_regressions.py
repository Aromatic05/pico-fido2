#!/usr/bin/env python3
"""P1 regressions against the product Host emulator, never physical devices."""

import argparse
from contextlib import contextmanager
from pathlib import Path
import tempfile
import shlex
import subprocess
import hmac
import time
from unittest import TestCase
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, LargeBlobs, CredentialManagement
from fido2.ctap2.pin import PinProtocolV2

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


def run_c_test(binary, source, extra_sources=()):
    build = binary.parent
    flags_file = build / "CMakeFiles/pico_fido2.dir/flags.make"
    flags = dict(line.split(" = ", 1) for line in flags_file.read_text().splitlines() if " = " in line)
    with tempfile.TemporaryDirectory(prefix="p1-hotp-button-") as tmp:
        executable = Path(tmp) / "hotp-button"
        subprocess.run([
            "cc", *shlex.split(flags["C_DEFINES"]), *shlex.split(flags["C_INCLUDES"]),
            *shlex.split(flags["C_FLAGS"]), "--param=asan-globals=0", "-Wl,--gc-sections",
            str(Path(__file__).with_name(source)), *map(str, extra_sources),
            str(build / "libmbedtls.a"), "-o", str(executable),
        ], check=True)
        subprocess.run([str(executable)], check=True, cwd=tmp)


def r2_05(binary):
    with tempfile.TemporaryDirectory(prefix="p1-oath-source-") as tmp:
        oath_source = Path(__file__).resolve().parents[1] / "pico-fido/src/fido/oath.c"
        # Keep the real HMAC implementation; applet registration is unnecessary
        # in this isolated button test and would retain unrelated APDU handlers.
        oath = Path(tmp) / "oath.c"
        oath.write_text('#include "pico_keys.h"\n#undef INITIALIZER\n'
                        '#define INITIALIZER(f) static void __attribute__((unused)) f(void)\n'
                        f'#include "{oath_source}"\n')
        run_c_test(binary, "otp_hotp_button_test.c", [oath])


def h_03(binary):
    from host_hsmauth import TcpSmartCardConnection
    from yubikit.piv import PivSession, DEFAULT_MANAGEMENT_KEY, MANAGEMENT_KEY_TYPE
    with tempfile.TemporaryDirectory(prefix="p1-piv-management-") as tmp:
        directory = Path(tmp)
        with running(binary, directory) as emulator:
            piv = PivSession(TcpSmartCardConnection(emulator.ccid))
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.set_management_key(MANAGEMENT_KEY_TYPE.AES192, bytes(range(24)))
            piv.authenticate(bytes(range(24)))
        with running(binary, directory) as emulator:
            piv = PivSession(TcpSmartCardConnection(emulator.ccid))
            piv.authenticate(bytes(range(24)))
            piv.set_management_key(MANAGEMENT_KEY_TYPE.AES192, DEFAULT_MANAGEMENT_KEY)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)


def h_04(binary):
    with tempfile.TemporaryDirectory(prefix="p1-oath-verify-") as tmp:
        with running(binary, Path(tmp)) as emulator:
            command(emulator, 0xA4, 4, data=bytes.fromhex("A0000005272101"))
            secret = b"12345678901234567890"
            name = b"\x71\x04hotp"
            command(emulator, 1, data=name + b"\x73\x16\x11\x06" + secret)
            verify = name + b"\x75\x04" + (755224).to_bytes(4, "big")
            command(emulator, 0xB1, data=verify)
            challenge = b"12345678"
            key = b"access-code-key"
            command(emulator, 3, data=bytes((0x73, len(key) + 1, 0x21)) + key
                    + b"\x74\x08" + challenge + b"\x75\x14" + hmac.digest(key, challenge, "sha1"))
            selected = command(emulator, 0xA4, 4, data=bytes.fromhex("A0000005272101"))
            command(emulator, 0xA1, expected=0x6982)
            command(emulator, 0xB1, data=verify, expected=0x6982)
            offset = selected.index(b"\x74\x08") + 2
            command(emulator, 0xA3, data=b"\x75\x14" + hmac.digest(key, selected[offset:offset + 8], "sha1")
                    + b"\x74\x08" + challenge)
            command(emulator, 0xB1, data=verify)

    run_c_test(binary, "oath_verify_hotp_test.c", [Path(__file__).resolve().parents[1] / "pico-keys-sdk/src/asn1.c"])

def r5_03(binary):
    with tempfile.TemporaryDirectory(prefix="p1-import-length-") as tmp:
        with running(binary, Path(tmp)) as emulator:
            openpgp(emulator)
            malformed = bytes.fromhex("4D13B6007F4808910192019382FFFF5F4803030507")
            command(emulator, 0xDB, 0x3F, 0xFF, malformed, 0x6700)
            for length in range(5, len(P256_IMPORT)):
                command(emulator, 0xDB, 0x3F, 0xFF, P256_IMPORT[:length], 0x6700)
            command(emulator, 0xDA, p2=0xC1, data=P256_SIG)
            command(emulator, 0xDB, 0x3F, 0xFF, P256_IMPORT)
            assert len(command(emulator, 0x47, 0x81, data=b"\xB6\x00")) > 64


def rsa_import(key):
    from yubikit.core import Tlv
    numbers = key.private_numbers()
    values = [value.to_bytes((value.bit_length() + 7) // 8, "big")
              for value in (numbers.public_numbers.e, numbers.p, numbers.q)]
    descriptors = b"".join(bytes(Tlv(tag, value))[:-len(value)]
                           for tag, value in zip((0x91, 0x92, 0x93), values))
    return bytes(Tlv(0x4D, b"\xB6\x00" + Tlv(0x7F48, descriptors) + Tlv(0x5F48, b"".join(values))))


def r3_03(binary):
    from cryptography.hazmat.primitives.asymmetric import rsa
    oversized = rsa_import(rsa.generate_private_key(public_exponent=65537, key_size=5120))
    normal = rsa_import(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    with tempfile.TemporaryDirectory(prefix="p1-rsa-import-") as tmp:
        with running(binary, Path(tmp)) as emulator:
            openpgp(emulator)
            command(emulator, 0xDB, 0x3F, 0xFF, oversized, 0x6700)
            command(emulator, 0xDB, 0x3F, 0xFF, normal)
            public = command(emulator, 0x47, 0x81, data=b"\xB6\x00")
            command(emulator, 0xDA, p2=0xC1, data=bytes.fromhex("010400002000"))
            command(emulator, 0xDB, 0x3F, 0xFF, normal, 0x6700)
            command(emulator, 0xDA, p2=0xC1, data=bytes.fromhex("010800002000"))
            command(emulator, 0xDB, 0x3F, 0xFF, normal)
            assert command(emulator, 0x47, 0x81, data=b"\xB6\x00") == public


def ctap_error(expected, operation, *args, **kwargs):
    with TestCase().assertRaises(CtapError) as raised:
        operation(*args, **kwargs)
    assert raised.exception.code == expected, raised.exception


def make_fido(ctap, client_pin, resident=False):
    protocol = PinProtocolV2()
    token = client_pin.get_pin_token("Security42", permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
                                     permissions_rpid="p1.invalid")
    made = ctap.make_credential(bytes(32), {"id": "p1.invalid"}, {"id": b"user"},
                                [{"type": "public-key", "alg": -7}], options={"rk": resident},
                                pin_uv_param=protocol.authenticate(token, bytes(32)), pin_uv_protocol=2)
    return made.auth_data.credential_data.credential_id


def r4_03(binary):
    with tempfile.TemporaryDirectory(prefix="p1-ga-lbw-") as tmp:
        with running(binary, Path(tmp)):
            device, ctap = open_fido()
            with device:
                pin = ClientPin(ctap)
                pin.set_pin("Security42")
                credential = make_fido(ctap, pin)
                protocol = PinProtocolV2()
                for permissions in (ClientPin.PERMISSION.GET_ASSERTION,
                                    ClientPin.PERMISSION.GET_ASSERTION | ClientPin.PERMISSION.LARGE_BLOB_WRITE):
                    token = pin.get_pin_token("Security42", permissions=permissions)
                    ctap.get_assertion("p1.invalid", bytes(32),
                                       allow_list=[{"type": "public-key", "id": credential}],
                                       pin_uv_param=protocol.authenticate(token, bytes(32)), pin_uv_protocol=2)
                    blobs = LargeBlobs(ctap, protocol, token)
                    # Every token keeps exactly the permissions it was granted.
                    expected = {ClientPin.PERMISSION.GET_ASSERTION: 0x33,
                                ClientPin.PERMISSION.GET_ASSERTION | ClientPin.PERMISSION.LARGE_BLOB_WRITE: 0}
                    payload = cbor.encode([{"marker": b"after-assertion"}])
                    import hashlib
                    data = payload + hashlib.sha256(payload).digest()[:16]
                    message = bytes([0xFF]) * 32 + b"\x0C\x00" + bytes(4) + hashlib.sha256(data).digest()
                    result = device.call(CTAPHID.CBOR, b"\x0C" + cbor.encode({
                        2: data, 3: 0, 4: len(data), 5: protocol.authenticate(token, message), 6: 2,
                    }))
                    assert result[0] == expected[permissions], result.hex()
                assert LargeBlobs(ctap).read_blob_array() == [{"marker": b"after-assertion"}]


def r6_01(binary):
    import hashlib
    with tempfile.TemporaryDirectory(prefix="p1-preview-auth-") as tmp:
        with running(binary, Path(tmp)):
            device, ctap = open_fido()
            with device:
                pin = ClientPin(ctap)
                pin.set_pin("Security42")
                credential = make_fido(ctap, pin, True)
                protocol = PinProtocolV2()
                rp_hash = hashlib.sha256(b"p1.invalid").digest()
                descriptor = {"type": "public-key", "id": credential}
                params = {1: {}, 2: {}, 4: {1: rp_hash}, 6: {2: descriptor}}

                def request(opcode, subcommand, token, expected):
                    subparams = params[subcommand]
                    message = bytes((subcommand,)) + (cbor.encode(subparams) if subparams else b"")
                    body = {1: subcommand, 3: 2, 4: protocol.authenticate(token, message)}
                    body.update({2: subparams} if subparams else {})
                    result = device.call(CTAPHID.CBOR, bytes((opcode,)) + cbor.encode(body))
                    assert result[0] == expected, (opcode, subcommand, result.hex())

                ga = pin.get_pin_token("Security42", permissions=ClientPin.PERMISSION.GET_ASSERTION)
                for opcode in (0x0A, 0x41):
                    for subcommand in params:
                        request(opcode, subcommand, ga, 0x33)
                wrong_rp = pin.get_pin_token("Security42", permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT,
                                              permissions_rpid="other.invalid")
                for opcode in (0x0A, 0x41):
                    request(opcode, 4, wrong_rp, 0x33)
                    request(opcode, 6, wrong_rp, 0x33)
                cm = pin.get_pin_token("Security42", permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
                assert CredentialManagement(ctap, protocol, cm).get_metadata()[1] == 1
                for opcode in (0x0A, 0x41):
                    request(opcode, 1, cm, 0)
                    request(opcode, 4, cm, 0)
                scoped = pin.get_pin_token("Security42", permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT,
                                            permissions_rpid="p1.invalid")
                request(0x41, 6, scoped, 0)
                cm = pin.get_pin_token("Security42", permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
                assert CredentialManagement(ctap, protocol, cm).get_metadata()[1] == 0


CASES = {"R2-02": r2_02, "R2-03": r2_03, "R2-04": r2_04, "R2-05": r2_05,
         "H-03": h_03, "H-04": h_04, "R5-03": r5_03, "R3-03": r3_03, "R4-03": r4_03,
         "R6-01": r6_01}


def r3_04(binary):
    run_c_test(binary, "pin_token_timer_test.c")
    with tempfile.TemporaryDirectory(prefix="p1-token-expiry-") as tmp:
        with running(binary, Path(tmp)):
            device, ctap = open_fido()
            with device:
                pin = ClientPin(ctap)
                pin.set_pin("Security42")
                token = pin.get_pin_token("Security42", permissions=(ClientPin.PERMISSION.CREDENTIAL_MGMT
                                          | ClientPin.PERMISSION.MAKE_CREDENTIAL))
                protocol = PinProtocolV2()
                cm = CredentialManagement(ctap, protocol, token)
                assert cm.get_metadata()[1] == 0
                time.sleep(31)
                ctap_error(CtapError.ERR.PIN_AUTH_INVALID, cm.get_metadata)
                ctap_error(CtapError.ERR.PIN_AUTH_INVALID, ctap.make_credential,
                           bytes(32), {"id": "expired.invalid"}, {"id": b"user"},
                           [{"type": "public-key", "alg": -7}],
                           pin_uv_param=protocol.authenticate(token, bytes(32)), pin_uv_protocol=2)
                fresh = pin.get_pin_token("Security42", permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
                assert CredentialManagement(ctap, protocol, fresh).get_metadata()[1] == 0


CASES["R3-04"] = r3_04


def r5_04(binary):
    old = b"\x80\x08" + b"12345678"
    wrong = b"\x80\x08" + b"00000000"
    new = b"\x81\x08" + b"87654321"
    with tempfile.TemporaryDirectory(prefix="p1-oath-pin-block-") as tmp:
        directory = Path(tmp)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=bytes.fromhex("A0000005272101"))
            command(emulator, 0xB4, data=old)
            command(emulator, 0xB3, data=wrong + new, expected=0x6982)
            for _ in range(2):
                command(emulator, 0xB2, data=wrong, expected=0x6982)
            command(emulator, 0xB2, data=old, expected=0x6982)
            command(emulator, 0xB3, data=old + new, expected=0x6982)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=bytes.fromhex("A0000005272101"))
            command(emulator, 0xB3, data=old + new, expected=0x6982)
    with tempfile.TemporaryDirectory(prefix="p1-oath-pin-change-") as tmp:
        directory = Path(tmp)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=bytes.fromhex("A0000005272101"))
            command(emulator, 0xB4, data=old)
            command(emulator, 0xB3, data=old + new)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=bytes.fromhex("A0000005272101"))
            command(emulator, 0xB2, data=old, expected=0x6982)
            command(emulator, 0xB2, data=b"\x80\x08" + b"87654321")


CASES["R5-04"] = r5_04


def r3_06(binary):
    from otp_sector_powercut_matrix import crc16, yubiotp_slot_payload, read_live_dynamic_record
    config = bytearray(yubiotp_slot_payload()[:52])
    config[45] = 0x20
    config[46] = 0x40
    config[47] = 2
    config[50:52] = ((~crc16(config[:50])) & 0xFFFF).to_bytes(2, "little")
    with tempfile.TemporaryDirectory(prefix="p1-otp-update-counter-") as tmp:
        directory = Path(tmp)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=bytes.fromhex("A0000005272001"))
            command(emulator, 1, 1, data=bytes(config) + bytes(8))
        flash = directory / "memory.flash"
        image = bytearray(flash.read_bytes())
        record = flash_record(image, 0xBB00)
        counter = bytes.fromhex("0000000012345678")
        image[record + 72:record + 80] = counter
        flash.write_bytes(image)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=bytes.fromhex("A0000005272001"))
            update = bytearray(config)
            update[46] |= 0x20
            update[50:52] = ((~crc16(update[:50])) & 0xFFFF).to_bytes(2, "little")
            command(emulator, 1, 4, data=bytes(update) + bytes(6))
        stored = read_live_dynamic_record(flash, 0xBB00)
        assert len(stored) == 60
        assert stored[52:] == counter
        assert stored[46] == 0x60
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=bytes.fromhex("A0000005272001"))
        assert read_live_dynamic_record(flash, 0xBB00)[52:] == counter


CASES["R3-06"] = r3_06


def r3_07(binary):
    from otp_sector_powercut_matrix import crc16, hmac_slot_payload, read_live_dynamic_record
    def configuration(ext=0, ticket=0x40):
        data = bytearray(hmac_slot_payload()[0][:52])
        data[45] = ext
        data[46] = ticket
        data[50:52] = ((~crc16(data[:50])) & 0xFFFF).to_bytes(2, "little")
        return bytes(data)
    with tempfile.TemporaryDirectory(prefix="p1-otp-policy-") as tmp:
        directory = Path(tmp)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=bytes.fromhex("A0000005272001"))
            command(emulator, 1, 1, data=configuration() + bytes(8))
            before = read_live_dynamic_record(directory / "memory.flash", 0xBB00)
            command(emulator, 1, 4, data=configuration(0x20) + bytes(6), expected=0x6985)
            assert read_live_dynamic_record(directory / "memory.flash", 0xBB00) == before
            command(emulator, 1, 1, data=configuration(0x60) + bytes(8))
            command(emulator, 1, 0x30, data=b"challenge", expected=0x6985)
            command(emulator, 1, 4, data=configuration(0x20) + bytes(6))
            assert len(command(emulator, 1, 0x30, data=b"challenge")) == 20
            command(emulator, 1, 1, data=configuration(0x20, 0xC0) + bytes(8))
            command(emulator, 1, 3, data=configuration(0x20) + bytes(8), expected=0x6982)
            command(emulator, 1, 1, data=configuration(0x20) + bytes(8))
            command(emulator, 1, 3, data=configuration(0x20) + bytes(8))
            command(emulator, 1, 1, data=configuration(0x20, 0xC0) + bytes(8))
            command(emulator, 1, 5, data=configuration(0x20) + bytes(6), expected=0x6982)
            command(emulator, 1, 3, data=bytes(58), expected=0x6982)
            command(emulator, 1, 6, expected=0x6982)
            command(emulator, 1, 1, data=configuration(0x20) + bytes(8))
            command(emulator, 1, 3, data=configuration(0x20, 0xC0) + bytes(8))
            command(emulator, 1, 1, data=configuration(0x20, 0xC0) + bytes(8))
            command(emulator, 1, 5, data=configuration(0x20) + bytes(6))
    r2_05(binary)


CASES["R3-07"] = r3_07


def r4_04(binary):
    with tempfile.TemporaryDirectory(prefix="p1-openpgp-aes-") as tmp:
        directory = Path(tmp)
        with running(binary, directory) as emulator:
            openpgp(emulator)
            command(emulator, 0xDA, p2=0xC2, data=bytes.fromhex("122A8648CE3D030107"))
            command(emulator, 0x47, 0x80, data=b"\xB8\x00")
            plaintext = command(emulator, 0x2A, 0x80, 0x86, b"\x02" + bytes(16))
            assert len(plaintext) == 16
        with running(binary, directory) as emulator:
            openpgp(emulator)
            assert command(emulator, 0x2A, 0x80, 0x86, b"\x02" + bytes(16)) == plaintext
        with running(binary, directory, {"PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": "0x00D5"}) as emulator:
            openpgp(emulator)
            assert command(emulator, 0x47, 0x80, data=b"\xB8\x00", expected=0x6400) == b""
            assert "PICO_KEYS_EMU_FILE_PUT_FAULT fid=0x00d5" in emulator.log_path.read_text()


CASES["R4-04"] = r4_04


def r4_02(binary):
    with tempfile.TemporaryDirectory(prefix="p1-get-data-capacity-") as tmp:
        directory = Path(tmp)
        with running(binary, directory) as emulator:
            openpgp(emulator)
            command(emulator, 0xDA, p2=0x5B, data=b"N" * 2041)
            command(emulator, 0xDA, 0x5F, 0x2D, b"en" * 32)
        with running(binary, directory) as emulator:
            command(emulator, 0xA4, 4, data=OPENPGP_AID)
            assert command(emulator, 0xCA, p2=0x65, expected=0x6700) == b""
            command(emulator, 0x20, p2=0x83, data=b"12345678")
            command(emulator, 0xDA, p2=0x5B, data=b"Normal Name")
            assert b"Normal Name" in command(emulator, 0xCA, p2=0x65)
            command(emulator, 0xDA, p2=0xC7, data=b"F" * 64)
            command(emulator, 0xCA, p2=0xC5, expected=0x6700)
            command(emulator, 0xDA, p2=0xC7, data=b"F" * 20)
            assert command(emulator, 0xCA, p2=0xC5) == b"F" * 20 + bytes(40)
            assert command(emulator, 0xCA, p2=0xC6) == bytes(60)
            assert command(emulator, 0xCA, p2=0xCD) == bytes(12)
            for tag in (0x6E, 0xFA):
                response = command(emulator, 0xCA, p2=tag)
                assert response[:2] == bytes((tag, 0x82))
                assert int.from_bytes(response[2:4], "big") == len(response) - 4


CASES["R4-02"] = r4_02


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
