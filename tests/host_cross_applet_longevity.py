#!/usr/bin/env python3
"""Long-lived local regression across the combined Aromatic Key applets.

A single disposable emulator flash image is populated once, then reopened for
many deterministic pseudo-random cycles. Each cycle exercises FIDO, PIV,
OpenPGP, OATH, OTP and HSM Auth through their normal host-facing interfaces and
ends with an immediate process stop. The next cycle must observe the same
persistent identities and usable credentials.

This test is local-emulator only. It never accesses a physical device.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import random
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.ctap2 import CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from yubikit.hsmauth import HsmAuthSession
from yubikit.core.smartcard.scp import StaticKeys


ROOT = Path(__file__).resolve().parents[1]
DURABILITY = ROOT / "tests" / "host_powercycle_durability.py"
HSM_TEST = ROOT / "tests" / "host_hsmauth.py"
OTP_TEST = ROOT / "tests" / "otp_sector_powercut_matrix.py"

PIV_AID = bytes.fromhex("A000000308")
OPENPGP_AID = bytes.fromhex("D27600012401")
OATH_AID = bytes.fromhex("A0000005272101")

FIDO_PIN = "CrossApplet42"
FIDO_RP = {"id": "ssh:", "name": "OpenSSH"}
FIDO_USER = {
    "id": b"cross-applet-resident-user",
    "name": "cross-applet",
    "displayName": "Cross Applet SSH",
}
PIV_PIN_DEFAULT = b"123456\xff\xff"
PIV_PIN = b"654321\xff\xff"
OPENPGP_PW3_DEFAULT = b"12345678"
OPENPGP_PW3 = b"87654321"
OATH_NAME = b"cross-applet-oath"
OATH_SECRET = bytes([0x39]) * 20
HSM_LABEL = "cross-applet-hsm"
HSM_KEY_ENC = bytes(range(16))
HSM_KEY_MAC = bytes(range(16, 32))
HSM_PASSWORD = b"cross-applet-key"
HSM_CONTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load local test helper: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def select(module, sock, aid: bytes) -> bytes:
    body, sw = module.transmit(sock, module.apdu(0xA4, 0x04, 0x00, aid))
    out = bytearray(body)
    while (sw >> 8) == 0x61:
        body, sw = module.transmit(
            sock, bytes((0x00, 0xC0, 0x00, 0x00, sw & 0xFF))
        )
        out.extend(body)
    if sw != 0x9000:
        raise RuntimeError(f"SELECT {aid.hex()} failed: {sw:04x}")
    return bytes(out)


def establish_state(module, hsm, otp, binary: Path, run_dir: Path):
    emu = module.Emulator(binary, run_dir)
    dev = None
    try:
        emu.start()
        assert emu.ccid is not None

        dev, ctap2 = module.open_fido()
        client_pin = ClientPin(ctap2)
        client_pin.set_pin(FIDO_PIN)
        protocol = PinProtocolV2()
        client_hash = os.urandom(32)
        token = client_pin.get_pin_token(
            FIDO_PIN,
            permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
            permissions_rpid=FIDO_RP["id"],
        )
        made = ctap2.make_credential(
            client_data_hash=client_hash,
            rp=FIDO_RP,
            user=FIDO_USER,
            key_params=[{"type": "public-key", "alg": -7}],
            options={"rk": True},
            pin_uv_param=protocol.authenticate(token, client_hash),
            pin_uv_protocol=protocol.VERSION,
        )
        credential_id = made.auth_data.credential_data.credential_id
        public_key = dict(made.auth_data.credential_data.public_key)
        sign_counter = made.auth_data.counter
        dev.close()
        dev = None

        select(module, emu.ccid, PIV_AID)
        _, sw = module.transmit(
            emu.ccid, module.apdu(0x24, 0x00, 0x80, PIV_PIN_DEFAULT + PIV_PIN)
        )
        if sw != 0x9000:
            raise RuntimeError(f"PIV setup failed: {sw:04x}")

        select(module, emu.ccid, OPENPGP_AID)
        _, sw = module.transmit(
            emu.ccid,
            module.apdu(0x24, 0x00, 0x83, OPENPGP_PW3_DEFAULT + OPENPGP_PW3),
        )
        if sw != 0x9000:
            raise RuntimeError(f"OpenPGP setup failed: {sw:04x}")

        select(module, emu.ccid, OATH_AID)
        oath_put = (
            bytes((0x71, len(OATH_NAME))) + OATH_NAME
            + bytes((0x73, len(OATH_SECRET) + 2, 0x21, 6)) + OATH_SECRET
        )
        _, sw = module.transmit(emu.ccid, module.apdu(0x01, data=oath_put))
        if sw != 0x9000:
            raise RuntimeError(f"OATH setup failed: {sw:04x}")

        otp_payload, otp_key = otp.hmac_slot_payload()
        status = otp.select_otp(module, emu.ccid)
        if otp.slot1_configured(status):
            raise RuntimeError("OTP slot unexpectedly configured before setup")
        _, sw = module.transmit(
            emu.ccid, module.apdu(0x01, 0x01, 0x00, otp_payload)
        )
        if sw != 0x9000:
            raise RuntimeError(f"OTP setup failed: {sw:04x}")

        hsm_session = HsmAuthSession(hsm.TcpSmartCardConnection(emu.ccid))
        hsm_session.put_credential_symmetric(
            hsm.DEFAULT_MANAGEMENT_KEY,
            HSM_LABEL,
            HSM_KEY_ENC,
            HSM_KEY_MAC,
            HSM_PASSWORD,
        )

        return credential_id, public_key, sign_counter, otp_key
    finally:
        if dev is not None:
            try:
                dev.close()
            except OSError:
                pass
        emu.stop()


def verify_fido(module, expected_id: bytes, expected_public_key: dict[int, object],
                previous_counter: int) -> int:
    dev = None
    try:
        dev, ctap2 = module.open_fido()
        if not ctap2.get_info().options.get("clientPin", False):
            raise RuntimeError("FIDO PIN state disappeared")
        client_pin = ClientPin(ctap2)
        protocol = PinProtocolV2()
        mgmt_token = client_pin.get_pin_token(
            FIDO_PIN, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT
        )
        cm = CredentialManagement(ctap2, protocol, mgmt_token)
        rp_hash = hashlib.sha256(FIDO_RP["id"].encode()).digest()
        matches = [
            item for item in cm.enumerate_creds(rp_hash)
            if item[CredentialManagement.RESULT.CREDENTIAL_ID]["id"] == expected_id
        ]
        if len(matches) != 1:
            raise RuntimeError("resident SSH credential disappeared or duplicated")
        if dict(matches[0][CredentialManagement.RESULT.PUBLIC_KEY]) != expected_public_key:
            raise RuntimeError("resident SSH public key changed")

        assertion_hash = os.urandom(32)
        token = client_pin.get_pin_token(
            FIDO_PIN,
            permissions=ClientPin.PERMISSION.GET_ASSERTION,
            permissions_rpid=FIDO_RP["id"],
        )
        assertion = ctap2.get_assertion(
            rp_id=FIDO_RP["id"],
            client_data_hash=assertion_hash,
            pin_uv_param=protocol.authenticate(token, assertion_hash),
            pin_uv_protocol=protocol.VERSION,
        )
        if assertion.credential["id"] != expected_id:
            raise RuntimeError("resident SSH assertion selected a different credential")
        public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(expected_public_key[-2], "big"),
            int.from_bytes(expected_public_key[-3], "big"),
            ec.SECP256R1(),
        ).public_key()
        public.verify(
            assertion.signature,
            bytes(assertion.auth_data) + assertion_hash,
            ec.ECDSA(hashes.SHA256()),
        )
        counter = assertion.auth_data.counter
        if counter <= previous_counter:
            raise RuntimeError(
                f"FIDO sign counter did not advance: {previous_counter} -> {counter}"
            )
        return counter
    finally:
        if dev is not None:
            dev.close()


def verify_piv(module, sock) -> None:
    select(module, sock, PIV_AID)
    _, sw = module.transmit(sock, module.apdu(0x20, 0x00, 0x80, PIV_PIN))
    if sw != 0x9000:
        raise RuntimeError(f"PIV PIN became unusable: {sw:04x}")


def verify_openpgp(module, sock) -> None:
    select(module, sock, OPENPGP_AID)
    _, sw = module.transmit(sock, module.apdu(0x20, 0x00, 0x83, OPENPGP_PW3))
    if sw != 0x9000:
        raise RuntimeError(f"OpenPGP PW3 became unusable: {sw:04x}")


def verify_oath(module, sock) -> None:
    select(module, sock, OATH_AID)
    body, sw = module.transmit(sock, module.apdu(0xA1))
    if sw != 0x9000 or OATH_NAME not in body:
        raise RuntimeError("OATH credential disappeared")


def verify_otp(module, otp, sock, otp_key: bytes) -> None:
    status = otp.select_otp(module, sock)
    if not otp.slot1_configured(status):
        raise RuntimeError("OTP slot disappeared")
    otp.validate_recovered_new_state(module, sock, otp_key)


def verify_hsm(hsm, sock) -> None:
    session = HsmAuthSession(hsm.TcpSmartCardConnection(sock))
    listed = [item for item in session.list_credentials() if item.label == HSM_LABEL]
    if len(listed) != 1:
        raise RuntimeError("HSM Auth credential disappeared or duplicated")
    expected = StaticKeys(HSM_KEY_ENC, HSM_KEY_MAC).derive(HSM_CONTEXT)
    actual = session.calculate_session_keys_symmetric(
        HSM_LABEL, HSM_CONTEXT, HSM_PASSWORD
    )
    if actual[:3] != expected[:3]:
        raise RuntimeError("HSM Auth session keys changed")


def run(binary: Path, iterations: int, seed: int) -> None:
    module = load_module(DURABILITY, "host_powercycle_durability")
    hsm = load_module(HSM_TEST, "host_hsmauth")
    otp = load_module(OTP_TEST, "otp_sector_powercut_matrix")

    with tempfile.TemporaryDirectory(prefix="pico-cross-applet-long-") as tmp:
        run_dir = Path(tmp)
        credential_id, public_key, counter, otp_key = establish_state(
            module, hsm, otp, binary, run_dir
        )
        rng = random.Random(seed)

        for iteration in range(iterations):
            emu = module.Emulator(binary, run_dir)
            emu.start()
            try:
                assert emu.ccid is not None
                actions = ["fido", "piv", "openpgp", "oath", "otp", "hsm"]
                rng.shuffle(actions)
                for action in actions:
                    if action == "fido":
                        counter = verify_fido(module, credential_id, public_key, counter)
                    elif action == "piv":
                        verify_piv(module, emu.ccid)
                    elif action == "openpgp":
                        verify_openpgp(module, emu.ccid)
                    elif action == "oath":
                        verify_oath(module, emu.ccid)
                    elif action == "otp":
                        verify_otp(module, otp, emu.ccid, otp_key)
                    elif action == "hsm":
                        verify_hsm(hsm, emu.ccid)
                emu.hard_kill()
            finally:
                emu.stop()

        print(
            f"cross-applet local longevity: PASS x{iterations} "
            f"(seed={seed}, FIDO/PIV/OpenPGP/OATH/OTP/HSM Auth)"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--iterations", type=int, default=24)
    parser.add_argument("--seed", type=int, default=0xA20A71C)
    args = parser.parse_args()
    if args.iterations < 1:
        raise SystemExit("--iterations must be >= 1")
    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"emulator binary not found: {binary}")
    run(binary, args.iterations, args.seed)


if __name__ == "__main__":
    main()
