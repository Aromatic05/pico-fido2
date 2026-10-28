#!/usr/bin/env python3
'Prepare and verify durable sibling applet sentinels on a disposable physical key.'

import argparse
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from smartcard.Exceptions import CardConnectionException
from cryptography.hazmat.primitives import serialization
from ykman.pcsc import list_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.core.smartcard.scp import StaticKeys
from yubikit.piv import PivSession, SLOT
from yubikit.openpgp import OpenPgpSession, KEY_REF
from yubikit.oath import OathSession, CredentialData, OATH_TYPE, HASH_ALGORITHM
from yubikit.hsmauth import HsmAuthSession
from yubikit.yubiotp import YubiOtpSession, SLOT as OTP_SLOT, HmacSha1SlotConfiguration

OATH_NAME = "aromatic-f11-oath"
HSM_LABEL = "aromatic-f11-hsm"
OTP_CHALLENGE = bytes(range(32))
HSM_CONTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
OATH_TIMESTAMP = 1234567890


def load_state(path, baseline):
    if path.exists():
        return json.loads(path.read_text())
    state = {
        "owner_authorized": True,
        "piv_f9_cert_sha256": baseline["piv_f9_cert_sha256"],
        "openpgp_sig_public_sha256": baseline["openpgp_sig_public_sha256"],
        "oath_secret": secrets.token_bytes(20).hex(),
        "hsm_key_enc": secrets.token_bytes(16).hex(),
        "hsm_key_mac": secrets.token_bytes(16).hex(),
        "hsm_password": secrets.token_bytes(16).hex(),
        "otp_secret": secrets.token_bytes(20).hex(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    fd = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as fp:
        json.dump(state, fp)
        fp.flush()
        os.fsync(fp.fileno())
    os.replace(temp, path)
    return state


def verify(conn, state, skip=None):
    if skip != "piv":
        piv = PivSession(conn)
        cert = piv.get_certificate(SLOT.ATTESTATION)
        assert hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest() == state["piv_f9_cert_sha256"]
        print("F11_PHYSICAL_PIV_F9_CERTIFICATE_PRESERVED: PASS", flush=True)
    if skip != "openpgp":
        pgp = OpenPgpSession(conn)
        pub = pgp.get_public_key(KEY_REF.SIG)
        digest = hashlib.sha256(pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        assert digest == state["openpgp_sig_public_sha256"]
        print("F11_PHYSICAL_OPENPGP_SIG_PUBLIC_KEY_PRESERVED: PASS", flush=True)
    if skip != "oath":
        oath = OathSession(conn)
        creds = [x for x in oath.list_credentials() if x.name == OATH_NAME]
        assert len(creds) == 1
        code = oath.calculate_code(creds[0], timestamp=OATH_TIMESTAMP)
        counter = OATH_TIMESTAMP // 30
        mac = hmac.digest(bytes.fromhex(state["oath_secret"]), counter.to_bytes(8, "big"), "sha1")
        offset = mac[-1] & 15
        expected = (int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF) % 1000000
        assert code.value == f"{expected:06d}"
        print("F11_PHYSICAL_OATH_TOTP_INDEPENDENT_MATCH: PASS", flush=True)
    if skip != "hsm":
        hsm = HsmAuthSession(conn)
        assert len([x for x in hsm.list_credentials() if x.label == HSM_LABEL]) == 1
        actual = hsm.calculate_session_keys_symmetric(HSM_LABEL, HSM_CONTEXT, bytes.fromhex(state["hsm_password"]))
        expected_hsm = StaticKeys(bytes.fromhex(state["hsm_key_enc"]), bytes.fromhex(state["hsm_key_mac"])).derive(HSM_CONTEXT)
        assert actual[:3] == expected_hsm[:3]
        print("F11_PHYSICAL_HSM_AUTH_INDEPENDENT_SESSION_KEYS_MATCH: PASS", flush=True)
    if skip != "otp":
        otp = YubiOtpSession(conn)
        assert otp.get_config_state().is_configured(OTP_SLOT.ONE)
        actual = otp.calculate_hmac_sha1(OTP_SLOT.ONE, OTP_CHALLENGE)
        assert actual == hmac.digest(bytes.fromhex(state["otp_secret"]), OTP_CHALLENGE, "sha1")
        print("F11_PHYSICAL_OTP_HMAC_INDEPENDENT_MATCH: PASS", flush=True)
    if skip is None:
        print("F11_PHYSICAL_FIVE_SIBLING_APPLETS_HAVE_USABLE_TEST_SENTINELS: PASS", flush=True)


def prepare(conn, state):
    oath = OathSession(conn)
    if not any(x.name == OATH_NAME for x in oath.list_credentials()):
        oath.put_credential(CredentialData(
            OATH_NAME, OATH_TYPE.TOTP, HASH_ALGORITHM.SHA1,
            bytes.fromhex(state["oath_secret"]),
        ))
        print("F11_OATH_TEST_SENTINEL_WRITTEN: PASS", flush=True)
    hsm = HsmAuthSession(conn)
    if not any(x.label == HSM_LABEL for x in hsm.list_credentials()):
        hsm.put_credential_symmetric(
            bytes(16), HSM_LABEL, bytes.fromhex(state["hsm_key_enc"]),
            bytes.fromhex(state["hsm_key_mac"]), bytes.fromhex(state["hsm_password"]),
        )
        print("F11_HSM_TEST_SENTINEL_WRITTEN: PASS", flush=True)
    otp = YubiOtpSession(conn)
    if not otp.get_config_state().is_configured(OTP_SLOT.ONE):
        otp.put_configuration(OTP_SLOT.ONE, HmacSha1SlotConfiguration(bytes.fromhex(state["otp_secret"])))
        print("F11_OTP_TEST_SENTINEL_WRITTEN: PASS", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("prepare", "verify"), required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--post-reset-pcsc-retries", type=int, default=0)
    args = parser.parse_args()
    print("AUTHORIZATION: Owner-authorized Aromatic Key experimental prototype F11.", flush=True)
    print(f"STAGE: {args.mode} five Applet sentinels; NO FIDO Reset.", flush=True)
    state = load_state(args.state, json.loads(args.baseline.read_text())) if args.mode == "prepare" else json.loads(args.state.read_text())
    if args.post_reset_pcsc_retries < 0:
        raise ValueError("PCSC re-enumeration retries must not be negative")
    if args.post_reset_pcsc_retries and args.mode != "verify":
        raise ValueError("PCSC re-enumeration retries apply only to read-only verification")
    for attempt in range(args.post_reset_pcsc_retries + 1):
        try:
            cards = list_devices()
            if len(cards) != 1:
                raise RuntimeError(f"Expected one test key: {len(cards)}")
            with cards[0].open_connection(SmartCardConnection) as conn:
                if args.mode == "prepare":
                    prepare(conn, state)
                verify(conn, state)
            break
        except CardConnectionException:
            if attempt == args.post_reset_pcsc_retries:
                raise
            print(f"F11_PHYSICAL_PCSC_REENUMERATION_RETRY: {attempt + 1}/{args.post_reset_pcsc_retries}", flush=True)
            time.sleep(5)
    print(f"F11_PHYSICAL_FIVE_APPLET_{args.mode.upper()}_FULL_CHAIN: PASS", flush=True)


if __name__ == "__main__":
    main()
