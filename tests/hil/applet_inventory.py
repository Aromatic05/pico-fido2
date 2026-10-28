#!/usr/bin/env python3
'Inventory and preserve a physical key baseline before destructive applet tests.'
import argparse
import sys

def smartcard():

    import argparse
    import hashlib
    import json
    import os
    from pathlib import Path

    from cryptography.hazmat.primitives import serialization
    from ykman.pcsc import list_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.piv import PivSession, SLOT
    from yubikit.openpgp import OpenPgpSession, KEY_REF
    from yubikit.oath import OathSession
    from yubikit.hsmauth import HsmAuthSession
    from yubikit.yubiotp import YubiOtpSession, SLOT as OTP_SLOT


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--output", required=True, type=Path)
        args = parser.parse_args()
        print("AUTHORIZATION: Owner-authorized Aromatic Key development F11 physical test.", flush=True)
        print("STAGE: READ-ONLY five-Applet inventory; NO RESET or PIN ATTEMPTS.", flush=True)
        cards = list_devices()
        if len(cards) != 1:
            raise RuntimeError(f"Expected exactly one 1050:0407 Key PCSC reader: {len(cards)}")
        with cards[0].open_connection(SmartCardConnection) as conn:
            piv = PivSession(conn)
            cert = piv.get_certificate(SLOT.ATTESTATION)
            piv_f9 = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
            print("F11_REAL_PIV_F9_CERT_SHA256", piv_f9, flush=True)

            pgp = OpenPgpSession(conn)
            sig = pgp.get_public_key(KEY_REF.SIG)
            pgp_sig = hashlib.sha256(sig.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )).hexdigest()
            print("F11_REAL_OPENPGP_SIG_PUBKEY_SHA256", pgp_sig, flush=True)

            oath = OathSession(conn)
            oath_items = sorted(x.id.hex() for x in oath.list_credentials())
            print("F11_REAL_OATH_CREDENTIAL_COUNT", len(oath_items), flush=True)

            hsm = HsmAuthSession(conn)
            hsm_items = sorted(x.label for x in hsm.list_credentials())
            print("F11_REAL_HSMAUTH_CREDENTIAL_COUNT", len(hsm_items), flush=True)

            otp = YubiOtpSession(conn)
            state = otp.get_config_state()
            otp_slots = [state.is_configured(OTP_SLOT.ONE), state.is_configured(OTP_SLOT.TWO)]
            print("F11_REAL_OTP_SLOT_CONFIG", otp_slots, flush=True)

        result = {
            "piv_f9_cert_sha256": piv_f9,
            "openpgp_sig_public_sha256": pgp_sig,
            "oath_credential_ids": oath_items,
            "hsmauth_labels": hsm_items,
            "otp_slots_configured": otp_slots,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temp = args.output.with_suffix(".tmp")
        fd = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as fp:
            json.dump(result, fp, indent=2, sort_keys=True)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(temp, args.output)
        print("F11_PHYSICAL_FIVE_APPLET_READ_ONLY_INVENTORY: PASS", flush=True)


    main()


def fido():

    import argparse
    import base64
    import hashlib
    import json
    from pathlib import Path

    from fido2 import cbor
    from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
    from fido2.ctap2.pin import PinProtocolV2
    from fido2.hid import CtapHidDevice


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--state-dir", required=True, type=Path)
        parser.add_argument("--f09-state", required=True, type=Path)
        args = parser.parse_args()
        print("AUTHORIZATION: Owner-authorized Aromatic Key HIL-A12 read-only physical preflight.", flush=True)
        print("SCOPE: SIX APPLETS' PRESENCE ONLY; NO RESET, NO PIN CHANGE, NO CREDENTIAL WRITE.", flush=True)
        test_pin = (args.state_dir / "real-card-test-pin.txt").read_text().strip()
        original = json.loads(args.f09_state.read_text())
        rp = original["rp"]
        devs = [dev for dev in CtapHidDevice.list_devices()
                if (dev.descriptor.vid, dev.descriptor.pid) == (0x1050, 0x0407)]
        if len(devs) != 1:
            for dev in devs:
                dev.close()
            raise RuntimeError(f"expected one physical developer Key, found {len(devs)}")
        dev = devs[0]
        try:
            ctap = Ctap2(dev)
            info = ctap.get_info()
            assert info.options.get("rk") is True and info.options.get("clientPin") is True
            assert info.options.get("credMgmt") is True
            cp = ClientPin(ctap)
            assert cp.get_pin_retries()[0] == 8
            token = cp.get_pin_token(test_pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
            manager = CredentialManagement(ctap, PinProtocolV2(), token)
            metadata = manager.get_metadata()
            existing = metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
            remaining = metadata[CredentialManagement.RESULT.MAX_REMAINING_COUNT]
            assert existing == 1 and remaining == 255, (existing, remaining)
            rp_hash = hashlib.sha256(rp.encode()).digest()
            matches = [item for item in manager.enumerate_creds(rp_hash)
                       if item[CredentialManagement.RESULT.CREDENTIAL_ID]["id"] == base64.b64decode(original["credential_id_b64"])]
            assert len(matches) == 1
            cred = matches[0]
            assert cred[CredentialManagement.RESULT.USER]["id"] == base64.b64decode(original["user_id_b64"])
            assert cbor.encode(dict(cred[CredentialManagement.RESULT.PUBLIC_KEY])) == base64.b64decode(original["public_key_cbor_b64"])
            print("A12_PHYSICAL_FIDO_RESIDENT_ID_USER_PUBLIC_KEY_AND_PIN_STABLE: PASS", flush=True)
            print(f"A12_PHYSICAL_FIDO_CREDENTIAL_MANAGEMENT: PASS count={existing} remaining={remaining} pin_retries=8", flush=True)
        finally:
            dev.close()


    main()


def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("case", choices=('smartcard', 'fido'))
    args, remaining = parser.parse_known_args()
    sys.argv = [sys.argv[0], *remaining]
    cases = {'smartcard': smartcard, 'fido': fido}
    cases[args.case]()


if __name__ == "__main__":
    main()
