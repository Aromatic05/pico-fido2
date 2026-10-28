#!/usr/bin/env python3
'Scoped physical applet reset, restoration and sibling isolation checks on disposable test state.'
import argparse
import sys

def fido():

    import argparse
    import time
    from datetime import datetime, timedelta
    from pathlib import Path

    from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
    from fido2.ctap2.pin import PinProtocolV2
    from fido2.hid import CtapHidDevice

    VID = "1050"
    PID = "0407"


    def key_devnum():
        for child in Path("/sys/bus/usb/devices").iterdir():
            try:
                if (child / "idVendor").read_text().strip() == VID and (child / "idProduct").read_text().strip() == PID:
                    return int((child / "devnum").read_text())
            except (FileNotFoundError, NotADirectoryError):
                pass
        return None


    def open_hid(wait_seconds=0):
        deadline = time.monotonic() + wait_seconds
        while True:
            matches = [
                d for d in CtapHidDevice.list_devices()
                if (d.descriptor.vid, d.descriptor.pid) == (0x1050, 0x0407)
            ]
            if len(matches) == 1:
                return matches[0]
            for dev in matches:
                dev.close()
            if time.monotonic() >= deadline:
                raise RuntimeError(f"expected one developer Key: {len(matches)}")
            time.sleep(0.12)


    def reset_once():
        print("AUTHORIZATION: Owner-authorized Aromatic Key physical development F11.", flush=True)
        print("SCOPE: Device holds ONLY disposable test data; CTAP2 FIDO-only Reset is explicitly authorized.", flush=True)
        print("PROTECTED: Non-FIDO five Applets and SecureBoot/eFuse/firmware are not reset.", flush=True)
        print("USER-PRESENCE: Real hardware BOOT input required; no bypass or mock.", flush=True)

        old_devnum = key_devnum()
        assert old_devnum is not None
        dev = open_hid()
        try:
            info = Ctap2(dev).get_info()
            assert info.options.get("clientPin") is True and info.options.get("rk") is True
        finally:
            dev.close()
        print(f"F11_REAL_PRE_RESET_HID_PRESENT: PASS devnum={old_devnum}", flush=True)

        # Observe a real physical USB power cycle before sending one Reset.
        # This avoids v59's deliberately disabled USB maintenance shortcut.
        expires_at = datetime.now().astimezone() + timedelta(minutes=30)
        print("F11_REAL_WAIT_FOR_OWNER_PHYSICAL_USB_UNPLUG_AND_REPLUG", flush=True)
        print(f"F11_REAL_ARMED_UNTIL: {expires_at.isoformat(timespec='seconds')}", flush=True)
        deadline = time.monotonic() + 1800
        newer = None
        while time.monotonic() < deadline:
            newer = key_devnum()
            if newer is not None and newer != old_devnum:
                break
            time.sleep(0.06)
        else:
            raise RuntimeError("no physical USB replug observed; no Reset was sent")
        print(f"F11_REAL_PHYSICAL_REPLUG_REENUMERATED: PASS devnum={newer}", flush=True)

        dev = open_hid(wait_seconds=7)
        try:
            ctap = Ctap2(dev)
            printed = set()
            def keepalive(code):
                status = str(code)
                if status not in printed:
                    printed.add(status)
                    print(f"F11_REAL_RESET_KEEPALIVE_{status}: WAITING_FOR_DEVICE", flush=True)
            print("F11_REAL_CTAP2_AUTHENTICATOR_RESET_APDU_BEGIN; TOUCH_BOOT_ON_KEY_NOW", flush=True)
            ctap.reset(on_keepalive=keepalive)
            print("F11_REAL_CTAP2_FIDO_ONLY_RESET_RETURNED_SUCCESS: PASS", flush=True)
        finally:
            dev.close()


    def verify_post_reset(new_pin):
        print("AUTHORIZATION: Owner-authorized F11 post-Reset verification and FIDO reinitialization.", flush=True)
        dev = open_hid(wait_seconds=12)
        try:
            ctap = Ctap2(dev)
            info = ctap.get_info()
            assert info.options.get("clientPin") is False and info.options.get("rk") is True
            print("F11_REAL_OLD_FIDO_PIN_CLEARED: PASS", flush=True)
            cp = ClientPin(ctap)
            cp.set_pin(new_pin)
            assert cp.get_pin_retries()[0] == 8
            protocol = PinProtocolV2()
            token = cp.get_pin_token(new_pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
            cm = CredentialManagement(ctap, protocol, token)
            meta = cm.get_metadata()
            count = meta[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
            remaining = meta[CredentialManagement.RESULT.MAX_REMAINING_COUNT]
            assert count == 0 and remaining == 256, (count, remaining)
            print(f"F11_REAL_ORIGINAL_THREE_RESIDENT_CLEARED: PASS count={count} remaining={remaining}", flush=True)
            print("F11_REAL_NEW_PIN_INITIALIZED_AND_EIGHT_RETRIES: PASS", flush=True)
        finally:
            dev.close()


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--action", choices=("reset", "post"), required=True)
        parser.add_argument("--state-dir", type=Path, required=True)
        args = parser.parse_args()
        if args.action == "reset":
            reset_once()
        else:
            pin = (args.state_dir / "real-card-test-pin.txt").read_text().strip()
            verify_post_reset(pin)


    main()


def fido_recover():

    import argparse
    import json
    import os
    import time
    from pathlib import Path

    from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
    from fido2.ctap2.pin import PinProtocolV2
    from fido2.hid import CtapHidDevice


    def physical_usb_device_number():
        matched = []
        for directory in Path("/sys/bus/usb/devices").iterdir():
            if not (directory / "idVendor").exists():
                continue
            if ((directory / "idVendor").read_text().strip(),
                (directory / "idProduct").read_text().strip()) == ("1050", "0407"):
                matched.append(int((directory / "devnum").read_text()))
        assert len(matched) == 1, matched
        return matched[0]


    def open_hid(wait=0):
        until = time.monotonic() + wait
        while True:
            cards = [device for device in CtapHidDevice.list_devices()
                     if (device.descriptor.vid, device.descriptor.pid) == (0x1050, 0x0407)]
            if len(cards) == 1:
                return cards[0]
            for card in cards:
                card.close()
            if time.monotonic() >= until:
                raise RuntimeError(f"expected one physical developer Key, got {len(cards)}")
            time.sleep(0.12)


    def record(path, phase, devnum):
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump({"phase": phase, "usb_device": devnum}, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        print(f"F12_PHYSICAL_RECOVERY_CHECKPOINT: {phase}", flush=True)


    def reset_once(hard_journal, reset_journal):
        if reset_journal.exists():
            raise RuntimeError("existing F12 Reset checkpoint; inspect before any new Reset command")
        previous = json.loads(hard_journal.read_text())
        assert previous["phase"] == "hard3-completed", previous
        first = physical_usb_device_number()
        card = open_hid()
        try:
            ctap = Ctap2(card)
            assert ctap.get_info().options.get("clientPin") is True
            assert ClientPin(ctap).get_pin_retries()[0] == 0
        finally:
            card.close()
        print("F12_PHYSICAL_PERMANENT_PIN_BLOCKED_0_OF_8_BEFORE_RESET: PASS", flush=True)
        record(reset_journal, "armed-waiting-for-real-usb-replug", first)
        print("F12_PHYSICAL_RESET_ARMED_UNPLUG_REPLUG_NOW_AND_TOUCH_REAL_BOOT_ON_PROMPT", flush=True)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            try:
                new = physical_usb_device_number()
            except (FileNotFoundError, AssertionError):
                new = None
            if new is not None and new != first:
                break
            time.sleep(0.06)
        else:
            print("F12_PHYSICAL_RESET_NOT_SENT_NO_REAL_REPLUG", flush=True)
            return
        print(f"F12_PHYSICAL_REAL_USB_REENUMERATED_FOR_FIDO_RESET: PASS devnum={new}", flush=True)
        card = open_hid(wait=7)
        try:
            ctap = Ctap2(card)
            record(reset_journal, "fido-only-reset-command-dispatched", new)
            seen = set()

            def keepalive(status):
                if status not in seen:
                    seen.add(status)
                    print(f"F12_PHYSICAL_RESET_KEEPALIVE_{status}: REAL_BOOT_REQUIRED", flush=True)

            print("F12_PHYSICAL_FIDO_ONLY_RESET_BEGIN_TOUCH_REAL_BOOT_NOW", flush=True)
            ctap.reset(on_keepalive=keepalive)
            record(reset_journal, "fido-only-reset-returned-success", new)
            print("F12_PHYSICAL_FIDO_ONLY_RESET_PROTOCOL_SUCCESS: PASS", flush=True)
        finally:
            card.close()


    def reinitialize(reset_journal, pin_path):
        marker = json.loads(reset_journal.read_text())
        assert marker["phase"] == "fido-only-reset-returned-success", marker
        pin = pin_path.read_text().strip()
        card = open_hid(wait=12)
        try:
            ctap = Ctap2(card)
            assert ctap.get_info().options.get("clientPin") is False
            print("F12_PHYSICAL_FIDO_PIN_CLEARED_BY_RESET: PASS", flush=True)
            cp = ClientPin(ctap)
            cp.set_pin(pin)
            assert cp.get_pin_retries()[0] == 8
            assert cp.get_pin_token(pin)
            token = cp.get_pin_token(pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
            manager = CredentialManagement(ctap, PinProtocolV2(), token)
            counts = manager.get_metadata()
            existing = counts[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
            remaining = counts[CredentialManagement.RESULT.MAX_REMAINING_COUNT]
            assert existing == 0 and remaining == 256, (existing, remaining)
            print("F12_PHYSICAL_FIDO_ORIGINAL_TEST_RESIDENT_CLEARED: PASS", flush=True)
            print("F12_PHYSICAL_FIDO_PIN_REINITIALIZED_EIGHT_RETRIES: PASS", flush=True)
        finally:
            card.close()
        record(reset_journal, "fido-reset-and-pin-reinitialization-complete", marker["usb_device"])
        print("F12_PHYSICAL_HARD_PIN_LOCK_RECOVERED_BY_REAL_FIDO_ONLY_RESET: PASS", flush=True)


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--action", choices=("reset", "post"), required=True)
        parser.add_argument("--hard-journal", type=Path, required=True)
        parser.add_argument("--reset-journal", type=Path, required=True)
        parser.add_argument("--pin-file", type=Path, required=True)
        args = parser.parse_args()
        print("AUTHORIZATION: Owner-authorized F12 physical permanent PIN lock recovery on disposable Aromatic Key prototype.", flush=True)
        print("SCOPE: CTAP2 FIDO-only Reset and test PIN reinit; preserve all five other Applets.", flush=True)
        print("USER PRESENCE: Real USB power cycle and physical BOOT; no simulated inputs.", flush=True)
        if args.action == "reset":
            reset_once(args.hard_journal, args.reset_journal)
        else:
            reinitialize(args.reset_journal, args.pin_file)


    main()


def hsm_otp():

    import argparse
    import json
    import os
    import time
    from pathlib import Path

    from smartcard.Exceptions import CardConnectionException
    from ykman.pcsc import list_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.hsmauth import HsmAuthSession
    from yubikit.yubiotp import SLOT, YubiOtpSession

    from hil import applet_sentinels as siblings


    def save_phase(path, target, phase):
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"applet": target, "phase": phase}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        print(f"A12_PHYSICAL_{target.upper()}_CHECKPOINT: {phase}", flush=True)


    def verify_absent(conn, target):
        if target == "hsm":
            assert not any(x.label == siblings.HSM_LABEL for x in HsmAuthSession(conn).list_credentials())
        else:
            assert not YubiOtpSession(conn).get_config_state().is_configured(SLOT.ONE)
        print(f"A12_PHYSICAL_{target.upper()}_ORIGINAL_TEST_CREDENTIAL_REMOVED: PASS", flush=True)


    def run(conn, target, state, journal):
        siblings.verify(conn, state)
        save_phase(journal, target, "pre-reset-baseline-verified")
        if target == "hsm":
            HsmAuthSession(conn).reset()
        else:
            YubiOtpSession(conn).delete_slot(SLOT.ONE)
        save_phase(journal, target, "dedicated-clear-returned")
        verify_absent(conn, target)
        siblings.verify(conn, state, skip=target)
        print(f"A12_PHYSICAL_{target.upper()}_OTHER_FOUR_CCID_APPLETS_ISOLATED: PASS", flush=True)
        save_phase(journal, target, "target-absent-other-four-verified")
        siblings.prepare(conn, state)
        siblings.verify(conn, state)
        save_phase(journal, target, "five-ccid-applets-verified-and-reprovisioned")
        print(f"A12_PHYSICAL_{target.upper()}_SMARTCARD_RESET_ISOLATION: PASS", flush=True)


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--applet", choices=("hsm", "otp"), required=True)
        parser.add_argument("--state", type=Path, required=True)
        parser.add_argument("--journal", type=Path, required=True)
        args = parser.parse_args()
        target = args.applet
        print(f"AUTHORIZATION: Owner-authorized Aromatic Key experimental HIL-A12 {target.upper()} test; only disposable user-created data.", flush=True)
        print("SCOPE: One selected Applet only; all other Applets, firmware and eFuse protected.", flush=True)
        state = json.loads(args.state.read_text())
        if args.journal.exists():
            raise RuntimeError(f"prior {target} reset journal exists; inspect before any repeat")
        for i in range(5):
            cards = list_devices()
            assert len(cards) == 1
            try:
                with cards[0].open_connection(SmartCardConnection) as conn:
                    run(conn, target, state, args.journal)
                return
            except CardConnectionException:
                if args.journal.exists() or i == 4:
                    raise
                time.sleep(5)


    main()


def oath():

    import argparse
    import json
    import os
    import time
    from pathlib import Path

    from smartcard.Exceptions import CardConnectionException
    from ykman.pcsc import list_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.oath import OathSession

    from hil import applet_sentinels as siblings


    def checkpoint(path, status):
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump({"applet": "oath", "status": status}, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp, path)
        print(f"A12_OATH_CHECKPOINT_{status.upper()}", flush=True)


    def run(conn, state, journal):
        siblings.verify(conn, state)
        checkpoint(journal, "before-reset")
        OathSession(conn).reset()
        checkpoint(journal, "reset-completed")
        assert not any(x.name == siblings.OATH_NAME for x in OathSession(conn).list_credentials())
        print("A12_PHYSICAL_OATH_ORIGINAL_TEST_CREDENTIAL_CLEARED: PASS", flush=True)
        siblings.verify(conn, state, skip="oath")
        print("A12_PHYSICAL_OATH_OTHER_FOUR_SMARTCARD_APPLETS_PRESERVED: PASS", flush=True)
        siblings.prepare(conn, state)
        siblings.verify(conn, state)
        checkpoint(journal, "five-smartcard-applets-verified")
        print("A12_PHYSICAL_OATH_SMARTCARD_ISOLATION_AND_RESEED: PASS", flush=True)


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--state", type=Path, required=True)
        parser.add_argument("--journal", type=Path, required=True)
        args = parser.parse_args()
        print("AUTHORIZATION: Owner explicitly authorized HIL-A12 testing of disposable OATH data on their experimental Aromatic Key.", flush=True)
        print("SCOPE: OATH application only. PIV/OpenPGP/HSM/OTP and FIDO test credential preserved.", flush=True)
        state = json.loads(args.state.read_text())
        if args.journal.exists():
            raise RuntimeError("OATH A12 journal exists: inspect before any repeat")
        for i in range(5):
            cards = list_devices()
            assert len(cards) == 1, len(cards)
            try:
                with cards[0].open_connection(SmartCardConnection) as conn:
                    run(conn, state, args.journal)
                return
            except CardConnectionException:
                if args.journal.exists() or i == 4:
                    raise
                time.sleep(5)


    main()


def openpgp():

    import argparse
    import json
    import os
    import time
    from pathlib import Path

    from smartcard.Exceptions import CardConnectionException
    from ykman.pcsc import list_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.openpgp import KEY_REF, KEY_STATUS, OpenPgpSession

    from hil import applet_sentinels as siblings


    def checkpoint(path, phase):
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"applet": "openpgp", "phase": phase}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        print(f"A12_PHYSICAL_OPENPGP_CHECKPOINT: {phase}", flush=True)


    def run(conn, state, journal):
        siblings.verify(conn, state)
        pgp = OpenPgpSession(conn)
        assert pgp.get_key_information().get(KEY_REF.SIG) == KEY_STATUS.GENERATED
        print("A12_PHYSICAL_OPENPGP_ORIGINAL_RSA_SIG_KEY_PRESENT: PASS", flush=True)
        checkpoint(journal, "sig-key-confirmed-before-reset")
        pgp.reset()
        checkpoint(journal, "openpgp-reset-returned")
        pgp = OpenPgpSession(conn)
        assert pgp.get_key_information().get(KEY_REF.SIG, KEY_STATUS.NONE) == KEY_STATUS.NONE
        print("A12_PHYSICAL_OPENPGP_ORIGINAL_RSA_SIG_KEY_CLEARED: PASS", flush=True)
        pgp.verify_admin("12345678")
        print("A12_PHYSICAL_OPENPGP_DEFAULT_ADMIN_PIN_RESTORED: PASS", flush=True)
        siblings.verify(conn, state, skip="openpgp")
        print("A12_PHYSICAL_OPENPGP_OTHER_FOUR_CCID_APPLETS_PRESERVED: PASS", flush=True)
        checkpoint(journal, "openpgp-erasure-and-other-four-verified")
        print("A12_PHYSICAL_OPENPGP_SMARTCARD_RESET_ISOLATION: PASS", flush=True)


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--state", required=True, type=Path)
        parser.add_argument("--journal", required=True, type=Path)
        args = parser.parse_args()
        print("AUTHORIZATION: Owner authorized experimental Aromatic Key OpenPGP-only Reset on disposable test data.", flush=True)
        print("SCOPE: OpenPGP test RSA SIG key and PIN only; FIDO, PIV, OATH, OTP and HSM Auth preserved.", flush=True)
        if args.journal.exists():
            raise RuntimeError("prior OpenPGP reset journal exists; no automatic repeat")
        state = json.loads(args.state.read_text())
        for i in range(5):
            cards = list_devices()
            assert len(cards) == 1
            try:
                with cards[0].open_connection(SmartCardConnection) as conn:
                    run(conn, state, args.journal)
                return
            except CardConnectionException:
                if args.journal.exists() or i == 4:
                    raise
                time.sleep(5)


    main()


def openpgp_reseed():

    import argparse
    import hashlib
    import json
    import os
    import time
    from pathlib import Path

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from smartcard.Exceptions import CardConnectionException
    from ykman.pcsc import list_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.openpgp import KEY_REF, KEY_STATUS, OpenPgpSession

    from hil import applet_sentinels as siblings


    def persist(path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(content, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)


    def digest(key):
        return hashlib.sha256(key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )).hexdigest()


    def run(conn, siblings_state, journal):
        siblings.verify(conn, siblings_state, skip="openpgp")
        pgp = OpenPgpSession(conn)
        assert pgp.get_key_information().get(KEY_REF.SIG, KEY_STATUS.NONE) == KEY_STATUS.NONE
        pgp.verify_admin("12345678")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        persist(journal, {"phase": "before-new-test-key-import"})
        pgp.put_key(KEY_REF.SIG, key)
        persist(journal, {"phase": "new-test-key-imported"})
        onboard = pgp.get_public_key(KEY_REF.SIG)
        fp = digest(onboard)
        assert fp == digest(key.public_key())
        assert pgp.get_key_information()[KEY_REF.SIG] != KEY_STATUS.NONE
        pgp.verify_pin("123456")
        message = b"aromatic-a12-reseed-disposable-openpgp-sig"
        signature = pgp.sign(message, hashes.SHA256())
        onboard.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        persist(journal, {"phase": "new-test-sig-verified", "public_sha256": fp})
        print("A12_PHYSICAL_NEW_OPENPGP_TEST_RSA_SIG_IMPORTED_AND_SIGNED: PASS", flush=True)
        siblings.verify(conn, siblings_state, skip="openpgp")
        print("A12_PHYSICAL_RESEEDED_OPENPGP_AND_OTHER_FOUR_CCID_APPLETS: PASS", flush=True)


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--sibling-state", type=Path, required=True)
        parser.add_argument("--journal", type=Path, required=True)
        args = parser.parse_args()
        print("AUTHORIZATION: Owner-authorized Aromatic Key test-only OpenPGP SIG reprovision after A12 Reset.", flush=True)
        print("SCOPE: Import one newly generated disposable RSA-2048 SIG and independently verify its signature; no Reset.", flush=True)
        if args.journal.exists():
            raise RuntimeError("OpenPGP reseed journal exists; do not repeat import")
        state = json.loads(args.sibling_state.read_text())
        for i in range(5):
            cards = list_devices()
            assert len(cards) == 1
            try:
                with cards[0].open_connection(SmartCardConnection) as conn:
                    run(conn, state, args.journal)
                return
            except CardConnectionException:
                if args.journal.exists() or i == 4:
                    raise
                time.sleep(5)


    main()


def piv_prepare():

    import argparse
    import hashlib
    import json
    import os
    import time
    from pathlib import Path

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from smartcard.Exceptions import CardConnectionException
    from ykman.pcsc import list_devices
    from yubikit.core.smartcard import ApduError, SmartCardConnection, SW
    from yubikit.openpgp import KEY_REF, OpenPgpSession
    from yubikit.piv import DEFAULT_MANAGEMENT_KEY, KEY_TYPE, PIN_POLICY, TOUCH_POLICY, PivSession, SLOT

    from hil import applet_sentinels as siblings


    def save(path, phase, sha=None):
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"phase": phase, "piv_public_sha256": sha}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)


    def digest(key):
        return hashlib.sha256(key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )).hexdigest()


    def run(conn, state, pgp_sha, journal):
        siblings.verify(conn, state, skip="openpgp")
        pgp = OpenPgpSession(conn)
        assert digest(pgp.get_public_key(KEY_REF.SIG)) == pgp_sha
        print("A12_PHYSICAL_PIV_PREPARE_OTHER_FIVE_APPLET_BASELINE: PASS", flush=True)
        piv = PivSession(conn)
        assert piv.get_pin_metadata().default_value
        assert piv.get_pin_attempts() == 3
        try:
            piv.get_slot_metadata(SLOT.AUTHENTICATION)
        except ApduError as exc:
            assert exc.sw == SW.REFERENCE_DATA_NOT_FOUND, exc
        else:
            raise AssertionError("PIV 9A slot is not empty")
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        save(journal, "piv-9a-preparation-started")
        piv.change_pin("123456", "654321")
        piv.verify_pin("654321")
        save(journal, "piv-test-pin-changed")
        public = piv.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256,
                                  PIN_POLICY.NEVER, TOUCH_POLICY.NEVER)
        assert piv.get_slot_metadata(SLOT.AUTHENTICATION).key_type == KEY_TYPE.ECCP256
        challenge = os.urandom(32)
        sig = piv.sign(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, challenge, hashes.SHA256())
        public.verify(sig, challenge, ec.ECDSA(hashes.SHA256()))
        save(journal, "piv-test-key-ready", digest(public))
        print("A12_PHYSICAL_PIV_9A_P256_DISPOSABLE_KEY_SIGN_VERIFY: PASS", flush=True)
        print("A12_PHYSICAL_PIV_TEST_PIN_AND_PRIVATE_KEY_PREPARED: PASS", flush=True)


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--state", type=Path, required=True)
        parser.add_argument("--openpgp", type=Path, required=True)
        parser.add_argument("--journal", type=Path, required=True)
        args = parser.parse_args()
        print("AUTHORIZATION: Owner-authorized disposable PIV 9A key and test PIN on Aromatic Key prototype.", flush=True)
        print("SCOPE: Preparation only; not a PIV or any other application Reset.", flush=True)
        if args.journal.exists():
            raise RuntimeError("PIV preparation journal exists; do not overwrite")
        state = json.loads(args.state.read_text())
        pgp_sha = json.loads(args.openpgp.read_text())["public_sha256"]
        for i in range(5):
            cards = list_devices()
            assert len(cards) == 1
            try:
                with cards[0].open_connection(SmartCardConnection) as conn:
                    run(conn, state, pgp_sha, args.journal)
                return
            except CardConnectionException:
                if args.journal.exists() or i == 4:
                    raise
                time.sleep(5)


    main()


def piv():

    import argparse
    import hashlib
    import json
    import os
    import time
    from pathlib import Path

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from smartcard.Exceptions import CardConnectionException
    from ykman.pcsc import list_devices
    from yubikit.core.smartcard import ApduError, SmartCardConnection, SW
    from yubikit.openpgp import KEY_REF, OpenPgpSession
    from yubikit.piv import PivSession, SLOT

    from hil import applet_sentinels as siblings


    def save(path, phase):
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"applet": "piv", "phase": phase}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)


    def public_sha(key):
        return hashlib.sha256(key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )).hexdigest()


    def verify_openpgp(conn, expected):
        pgp = OpenPgpSession(conn)
        public = pgp.get_public_key(KEY_REF.SIG)
        assert public_sha(public) == expected
        pgp.verify_pin("123456")
        payload = b"a12-piv-reset-protects-openpgp-disposable-sig"
        sig = pgp.sign(payload, hashes.SHA256())
        public.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())
        print("A12_PHYSICAL_PIV_OPENPGP_NEW_SIG_PRIVATE_KEY_PRESERVED: PASS", flush=True)


    def run(conn, state, pgp_sha, journal):
        siblings.verify(conn, state, skip="openpgp")
        verify_openpgp(conn, pgp_sha)
        piv = PivSession(conn)
        assert not piv.get_pin_metadata().default_value
        assert piv.get_slot_metadata(SLOT.AUTHENTICATION)
        print("A12_PHYSICAL_PIV_NONDEFAULT_PIN_AND_DISPOSABLE_9A_KEY_PRESENT: PASS", flush=True)
        save(journal, "reset-requested")
        piv.reset()
        save(journal, "piv-reset-returned")
        piv = PivSession(conn)
        try:
            piv.get_slot_metadata(SLOT.AUTHENTICATION)
        except ApduError as exc:
            assert exc.sw == SW.REFERENCE_DATA_NOT_FOUND, exc
        else:
            raise AssertionError("PIV test 9A private key survived Reset")
        assert piv.get_pin_metadata().default_value
        piv.verify_pin("123456")
        print("A12_PHYSICAL_PIV_TEST_PRIVATE_KEY_ERASED_AND_DEFAULT_PIN_RESTORED: PASS", flush=True)
        siblings.verify(conn, state, skip="openpgp")
        verify_openpgp(conn, pgp_sha)
        save(journal, "piv-target-erased-and-five-other-ccid-functions-verified")
        print("A12_PHYSICAL_PIV_SMARTCARD_RESET_AND_SIBLING_ISOLATION: PASS", flush=True)


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--state", type=Path, required=True)
        parser.add_argument("--openpgp", type=Path, required=True)
        parser.add_argument("--piv-prepared", type=Path, required=True)
        parser.add_argument("--journal", type=Path, required=True)
        args = parser.parse_args()
        print("AUTHORIZATION: Owner-authorized Aromatic Key PIV-only Reset on prepared test key.", flush=True)
        print("SCOPE: Erase disposable PIV 9A and restore PIV default PIN; other Applets and firmware preserved.", flush=True)
        if args.journal.exists():
            raise RuntimeError("prior PIV Reset journal exists; do not repeat")
        prepared = json.loads(args.piv_prepared.read_text())
        assert prepared["phase"] == "piv-test-key-ready"
        state = json.loads(args.state.read_text())
        pgp_sha = json.loads(args.openpgp.read_text())["public_sha256"]
        for i in range(5):
            cards = list_devices()
            assert len(cards) == 1
            try:
                with cards[0].open_connection(SmartCardConnection) as conn:
                    run(conn, state, pgp_sha, args.journal)
                return
            except CardConnectionException:
                if args.journal.exists() or i == 4:
                    raise
                time.sleep(5)


    main()


def verify_siblings():

    import argparse
    import hashlib
    import json
    import time
    from pathlib import Path

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from smartcard.Exceptions import CardConnectionException
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.openpgp import KEY_REF, OpenPgpSession
    from ykman.pcsc import list_devices

    from hil import applet_sentinels as siblings


    def verify(conn, baseline, openpgp_hash, phase):
        siblings.verify(conn, baseline, skip="openpgp")
        pgp = OpenPgpSession(conn)
        public = pgp.get_public_key(KEY_REF.SIG)
        digest = hashlib.sha256(public.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )).hexdigest()
        assert digest == openpgp_hash
        pgp.verify_pin("123456")
        message = b"aromatic-f12-fido-reset-sibling-preservation-" + phase.encode()
        signature = pgp.sign(message, hashes.SHA256())
        public.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        print(f"F12_PHYSICAL_{phase.upper()}_OPENPGP_CURRENT_SIG_INDEPENDENT_VERIFY: PASS", flush=True)
        print(f"F12_PHYSICAL_{phase.upper()}_FIVE_NONFIDO_APPLETS_INDEPENDENT_BUSINESS_VERIFY: PASS", flush=True)


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--phase", choices=("before", "after"), required=True)
        parser.add_argument("--baseline", type=Path, required=True)
        parser.add_argument("--new-openpgp", type=Path, required=True)
        args = parser.parse_args()
        print("AUTHORIZATION: Owner-authorized Aromatic Key physical F12 five-Applet integrity verification.", flush=True)
        print("SCOPE: Read-only identities and actual crypto operations; no FIDO or Applet Reset.", flush=True)
        baseline = json.loads(args.baseline.read_text())
        meta = json.loads(args.new_openpgp.read_text())
        assert meta["phase"] == "new-test-sig-verified"
        for attempt in range(5):
            devices = list_devices()
            assert len(devices) == 1, len(devices)
            try:
                with devices[0].open_connection(SmartCardConnection) as conn:
                    verify(conn, baseline, meta["public_sha256"], args.phase)
                return
            except CardConnectionException:
                if attempt == 4:
                    raise
                print(f"F12_PHYSICAL_PCSC_REENUMERATION_RETRY: {attempt + 1}/4", flush=True)
                time.sleep(5)


    main()


def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("case", choices=('fido', 'fido_recover', 'hsm_otp', 'oath', 'openpgp', 'openpgp_reseed', 'piv_prepare', 'piv', 'verify_siblings'))
    args, remaining = parser.parse_known_args()
    sys.argv = [sys.argv[0], *remaining]
    cases = {'fido': fido, 'fido_recover': fido_recover, 'hsm_otp': hsm_otp, 'oath': oath, 'openpgp': openpgp, 'openpgp_reseed': openpgp_reseed, 'piv_prepare': piv_prepare, 'piv': piv, 'verify_siblings': verify_siblings}
    cases[args.case]()


if __name__ == "__main__":
    main()
