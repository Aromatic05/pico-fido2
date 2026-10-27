#!/usr/bin/env python3
'Physical PIN change, temporary lock recovery and permanent retry exhaustion on disposable credentials.'
import argparse
import sys

import re
import subprocess

def usb_id():
    raw = subprocess.run(["lsusb", "-d", "1050:0407"],
                         capture_output=True, text=True, check=True).stdout
    matches = re.findall(r"Bus (\d+) Device (\d+):", raw)
    assert len(matches) == 1, matches
    return "/".join(matches[0])


def change():

    import argparse
    import base64
    import hashlib
    import json
    import os
    import secrets
    import time
    from pathlib import Path

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from fido2 import cbor
    from fido2.ctap import CtapError
    from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
    from fido2.ctap2.pin import PinProtocolV2
    from fido2.hid import CtapHidDevice

    RP = {"id": "f09.aromatic-key.invalid", "name": "Aromatic Key F09 HIL"}
    SENTINEL_NAME = "aromatic-f09-resident"


    def atomic_private_json(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)


    def open_key():
        matches = [dev for dev in CtapHidDevice.list_devices()
                   if (dev.descriptor.vid, dev.descriptor.pid) == (0x1050, 0x0407)]
        if len(matches) != 1:
            for dev in matches:
                dev.close()
            raise RuntimeError(f"expected one physical development Key, found {len(matches)}")
        return matches[0], Ctap2(matches[0])


    def touch_progress(label):
        seen = set()

        def on_keepalive(status):
            if status not in seen:
                seen.add(status)
                print(f"F09_{label}_KEEPALIVE_{status}: WAITING_FOR_REAL_BOOT", flush=True)

        print(f"F09_{label}_CTAP2_BEGIN: PHYSICAL_BOOT_MAY_BE_REQUIRED", flush=True)
        return on_keepalive


    def metadata(ctap, pin):
        cp = ClientPin(ctap)
        token = cp.get_pin_token(pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        manager = CredentialManagement(ctap, PinProtocolV2(), token)
        return manager, manager.get_metadata()


    def verify(ctap, pin, state, phase):
        cp = ClientPin(ctap)
        assert ctap.get_info().options.get("clientPin") is True
        assert cp.get_pin_retries()[0] == 8
        manager, counts = metadata(ctap, pin)
        existing = counts[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
        remaining = counts[CredentialManagement.RESULT.MAX_REMAINING_COUNT]
        assert existing >= 1 and existing + remaining == 256, (existing, remaining)
        rp_hash = hashlib.sha256(RP["id"].encode()).digest()
        creds = [item for item in manager.enumerate_creds(rp_hash)
                 if item[CredentialManagement.RESULT.CREDENTIAL_ID]["id"] == base64.b64decode(state["credential_id_b64"])]
        assert len(creds) == 1
        item = creds[0]
        assert item[CredentialManagement.RESULT.USER]["id"] == base64.b64decode(state["user_id_b64"])
        assert cbor.encode(dict(item[CredentialManagement.RESULT.PUBLIC_KEY])) == base64.b64decode(state["public_key_cbor_b64"])
        print(f"F09_{phase}_RESIDENT_ID_USER_PUBLIC_KEY_STABLE: PASS", flush=True)

        client_hash = os.urandom(32)
        protocol = PinProtocolV2()
        for attempt in range(3):
            token = cp.get_pin_token(pin, permissions=ClientPin.PERMISSION.GET_ASSERTION,
                                     permissions_rpid=RP["id"])
            try:
                assertion = ctap.get_assertion(
                    rp_id=RP["id"], client_data_hash=client_hash,
                    pin_uv_param=protocol.authenticate(token, client_hash),
                    pin_uv_protocol=protocol.VERSION,
                    on_keepalive=touch_progress(phase + "_ASSERTION"),
                )
                break
            except CtapError as exc:
                if exc.code != CtapError.ERR.OPERATION_DENIED or attempt == 2:
                    raise
                print(f"F09_{phase}_REAL_BOOT_NOT_CONFIRMED_RETRY: {attempt + 1}/2", flush=True)
                time.sleep(2)
        assert assertion.credential["id"] == base64.b64decode(state["credential_id_b64"])
        assert int(assertion.auth_data.flags) & 1
        public_key = cbor.decode(base64.b64decode(state["public_key_cbor_b64"]))
        public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(public_key[-2], "big"),
            int.from_bytes(public_key[-3], "big"),
            ec.SECP256R1(),
        ).public_key()
        public.verify(assertion.signature, bytes(assertion.auth_data) + client_hash,
                      ec.ECDSA(hashes.SHA256()))
        old_counter = state["counter"]
        assert assertion.auth_data.counter > old_counter, (old_counter, assertion.auth_data.counter)
        state["counter"] = assertion.auth_data.counter
        print(f"F09_{phase}_GET_ASSERTION_INDEPENDENT_SIGNATURE_AND_COUNTER: PASS", flush=True)
        return state


    def seed(ctap, original_pin, state_path):
        if state_path.exists():
            print("F09_PHYSICAL_SEED_ALREADY_EXISTS; VERIFY_EXISTING", flush=True)
            state = json.loads(state_path.read_text())
            state = verify(ctap, original_pin, state, "SEED_RECHECK")
        else:
            cp = ClientPin(ctap)
            assert ctap.get_info().options.get("clientPin") is True
            assert cp.get_pin_retries()[0] == 8
            _, counts = metadata(ctap, original_pin)
            assert counts[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 0
            assert counts[CredentialManagement.RESULT.MAX_REMAINING_COUNT] == 256
            print("F09_PHYSICAL_POST_F11_FIDO_EMPTY_STORE_AND_PIN: PASS", flush=True)

            protocol = PinProtocolV2()
            user_id = os.urandom(16)
            client_hash = os.urandom(32)
            token = cp.get_pin_token(original_pin, permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
                                     permissions_rpid=RP["id"])
            created = ctap.make_credential(
                client_data_hash=client_hash, rp=RP,
                user={"id": user_id, "name": SENTINEL_NAME, "displayName": SENTINEL_NAME},
                key_params=[{"type": "public-key", "alg": -7}],
                options={"rk": True},
                pin_uv_param=protocol.authenticate(token, client_hash),
                pin_uv_protocol=protocol.VERSION,
                on_keepalive=touch_progress("SEED_MAKE_CREDENTIAL"),
            )
            credential = created.auth_data.credential_data
            assert credential is not None
            state = {
                "rp": RP["id"],
                "user_id_b64": base64.b64encode(user_id).decode(),
                "credential_id_b64": base64.b64encode(credential.credential_id).decode(),
                "public_key_cbor_b64": base64.b64encode(cbor.encode(dict(credential.public_key))).decode(),
                "counter": created.auth_data.counter,
            }
            atomic_private_json(state_path, state)
            print("F09_PHYSICAL_NEW_REAL_RESIDENT_CREATED: PASS", flush=True)
            state = verify(ctap, original_pin, state, "BEFORE_CHANGE")
        atomic_private_json(state_path, state)
        print("F09_PHYSICAL_SEED_CREDENTIAL_SIGN_VERIFY: PASS", flush=True)


    def change_and_restore(ctap, original_pin, state_path, checkpoint):
        state = json.loads(state_path.read_text())
        if checkpoint.exists():
            raise RuntimeError("F09 PIN transition checkpoint already exists; recover before continuing")
        cp = ClientPin(ctap)
        assert cp.get_pin_retries()[0] == 8
        temporary_pin = "F09-" + secrets.token_urlsafe(12)
        atomic_private_json(checkpoint, {"temporary_pin": temporary_pin, "phase": "before-change"})
        changed = False
        try:
            cp.change_pin(original_pin, temporary_pin)
            changed = True
            atomic_private_json(checkpoint, {"temporary_pin": temporary_pin, "phase": "temporary-active"})
            print("F09_PHYSICAL_CHANGE_PIN_TO_TEMPORARY: PASS", flush=True)
            state = verify(ctap, temporary_pin, state, "TEMPORARY_PIN")
            atomic_private_json(state_path, state)
        finally:
            if changed:
                cp.change_pin(temporary_pin, original_pin)
                token = cp.get_pin_token(original_pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
                assert token
                checkpoint.unlink()
                print("F09_PHYSICAL_ORIGINAL_PIN_RESTORED: PASS", flush=True)
        if not changed:
            raise RuntimeError("PIN change did not complete; inspect F09 checkpoint")
        state = verify(ctap, original_pin, state, "RESTORED_PIN")
        atomic_private_json(state_path, state)
        print("HIL_F09_PHYSICAL_CHANGE_RESTORE_AND_RESIDENT_FULL_CHAIN: PASS", flush=True)


    def recover(ctap, original_pin, checkpoint):
        transition = json.loads(checkpoint.read_text())
        if transition["phase"] != "temporary-active":
            raise RuntimeError("F09 change result uncertain; inspect journal before manual recovery")
        cp = ClientPin(ctap)
        cp.change_pin(transition["temporary_pin"], original_pin)
        assert cp.get_pin_token(original_pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        checkpoint.unlink()
        print("F09_PHYSICAL_ORIGINAL_PIN_RECOVERED: PASS", flush=True)


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--action", choices=("seed", "change-restore", "recover"), required=True)
        parser.add_argument("--state-dir", type=Path, required=True)
        parser.add_argument("--evidence-dir", type=Path, required=True)
        args = parser.parse_args()
        print("AUTHORIZATION: Owner-authorized Aromatic Key physical F09 functional test on disposable test data.", flush=True)
        print("SCOPE: Real FIDO Resident create/assertion, ClientPIN change and restore; never FIDO/applet/device Reset.", flush=True)
        original_pin = (args.state_dir / "real-card-test-pin.txt").read_text().strip()
        state_path = args.evidence_dir / "f09-physical-resident.json"
        checkpoint = args.evidence_dir / "f09-physical-pin-transition.json"
        dev, ctap = open_key()
        try:
            if args.action == "seed":
                if checkpoint.exists():
                    raise RuntimeError("F09 prior PIN transition not reconciled")
                seed(ctap, original_pin, state_path)
            elif args.action == "change-restore":
                change_and_restore(ctap, original_pin, state_path, checkpoint)
            else:
                recover(ctap, original_pin, checkpoint)
        finally:
            dev.close()


    main()


def temporary_lock():

    import argparse
    import json
    import os
    import re
    import subprocess
    from pathlib import Path

    from fido2.ctap import CtapError
    from fido2.ctap2 import Ctap2, ClientPin
    from fido2.hid import CtapHidDevice

    WRONG_PIN = "F12-Wrong-Aromatic-PIN"


    def usb_id():
        raw = subprocess.run(["lsusb", "-d", "1050:0407"],
                             capture_output=True, text=True, check=True).stdout
        matches = re.findall(r"Bus (\d+) Device (\d+):", raw)
        assert len(matches) == 1, matches
        return "/".join(matches[0])


    def save(path, phase, devnum):
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"phase": phase, "usb_device": devnum}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        print(f"F12_PHYSICAL_SOFTLOCK_CHECKPOINT: {phase}", flush=True)


    def open_card():
        devices = [dev for dev in CtapHidDevice.list_devices()
                   if (dev.descriptor.vid, dev.descriptor.pid) == (0x1050, 0x0407)]
        if len(devices) != 1:
            for dev in devices:
                dev.close()
            raise RuntimeError(f"expected exactly one FIDO test Key, got {len(devices)}")
        return devices[0], Ctap2(devices[0])


    def softlock(ctap, pin, journal, device_id):
        if journal.exists():
            raise RuntimeError("earlier F12 soft-lock journal exists; recover, do not repeat")
        cp = ClientPin(ctap)
        assert ctap.get_info().options.get("clientPin") is True
        assert cp.get_pin_retries()[0] == 8
        assert cp.get_pin_token(pin)
        save(journal, "before-three-invalid-pins", device_id)
        for attempt in range(3):
            try:
                cp.get_pin_token(WRONG_PIN)
            except CtapError as error:
                expected = (CtapError.ERR.PIN_INVALID if attempt < 2
                            else CtapError.ERR.PIN_AUTH_BLOCKED)
                assert error.code == expected, (attempt, error.code, expected)
                print(f"F12_PHYSICAL_SOFTLOCK_WRONG_PIN_{attempt + 1}: {error.code.name}", flush=True)
            else:
                raise AssertionError("invalid PIN unexpectedly authenticated")
        assert cp.get_pin_retries()[0] == 5
        try:
            cp.get_pin_token(pin)
        except CtapError as error:
            assert error.code == CtapError.ERR.PIN_AUTH_BLOCKED, error
        else:
            raise AssertionError("temporary lockout did not prevent PIN authentication")
        save(journal, "temporary-locked-five-retries", device_id)
        print("F12_PHYSICAL_SOFT_PIN_LOCK_AND_RETRIES_5_OF_8: PASS", flush=True)
        print("F12_PHYSICAL_NEEDS_ONE_REAL_USB_UNPLUG_REPLUG_TO_RECOVER", flush=True)


    def recover(ctap, pin, journal, device_id):
        record = json.loads(journal.read_text())
        assert record["phase"] == "temporary-locked-five-retries", record["phase"]
        assert device_id != record["usb_device"], "physical USB replug has not occurred"
        cp = ClientPin(ctap)
        assert cp.get_pin_retries()[0] == 5
        assert cp.get_pin_token(pin)
        assert cp.get_pin_retries()[0] == 8
        save(journal, "replug-and-correct-pin-restored-eight-retries", device_id)
        print("F12_PHYSICAL_SOFT_PIN_LOCK_USB_REPLUG_RECOVERED: PASS", flush=True)


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--phase", choices=("softlock", "recover"), required=True)
        parser.add_argument("--state-dir", type=Path, required=True)
        parser.add_argument("--journal", type=Path, required=True)
        args = parser.parse_args()
        print("AUTHORIZATION: Owner-authorized Aromatic Key F12 experimental soft PIN lockout using disposable test credentials.", flush=True)
        print("SCOPE: Three known-invalid FIDO PIN attempts, then one real USB replug and correct PIN recovery; NO hard lock or Reset.", flush=True)
        pin = (args.state_dir / "real-card-test-pin.txt").read_text().strip()
        devnum = usb_id()
        dev, ctap = open_card()
        try:
            if args.phase == "softlock":
                softlock(ctap, pin, args.journal, devnum)
            else:
                recover(ctap, pin, args.journal, devnum)
        finally:
            dev.close()


    main()


def permanent_lock():

    import argparse
    import json
    import os
    from pathlib import Path

    from fido2.ctap import CtapError
    from fido2.ctap2 import Ctap2, ClientPin
    from fido2.hid import CtapHidDevice

    from hil.fido_pin import usb_id

    STAGES = {
        "hard1": (8, 3, 5),
        "hard2": (5, 3, 2),
        "hard3": (2, 2, 0),
    }


    def write_journal(path, phase, usb):
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as out:
            json.dump({"phase": phase, "usb_device": usb}, out)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        print(f"F12_PHYSICAL_HARDLOCK_CHECKPOINT: {phase}", flush=True)


    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("--stage", choices=STAGES, required=True)
        parser.add_argument("--soft-journal", type=Path, required=True)
        parser.add_argument("--hard-journal", type=Path, required=True)
        parser.add_argument("--state-dir", type=Path, required=True)
        args = parser.parse_args()
        print("AUTHORIZATION: Owner-authorized Aromatic Key experimental F12 hard PIN-lock test, all credentials disposable.", flush=True)
        print("SCOPE: FIDO PIN retry-state only; no applet/device Reset, no firmware or eFuse operation.", flush=True)

        if args.stage == "hard1":
            soft = json.loads(args.soft_journal.read_text())
            assert soft["phase"] == "replug-and-correct-pin-restored-eight-retries"
            assert not args.hard_journal.exists()
            previous_usb = None
        else:
            old = json.loads(args.hard_journal.read_text())
            previous = "hard1" if args.stage == "hard2" else "hard2"
            assert old["phase"] == f"{previous}-completed", old
            previous_usb = old["usb_device"]

        actual_usb = usb_id()
        if previous_usb is not None:
            assert actual_usb != previous_usb, "physically unplug and replug the Key before next stage"
        vid_pid = (0x1050, 0x0407)
        devices = [dev for dev in CtapHidDevice.list_devices()
                   if (dev.descriptor.vid, dev.descriptor.pid) == vid_pid]
        assert len(devices) == 1, len(devices)
        dev = devices[0]
        try:
            cp = ClientPin(Ctap2(dev))
            before, attempts, after = STAGES[args.stage]
            assert cp.get_pin_retries()[0] == before
            write_journal(args.hard_journal, f"{args.stage}-in-progress", actual_usb)
            for n in range(attempts):
                try:
                    cp.get_pin_token("F12-Incorrect-Disposable-PIN")
                except CtapError as exc:
                    assert exc.code in (
                        CtapError.ERR.PIN_INVALID,
                        CtapError.ERR.PIN_AUTH_BLOCKED,
                        CtapError.ERR.PIN_BLOCKED,
                    ), exc
                    print(f"F12_PHYSICAL_{args.stage.upper()}_INVALID_PIN_{n + 1}: {exc.code.name}", flush=True)
                else:
                    raise AssertionError("unexpectedly accepted wrong PIN")
            assert cp.get_pin_retries()[0] == after
            if after == 0:
                real_pin = (args.state_dir / "real-card-test-pin.txt").read_text().strip()
                try:
                    cp.get_pin_token(real_pin)
                except CtapError as exc:
                    assert exc.code == CtapError.ERR.PIN_BLOCKED, exc
                else:
                    raise AssertionError("permanent PIN lockout was not enforced")
                print("F12_PHYSICAL_PERMANENT_PIN_LOCKED_AND_VALID_PIN_REJECTED: PASS", flush=True)
            write_journal(args.hard_journal, f"{args.stage}-completed", actual_usb)
            print(f"F12_PHYSICAL_{args.stage.upper()}_RETRY_COUNT_{after}: PASS", flush=True)
            if after:
                print("F12_PHYSICAL_REAL_USB_REPLUG_REQUIRED_BEFORE_NEXT_STAGE", flush=True)
            else:
                print("F12_PHYSICAL_PIN_PERMANENTLY_BLOCKED_UNTIL_AUTHORIZED_FIDO_RESET", flush=True)
        finally:
            dev.close()


    main()


def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("case", choices=('change', 'temporary_lock', 'permanent_lock'))
    args, remaining = parser.parse_known_args()
    sys.argv = [sys.argv[0], *remaining]
    cases = {'change': change, 'temporary_lock': temporary_lock, 'permanent_lock': permanent_lock}
    cases[args.case]()


if __name__ == "__main__":
    main()
