#!/usr/bin/env python3
"""Journaled 256-credential fill, power-cycle, overflow, refill and signature checks."""

import argparse
import hashlib
import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import AttestationResponse, ClientPin, CredentialManagement, Ctap2
from fido2.ctap2.base import args as ctap_args
from fido2.ctap2.pin import PinProtocolV2

from hil import fido_capacity_support as capacity
from hil import fido_attestation as probe

EVIDENCE_DIR = None


def message(text):
    print(text, flush=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(value, output, sort_keys=True)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temp, path)


def usb_number():
    matches = []
    for item in Path("/sys/bus/usb/devices").iterdir():
        if not (item / "idVendor").exists():
            continue
        if (item / "idVendor").read_text().strip() == "1050" and (item / "idProduct").read_text().strip() == "0407":
            matches.append(f"{int((item / 'busnum').read_text()):03}/{int((item / 'devnum').read_text()):03}")
    assert len(matches) == 1, matches
    return matches[0]


def verified_metadata(manager, evidence):
    # A real USB run returned a metadata map without key 1 after successful
    # registration #48. Persist the malformed read, then retry only the
    # read-only metadata command. Never repeat the MakeCredential request.
    for attempt in range(1, 4):
        metadata = manager.get_metadata()
        if (isinstance(metadata, dict)
                and CredentialManagement.RESULT.EXISTING_CRED_COUNT in metadata
                and CredentialManagement.RESULT.MAX_REMAINING_COUNT in metadata):
            existing = metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
            remaining = metadata[CredentialManagement.RESULT.MAX_REMAINING_COUNT]
            assert isinstance(existing, int) and isinstance(remaining, int)
            assert 0 <= existing <= capacity.CAPACITY and existing + remaining == capacity.CAPACITY, metadata
            return metadata
        evidence.mkdir(parents=True, exist_ok=True)
        name = f"f12-full-invalid-metadata-decoded-{time.time_ns()}-{attempt}.cbor"
        path = evidence / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(cbor.encode(metadata))
            output.flush()
            os.fsync(output.fileno())
        keys = [str(k) for k in metadata] if isinstance(metadata, dict) else []
        message(f"F12_METADATA_SCHEMA_ERROR: read={attempt}/3 keys={keys} decoded_map={name}; only metadata read will be retried")
        time.sleep(0.2)
    raise RuntimeError("F12 metadata missing required fields on three reads; request not repeated")


def count(ctap, pin, evidence=None):
    metadata = verified_metadata(capacity.management(ctap, pin), evidence or EVIDENCE_DIR)
    return metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT]


class CheckedMetadataManager:
    def __init__(self, manager, evidence):
        self.manager = manager
        self.evidence = evidence

    def get_metadata(self):
        return verified_metadata(self.manager, self.evidence)

    def enumerate_rps(self):
        return self.manager.enumerate_rps()

    def enumerate_creds(self, rp_hash):
        return self.manager.enumerate_creds(rp_hash)


def current_ids(ctap, pin):
    return capacity.entries(CheckedMetadataManager(capacity.management(ctap, pin), EVIDENCE_DIR))


def ensure_id_hashes(actual, hashes):
    for index, digest in hashes.items():
        assert int(index) in actual, f"previous credential {index} disappeared"
        assert sha(actual[int(index)]) == digest, f"credential {index} changed"


def read_full_snapshot(ctap, pin):
    ids = current_ids(ctap, pin)
    assert set(ids) == set(range(capacity.CAPACITY))
    manager = CheckedMetadataManager(capacity.management(ctap, pin), EVIDENCE_DIR)
    rows = manager.enumerate_creds(hashlib.sha256(capacity.RP_ID.encode()).digest())
    result = {}
    for row in rows:
        index = int.from_bytes(row[CredentialManagement.RESULT.USER]["id"], "big")
        cred_id = row[CredentialManagement.RESULT.CREDENTIAL_ID]["id"]
        assert cred_id == ids[index]
        pubkey = row[CredentialManagement.RESULT.PUBLIC_KEY]
        result[str(index)] = {
            "credential_sha256": sha(cred_id),
            "public_sha256": sha(cbor.encode(dict(pubkey))),
        }
    assert len(result) == capacity.CAPACITY
    return result


def get_token(ctap, pin):
    return ClientPin(ctap).get_pin_token(
        pin,
        permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
        permissions_rpid=capacity.RP_ID,
    )


def register(ctap, pin, index, evidence):
    challenge = os.urandom(32)
    protocol = PinProtocolV2()
    token = get_token(ctap, pin)
    message(f"F12_TOUCH_BOOT: credential {index + 1}/256; press once when yellow")
    seen = set()

    def keepalive(status):
        if status not in seen:
            seen.add(status)
            message(f"F12_TOUCH_KEEPALIVE: {index + 1}/256 status={status}; REAL_BOOT_REQUIRED")

    response = ctap.send_cbor(
        Ctap2.CMD.MAKE_CREDENTIAL,
        ctap_args(
            challenge,
            {"id": capacity.RP_ID, "name": "Aromatic Key disposable capacity test"},
            {"id": index.to_bytes(4, "big"), "name": f"capacity-{index}"},
            [{"type": "public-key", "alg": -7}],
            None, None, {"rk": True},
            protocol.authenticate(token, challenge), protocol.VERSION,
        ),
        on_keepalive=keepalive,
    )
    try:
        attestation = AttestationResponse.from_dict(response)
    except (ValueError, TypeError) as error:
        attempt = 1
        while True:
            raw = evidence / f"f12-full-invalid-attestation-{index + 1:03}-{attempt:02}.cbor"
            try:
                fd = os.open(raw, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                break
            except FileExistsError:
                attempt += 1
        with os.fdopen(fd, "wb") as output:
            output.write(cbor.encode(response))
            output.flush()
            os.fsync(output.fileno())
        probe.describe(response)
        message(f"F12_ATTESTATION_PARSER_FAIL: index={index + 1} {type(error).__name__}: {error}; raw={raw.name}")
        return None, str(error)
    credential = attestation.auth_data.credential_data
    assert credential is not None
    assert int(attestation.auth_data.flags) & 1, "missing actual User Presence flag"
    return credential.credential_id, None


def perform_registration(ctap, pin, index, state, evidence, journal, allowed_before):
    while True:
        try:
            parsed_id, parse_error = register(ctap, pin, index, evidence)
            break
        except CtapError as error:
            if error.code != CtapError.ERR.OPERATION_DENIED:
                raise
            assert count(ctap, pin, evidence) == allowed_before, "operation denied but credential count changed"
            message(f"F12_TOUCH_MISSED: {index + 1}/256, retrying same index (Ctrl+C pauses)")
            time.sleep(1)
    state["inflight"] = {
        "index": index,
        "credential_sha256": sha(parsed_id) if parsed_id is not None else None,
        "parse_error": parse_error,
    }
    atomic_json(journal, state)
    assert count(ctap, pin, evidence) == allowed_before + 1, "MakeCredential count did not increment by one"
    if parse_error:
        actual = current_ids(ctap, pin)
        assert set(actual) == set(range(allowed_before + 1))
        ensure_id_hashes(actual, state["ids"])
        committed_id = actual[index]
        state["attestation_failures"].append({"index": index + 1, "error": parse_error})
        message(f"F12_ATTESTATION_FAILED_BUT_STORED: index={index + 1}; continuing capacity test")
    else:
        committed_id = parsed_id
    state["ids"][str(index)] = sha(committed_id)
    state.pop("inflight", None)
    atomic_json(journal, state)
    if index % 16 == 15 or index == capacity.CAPACITY - 1:
        actual = current_ids(ctap, pin)
        assert set(actual) == set(range(index + 1))
        ensure_id_hashes(actual, state["ids"])
        message(f"F12_STORE_CHECKPOINT: PASS existing={index + 1} remaining={255 - index}")
    else:
        message(f"F12_REGISTERED: {index + 1}/256; remaining={255 - index}")


def reconcile_inflight(actual, state, journal):
    pending = state.get("inflight")
    if pending is None:
        return
    index = pending["index"]
    if str(index) not in state["ids"]:
        assert index in actual, "attestation returned but credential absent: inspect before retrying"
        expected = pending["credential_sha256"]
        if expected is not None:
            assert sha(actual[index]) == expected, "persisted ID disagrees with attestation"
        else:
            state["attestation_failures"].append({"index": index + 1, "error": pending["parse_error"]})
        state["ids"][str(index)] = sha(actual[index])
    else:
        assert sha(actual[index]) == state["ids"][str(index)]
    state.pop("inflight", None)
    atomic_json(journal, state)
    message(f"F12_INFLIGHT_RETURNED_ATTESTATION_RECOVERED: {index + 1}/256; no duplicate registration")


def verify_recovered_writes(ctap, pin, state, journal, actual):
    for one_based in list(state["unconfirmed_writes"]):
        index = one_based - 1
        assert index in actual
        identity = actual[index]
        rp_hash = hashlib.sha256(capacity.RP_ID.encode()).digest()
        manager = capacity.management(ctap, pin)
        listed = manager.enumerate_creds(rp_hash)
        selected = [entry for entry in listed
                    if entry[CredentialManagement.RESULT.USER]["id"] == index.to_bytes(4, "big")]
        assert len(selected) == 1
        item = selected[0]
        assert item[CredentialManagement.RESULT.CREDENTIAL_ID]["id"] == identity
        key = item[CredentialManagement.RESULT.PUBLIC_KEY]
        public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big"), ec.SECP256R1(),
        ).public_key()
        message(f"F12_RECOVERED_RESIDENT_{one_based}_ASSERTION: touch real BOOT once to independently verify the interrupted registration")
        while True:
            challenge = os.urandom(32)
            protocol = PinProtocolV2()
            token = ClientPin(ctap).get_pin_token(
                pin, permissions=ClientPin.PERMISSION.GET_ASSERTION,
                permissions_rpid=capacity.RP_ID,
            )
            try:
                assertion = ctap.get_assertion(
                    rp_id=capacity.RP_ID,
                    client_data_hash=challenge,
                    allow_list=[{"type": "public-key", "id": identity}],
                    pin_uv_param=protocol.authenticate(token, challenge),
                    pin_uv_protocol=protocol.VERSION,
                    on_keepalive=lambda status: message(
                        f"F12_RECOVERED_ASSERTION_KEEPALIVE_{status}: REAL_BOOT_REQUIRED"),
                )
                break
            except CtapError as error:
                if error.code != CtapError.ERR.OPERATION_DENIED:
                    raise
                message(f"F12_RECOVERED_RESIDENT_{one_based}_TOUCH_MISSED: retrying assertion only")
        assert assertion.auth_data.rp_id_hash == rp_hash
        assert int(assertion.auth_data.flags) & 1
        if assertion.credential is not None:
            assert assertion.credential["id"] == identity
        public.verify(assertion.signature, bytes(assertion.auth_data) + challenge,
                      ec.ECDSA(hashes.SHA256()))
        assert current_ids(ctap, pin) == actual
        state["unconfirmed_writes"].remove(one_based)
        state.setdefault("verified_recoveries", []).append(one_based)
        atomic_json(journal, state)
        message(f"F12_RECOVERED_RESIDENT_{one_based}_REAL_PRIVATE_KEY_SIGNATURE: PASS; original attestation ID was not journaled")


def fill(ctap, pin, state, journal, evidence):
    actual = current_ids(ctap, pin)
    before = len(actual)
    assert set(actual) == set(range(before)), "cannot sequentially fill after deletion"
    ensure_id_hashes(actual, state["ids"])
    reconcile_inflight(actual, state, journal)
    for index in range(before):
        if str(index) not in state["ids"]:
            state["ids"][str(index)] = sha(actual[index])
            state["unconfirmed_writes"].append(index + 1)
            message(f"F12_INTERRUPTED_WRITE_RECOVERED: index={index + 1}; stored ID verified, original attestation ID not journaled")
    atomic_json(journal, state)
    verify_recovered_writes(ctap, pin, state, journal, actual)
    message(f"F12_FILL_RESUME: existing={before}/256; remaining={256 - before}")
    for index in range(before, capacity.CAPACITY):
        perform_registration(ctap, pin, index, state, evidence, journal, index)
    state["full_snapshot"] = read_full_snapshot(ctap, pin)
    state["powercycle_usb"] = usb_number()
    state["phase"] = "await-real-usb-replug"
    atomic_json(journal, state)
    message("F12_PHYSICAL_FULL_256_OF_256: PASS (real registrations and full CredentialManagement enumeration)")


def verify_resident_signature(ctap, pin, target_index):
    before_ids = capacity.entries(capacity.management(ctap, pin))
    assert target_index in before_ids
    rp_hash = hashlib.sha256(capacity.RP_ID.encode()).digest()
    listed = capacity.management(ctap, pin).enumerate_creds(rp_hash)
    target = [entry for entry in listed if entry[CredentialManagement.RESULT.USER]["id"] == target_index.to_bytes(4, "big")]
    assert len(target) == 1
    credential_id = target[0][CredentialManagement.RESULT.CREDENTIAL_ID]["id"]
    assert credential_id == before_ids[target_index]
    key = target[0][CredentialManagement.RESULT.PUBLIC_KEY]
    assert key[1] == 2 and key[3] == -7 and key[-1] == 1
    public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big"), ec.SECP256R1(),
    ).public_key()
    challenge = os.urandom(32)
    protocol = PinProtocolV2()
    token = ClientPin(ctap).get_pin_token(
        pin, permissions=ClientPin.PERMISSION.GET_ASSERTION,
        permissions_rpid=capacity.RP_ID,
    )
    message(f"F12_PHYSICAL_RESIDENT_{(target_index + 1)}_GET_ASSERTION_WAIT_FOR_REAL_BOOT")
    response = ctap.get_assertion(
        rp_id=capacity.RP_ID,
        client_data_hash=challenge,
        allow_list=[{"type": "public-key", "id": credential_id}],
        pin_uv_param=protocol.authenticate(token, challenge),
        pin_uv_protocol=protocol.VERSION,
        on_keepalive=lambda status: message(
            f"F12_PHYSICAL_RESIDENT_{(target_index + 1)}_ASSERTION_KEEPALIVE_{status}: REAL_BOOT_REQUIRED",
        ),
    )
    assert response.auth_data.rp_id_hash == rp_hash
    assert int(response.auth_data.flags) & 1, "real physical user presence not recorded"
    if response.credential is not None:
        assert response.credential["id"] == credential_id
    public.verify(response.signature, bytes(response.auth_data) + challenge, ec.ECDSA(hashes.SHA256()))
    after_ids = capacity.entries(capacity.management(ctap, pin))
    assert after_ids == before_ids
    message(f"F12_PHYSICAL_RESIDENT_{(target_index + 1)}_REAL_PRIVATE_KEY_INDEPENDENT_ES256_SIGNATURE: PASS")
    message(f"F12_PHYSICAL_RESIDENT_{(target_index + 1)}_IDENTITY_AND_CAPACITY_PRESERVED: PASS existing={len(after_ids)} remaining={capacity.CAPACITY - len(after_ids)}")


def after_replug(pin, state, journal):
    old = state["powercycle_usb"]
    message(f"F12_REAL_USB_POWER_CYCLE_REQUIRED: unplug/replug once now; old USB={old}")
    while True:
        try:
            now = usb_number()
        except (AssertionError, FileNotFoundError):
            now = None
        if now is not None and now != old:
            break
        time.sleep(0.2)
    message(f"F12_REAL_USB_REENUMERATION: PASS {old} -> {now}")
    for attempt in range(20):
        try:
            device, ctap = capacity.card()
            break
        except (RuntimeError, OSError):
            if attempt == 19:
                raise
            time.sleep(1)
    try:
        assert ClientPin(ctap).get_pin_retries()[0] == 8
        assert read_full_snapshot(ctap, pin) == state["full_snapshot"]
        verify_resident_signature(ctap, pin, 0)
        verify_resident_signature(ctap, pin, capacity.CAPACITY - 1)
    finally:
        device.close()
    state["phase"] = "overflow"
    atomic_json(journal, state)
    message("F12_PHYSICAL_FULL_256_IDENTITIES_AND_PUBLIC_KEYS_AFTER_REPLUG: PASS")


def overflow(ctap, pin, state, journal):
    assert read_full_snapshot(ctap, pin) == state["full_snapshot"]
    while True:
        challenge = os.urandom(32)
        protocol = PinProtocolV2()
        token = get_token(ctap, pin)
        message("F12_257TH_REQUEST: expect KEY_STORE_FULL; touch BOOT if yellow")
        try:
            ctap.send_cbor(
                Ctap2.CMD.MAKE_CREDENTIAL,
                ctap_args(
                    challenge,
                    {"id": capacity.RP_ID, "name": "Aromatic Key disposable capacity test"},
                    {"id": (256).to_bytes(4, "big"), "name": "capacity-overflow-256"},
                    [{"type": "public-key", "alg": -7}],
                    None, None, {"rk": True},
                    protocol.authenticate(token, challenge), protocol.VERSION,
                ),
                on_keepalive=lambda status: message(f"F12_257TH_KEEPALIVE: status={status}; REAL_BOOT_REQUIRED"),
            )
        except CtapError as error:
            if error.code == CtapError.ERR.OPERATION_DENIED:
                assert count(ctap, pin) == 256
                message("F12_257TH_TOUCH_MISSED: retrying same overflow request")
                time.sleep(1)
                continue
            assert error.code in (CtapError.ERR.KEY_STORE_FULL, CtapError.ERR.LIMIT_EXCEEDED), error
            message(f"F12_257TH_REJECTED: PASS {error.code.name}")
            break
        else:
            raise AssertionError("257th credential succeeded; capacity overflow failed")
    assert read_full_snapshot(ctap, pin) == state["full_snapshot"]
    state["phase"] = "delete-one"
    atomic_json(journal, state)
    message("F12_257TH_OVERFLOW_LEFT_256_CREDENTIALS_UNCHANGED: PASS")


def delete_one(ctap, pin, state, journal):
    actual = current_ids(ctap, pin)
    if len(actual) == 256:
        assert set(actual) == set(range(256))
        target = actual[255]
        old_hash = sha(target)
        assert old_hash == state["full_snapshot"]["255"]["credential_sha256"]
        state["deleted_credential_hash"] = old_hash
        atomic_json(journal, state)
        capacity.management(ctap, pin).delete_cred({"id": target, "type": "public-key"})
    assert "deleted_credential_hash" in state
    assert len(current_ids(ctap, pin)) == 255
    remaining = current_ids(ctap, pin)
    assert set(remaining) == set(range(255))
    ensure_id_hashes(remaining, {str(i): state["ids"][str(i)] for i in range(255)})
    state["phase"] = "refill"
    atomic_json(journal, state)
    message("F12_DELETE_ONE_FREES_ONE_SLOT: PASS existing=255 remaining=1")


def refill(ctap, pin, state, journal, evidence):
    actual = current_ids(ctap, pin)
    assert len(actual) in (255, 256)
    ensure_id_hashes(actual, {str(i): state["ids"][str(i)] for i in range(255)})
    reconcile_inflight(actual, state, journal)
    if len(actual) == 255:
        assert set(actual) == set(range(255))
        state["ids"].pop("255", None)
        atomic_json(journal, state)
        perform_registration(ctap, pin, 255, state, evidence, journal, 255)
        actual = current_ids(ctap, pin)
    assert set(actual) == set(range(256))
    assert sha(actual[255]) != state["deleted_credential_hash"], "refill reused deleted credential ID"
    state["ids"]["255"] = sha(actual[255])
    state["phase"] = "cleanup"
    atomic_json(journal, state)
    message("F12_DELETE_REFILL_RETURNS_TO_FULL_256: PASS")


def cleanup(ctap, pin, state, journal):
    actual = current_ids(ctap, pin)
    message(f"F12_CLEANUP: selectively remove {len(actual)} disposable F12 RP credentials; NO Reset")
    manager = capacity.management(ctap, pin)
    for number, (index, cred_id) in enumerate(sorted(actual.items()), 1):
        manager.delete_cred({"id": cred_id, "type": "public-key"})
        if number % 16 == 0 or number == len(actual):
            message(f"F12_CLEANUP_PROGRESS: removed={number}/{len(actual)}")
    assert current_ids(ctap, pin) == {}
    assert ClientPin(ctap).get_pin_retries()[0] == 8
    state["phase"] = "done"
    atomic_json(journal, state)
    message("F12_DISPOSABLE_CREDENTIALS_CLEANED: PASS existing=0 remaining=256; PIN still 8/8")


def main():
    global EVIDENCE_DIR
    parser = argparse.ArgumentParser()
    parser.add_argument("--pin-file", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--status", action="store_true")
    options = parser.parse_args()
    EVIDENCE_DIR = options.evidence_dir
    message("AUTHORIZATION: Owner-approved personal Aromatic Key full physical F12 acceptance; all test credentials disposable.")
    message("SCOPE: FIDO-only RP test credentials; no Factory/FIDO Reset, no firmware/OTP/OpenPGP/PIV/OATH/HSM changes.")
    message("PRESENCE: Real BOOT for each registration; actual unplug/replug once at 256; no simulated touches.")
    pin = options.pin_file.read_text().strip()
    state = json.loads(options.journal.read_text()) if options.journal.exists() else None
    if options.status:
        device, ctap = capacity.card()
        try:
            current = current_ids(ctap, pin)
            message(f"F12_FULL_STATUS: existing={len(current)} remaining={256 - len(current)} phase={state['phase'] if state else 'new'}")
        finally:
            device.close()
        return

    if state is None:
        device, ctap = capacity.card()
        try:
            assert ClientPin(ctap).get_pin_retries()[0] == 8
            initial = current_ids(ctap, pin)
        finally:
            device.close()
        assert set(initial) == set(range(len(initial)))
        state = {
            "phase": "fill",
            "initial_existing": len(initial),
            "ids": {str(i): sha(cred_id) for i, cred_id in initial.items()},
            "attestation_failures": [],
            "unconfirmed_writes": [],
        }
        atomic_json(options.journal, state)

    if state["phase"] == "done":
        device, ctap = capacity.card()
        try:
            assert current_ids(ctap, pin) == {}
            assert ClientPin(ctap).get_pin_retries()[0] == 8
        finally:
            device.close()
        message("F12_PHYSICAL_FULL_ALREADY_COMPLETED: PASS actual store empty, PIN 8/8")
        message(f"F12_THIS_RUN_ATTESTATION_FAILURES: {len(state['attestation_failures'])}")
        message(f"F12_THIS_RUN_INTERRUPTED_WRITE_RECOVERIES: {len(state['unconfirmed_writes'])}")
        message(f"F12_THIS_RUN_INDEPENDENTLY_VERIFIED_RECOVERIES: {state.get('verified_recoveries', [])}")
        if state["attestation_failures"] or state["unconfirmed_writes"]:
            raise SystemExit(2)
        return

    device = None
    try:
        while state["phase"] != "done":
            if state["phase"] == "await-real-usb-replug":
                if device is not None:
                    device.close()
                    device = None
                after_replug(pin, state, options.journal)
                continue
            if device is None:
                device, ctap = capacity.card()
            assert ClientPin(ctap).get_pin_retries()[0] == 8
            phase = state["phase"]
            message(f"F12_FULL_PHASE: {phase}")
            if phase == "fill":
                fill(ctap, pin, state, options.journal, options.evidence_dir)
            elif phase == "overflow":
                overflow(ctap, pin, state, options.journal)
            elif phase == "delete-one":
                delete_one(ctap, pin, state, options.journal)
            elif phase == "refill":
                refill(ctap, pin, state, options.journal, options.evidence_dir)
            elif phase == "cleanup":
                cleanup(ctap, pin, state, options.journal)
            else:
                raise ValueError(f"unrecognized F12 state: {phase}")
    finally:
        if device is not None:
            device.close()
    message("F12_PHYSICAL_CAPACITY_OVERFLOW_REPLUG_REFILL_CLEANUP: PASS")
    message(f"F12_THIS_RUN_ATTESTATION_FAILURES: {len(state['attestation_failures'])}")
    message(f"F12_THIS_RUN_INTERRUPTED_WRITE_RECOVERIES: {len(state['unconfirmed_writes'])}")
    message(f"F12_THIS_RUN_INDEPENDENTLY_VERIFIED_RECOVERIES: {state.get('verified_recoveries', [])}")
    if state["attestation_failures"] or state["unconfirmed_writes"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
