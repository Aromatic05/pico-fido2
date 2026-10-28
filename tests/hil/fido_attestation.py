#!/usr/bin/env python3
'Capture and validate a physical FIDO attestation response.'

import argparse
import hashlib
import json
import os
from pathlib import Path

from fido2 import cbor
from fido2.ctap2 import Ctap2, ClientPin, AttestationResponse
from fido2.ctap2.base import args
from fido2.ctap2.pin import PinProtocolV2

from hil import fido_capacity_support as capacity


def save_raw(raw_response, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(cbor.encode(raw_response))
        output.flush()
        os.fsync(output.fileno())
    print(f"F12_PHYSICAL_ATTESTATION_INVALID_RESPONSE_SAVED_PRIVATE: {path.name}", flush=True)


def describe(response):
    auth_data = response.get(2, b"")
    print(f"F12_ATTESTATION_AUTHDATA_TOTAL_LEN: {len(auth_data)}", flush=True)
    if len(auth_data) < 55:
        print("F12_ATTESTATION_AUTHDATA_TOO_SHORT_FOR_CREDENTIAL", flush=True)
        return
    flags = auth_data[32]
    cred_length = int.from_bytes(auth_data[53:55], "big")
    cose_start = 55 + cred_length
    print(f"F12_ATTESTATION_FLAGS: {flags:#04x} CRED_ID_LEN: {cred_length} COSE_OFFSET: {cose_start}", flush=True)
    if cose_start <= len(auth_data):
        try:
            key, trailing = cbor.decode_from(auth_data[cose_start:])
            print(f"F12_ATTESTATION_COSE_KEY_TYPE: {type(key).__name__} TRAILING_BYTES: {len(trailing)}", flush=True)
            print(f"F12_ATTESTATION_TRAILING_PREFIX: {trailing[:12].hex()}", flush=True)
        except Exception as error:
            print(f"F12_ATTESTATION_COSE_DECODE_ERROR: {type(error).__name__}: {error}", flush=True)


def run(ctap, pin, destination):
    before = capacity.entries(capacity.management(ctap, pin))
    count = len(before)
    assert set(before) == set(range(count)) and count < capacity.CAPACITY
    print(f"F12_PHYSICAL_ATTESTATION_BEFORE: count={count} remaining={capacity.CAPACITY - count}", flush=True)
    client_hash = os.urandom(32)
    protocol = PinProtocolV2()
    token = ClientPin(ctap).get_pin_token(
        pin, permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
        permissions_rpid=capacity.RP_ID,
    )
    print(f"F12_PHYSICAL_ATTESTATION_REQUEST_CREDENTIAL_{count + 1}_WAIT_FOR_REAL_BOOT", flush=True)
    response = ctap.send_cbor(
        Ctap2.CMD.MAKE_CREDENTIAL,
        args(client_hash,
             {"id": capacity.RP_ID, "name": "Aromatic Key disposable capacity test"},
             {"id": count.to_bytes(4, "big"), "name": f"capacity-{count}"},
             [{"type": "public-key", "alg": -7}],
             None, None, {"rk": True},
             protocol.authenticate(token, client_hash), protocol.VERSION),
        on_keepalive=lambda status: print(f"F12_PHYSICAL_ATTESTATION_KEEPALIVE_{status}: REAL_BOOT_REQUIRED", flush=True),
    )
    try:
        attestation = AttestationResponse.from_dict(response)
    except ValueError as error:
        describe(response)
        save_raw(response, destination / f"f12-physical-invalid-attestation-{count + 1}.cbor")
        print(f"F12_PHYSICAL_ATTESTATION_STANDARD_PARSER: FAIL {type(error).__name__}: {error}", flush=True)
        raise
    assert attestation.auth_data.credential_data is not None
    after = capacity.entries(capacity.management(ctap, pin))
    assert set(after) == set(range(count + 1))
    assert all(after[index] == old_id for index, old_id in before.items())
    assert after[count] == attestation.auth_data.credential_data.credential_id
    print(f"F12_PHYSICAL_ATTESTATION_STANDARD_PARSER_AND_STORE: PASS existing={len(after)} remaining={capacity.CAPACITY - len(after)}", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pin-file", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    print("AUTHORIZATION: Owner-authorized experimental Aromatic Key real CTAP2 response analysis; only disposable test data.", flush=True)
    print("SCOPE: One normal resident registration with real BOOT; preserve failed response privately, never simulate touch.", flush=True)
    pin = args.pin_file.read_text().strip()
    device, ctap = capacity.card()
    try:
        assert ClientPin(ctap).get_pin_retries()[0] == 8
        run(ctap, pin, args.evidence_dir)
    finally:
        device.close()


if __name__ == "__main__":
    main()
