#!/usr/bin/env python3
"""Replay the real F12 MakeCredential input profile on isolated virtual Flash.

Emulated user presence here is not hardware BOOT. This compares the standard
python-fido2 attestation parser against the exact RP/user/options supplied in
the physical test that returned ValueError('Wrong length').
"""

import hashlib
import os
from pathlib import Path

from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
from fido2.ctap2.pin import PinProtocolV2
from fido2.hid import CtapHidDevice

from hil import fido_capacity as full

RP_ID = "f12-capacity.aromatic-key.invalid"
PIN = "F12VirtualProfilePin42"
COUNT = 32


def main():
    devices = list(CtapHidDevice.list_devices())
    assert len(devices) == 1
    device = devices[0]
    try:
        ctap = Ctap2(device)
        ClientPin(ctap).set_pin(PIN)
        expected = {}
        for index in range(COUNT):
            challenge = os.urandom(32)
            protocol = PinProtocolV2()
            token = ClientPin(ctap).get_pin_token(
                PIN, permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
                permissions_rpid=RP_ID,
            )
            response = ctap.make_credential(
                client_data_hash=challenge,
                rp={"id": RP_ID, "name": "Aromatic Key disposable capacity test"},
                user={"id": index.to_bytes(4, "big"), "name": f"capacity-{index}"},
                key_params=[{"type": "public-key", "alg": -7}],
                options={"rk": True},
                pin_uv_param=protocol.authenticate(token, challenge),
                pin_uv_protocol=protocol.VERSION,
            )
            assert response.auth_data.credential_data is not None
            expected[index] = response.auth_data.credential_data.credential_id
            if (index + 1) % 4 == 0:
                print(f"F12_VIRTUAL_PHYSICAL_PROFILE_STANDARD_ATTESTATION_PARSED: PASS count={index + 1}", flush=True)
        token = ClientPin(ctap).get_pin_token(PIN, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        manager = CredentialManagement(ctap, PinProtocolV2(), token)
        meta = manager.get_metadata()
        assert meta[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == COUNT
        assert meta[CredentialManagement.RESULT.MAX_REMAINING_COUNT] == 256 - COUNT
        found = manager.enumerate_creds(hashlib.sha256(RP_ID.encode()).digest())
        assert len(found) == COUNT
        for item in found:
            index = int.from_bytes(item[CredentialManagement.RESULT.USER]["id"], "big")
            assert item[CredentialManagement.RESULT.CREDENTIAL_ID]["id"] == expected[index]
        print("F12_VIRTUAL_EXACT_PHYSICAL_PROFILE_ATTESTATIONS_AND_RESIDENT_STORE: PASS count=32", flush=True)
        full.EVIDENCE_DIR = Path(".")
        full.message = lambda value: print(
            value.replace("REAL_PRIVATE_KEY_SIGNATURE", "VIRTUAL_SIGNATURE")
                 .replace("touch real BOOT once", "virtual card uses synthetic UP")
                 .replace("REAL_BOOT_REQUIRED", "SYNTHETIC_UP"),
            flush=True,
        )
        state = {"unconfirmed_writes": [4], "verified_recoveries": []}
        full.verify_recovered_writes(ctap, PIN, state, Path("f12-virtual-recovered.json"), expected)
        assert state["unconfirmed_writes"] == [] and state["verified_recoveries"] == [4]
        refreshed = full.capacity.management(ctap, PIN)
        assert refreshed.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == COUNT
        print("F12_VIRTUAL_INTERRUPTED_WRITE_GET_ASSERTION_RECOVERY: PASS (synthetic UP)", flush=True)
    finally:
        device.close()


if __name__ == "__main__":
    main()
