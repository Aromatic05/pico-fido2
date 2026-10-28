"""Shared physical FIDO capacity protocol operations."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
from fido2.ctap2.pin import PinProtocolV2
from fido2.hid import CtapHidDevice

RP_ID = "f12-capacity.aromatic-key.invalid"
CAPACITY = 256


def card():
    matches = [dev for dev in CtapHidDevice.list_devices()
               if (dev.descriptor.vid, dev.descriptor.pid) == (0x1050, 0x0407)]
    if len(matches) != 1:
        for dev in matches:
            dev.close()
        raise RuntimeError(f"expected one physical test Key, got {len(matches)}")
    return matches[0], Ctap2(matches[0])


def management(ctap, pin):
    token = ClientPin(ctap).get_pin_token(
        pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT,
    )
    return CredentialManagement(ctap, PinProtocolV2(), token)


def entries(manager):
    meta = manager.get_metadata()
    count = meta[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
    remaining = meta[CredentialManagement.RESULT.MAX_REMAINING_COUNT]
    assert count + remaining == CAPACITY, (count, remaining)
    if count == 0:
        return {}
    rps = manager.enumerate_rps()
    assert [x[CredentialManagement.RESULT.RP]["id"] for x in rps] == [RP_ID]
    listing = manager.enumerate_creds(hashlib.sha256(RP_ID.encode()).digest())
    assert len(listing) == count, (len(listing), count)
    indexed = {}
    public_points = set()
    for item in listing:
        user = item[CredentialManagement.RESULT.USER]["id"]
        assert len(user) == 4
        index = int.from_bytes(user, "big")
        assert index not in indexed and index < CAPACITY
        indexed[index] = item[CredentialManagement.RESULT.CREDENTIAL_ID]["id"]
        key = item[CredentialManagement.RESULT.PUBLIC_KEY]
        assert key[1] == 2 and key[3] == -7 and key[-1] == 1
        x, y = key[-2], key[-3]
        assert len(x) == 32 and len(y) == 32
        ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
        public_points.add((x, y))
    assert len(set(indexed.values())) == count
    assert len(public_points) == count
    return indexed




















