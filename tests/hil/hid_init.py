#!/usr/bin/env python3
'Verify distinct CTAPHID broadcast INIT channels on a physical key.'
import argparse
import os
import struct

from fido2.hid import CtapHidDevice, CTAPHID
from fido2.ctap2 import Ctap2

parser = argparse.ArgumentParser()
parser.add_argument("--rounds", type=int, default=8)
args = parser.parse_args()
if not 2 <= args.rounds <= 64:
    raise SystemExit("rounds must be within [2, 64]")

cids = []
for index in range(args.rounds):
    cards = [
        dev for dev in CtapHidDevice.list_devices()
        if (dev.descriptor.vid, dev.descriptor.pid) == (0x1050, 0x0407)
    ]
    if len(cards) != 1:
        for d in cards:
            d.close()
        raise RuntimeError(f"expected 1 physical FIDO Key; got {len(cards)}")
    dev = cards[0]
    try:
        cid = dev._channel_id
        assert cid not in (0, 0xFFFFFFFF), (index, cid)
        cids.append(cid)
        nonce = os.urandom(8)
        init_again = dev.call(CTAPHID.INIT, nonce)
        assert init_again[:8] == nonce, "INIT nonce mismatch"
        same_cid = struct.unpack(">I", init_again[8:12])[0]
        assert same_cid == cid, (cid, same_cid)
        info = Ctap2(dev).get_info()
        assert "FIDO_2_1" in info.versions
    finally:
        dev.close()

distinct = len(set(cids))
print(f"CTAPHID_BROADCAST_INIT_DISTINCT: {distinct}/{args.rounds}")
print("CTAPHID_CONNECTED_CHANNEL_REINIT_PRESERVED: PASS")
print(f"CTAPHID_INFO: {args.rounds}/{args.rounds}")
if distinct != args.rounds:
    raise AssertionError(f"broadcast INIT reused CID: {distinct}/{args.rounds} distinct")
print("PHYSICAL_CTAPHID_INIT_CHANNEL_ALLOCATION: PASS")
