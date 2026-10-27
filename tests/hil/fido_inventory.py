#!/usr/bin/env python3
'Read physical FIDO credential identity and capacity metadata.'
import argparse
import base64
import hashlib
import json
from pathlib import Path

from fido2 import cbor
from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
from fido2.ctap2.pin import PinProtocolV2
from fido2.hid import CtapHidDevice

parser=argparse.ArgumentParser()
parser.add_argument("--state-dir",type=Path,required=True)
parser.add_argument("--reads",type=int,default=30)
args=parser.parse_args()
if not 1<=args.reads<=100:raise SystemExit("reads must be 1..100")

devs=[d for d in CtapHidDevice.list_devices()
      if (d.descriptor.vid,d.descriptor.pid)==(0x1050,0x0407)]
assert len(devs)==1,len(devs)
dev=devs[0]
try:
    ctap=Ctap2(dev)
    opts=[ctap.get_info().options for _ in range(args.reads)]
    states={o.get("alwaysUv") for o in opts}
    assert len(states)==1,states
    assert all(o.get("rk") is True and o.get("clientPin") is True and
               o.get("credMgmt") is True and o.get("authnrCfg") is True
               for o in opts)
    print(f"FIDO_GETINFO_STABLE: {args.reads}/{args.reads} alwaysUv={next(iter(states))}",flush=True)

    cp=ClientPin(ctap)
    pin=args.state_dir.joinpath("real-card-test-pin.txt").read_text().strip()
    retries_before=cp.get_pin_retries()[0]
    token=cp.get_pin_token(pin,permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
    manager=CredentialManagement(ctap,PinProtocolV2(),token)
    metadata=manager.get_metadata()
    existing=metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
    remaining=metadata[CredentialManagement.RESULT.MAX_REMAINING_COUNT]
    rps=manager.enumerate_rps()
    by_rp={}
    total=0
    for rp in rps:
        name=rp[CredentialManagement.RESULT.RP]["id"]
        rp_hash=hashlib.sha256(name.encode()).digest()
        creds=manager.enumerate_creds(rp_hash)
        by_rp[name]=creds
        total+=len(creds)
    assert total==existing,(total,existing)
    print(f"FIDO_CRED_METADATA_AND_COMPLETE_ENUMERATION: PASS existing={existing} remaining={remaining} rps={len(rps)}",flush=True)

    for case in ("hsmreset","multi2","multi3"):
        state=json.loads(args.state_dir.joinpath("real-card-"+case+"-resident.json").read_text())
        rp=state["rp"]
        matches=[c for c in by_rp.get(rp,[]) if
                 c[CredentialManagement.RESULT.CREDENTIAL_ID]["id"]==
                 base64.b64decode(state["credential_id_b64"])]
        assert len(matches)==1,(case,"missing or duplicate")
        value=matches[0]
        assert value[CredentialManagement.RESULT.USER]["id"]==base64.b64decode(state["user_id_b64"])
        assert cbor.encode(dict(value[CredentialManagement.RESULT.PUBLIC_KEY]))==base64.b64decode(state["cose_public_key_b64"])
        print(f"FIDO_ORIGINAL_RESIDENT_{case.upper()}: PASS",flush=True)
    assert cp.get_pin_retries()[0]==retries_before
    print(f"FIDO_PIN_RETRIES_UNCHANGED: PASS {retries_before}",flush=True)
finally:
    dev.close()
