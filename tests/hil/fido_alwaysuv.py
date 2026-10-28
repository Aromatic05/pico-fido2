#!/usr/bin/env python3
'Verify persistent alwaysUv across physical key restarts.'
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

from fido2 import cbor
from fido2.ctap2 import Ctap2, ClientPin, Config, CredentialManagement
from fido2.ctap2.pin import PinProtocolV2
from fido2.hid import CtapHidDevice

parser=argparse.ArgumentParser()
parser.add_argument("phase", choices=["enable","verify-on-and-disable","verify-off","restore"])
parser.add_argument("--state-dir",type=Path,required=True)
parser.add_argument("--checkpoint",type=Path,required=True)
args=parser.parse_args()

pin=args.state_dir.joinpath("real-card-test-pin.txt").read_text().strip()
assert len(pin)>=4
cards=[dev for dev in CtapHidDevice.list_devices()
       if (dev.descriptor.vid,dev.descriptor.pid)==(0x1050,0x0407)]
assert len(cards)==1,len(cards)
device=cards[0]
ctap=Ctap2(device)
protocol=PinProtocolV2()

def policy():
    readings=[ctap.get_info().options for _ in range(5)]
    assert all(i.get("authnrCfg") is True and i.get("clientPin") is True and i.get("credMgmt") is True
               for i in readings)
    states=[i.get("alwaysUv") for i in readings]
    assert len(set(states))==1,states
    return states[0]

def inventory():
    pin_api=ClientPin(ctap)
    retries=pin_api.get_pin_retries()[0]
    assert retries==8, f"original PIN retry baseline changed: {retries}"
    token=pin_api.get_pin_token(pin,permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
    manager=CredentialManagement(ctap,protocol,token)
    metadata=manager.get_metadata()
    rps=manager.enumerate_rps()
    assert metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT]>=3
    count=0
    rp_map={}
    for entry in rps:
        rp=entry[CredentialManagement.RESULT.RP]["id"]
        creds=manager.enumerate_creds(hashlib.sha256(rp.encode()).digest())
        count+=len(creds)
        rp_map[rp]=creds
    assert count==metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
    for case in ("hsmreset","multi2","multi3"):
        state=json.loads(args.state_dir.joinpath("real-card-"+case+"-resident.json").read_text())
        items=[item for item in rp_map.get(state["rp"],[]) if
               item[CredentialManagement.RESULT.CREDENTIAL_ID]["id"]==
               base64.b64decode(state["credential_id_b64"])]
        assert len(items)==1, (case,"missing or duplicated resident")
        item=items[0]
        assert item[CredentialManagement.RESULT.USER]["id"]==base64.b64decode(state["user_id_b64"])
        assert cbor.encode(dict(item[CredentialManagement.RESULT.PUBLIC_KEY]))==base64.b64decode(state["cose_public_key_b64"])
    assert pin_api.get_pin_retries()[0]==retries
    print(f"FIDO_3_ORIGINAL_RESIDENTS_AND_PIN_RETRIES: PASS retries={retries} existing={count}",flush=True)

def toggle():
    token=ClientPin(ctap).get_pin_token(pin,permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    Config(ctap,protocol,token).toggle_always_uv()

def checkpoint_read():
    if not args.checkpoint.is_file():
        raise RuntimeError("I09 checkpoint missing")
    return json.loads(args.checkpoint.read_text())

def checkpoint_write(phase):
    args.checkpoint.parent.mkdir(parents=True,exist_ok=True)
    payload=json.dumps({"phase":phase,"initialPolicy":False,"originalSentinels":3})+"\n"
    path=args.checkpoint.with_suffix(".tmp")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,"w") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    os.replace(path,args.checkpoint)

try:
    if args.phase=="enable":
        if args.checkpoint.exists():
            raise RuntimeError("prior I09 configuration checkpoint present; use verify-on-and-disable or restore")
        assert policy() is False,"original alwaysUv policy was not Off"
        inventory()
        checkpoint_write("before-enable")
        toggle()
        assert policy() is True
        checkpoint_write("enabled")
        inventory()
        print("I09_PHYSICAL_ALWAYSUV_ENABLED: PASS; unplug/reinsert the Key next",flush=True)
    elif args.phase=="verify-on-and-disable":
        assert checkpoint_read()["phase"] in ("before-enable","enabled")
        assert policy() is True,"alwaysUv did not survive USB replug"
        inventory()
        print("I09_PHYSICAL_ALWAYSUV_PERSISTED_AFTER_REPLUG: PASS",flush=True)
        toggle()
        assert policy() is False
        checkpoint_write("disabled")
        inventory()
        print("I09_PHYSICAL_ALWAYSUV_RESTORED_OFF: PASS; unplug/reinsert the Key next",flush=True)
    elif args.phase=="verify-off":
        assert checkpoint_read()["phase"]=="disabled"
        assert policy() is False,"restored Off did not survive USB replug"
        inventory()
        args.checkpoint.unlink()
        print("I09_PHYSICAL_ALWAYSUV_ON_OFF_PERSISTENCE: PASS",flush=True)
    else:
        if policy() is True:
            toggle()
        assert policy() is False
        inventory()
        if args.checkpoint.exists(): args.checkpoint.unlink()
        print("I09_ALWAYSUV_RECOVERED_TO_ORIGINAL_OFF: PASS",flush=True)
finally:
    device.close()
