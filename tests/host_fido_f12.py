#!/usr/bin/env python3
"""F12 test on a disposable software-card Flash: complete resident capacity and PIN state.

This is intentionally not a real USB test; the destructive hard PIN lockout
and credential-store saturation happen only in an isolated Virtual CTAP card.
"""
import argparse
import hashlib
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2,ClientPin,CredentialManagement
from fido2.ctap2.pin import PinProtocolV2
from fido2.hid import CtapHidDevice

PIN="AromaticF12Disposable42"
RP="f12-capacity.aromatic.invalid"
def card():
    d=list(CtapHidDevice.list_devices())
    assert len(d)==1,d
    return d[0],Ctap2(d[0])
def metadata(ctap):
    cp=ClientPin(ctap)
    t=cp.get_pin_token(PIN,permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
    return CredentialManagement(ctap,PinProtocolV2(),t).get_metadata()
def expect_count(ctap,total,remaining):
    m=metadata(ctap)
    assert m[CredentialManagement.RESULT.EXISTING_CRED_COUNT]==total,m
    assert m[CredentialManagement.RESULT.MAX_REMAINING_COUNT]==remaining,m
    return m
def create(ctap,index):
    nonce=hashlib.sha256(b"f12-capacity-"+str(index).encode()).digest()
    token=ClientPin(ctap).get_pin_token(PIN,permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,permissions_rpid=RP)
    p=PinProtocolV2()
    return ctap.make_credential(
        client_data_hash=nonce,
        rp={"id":RP,"name":"Disposable capacity test"},
        user={"id":index.to_bytes(4,"big"),"name":str(index)},
        key_params=[{"alg":-7,"type":"public-key"}],
        options={"rk":True},
        pin_uv_param=p.authenticate(token,nonce),pin_uv_protocol=p.VERSION,
    )
parser=argparse.ArgumentParser()
parser.add_argument("phase",choices=["fill","check-full","pin-make","pin-softlock","pin-unlock","pin-hardlock1","pin-hardlock2","pin-hardlock3","pin-reset"])
phase=parser.parse_args().phase
dev,ctap=card()
try:
    if phase=="fill":
        ClientPin(ctap).set_pin(PIN)
        # MAX_RESIDENT_CREDENTIALS=256 from the actual firmware, not a
        # guessed lower threshold or an already-created credential count.
        capacity=256
        assert ClientPin(ctap).get_pin_retries()[0]==8
        print("F12_VIRTUAL_CONFIGURED_RESIDENT_CAPACITY",capacity,flush=True)
        for i in range(capacity):
            response=create(ctap,i)
            assert response.auth_data.credential_data is not None,i
            if i%32==31 or i==capacity-1:
                print("F12_VIRTUAL_RESIDENTS_CREATED",i+1,flush=True)
        expect_count(ctap,capacity,0)
        print("F12_VIRTUAL_FULL_CAPACITY_METADATA: PASS",flush=True)
        try:create(ctap,capacity)
        except CtapError as e:
            assert e.code in (CtapError.ERR.KEY_STORE_FULL,CtapError.ERR.LIMIT_EXCEEDED),e
            print("F12_VIRTUAL_FULL_CAPACITY_REJECTED",e.code.name,flush=True)
        else:raise AssertionError("capacity overflow accepted a new Resident")
        expect_count(ctap,capacity,0)
        print("F12_VIRTUAL_BOUNDARY_CAPACITY_AND_OVERFLOW: PASS",flush=True)
    elif phase=="check-full":
        m=metadata(ctap)
        total=m[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
        assert total>1 and m[CredentialManagement.RESULT.MAX_REMAINING_COUNT]==0
        t=ClientPin(ctap).get_pin_token(PIN,permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        mg=CredentialManagement(ctap,PinProtocolV2(),t)
        rps=mg.enumerate_rps()
        assert len(rps)==1
        rp_hash=hashlib.sha256(RP.encode()).digest()
        creds=mg.enumerate_creds(rp_hash)
        assert len(creds)==total
        print("F12_VIRTUAL_FULL_ENUMERATION_AFTER_RESTART",total,flush=True)
        descriptor=creds[0][CredentialManagement.RESULT.CREDENTIAL_ID]
        mg.delete_cred(descriptor)
        expect_count(ctap,total-1,1)
        print("F12_VIRTUAL_DELETE_ONE_RESTORES_ONE_CAPACITY: PASS",flush=True)
        response=create(ctap,total+1)
        assert response.auth_data.credential_data
        expect_count(ctap,total,0)
        print("F12_VIRTUAL_REINSERT_AT_CAPACITY: PASS",flush=True)
    elif phase=="pin-make":
        cp=ClientPin(ctap)
        cp.set_pin(PIN)
        print("F12_PIN_MAKE_INIT_RETRIES",cp.get_pin_retries()[0],flush=True)
        t=cp.get_pin_token(PIN,permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,permissions_rpid=RP)
        p=PinProtocolV2()
        nonce=hashlib.sha256(b"aromatic-f12-pin-make-first").digest()
        response=ctap.make_credential(
            client_data_hash=nonce,rp={"id":RP,"name":"F12"},
            user={"id":b"f12-user","name":"f12-user"},
            key_params=[{"type":"public-key","alg":-7}],options={"rk":True},
            pin_uv_param=p.authenticate(t,nonce),pin_uv_protocol=p.VERSION)
        assert response.auth_data.credential_data is not None
        print("F12_SOFTWARE_PIN_MAKE_CREDENTIAL_FRESH: PASS",flush=True)
    elif phase=="pin-softlock":
        cp=ClientPin(ctap)
        cp.set_pin(PIN)
        for i in range(3):
            try:cp.get_pin_token("WrongF12Pin!")
            except CtapError as e:
                print("F12_VIRTUAL_WRONG_PIN",i+1,e.code.name,flush=True)
            else:raise AssertionError("wrong PIN accepted")
        attempts=cp.get_pin_retries()
        assert attempts[0]==5,attempts
        try:cp.get_pin_token(PIN)
        except CtapError as e:
            assert e.code==CtapError.ERR.PIN_AUTH_BLOCKED,e
        else:raise AssertionError("temporary PIN auth lockout not enforced")
        print("F12_VIRTUAL_SOFT_PIN_LOCK_AND_RETRIES: PASS",flush=True)
    elif phase=="pin-unlock":
        cp=ClientPin(ctap)
        assert cp.get_pin_retries()[0]==5
        cp.get_pin_token(PIN)
        assert cp.get_pin_retries()[0]==8
        print("F12_VIRTUAL_REBOOT_CLEARS_SOFT_LOCK_WITH_CORRECT_PIN: PASS",flush=True)
    elif phase.startswith("pin-hardlock"):
        cp=ClientPin(ctap)
        pass_no=int(phase[-1])
        if pass_no==1:
            assert ctap.get_info().options.get("clientPin") is False
            cp.set_pin(PIN)
        initial={1:8,2:5,3:2}[pass_no]
        wrong_count={1:3,2:3,3:2}[pass_no]
        assert cp.get_pin_retries()[0]==initial
        for i in range(wrong_count):
            try:cp.get_pin_token("WrongF12Pin!")
            except CtapError as e:
                assert e.code in (CtapError.ERR.PIN_INVALID,
                                  CtapError.ERR.PIN_AUTH_BLOCKED,
                                  CtapError.ERR.PIN_BLOCKED),e
            else:raise AssertionError("wrong PIN accepted")
        assert cp.get_pin_retries()[0]==initial-wrong_count
        print("F12_VIRTUAL_LOCKOUT_STAGE",pass_no,"RETRIES",initial-wrong_count,flush=True)
        if pass_no==3:
            print("F12_VIRTUAL_HARD_LOCK_RETRIES_EXHAUSTED: PASS",flush=True)
    else:
        cp=ClientPin(ctap)
        assert cp.get_pin_retries()[0]==0
        try:cp.get_pin_token(PIN)
        except CtapError as e:assert e.code==CtapError.ERR.PIN_BLOCKED,e
        else:raise AssertionError("permanently locked PIN unexpectedly accepted")
        ctap.reset()
        assert ctap.get_info().options.get("clientPin") is False
        cp.set_pin(PIN)
        assert cp.get_pin_retries()[0]==8
        print("F12_VIRTUAL_HARD_LOCK_RECOVERED_BY_DISPOSABLE_RESET: PASS",flush=True)
finally:
    dev.close()
