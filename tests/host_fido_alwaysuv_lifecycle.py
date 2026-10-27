#!/usr/bin/env python3
"""Software-card FIDO2 alwaysUv test, with actual source and restart across phases."""
import argparse
import hashlib
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, ClientPin, Config, CredentialManagement
from fido2.ctap2.pin import PinProtocolV2
from fido2.hid import CtapHidDevice

PIN = "AromaticAlwaysUv42"
RP = "aromatic-alwaysuv-test.invalid"

def open_card():
    devices=list(CtapHidDevice.list_devices())
    assert len(devices)==1,len(devices)
    ctap=Ctap2(devices[0])
    return devices[0],ctap

def policy(ctap):
    info=ctap.get_info()
    assert info.options.get("clientPin") is True
    assert info.options.get("authnrCfg") is True
    assert info.options.get("credMgmt") is True
    return info.options.get("alwaysUv")

def config_token(ctap):
    pin=ClientPin(ctap)
    assert pin.get_pin_retries()[0]==8
    token=pin.get_pin_token(PIN,permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    return Config(ctap, PinProtocolV2(), token)

def assertion_error(ctap, pin_authenticated=False):
    protocol=PinProtocolV2()
    kwargs={"rp_id":RP,"client_data_hash":hashlib.sha256(b"alwaysUv").digest(),
            "options":{"up":False}}
    if pin_authenticated:
        token=ClientPin(ctap).get_pin_token(
            PIN,permissions=ClientPin.PERMISSION.GET_ASSERTION,permissions_rpid=RP)
        kwargs["pin_uv_param"]=protocol.authenticate(token,kwargs["client_data_hash"])
        kwargs["pin_uv_protocol"]=protocol.VERSION
    try:
        ctap.get_assertion(**kwargs)
    except CtapError as exc:
        return exc.code
    raise AssertionError("Unexpectedly produced an assertion for nonexistent RP")

def make_credential_without_uv_error(ctap):
    try:
        ctap.make_credential(
            client_data_hash=hashlib.sha256(b"alwaysUv-register").digest(),
            rp={"id":RP,"name":"Always UV test"},
            user={"id":b"alwaysuv-noauth","name":"alwaysuv"},
            key_params=[{"type":"public-key","alg":-7}],
            options={"rk":False},
        )
    except CtapError as exc:
        return exc.code
    raise AssertionError("Unverified MakeCredential bypassed alwaysUv policy")

parser=argparse.ArgumentParser()
parser.add_argument("phase",choices=["prepare","after-enable","after-disable"])
phase=parser.parse_args().phase
device,ctap=open_card()
try:
    if phase=="prepare":
        assert ctap.get_info().options.get("clientPin") is False
        ClientPin(ctap).set_pin(PIN)
        assert policy(ctap) is False
        assert ClientPin(ctap).get_pin_retries()[0]==8
        token=ClientPin(ctap).get_pin_token(PIN,permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        metadata=CredentialManagement(ctap,PinProtocolV2(),token).get_metadata()
        assert metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT]==0,metadata
        print("ALWAYSUV_OLD_DEFAULT_AND_EMPTY_CRED_STORE: PASS",flush=True)
        try:
            Config(ctap).toggle_always_uv()
        except CtapError as exc:
            assert exc.code == CtapError.ERR.PUAT_REQUIRED, exc
        else:
            raise AssertionError("unauthenticated alwaysUv toggle accepted")
        try:
            Config(ctap,PinProtocolV2(),token).toggle_always_uv()
        except CtapError as exc:
            assert exc.code == CtapError.ERR.PIN_AUTH_INVALID, exc
        else:
            raise AssertionError("Credential Management token changed alwaysUv policy")
        assert policy(ctap) is False
        print("ALWAYSUV_REJECTS_MISSING_AND_WRONG_SCOPE_AUTH: PASS",flush=True)
        config_token(ctap).toggle_always_uv()
        assert all(policy(ctap) is True for _ in range(5))
        print("ALWAYSUV_ENABLE_WITH_AUTHCFG_PIN: PASS",flush=True)
        assert assertion_error(ctap)==CtapError.ERR.PUAT_REQUIRED
        assert assertion_error(ctap,pin_authenticated=True)==CtapError.ERR.NO_CREDENTIALS
        print("ALWAYSUV_REQUIRES_PIN_FOR_GET_ASSERTION: PASS",flush=True)
        assert make_credential_without_uv_error(ctap)==CtapError.ERR.PUAT_REQUIRED
        print("ALWAYSUV_REQUIRES_PIN_FOR_MAKE_CREDENTIAL: PASS",flush=True)
    elif phase=="after-enable":
        assert all(policy(ctap) is True for _ in range(5))
        print("ALWAYSUV_PERSISTED_AFTER_EMULATOR_RESTART: PASS",flush=True)
        assert assertion_error(ctap)==CtapError.ERR.PUAT_REQUIRED
        assert make_credential_without_uv_error(ctap)==CtapError.ERR.PUAT_REQUIRED
        config_token(ctap).toggle_always_uv()
        assert all(policy(ctap) is False for _ in range(5))
        assert assertion_error(ctap,pin_authenticated=True)==CtapError.ERR.NO_CREDENTIALS
        print("ALWAYSUV_DISABLE_WITH_AUTHCFG_PIN: PASS",flush=True)
    else:
        assert all(policy(ctap) is False for _ in range(5))
        assert ClientPin(ctap).get_pin_retries()[0]==8
        assert assertion_error(ctap,pin_authenticated=True)==CtapError.ERR.NO_CREDENTIALS
        print("ALWAYSUV_DISABLED_AFTER_SECOND_RESTART: PASS",flush=True)
finally:
    device.close()
