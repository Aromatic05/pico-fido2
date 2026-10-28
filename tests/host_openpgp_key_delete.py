#!/usr/bin/env python3
"""Exact OpenPGP v4 YubiKit delete_key contract on real-source Virtual PCD."""
import hashlib
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from ykman.pcsc import list_devices
from yubikit.core.smartcard import ApduError,SmartCardConnection,SW
from yubikit.openpgp import OpenPgpSession,KEY_REF,KEY_STATUS,DO

def fingerprint(k):
    return hashlib.sha256(k.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).digest()

devices=list_devices("Virtual PCD 00 00")
assert len(devices)==1,devices
with devices[0].open_connection(SmartCardConnection) as conn:
    s=OpenPgpSession(conn)
    raw=s.get_data(DO.ALGORITHM_INFORMATION)
    print("OPENPGP_VIRTUAL_PROFILE_VERSION",s.version,flush=True)
    print("OPENPGP_VIRTUAL_0XFA_RAW_BYTES",len(raw),"DECLARED",int.from_bytes(raw[2:4],"big"),"PREFIX",raw[:8].hex(),flush=True)
    assert all(x==KEY_STATUS.NONE for x in s.get_key_information().values())
    s.verify_admin("12345678")
    sig_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    s.put_key(KEY_REF.SIG,sig_key)
    sig_fp=fingerprint(s.get_public_key(KEY_REF.SIG))
    print("OPENPGP_OWNED_SIG_INITIALIZED: PASS",flush=True)
    for slot in (KEY_REF.DEC,KEY_REF.AUT):
        existing_attrs=s.get_algorithm_attributes(slot)
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        s.put_key(slot,key)
        assert s.get_key_information()[slot]!=KEY_STATUS.NONE
        assert fingerprint(s.get_public_key(slot))==fingerprint(key.public_key())
        print("OPENPGP_"+slot.name+"_IMPORT: PASS",flush=True)
        s.delete_key(slot)
        info=s.get_key_information()
        assert info[slot]==KEY_STATUS.NONE,("OpenPGP key deletion failed",slot.name,info[slot])
        try:s.get_public_key(slot)
        except ApduError as e:assert e.sw==SW.REFERENCE_DATA_NOT_FOUND,e
        else:raise AssertionError("deleted slot public key still returned")
        assert fingerprint(s.get_public_key(KEY_REF.SIG))==sig_fp
        print("OPENPGP_"+slot.name+"_KEY_DELETION_AND_SIG_PRESERVATION: PASS",flush=True)
    s.verify_pin("123456")
    msg=b"disposable signed data"
    sig=s.sign(msg,hashes.SHA256())
    sig_key.public_key().verify(sig,msg,padding.PKCS1v15(),hashes.SHA256())
    print("OPENPGP_OLD_SIG_PRIVATE_KEY_STILL_WORKS: PASS",flush=True)
print("OPENPGP_STANDARD_KEY_DELETION_BOTH_SLOTS: PASS",flush=True)
