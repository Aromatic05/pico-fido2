#!/usr/bin/env python3
'Physical OpenPGP decryption, authentication and interrupted import recovery.'
import argparse
import sys

def keys():
    import argparse
    import hashlib
    import json
    import os
    from pathlib import Path

    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519,padding,rsa
    from ykman.device import list_all_devices
    from ykman.pcsc import list_devices as list_virtual_devices
    from yubikit.core.smartcard import ApduError,SmartCardConnection,SW
    from yubikit.openpgp import OpenPgpSession,KEY_REF,KEY_STATUS

    parser=argparse.ArgumentParser()
    parser.add_argument("case",choices=["dec-rsa","aut-rsa","aut-ed25519"])
    parser.add_argument("--checkpoint",type=Path,required=True)
    parser.add_argument("--virtual",action="store_true")
    args=parser.parse_args()
    assert not args.checkpoint.exists(),"existing OpenPGP recovery checkpoint; do not overwrite"
    assert "AROMATIC_TEST_OPENPGP_ADMIN_PIN" in os.environ
    assert "AROMATIC_TEST_OPENPGP_USER_PIN" in os.environ

    slot=KEY_REF.DEC if args.case=="dec-rsa" else KEY_REF.AUT
    cards=(list_virtual_devices("Virtual PCD 00 00") if args.virtual else [d[0] for d in list_all_devices()])
    assert len(cards)==1,len(cards)
    def checkpoint(phase,public_hash=None):
        args.checkpoint.parent.mkdir(parents=True,exist_ok=True)
        path=args.checkpoint.with_suffix(".tmp")
        data={"case":args.case,"slot":slot.name,"phase":phase}
        if public_hash:data["public_sha256"]=public_hash
        fd=os.open(path,os.O_CREAT|os.O_WRONLY|os.O_TRUNC,0o600)
        with os.fdopen(fd,"w") as f:
            json.dump(data,f)
            f.flush();os.fsync(f.fileno())
        os.replace(path,args.checkpoint)

    def pubhash(key):
        der=key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(der).hexdigest()

    with cards[0].open_connection(SmartCardConnection) as conn:
        session=OpenPgpSession(conn)
        info=session.get_key_information()
        assert info[KEY_REF.SIG]==KEY_STATUS.GENERATED,info
        assert info[slot]==KEY_STATUS.NONE,(slot,info)
        sig_before=pubhash(session.get_public_key(KEY_REF.SIG))
        count_before=session.get_signature_counter()
        attrs_before=session.get_algorithm_attributes(slot)
        tries_before=session.get_pin_status()
        print("OPENPGP_A11_RETRIES_BEFORE", tries_before.attempts_admin,
              tries_before.attempts_user, flush=True)
        session.verify_admin(os.environ["AROMATIC_TEST_OPENPGP_ADMIN_PIN"])
        session.verify_pin(os.environ["AROMATIC_TEST_OPENPGP_USER_PIN"],extended=True)
        print("OPENPGP_A11_AUTHORIZATION_WITH_EXISTING_TEST_PINS: PASS",flush=True)
        # Keep host private keys in RAM only. Avoid on-card RSA key generation,
        # which has a separately recorded long-running firmware behavior.
        private=(ed25519.Ed25519PrivateKey.generate() if args.case=="aut-ed25519"
                 else rsa.generate_private_key(public_exponent=65537,key_size=2048))
        original_public=private.public_key()
        checkpoint("before-import",pubhash(original_public))
        try:
            session.put_key(slot,private)
            print("OPENPGP_A11_"+args.case.upper()+"_IMPORT_APDU: PASS",flush=True)
            checkpoint("imported",pubhash(original_public))
            metadata=session.get_key_information()
            assert metadata[slot]!=KEY_STATUS.NONE
            onboard=session.get_public_key(slot)
            assert pubhash(onboard)==pubhash(original_public)
            print("OPENPGP_A11_"+args.case.upper()+"_KEY_METADATA_AND_PUBLIC: PASS",flush=True)
            message=b"aromatic-openpgp-a11-disposable-"+args.case.encode()
            if args.case=="dec-rsa":
                encrypted=original_public.encrypt(message,padding.PKCS1v15())
                decrypted=session.decrypt(encrypted)
                assert decrypted==message,(len(decrypted),len(message))
                print("OPENPGP_A11_RSA2048_DEC_DECRYPT_MATCH: PASS",flush=True)
            else:
                signature=session.authenticate(message,hashes.SHA256())
                if args.case=="aut-rsa":
                    onboard.verify(signature,message,padding.PKCS1v15(),hashes.SHA256())
                    print("OPENPGP_A11_RSA2048_AUT_SIGN_VERIFY: PASS",flush=True)
                else:
                    onboard.verify(signature,message)
                    print("OPENPGP_A11_ED25519_AUT_SIGN_VERIFY: PASS",flush=True)
        finally:
            # DEC/AUT were verified empty before any test data was submitted.
            session.verify_admin(os.environ["AROMATIC_TEST_OPENPGP_ADMIN_PIN"])
            session.delete_key(slot)
            session.put_data(slot.algorithm_attributes_do,attrs_before)
            after=session.get_key_information()
            assert after[slot]==KEY_STATUS.NONE,after
            checkpoint("deleted")
            print("OPENPGP_A11_"+slot.name+"_TEMPORARY_KEY_DELETED: PASS",flush=True)
        sig_after=pubhash(session.get_public_key(KEY_REF.SIG))
        assert sig_before==sig_after
        assert session.get_signature_counter()==count_before
        tries_after=session.get_pin_status()
        assert tries_after.attempts_admin >= tries_before.attempts_admin
        assert tries_after.attempts_user >= tries_before.attempts_user
        print("OPENPGP_A11_EXISTING_SIG_PUBLIC_COUNTER_AND_PIN_UNCHANGED: PASS",flush=True)
    args.checkpoint.unlink()
    print("OPENPGP_A11_"+args.case.upper()+("_VIRTUAL_COMPLETE" if args.virtual else "_PHYSICAL_COMPLETE")+": PASS",flush=True)


def recover():
    import argparse
    import hashlib
    import json
    import os
    from pathlib import Path

    from cryptography.hazmat.primitives import serialization
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import ApduError, SmartCardConnection, SW
    from yubikit.openpgp import KEY_REF, KEY_STATUS, OpenPgpSession


    def fingerprint(key):
        der=key.public_bytes(serialization.Encoding.DER,
                             serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(der).hexdigest()


    parser=argparse.ArgumentParser()
    parser.add_argument("--checkpoint",type=Path,required=True)
    args=parser.parse_args()
    record=json.loads(args.checkpoint.read_text())
    assert record["case"]=="dec-rsa" and record["slot"]=="DEC"
    assert record["phase"]=="imported"
    assert len(record["public_sha256"])==64
    assert "AROMATIC_TEST_OPENPGP_ADMIN_PIN" in os.environ
    cards=list_all_devices()
    assert len(cards)==1,len(cards)

    with cards[0][0].open_connection(SmartCardConnection) as connection:
        app=OpenPgpSession(connection)
        print("OPENPGP_A11_RECOVERY_YUBIKIT_VERSION",app.version,flush=True)
        assert app.version >= (5,6,1), "Firmware must advertise new corrected 0xFA algorithm profile"
        information=app.get_key_information()
        assert information[KEY_REF.SIG]==KEY_STATUS.GENERATED
        assert information[KEY_REF.DEC]!=KEY_STATUS.NONE, information
        assert information[KEY_REF.AUT]==KEY_STATUS.NONE, information
        sig_before=fingerprint(app.get_public_key(KEY_REF.SIG))
        sig_count=app.get_signature_counter()
        tries=app.get_pin_status()
        print("OPENPGP_A11_RETRIES_BEFORE", tries.attempts_admin,
              tries.attempts_user, flush=True)
        dec_hash=fingerprint(app.get_public_key(KEY_REF.DEC))
        assert dec_hash==record["public_sha256"], "Not the tracked disposable DEC test key"
        print("OPENPGP_A11_EXISTING_DEC_MATCHES_PRIOR_TEST_CHECKPOINT: PASS",flush=True)
        app.verify_admin(os.environ["AROMATIC_TEST_OPENPGP_ADMIN_PIN"])
        app.delete_key(KEY_REF.DEC)
        assert app.get_key_information()[KEY_REF.DEC]==KEY_STATUS.NONE
        try:
            app.get_public_key(KEY_REF.DEC)
        except ApduError as error:
            assert error.sw==SW.REFERENCE_DATA_NOT_FOUND,error
        else:
            raise AssertionError("DEC test private key remains readable")
        assert fingerprint(app.get_public_key(KEY_REF.SIG))==sig_before
        assert app.get_signature_counter()==sig_count
        updated=app.get_pin_status()
        assert updated.attempts_admin >= tries.attempts_admin
        assert updated.attempts_user >= tries.attempts_user
        print("OPENPGP_A11_DEC_TEST_KEY_REMOVED_AND_SIG_RETAINED: PASS",flush=True)

    args.checkpoint.unlink()
    print("OPENPGP_A11_PREVIOUS_TEST_CHECKPOINT_CLEARED: PASS",flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("case", choices=('keys', 'recover'))
    args, remaining = parser.parse_known_args()
    sys.argv = [sys.argv[0], *remaining]
    cases = {'keys': keys, 'recover': recover}
    cases[args.case]()


if __name__ == "__main__":
    main()
