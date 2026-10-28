#!/usr/bin/env python3
'Physical PIV key generation, private operations, attestation, certificates and interrupted-operation recovery.'
import argparse
import sys

def keys():
    import argparse
    import hashlib
    import json
    import os
    import time
    from pathlib import Path

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, x25519
    from ykman.pcsc import list_devices
    from yubikit.core.smartcard import ApduError, SmartCardConnection, SW
    from yubikit.piv import (
        DEFAULT_MANAGEMENT_KEY,
        KEY_TYPE,
        PIN_POLICY,
        PivSession,
        SLOT,
        TOUCH_POLICY,
    )

    ALGORITHMS = {
        "p384": KEY_TYPE.ECCP384,
        "rsa3072": KEY_TYPE.RSA3072,
        "rsa4096": KEY_TYPE.RSA4096,
        "ed25519": KEY_TYPE.ED25519,
        "x25519": KEY_TYPE.X25519,
    }
    SLOT_TEST = SLOT.AUTHENTICATION


    def public_der(key):
        return key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


    def fingerprint(key):
        return hashlib.sha256(public_der(key)).hexdigest()


    def read_slot(session):
        try:
            return session.get_slot_metadata(SLOT_TEST)
        except ApduError as exc:
            if exc.sw == SW.REFERENCE_DATA_NOT_FOUND:
                return None
            raise


    def record_checkpoint(path, algorithm, phase, public_hash=None):
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {"algorithm": algorithm, "phase": phase}
        if public_hash:
            data["public_sha256"] = public_hash
        temp = path.with_suffix(".tmp")
        fd = os.open(temp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(data, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)


    def private_operation(session, key_type, pub):
        if key_type == KEY_TYPE.ECCP384:
            message = b"aromatic-hil-a10-physical-p384"
            sig = session.sign(SLOT_TEST, key_type, message, hashes.SHA384())
            pub.verify(sig, message, ec.ECDSA(hashes.SHA384()))
            return "ECDSA_SHA384_SIGN_VERIFY"
        if key_type in (KEY_TYPE.RSA3072, KEY_TYPE.RSA4096):
            message = b"aromatic-hil-a10-physical-rsa"
            sig = session.sign(SLOT_TEST, key_type, message, hashes.SHA256(), padding.PKCS1v15())
            pub.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())
            return "RSA_SHA256_PKCS1V15_SIGN_VERIFY"
        if key_type == KEY_TYPE.ED25519:
            message = b"aromatic-hil-a10-physical-ed25519"
            sig = session.sign(SLOT_TEST, key_type, message, None)
            pub.verify(sig, message)
            return "ED25519_SIGN_VERIFY"
        if key_type == KEY_TYPE.X25519:
            peer = x25519.X25519PrivateKey.generate()
            card = session.calculate_secret(SLOT_TEST, peer.public_key())
            host = peer.exchange(pub)
            assert card == host and len(card) == 32
            return "X25519_ECDH_MATCH"
        raise AssertionError(key_type)


    def verify_attestation(session, public_key):
        cert = session.attest_key(SLOT_TEST)
        assert public_der(cert.public_key()) == public_der(public_key)
        f9 = session.get_certificate(SLOT.ATTESTATION)
        issuer = f9.public_key()
        assert isinstance(issuer, ec.EllipticCurvePublicKey)
        issuer.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        print("PIV_A10_SLOT_ATTESTATION_PUBLIC_AND_F9_SIGNATURE: PASS",flush=True)
        print("PIV_A10_ATTESTATION_DER_SIZE:",len(cert.public_bytes(serialization.Encoding.DER)),flush=True)


    parser = argparse.ArgumentParser()
    parser.add_argument("algorithm", choices=ALGORITHMS)
    parser.add_argument("--checkpoint", type=Path, required=True)
    args = parser.parse_args()

    assert not args.checkpoint.exists(), "a prior PIV test slot requires explicit recovery"
    cards = list_devices()
    assert len(cards) == 1, len(cards)
    with cards[0].open_connection(SmartCardConnection) as connection:
        session = PivSession(connection)
        assert read_slot(session) is None, "PIV 9A slot is not empty; refusing to overwrite"
        print("PIV_A10_9A_EMPTY_BEFORE: PASS", flush=True)
        session.authenticate(DEFAULT_MANAGEMENT_KEY)
        print("PIV_A10_AES192_MANAGEMENT_AUTH: PASS",flush=True)
        key_type = ALGORITHMS[args.algorithm]
        record_checkpoint(args.checkpoint, args.algorithm, "before-create")
        generated = False
        try:
            keygen_begin = time.monotonic_ns()
            print("PIV_A10_"+args.algorithm.upper()+"_GENERATE_APDU_BEGIN", flush=True)
            public_key = session.generate_key(
                SLOT_TEST, key_type, PIN_POLICY.NEVER, TOUCH_POLICY.NEVER
            )
            print("PIV_A10_"+args.algorithm.upper()+"_GENERATE_APDU_RETURN_MS",
                  (time.monotonic_ns() - keygen_begin) // 1_000_000, flush=True)
            generated = True
            digest = fingerprint(public_key)
            record_checkpoint(args.checkpoint, args.algorithm, "generated", digest)
            metadata = read_slot(session)
            assert metadata is not None and metadata.generated is True
            assert metadata.key_type == key_type
            assert fingerprint(metadata.public_key) == digest
            print("PIV_A10_"+args.algorithm.upper()+"_KEYGEN_METADATA: PASS",flush=True)
            operation = private_operation(session, key_type, public_key)
            print("PIV_A10_"+args.algorithm.upper()+"_"+operation+": PASS",flush=True)
            verify_attestation(session, public_key)
        finally:
            # Delete only the disposable key generated by this invocation.
            if generated:
                session.delete_key(SLOT_TEST)
                assert read_slot(session) is None, "temporary 9A key still present"
                args.checkpoint.unlink()
                print("PIV_A10_9A_TEST_KEY_REMOVED: PASS",flush=True)
        print("PIV_A10_"+args.algorithm.upper()+"_PHYSICAL_FULL_CHAIN: PASS",flush=True)


def certificate():
    import argparse
    import json
    import os
    from datetime import datetime, timedelta, timezone
    from pathlib import Path

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import ApduError, SmartCardConnection, SW
    from yubikit.piv import DEFAULT_MANAGEMENT_KEY, KEY_TYPE, PIN_POLICY, PivSession, SLOT, TOUCH_POLICY, OBJECT_ID

    parser=argparse.ArgumentParser()
    parser.add_argument("--checkpoint",type=Path,required=True)
    args=parser.parse_args()
    assert not args.checkpoint.exists(), "PIV test slot is reserved by an incomplete earlier test"

    cards=list_all_devices()
    assert len(cards)==1,len(cards)

    def open_piv():
        return cards[0][0].open_connection(SmartCardConnection)

    def ensure_empty(session):
        try:
            session.get_slot_metadata(SLOT.AUTHENTICATION)
        except ApduError as e:
            assert e.sw==SW.REFERENCE_DATA_NOT_FOUND,e
        else:
            raise AssertionError("PIV 9A private key already exists")
        try:
            session.get_object(OBJECT_ID.from_slot(SLOT.AUTHENTICATION))
        except ApduError as exc:
            assert exc.sw == SW.FILE_NOT_FOUND, exc
        else:
            raise AssertionError("PIV 9A certificate object already exists")
        print("PIV_A10_CERT_SLOT_KEY_AND_CERT_EMPTY: PASS",flush=True)

    def save_checkpoint(phase):
        args.checkpoint.parent.mkdir(parents=True,exist_ok=True)
        tmp=args.checkpoint.with_suffix(".tmp")
        fd=os.open(tmp,os.O_CREAT|os.O_WRONLY|os.O_TRUNC,0o600)
        with os.fdopen(fd,"w") as f:
            json.dump({"algorithm":"p256","phase":phase,"slot":"9a"},f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp,args.checkpoint)

    with open_piv() as connection:
        session=PivSession(connection)
        ensure_empty(session)
        session.authenticate(DEFAULT_MANAGEMENT_KEY)
        save_checkpoint("before-create")
        private_created=False
        cert_written=False
        try:
            public=session.generate_key(SLOT.AUTHENTICATION,KEY_TYPE.ECCP256,PIN_POLICY.NEVER,TOUCH_POLICY.NEVER)
            private_created=True
            save_checkpoint("key-generated")
            issuer_private=ec.generate_private_key(ec.SECP256R1())
            now=datetime.now(timezone.utc)
            issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Aromatic Key A10 Test Issuer")])
            subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Aromatic Key A10 Temporary 9A")])
            cert=(x509.CertificateBuilder()
                .subject_name(subject).issuer_name(issuer).public_key(public)
                .serial_number(x509.random_serial_number())
                .not_valid_before(now-timedelta(minutes=1))
                .not_valid_after(now+timedelta(days=1))
                .sign(issuer_private,hashes.SHA256()))
            cert_written=True
            session.put_certificate(SLOT.AUTHENTICATION,cert)
            save_checkpoint("cert-stored")
            reread=session.get_certificate(SLOT.AUTHENTICATION)
            der=cert.public_bytes(serialization.Encoding.DER)
            assert reread.public_bytes(serialization.Encoding.DER)==der
            issuer_private.public_key().verify(
                reread.signature,reread.tbs_certificate_bytes,
                ec.ECDSA(reread.signature_hash_algorithm))
            print("PIV_A10_9A_CERT_STORE_READ_AND_HOST_CA_VERIFY: PASS",flush=True)
        finally:
            if cert_written:
                session.delete_certificate(SLOT.AUTHENTICATION)
                save_checkpoint("cert-deleted")
                print("PIV_A10_9A_CERT_DELETED: PASS",flush=True)
            if private_created:
                session.delete_key(SLOT.AUTHENTICATION)
                save_checkpoint("key-deleted")
                print("PIV_A10_9A_TEST_PRIVATE_KEY_DELETED: PASS",flush=True)
        ensure_empty(session)

    args.checkpoint.unlink()
    print("PIV_A10_CERTIFICATE_STORE_READ_VERIFY_DELETE: PASS",flush=True)


def recover_rsa4096():
    import argparse
    import json
    from pathlib import Path
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ec,padding
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import ApduError,SmartCardConnection,SW
    from yubikit.piv import PivSession,SLOT,KEY_TYPE,DEFAULT_MANAGEMENT_KEY

    parser=argparse.ArgumentParser()
    parser.add_argument("--checkpoint",type=Path,required=True)
    args=parser.parse_args()
    state=json.loads(args.checkpoint.read_text())
    assert state["algorithm"]=="rsa4096" and state["phase"]=="before-create",state
    cards=list_all_devices()
    assert len(cards)==1,len(cards)

    with cards[0][0].open_connection(SmartCardConnection) as connection:
        session=PivSession(connection)
        metadata=session.get_slot_metadata(SLOT.AUTHENTICATION)
        assert metadata.key_type==KEY_TYPE.RSA4096 and metadata.generated is True
        pub=metadata.public_key
        assert pub.key_size==4096
        print("PIV_RSA4096_GENERATED_ON_CARD_AFTER_REQUEST_TIMEOUT: PASS",flush=True)
        session.authenticate(DEFAULT_MANAGEMENT_KEY)
        try:
            challenge=b"aromatic-hil-a10-rsa4096-postrequest"
            sig=session.sign(SLOT.AUTHENTICATION,KEY_TYPE.RSA4096,challenge,hashes.SHA256(),padding.PKCS1v15())
            assert len(sig)==512,len(sig)
            pub.verify(sig,challenge,padding.PKCS1v15(),hashes.SHA256())
            print("PIV_RSA4096_EXISTING_PRIVATE_SIGN_VERIFY: PASS",flush=True)
            attest=session.attest_key(SLOT.AUTHENTICATION)
            subject=attest.public_key().public_bytes(
                serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
            origin=pub.public_bytes(
                serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
            assert subject==origin
            issuer=session.get_certificate(SLOT.ATTESTATION).public_key()
            assert isinstance(issuer,ec.EllipticCurvePublicKey)
            issuer.verify(attest.signature,attest.tbs_certificate_bytes,ec.ECDSA(attest.signature_hash_algorithm))
            print("PIV_RSA4096_EXISTING_KEY_F9_ATTESTATION: PASS",flush=True)
            print("PIV_RSA4096_ATTESTATION_DER_SIZE",len(attest.public_bytes(serialization.Encoding.DER)),flush=True)
        finally:
            session.delete_key(SLOT.AUTHENTICATION)
            try:
                session.get_slot_metadata(SLOT.AUTHENTICATION)
            except ApduError as exc:
                assert exc.sw==SW.REFERENCE_DATA_NOT_FOUND,exc
            else:
                raise AssertionError("test key 9A still exists")
            args.checkpoint.unlink()
            print("PIV_RSA4096_TEST_KEY_REMOVED_9A_EMPTY: PASS",flush=True)
    print("PIV_RSA4096_POST_TIMEOUT_CRYPTO_AND_CLEANUP: PASS",flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("case", choices=('keys', 'certificate', 'recover_rsa4096'))
    args, remaining = parser.parse_known_args()
    sys.argv = [sys.argv[0], *remaining]
    cases = {'keys': keys, 'certificate': certificate, 'recover_rsa4096': recover_rsa4096}
    cases[args.case]()


if __name__ == "__main__":
    main()
