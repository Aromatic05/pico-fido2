#!/usr/bin/env bash
set -euo pipefail

runtime="${CONTAINER_RUNTIME:-podman}"
image="${YKMAN_TEST_IMAGE:-localhost/pico-fido2-ykman-test:5.9.2}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/pico-fido2-piv57.XXXXXX")"

cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT

command -v "$runtime" >/dev/null || { echo "$runtime not found" >&2; exit 2; }
[[ -x "$root/tools/prepare_host_eddsa_mbedtls.sh" ]] || {
    echo 'host EdDSA preparation helper is missing' >&2
    exit 2
}

"$root/tools/prepare_host_eddsa_mbedtls.sh" "$work/mbedtls"

"$runtime" run --rm -i --network none \
    -v "$root:/src:ro" \
    -v "$work/mbedtls:/src/pico-keys-sdk/mbedtls:ro" \
    "$image" bash -s <<'INNER'
set -euo pipefail
mkdir -p /work/build /work/run
cmake -S /src -B /work/build \
    -DENABLE_EMULATION=1 -DENABLE_EDDSA=1 -DCMAKE_BUILD_TYPE=Release \
    >/work/cmake.log
cmake --build /work/build -j"$(nproc)" >/work/build.log

/usr/sbin/pcscd --foreground >/work/pcscd.log 2>&1 &
pcsc_pid=$!
sleep 1
cd /work/run
/work/build/pico_fido2 >emulator.log 2>&1 &
emu_pid=$!
cleanup_inner() {
    kill "$emu_pid" "$pcsc_pid" 2>/dev/null || true
}
trap cleanup_inner EXIT
sleep 1

python3 - <<'PY'
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, x25519
from ykman.pcsc import list_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.piv import (
    DEFAULT_MANAGEMENT_KEY,
    KEY_TYPE,
    MANAGEMENT_KEY_TYPE,
    PIN_POLICY,
    PivSession,
    SLOT,
    TOUCH_POLICY,
)


def raw_public(key):
    if isinstance(key, (ed25519.Ed25519PublicKey, x25519.X25519PublicKey)):
        return key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return key.public_numbers()


def verify_private_operation(session, slot, key_type, public_key):
    if key_type.algorithm.name == "RSA":
        message = b"aromatic-piv-rsa57"
        signature = session.sign(
            slot, key_type, message, hashes.SHA256(), padding.PKCS1v15()
        )
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    elif key_type == KEY_TYPE.ED25519:
        message = b"aromatic-piv-ed25519"
        signature = session.sign(slot, key_type, message, None)
        public_key.verify(signature, message)
    elif key_type == KEY_TYPE.X25519:
        peer = x25519.X25519PrivateKey.generate()
        card_secret = session.calculate_secret(slot, peer.public_key())
        host_secret = peer.exchange(public_key)
        assert card_secret == host_secret
    else:
        raise AssertionError(key_type)


devices = list_devices("Virtual PCD 00 00")
assert len(devices) == 1, devices
with devices[0].open_connection(SmartCardConnection) as conn:
    session = PivSession(conn)
    assert str(session.version) == "5.7.0", session.version

    # F9 GET DATA must expose a PIV certificate object (0x70 certificate TLV),
    # not a bare DER blob wrapped only in the outer 0x53 object container.
    f9 = session.get_certificate(SLOT.ATTESTATION)
    assert f9.public_key().key_size == 384
    print("PIV F9 attestation certificate export: PASS")

    management = session.get_management_key_metadata()
    assert management.key_type == MANAGEMENT_KEY_TYPE.AES192, management
    assert management.default_value is True, management
    assert management.touch_policy == TOUCH_POLICY.NEVER, management
    session.authenticate(DEFAULT_MANAGEMENT_KEY)
    print("PIV 5.7 AES-192 default management key: PASS")

    slot = SLOT.AUTHENTICATION
    new_types = (
        KEY_TYPE.RSA3072,
        KEY_TYPE.RSA4096,
        KEY_TYPE.ED25519,
        KEY_TYPE.X25519,
    )

    for key_type in new_types:
        public_key = session.generate_key(
            slot, key_type, PIN_POLICY.NEVER, TOUCH_POLICY.NEVER
        )
        metadata = session.get_slot_metadata(slot)
        assert metadata.key_type == key_type, metadata
        assert metadata.generated is True, metadata
        verify_private_operation(session, slot, key_type, public_key)
        certificate = session.attest_key(slot)
        assert raw_public(certificate.public_key()) == raw_public(public_key)
        print(f"{key_type.name}: generate/metadata/private-operation/attestation PASS")
        session.delete_key(slot)

    imported = (
        (KEY_TYPE.RSA3072, rsa.generate_private_key(public_exponent=65537, key_size=3072)),
        (KEY_TYPE.RSA4096, rsa.generate_private_key(public_exponent=65537, key_size=4096)),
        (KEY_TYPE.ED25519, ed25519.Ed25519PrivateKey.generate()),
        (KEY_TYPE.X25519, x25519.X25519PrivateKey.generate()),
    )
    for key_type, private_key in imported:
        assert session.put_key(
            slot, private_key, PIN_POLICY.NEVER, TOUCH_POLICY.NEVER
        ) == key_type
        metadata = session.get_slot_metadata(slot)
        assert metadata.key_type == key_type, metadata
        assert metadata.generated is False, metadata
        verify_private_operation(session, slot, key_type, private_key.public_key())
        print(f"{key_type.name}: import/metadata/private-operation PASS")
        session.delete_key(slot)

    public_key = session.generate_key(
        SLOT.AUTHENTICATION, KEY_TYPE.ED25519,
        PIN_POLICY.NEVER, TOUCH_POLICY.NEVER,
    )
    session.move_key(SLOT.AUTHENTICATION, SLOT.SIGNATURE)
    moved = session.get_slot_metadata(SLOT.SIGNATURE)
    assert moved.key_type == KEY_TYPE.ED25519 and moved.generated is True, moved
    assert raw_public(moved.public_key) == raw_public(public_key)
    session.delete_key(SLOT.SIGNATURE)
    print("Ed25519 move/delete: PASS")

print("YubiKey 5.7 PIV compatibility gate: PASS")
print("No physical device was accessed.")
PY
INNER
