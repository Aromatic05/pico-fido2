#!/usr/bin/env bash
set -euo pipefail

source_tree="$(mktemp -d /tmp/aromatic-openpgp-eddsa.XXXXXX)"
trap 'rm -rf "$source_tree"' EXIT
./tools/prepare_host_eddsa_mbedtls.sh "$source_tree"

podman run --rm -i --network none \
  -v "$PWD:/src:ro" \
  -v "$source_tree:/src/pico-keys-sdk/mbedtls:ro" \
  localhost/pico-fido2-ykman-test:5.9.2 bash -s <<'INNER'
set -euo pipefail
mkdir -p /work/run
cmake -S /src -B /work/build -DENABLE_EMULATION=1 -DENABLE_EDDSA=1 -DCMAKE_BUILD_TYPE=Release >/work/cmake.log
cmake --build /work/build -j"$(nproc)" >/work/build.log
/usr/sbin/pcscd --foreground >/work/pcscd.log 2>&1 &
pcsc_pid=$!
emu_pid=""
cleanup() {
    [[ -z "$emu_pid" ]] || kill "$emu_pid" 2>/dev/null || true
    [[ -z "$emu_pid" ]] || wait "$emu_pid" 2>/dev/null || true
    kill "$pcsc_pid" 2>/dev/null || true
}
trap cleanup EXIT
sleep 1
cd /work/run
/work/build/pico_fido2 >emulator.log 2>&1 &
emu_pid=$!
sleep 1
kill -0 "$emu_pid" 2>/dev/null || { cat emulator.log >&2; exit 1; }

python3 - <<'PY'
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from ykman.pcsc import list_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.openpgp import OpenPgpSession, KEY_REF, KEY_STATUS, RSA_SIZE, DO

devices=list_devices('Virtual PCD 00 00')
assert len(devices)==1, f'virtual card count: {len(devices)}'
with devices[0].open_connection(SmartCardConnection) as conn:
    card=OpenPgpSession(conn)
    original=card.get_data(DO.SECURITY_SUPPORT_TEMPLATE)
    assert original[:2]==b'\x7a\x05', original[:2].hex()
    assert card.get_signature_counter()==0
    print('OPENPGP_7A_CONSTRUCTED_COUNTER_ZERO: PASS')

    info=card.get_key_information()
    assert info[KEY_REF.SIG]==KEY_STATUS.NONE, info
    assert info[KEY_REF.DEC]==KEY_STATUS.NONE, info
    assert info[KEY_REF.AUT]==KEY_STATUS.NONE, info
    app=card.get_application_related_data()
    assert app.discretionary.key_information == info
    print('OPENPGP_DE_WITHIN_73_INITIAL_STATUS: PASS')

    card.verify_admin('12345678')
    pub=card.generate_rsa_key(KEY_REF.SIG,RSA_SIZE.RSA2048)
    after=card.get_key_information()
    assert after[KEY_REF.SIG]==KEY_STATUS.GENERATED, after
    assert after[KEY_REF.DEC]==KEY_STATUS.NONE
    assert after[KEY_REF.AUT]==KEY_STATUS.NONE
    print('OPENPGP_DE_REAL_GENERATED_SIG_STATUS: PASS')

    card.verify_pin('123456')
    message=b'OpenPGP actual emulator metadata and signature integration'
    signature=card.sign(message, hashes.SHA256())
    pub.verify(signature,message,padding.PKCS1v15(),hashes.SHA256())
    counter=card.get_signature_counter()
    assert counter==1,counter
    print('OPENPGP_RSA_SIG_VERIFY_AND_7A_COUNTER_INCREMENT: PASS')
print('OpenPGP source-backed official YubiKit metadata integration: PASS')
PY
INNER
