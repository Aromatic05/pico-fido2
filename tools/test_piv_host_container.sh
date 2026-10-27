#!/usr/bin/env bash
set -euo pipefail

runtime="${CONTAINER_RUNTIME:-podman}"
image="${PIV_TEST_IMAGE:-localhost/pico-fido2-piv-test:jammy}"

fail() {
    echo "piv-host: $*" >&2
    exit 1
}

command -v "$runtime" >/dev/null || fail "$runtime not found"
[[ -f pico-openpgp/tests/docker/jammy/Dockerfile ]] || fail 'run from pico-fido2 repository root'

if ! "$runtime" image exists "$image" >/dev/null 2>&1; then
    "$runtime" build -f pico-openpgp/tests/docker/jammy/Dockerfile \
        -t "$image" pico-openpgp
fi

"$runtime" run --rm -i --network none -v "$PWD:/src:ro" "$image" bash -s <<'INNER'
set -euo pipefail
mkdir -p /work/build /work/run /work/tests
cmake -S /src -B /work/build -DENABLE_EMULATION=1 -DCMAKE_BUILD_TYPE=Release >/work/cmake.log
cmake --build /work/build -j"$(nproc)" >/work/build.log
cp -a /src/pico-openpgp/tests/scripts /work/tests/

/usr/sbin/pcscd --foreground >/work/pcscd.log 2>&1 &
pcsc_pid=$!
emu_pid=""
cleanup() {
    [[ -z "$emu_pid" ]] || kill "$emu_pid" 2>/dev/null || true
    kill "$pcsc_pid" 2>/dev/null || true
}
trap cleanup EXIT
sleep 1

start_emulator() {
    rm -f /work/run/memory.flash /work/run/emulator.log
    cd /work/run
    /work/build/pico_fido2 >emulator.log 2>&1 &
    emu_pid=$!
    cd /work
    sleep 1
    if ! kill -0 "$emu_pid" 2>/dev/null; then
        cat /work/run/emulator.log >&2
        return 1
    fi
}

stop_emulator() {
    [[ -z "$emu_pid" ]] || kill "$emu_pid" 2>/dev/null || true
    [[ -z "$emu_pid" ]] || wait "$emu_pid" 2>/dev/null || true
    emu_pid=""
    sleep 1
}

run_cli_stage() {
    local name=$1 script=$2
    start_emulator
    set +e
    cd /work
    "$script" >"$name.log" 2>&1
    local rc=$?
    set -e
    if [[ "$rc" -ne 0 ]]; then
        cat "/work/$name.log" >&2
        exit "$rc"
    fi
    stop_emulator
}

run_cli_stage version /work/tests/scripts/version.sh

start_emulator
python3 - <<'PYRESET'
from smartcard.System import readers
from smartcard.scard import SCARD_RESET_CARD

reader = [r for r in readers() if 'Virtual PCD 00 00' in str(r)][0]
conn = reader.createConnection()
conn.connect()
aid = bytes.fromhex('A000000308')
_, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(aid), *aid])
assert sw1 == 0x61 or (sw1, sw2) == (0x90, 0x00), (sw1, sw2)
_, sw1, sw2 = conn.transmit([0x00, 0xFD, 0x00, 0x00])
assert (sw1, sw2) == (0x90, 0x00), (sw1, sw2)
pin = b'123456\xff\xff'
_, sw1, sw2 = conn.transmit([0x00, 0x20, 0x00, 0x80, len(pin), *pin])
assert (sw1, sw2) == (0x90, 0x00), (sw1, sw2)
_, sw1, sw2 = conn.transmit([0x00, 0x20, 0x00, 0x80])
assert (sw1, sw2) == (0x90, 0x00), (sw1, sw2)
conn.reconnect(disposition=SCARD_RESET_CARD)
# A warm PC/SC reset keeps the selected application but drops PIN/auth state.
_, sw1, sw2 = conn.transmit([0x00, 0xFD, 0x00, 0x00])
assert (sw1, sw2) == (0x90, 0x00), f'PIV selection lost across warm reset: {sw1:02x}{sw2:02x}'
_, sw1, sw2 = conn.transmit([0x00, 0x20, 0x00, 0x80])
assert sw1 == 0x63 and (sw2 & 0xF0) == 0xC0, f'PIV PIN auth survived reset: {sw1:02x}{sw2:02x}'
print(f'vpcd warm reset preserves PIV selection and clears PIN auth: PASS ({sw1:02x}{sw2:02x})')
PYRESET
stop_emulator

start_emulator
yubico-piv-tool -r "Virtual PCD 00 00" -agenerate -s9a -ARSA1024 -opublic.pem >/work/move-generate.log 2>&1
yubico-piv-tool -r "Virtual PCD 00 00" -amove-key -s9a --to-slot=9c >/work/move-key.log 2>&1
python3 - <<'PYMETA'
from smartcard.System import readers

reader = [r for r in readers() if 'Virtual PCD 00 00' in str(r)][0]
conn = reader.createConnection()
conn.connect()
aid = bytes.fromhex('A000000308')
_, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(aid), *aid])
assert sw1 == 0x61 or (sw1, sw2) == (0x90, 0x00), (sw1, sw2)

def metadata(slot):
    data, s1, s2 = conn.transmit([0x00, 0xF7, 0x00, slot])
    return bytes(data), (s1, s2)

source, source_sw = metadata(0x9A)
assert source_sw != (0x90, 0x00), (source.hex(), source_sw)
dest, dest_sw = metadata(0x9C)
assert dest_sw == (0x90, 0x00), (dest.hex(), dest_sw)
assert dest[:3] == bytes([0x01, 0x01, 0x06]), dest.hex()
print('PIV move-key metadata follows destination: PASS')
PYMETA
yubico-piv-tool -r "Virtual PCD 00 00" -adelete-key -s9c >/work/delete-key.log 2>&1
python3 - <<'PYDELETE'
from smartcard.System import readers
reader = [r for r in readers() if 'Virtual PCD 00 00' in str(r)][0]
conn = reader.createConnection(); conn.connect()
aid = bytes.fromhex('A000000308')
_, s1, s2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(aid), *aid])
assert s1 == 0x61 or (s1, s2) == (0x90, 0x00)
data, s1, s2 = conn.transmit([0x00, 0xF7, 0x00, 0x9C])
assert (s1, s2) != (0x90, 0x00), (bytes(data).hex(), s1, s2)
print('PIV delete-key removes key metadata visibility: PASS')
PYDELETE
stop_emulator

run_cli_stage keygen /work/tests/scripts/keygen.sh
keygen_count=$(grep -Ec '^  Test (RSA1024|RSA2048|ECCP256|ECCP384) in slot ' /work/keygen.log || true)
[[ "$keygen_count" -eq 96 ]] || { cat /work/keygen.log >&2; echo "unexpected keygen count: $keygen_count" >&2; exit 1; }
printf 'Yubico PIV keygen/delete: PASS (96/96)\n'

run_cli_stage signatures /work/tests/scripts/signatures.sh
sign_count=$(grep -c '^  Test signature with ' /work/signatures.log || true)
[[ "$sign_count" -eq 96 ]] || { cat /work/signatures.log >&2; echo "unexpected signature count: $sign_count" >&2; exit 1; }
printf 'Yubico PIV certificate/signature: PASS (96/96)\n'

run_cli_stage attestation /work/tests/scripts/attestation.sh
attest_count=$(grep -c '^  Test attestation with ' /work/attestation.log || true)
[[ "$attest_count" -eq 96 ]] || { cat /work/attestation.log >&2; echo "unexpected attestation count: $attest_count" >&2; exit 1; }
printf 'Yubico PIV attestation: PASS (96/96)\n'

stop_emulator
start_emulator
set +e
cd /yubico-piv-tool/build/lib/tests
YKPIV_ENV_HWTESTS_CONFIRMED=1 ./test_api > /work/api.log 2>&1
api_rc=$?
set -e
passed=$(grep -c ':P:api:' /work/api.log || true)
failed=$(grep -c ':F:api:' /work/api.log || true)
errors=$(grep -c ':E:api:' /work/api.log || true)
if [[ "$api_rc" -eq 0 ]]; then
    [[ "$passed" -eq 13 && "$failed" -eq 0 && "$errors" -eq 0 ]] || { cat /work/api.log >&2; exit 1; }
    printf 'Yubico libykpiv API: PASS (13/13)\n'
elif [[ "$passed" -eq 12 && "$failed" -eq 1 && "$errors" -eq 0 ]] \
    && grep -q ':F:api:test_devicemodel:' /work/api.log \
    && grep -q "Found device: Virtual PCD" /work/api.log; then
    printf 'Yubico libykpiv API: PASS (12 protocol tests + 1 expected virtual-reader devicemodel mismatch)\n'
else
    cat /work/api.log >&2
    exit "$api_rc"
fi

kill -0 "$emu_pid" 2>/dev/null || { cat /work/run/emulator.log >&2; exit 1; }
printf 'PIV host compatibility gate: PASS\n'
printf 'No physical device was accessed.\n'
INNER
