#!/usr/bin/env bash
set -euo pipefail
source_tree="$(mktemp -d /tmp/aromatic-openpgp-a11.XXXXXX)"
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
sleep 1
cd /work/run
/work/build/pico_fido2 >emulator.log 2>&1 &
emu_pid=$!
trap 'kill "$emu_pid" "$pcsc_pid" 2>/dev/null || true' EXIT
sleep 2
kill -0 "$emu_pid" || { cat emulator.log; cat /work/pcscd.log; exit 1; }
python3 -u /src/tests/host_openpgp_key_delete.py || { tail -30 emulator.log; exit 1; }
export AROMATIC_TEST_OPENPGP_ADMIN_PIN=12345678 AROMATIC_TEST_OPENPGP_USER_PIN=123456
for case in dec-rsa aut-rsa aut-ed25519; do
  timeout 35s python3 -u /src/tests/hil_real_openpgp_dec_aut.py "$case" --virtual --checkpoint /work/run/a11-pending.json || { tail -30 emulator.log; exit 1; }
done
echo "OPENPGP_A11_REAL_SOURCE_VIRTUAL_FULL_DEC_AUT: PASS"
echo "No physical USB device was accessed."
INNER
