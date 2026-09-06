#!/usr/bin/env bash
set -euo pipefail

runtime="${CONTAINER_RUNTIME:-podman}"
base_image="${PIV_TEST_IMAGE:-localhost/pico-fido2-piv-test:jammy}"
image="${YKMAN_TEST_IMAGE:-localhost/pico-fido2-ykman-test:5.9.2}"

if ! "$runtime" image exists "$base_image" >/dev/null 2>&1; then
    "$runtime" build -f pico-openpgp/tests/docker/jammy/Dockerfile \
        -t "$base_image" pico-openpgp
fi
if ! "$runtime" image exists "$image" >/dev/null 2>&1; then
    printf 'FROM %s\nRUN pip3 install --no-cache-dir yubikey-manager==5.9.2\n' "$base_image" \
        | "$runtime" build -t "$image" -f - .
fi

"$runtime" run --rm -i --network none -v "$PWD:/src:ro" "$image" bash -s <<'INNER'
set -euo pipefail
mkdir -p /work/build /work/run /work/out
cmake -S /src -B /work/build -DENABLE_EMULATION=1 -DCMAKE_BUILD_TYPE=Release >/work/cmake.log
cmake --build /work/build -j"$(nproc)" >/work/build.log
rm -f /work/run/memory.flash

/usr/sbin/pcscd --foreground >/work/pcscd.log 2>&1 &
pcsc_pid=$!
emu_pid=""
cleanup() {
    local rc=$?
    if [[ "$rc" -ne 0 ]]; then
        echo "ykman-hsmauth: failure rc=$rc" >&2
        for log in /work/out/*.txt; do
            [[ -f "$log" ]] || continue
            echo "--- $log ---" >&2
            tail -40 "$log" >&2 || true
        done
        echo "--- emulator ---" >&2
        tail -60 /work/run/emulator.log >&2 || true
    fi
    [[ -z "$emu_pid" ]] || kill "$emu_pid" 2>/dev/null || true
    [[ -z "$emu_pid" ]] || wait "$emu_pid" 2>/dev/null || true
    kill "$pcsc_pid" 2>/dev/null || true
}
trap cleanup EXIT
sleep 1

start_emulator() {
    cd /work/run
    /work/build/pico_fido2 >emulator.log 2>&1 &
    emu_pid=$!
    cd /work
    sleep 1
    if ! kill -0 "$emu_pid" 2>/dev/null; then
        cat /work/run/emulator.log >&2
        exit 1
    fi
}

stop_emulator() {
    [[ -z "$emu_pid" ]] || kill "$emu_pid" 2>/dev/null || true
    [[ -z "$emu_pid" ]] || wait "$emu_pid" 2>/dev/null || true
    emu_pid=""
    sleep 1
}

reader='Virtual PCD 00 00'
mgmt_old=''
mgmt_new='new-management'
credential_password='credpass'
enc_key='000102030405060708090a0b0c0d0e0f'
mac_key='101112131415161718191a1b1c1d1e1f'

start_emulator
ykman -r "$reader" hsmauth reset --force >/work/out/reset-initial.txt
ykman -r "$reader" hsmauth info >/work/out/info-initial.txt
grep -Eq '^YubiHSM Auth version:[[:space:]]+5\.7\.0$' /work/out/info-initial.txt
grep -Eq '^Management key retries remaining:[[:space:]]+8/8$' /work/out/info-initial.txt

ykman -r "$reader" hsmauth credentials symmetric sym-cli \
    --enc-key "$enc_key" --mac-key "$mac_key" \
    --credential-password "$credential_password" \
    --management-password "$mgmt_old" >/work/out/symmetric.txt

ykman -r "$reader" hsmauth credentials derive derived-cli \
    --derivation-password 'derive-secret' \
    --credential-password "$credential_password" \
    --management-password "$mgmt_old" >/work/out/derived.txt

ykman -r "$reader" hsmauth credentials generate generated-cli \
    --credential-password "$credential_password" \
    --management-password "$mgmt_old" >/work/out/generated.txt

grep -q 'Asymmetric credential generated.' /work/out/generated.txt

ykman -r "$reader" hsmauth credentials export generated-cli \
    /work/out/generated-public.pem >/work/out/export-generated.txt
openssl pkey -pubin -in /work/out/generated-public.pem -noout >/dev/null

openssl ecparam -name prime256v1 -genkey -noout -out /work/out/import-private.pem
ykman -r "$reader" hsmauth credentials import imported-cli \
    /work/out/import-private.pem \
    --credential-password "$credential_password" \
    --management-password "$mgmt_old" >/work/out/imported.txt

ykman -r "$reader" hsmauth credentials export imported-cli \
    /work/out/imported-public.pem >/work/out/export-imported.txt
openssl pkey -in /work/out/import-private.pem -pubout -outform DER \
    >/work/out/import-expected-public.der
openssl pkey -pubin -in /work/out/imported-public.pem -pubout -outform DER \
    >/work/out/import-actual-public.der
cmp /work/out/import-expected-public.der /work/out/import-actual-public.der

ykman -r "$reader" hsmauth credentials list >/work/out/list-before-cycle.txt
for label in sym-cli derived-cli generated-cli imported-cli; do
    grep -q "$label" /work/out/list-before-cycle.txt
done
grep -q 'Symmetric' /work/out/list-before-cycle.txt
grep -q 'Asymmetric' /work/out/list-before-cycle.txt

stop_emulator
start_emulator
ykman -r "$reader" hsmauth credentials list >/work/out/list-after-cycle.txt
for label in sym-cli derived-cli generated-cli imported-cli; do
    grep -q "$label" /work/out/list-after-cycle.txt
done
ykman -r "$reader" hsmauth credentials export generated-cli \
    /work/out/generated-public-after-cycle.pem >/dev/null
cmp /work/out/generated-public.pem /work/out/generated-public-after-cycle.pem

ykman -r "$reader" hsmauth access change-management-password \
    --management-password "$mgmt_old" \
    --new-management-password "$mgmt_new" >/work/out/change-management.txt
grep -q 'Management password changed.' /work/out/change-management.txt

set +e
ykman -r "$reader" hsmauth credentials delete sym-cli \
    --management-password "$mgmt_old" --force \
    >/work/out/delete-old-mgmt.txt 2>&1
old_rc=$?
set -e
[[ "$old_rc" -ne 0 ]]
grep -q '7 attempts remaining.' /work/out/delete-old-mgmt.txt

ykman -r "$reader" hsmauth credentials delete sym-cli \
    --management-password "$mgmt_new" --force >/work/out/delete-sym.txt
ykman -r "$reader" hsmauth credentials delete derived-cli \
    --management-password "$mgmt_new" --force >/work/out/delete-derived.txt
ykman -r "$reader" hsmauth credentials delete generated-cli \
    --management-password "$mgmt_new" --force >/work/out/delete-generated.txt
ykman -r "$reader" hsmauth credentials delete imported-cli \
    --management-password "$mgmt_new" --force >/work/out/delete-imported.txt

ykman -r "$reader" hsmauth info >/work/out/info-after-new-mgmt.txt
grep -Eq '^Management key retries remaining:[[:space:]]+8/8$' /work/out/info-after-new-mgmt.txt
ykman -r "$reader" hsmauth credentials list >/work/out/list-empty.txt
grep -q '^No items found$' /work/out/list-empty.txt

stop_emulator
start_emulator
ykman -r "$reader" hsmauth info >/work/out/info-new-mgmt-cycle.txt
grep -Eq '^Management key retries remaining:[[:space:]]+8/8$' /work/out/info-new-mgmt-cycle.txt

ykman -r "$reader" hsmauth reset --force >/work/out/reset-final.txt
ykman -r "$reader" hsmauth info >/work/out/info-reset.txt
ykman -r "$reader" hsmauth credentials list >/work/out/list-reset.txt
grep -Eq '^Management key retries remaining:[[:space:]]+8/8$' /work/out/info-reset.txt
grep -q '^No items found$' /work/out/list-reset.txt

ykman -r "$reader" hsmauth credentials symmetric reset-default-key \
    --enc-key "$enc_key" --mac-key "$mac_key" \
    --credential-password "$credential_password" \
    --management-password '' >/work/out/reset-default-key.txt
ykman -r "$reader" hsmauth credentials delete reset-default-key \
    --management-password '' --force >/dev/null

printf 'stock ykman 5.9.2 HSM Auth CLI lifecycle: PASS\n'
printf 'symmetric + derived credential import: PASS\n'
printf 'device-generated P-256 credential + public-key export: PASS\n'
printf 'imported P-256 credential public-key identity: PASS\n'
printf 'credential persistence across power cycle: PASS\n'
printf 'management-password change/retry/persistence: PASS\n'
printf 'reset restores empty management password: PASS\n'
printf 'No physical device was accessed.\n'
INNER
