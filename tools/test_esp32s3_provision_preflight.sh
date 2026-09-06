#!/usr/bin/env bash
set -euo pipefail

run_dir="${TMPDIR:-/tmp}/pico-fido2-provision-preflight-$$"
trap 'rm -rf "$run_dir"' EXIT
mkdir -p "$run_dir"

fail() {
    echo "provision-preflight-test: $*" >&2
    exit 1
}

tool=./tools/esp32s3_provision.py

python3 tests/esp32s3_provision_preflight_test.py >/dev/null
python3 -m py_compile "$tool" tests/esp32s3_provision_preflight_test.py

! "$tool" preflight --help | grep -q -- '--apply' \
    || fail 'preflight unexpectedly exposes --apply'
! "$tool" verify-device --help | grep -q -- '--apply' \
    || fail 'verify-device unexpectedly exposes --apply'

set +e
"$tool" preflight --port /dev/does-not-exist >"$run_dir/missing-mac.txt" 2>&1
missing_mac_rc=$?
set -e
[[ "$missing_mac_rc" -ne 0 ]] || fail 'unguarded real-device preflight unexpectedly succeeded'
grep -q 'real-device provisioning inspection requires --expect-mac' "$run_dir/missing-mac.txt"
! grep -q 'Could not open' "$run_dir/missing-mac.txt" \
    || fail 'missing MAC guard attempted to open the serial port'

[[ -n "${IDF_PATH:-}" ]] || fail 'IDF_PATH is not set; activate ESP-IDF 5.5 first'
efuse="$run_dir/blank-efuse.bin"
"$tool" preflight --virt-file "$efuse" >"$run_dir/blank.txt"
grep -q 'ESP32-S3 blank-device preflight: PASS' "$run_dir/blank.txt"
grep -q 'KEY0/1/3/4 empty:    PASS' "$run_dir/blank.txt"
grep -q 'device write:        no' "$run_dir/blank.txt"

before="$(sha256sum "$efuse" | awk '{print $1}')"
"$tool" preflight --virt-file "$efuse" >"$run_dir/blank-repeat.txt"
after="$(sha256sum "$efuse" | awk '{print $1}')"
[[ "$before" == "$after" ]] || fail 'repeat preflight modified virtual eFuse state'

"$tool" verify build-provisioning/manifest.json >/dev/null

printf 'ESP32-S3 provisioning preflight gate: PASS\n'
printf 'blank KEY0/1/3/4 inspection: PASS\n'
printf 'real-device expected-MAC guard before port open: PASS\n'
printf 'read-only CLI surface: PASS\n'
printf 'repeat inspection no-write: PASS\n'
printf 'SECURE_VERSION apply path not exercised\n'
printf 'No physical device was accessed.\n'
