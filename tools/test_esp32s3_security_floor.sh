#!/usr/bin/env bash
set -euo pipefail

run_dir="${TMPDIR:-/tmp}/pico-fido2-security-floor-$$"
trap 'rm -rf "$run_dir"' EXIT
mkdir -p "$run_dir"

fail() {
    echo "security-floor-test: $*" >&2
    exit 1
}

[[ -n "${IDF_PATH:-}" ]] || fail 'IDF_PATH is not set; activate ESP-IDF 5.5 first'
command -v python >/dev/null || fail 'python not found'

tool=./tools/esp32s3_provision.py

set +e
$tool security-version --port /dev/does-not-exist --target 1 --expect-current 0 --apply \
    >"$run_dir/missing-mac.txt" 2>&1
missing_mac_rc=$?
set -e
[[ "$missing_mac_rc" -ne 0 ]] || fail 'real apply without MAC guard unexpectedly succeeded'
grep -q -- '--apply on a real device requires --expect-mac' "$run_dir/missing-mac.txt"
! grep -q 'Could not open' "$run_dir/missing-mac.txt" || fail 'missing MAC guard attempted to open the serial port'

offline="$($tool security-version --current 0 --target 2)"
grep -q 'current floor: 0 (raw 0x0000)' <<<"$offline"
grep -q 'target floor:  2 (raw 0x0003)' <<<"$offline"
grep -q 'new bits:      0x0003' <<<"$offline"
grep -q 'device write:  no' <<<"$offline"

efuse="$run_dir/efuse.bin"
$tool security-version --virt-file "$efuse" --target 2 --expect-current 0 --apply >"$run_dir/apply2.txt"
grep -q 'current floor: 0 (raw 0x0000)' "$run_dir/apply2.txt"
grep -q 'target floor:  2 (raw 0x0003)' "$run_dir/apply2.txt"
grep -q 'device write:  virtual eFuse applied' "$run_dir/apply2.txt"
python -m espefuse --chip esp32s3 --virt --path-efuse-file "$efuse" \
    summary SECURE_VERSION --format value_only >"$run_dir/value2.txt"
[[ "$(tail -n 1 "$run_dir/value2.txt")" == 3 ]] || fail 'floor2 raw value is not 0x0003'

before="$(sha256sum "$efuse" | awk '{print $1}')"
$tool security-version --virt-file "$efuse" --target 3 >"$run_dir/dry3.txt"
after="$(sha256sum "$efuse" | awk '{print $1}')"
[[ "$before" == "$after" ]] || fail 'dry-run modified virtual eFuse'
grep -q 'current floor: 2 (raw 0x0003)' "$run_dir/dry3.txt"
grep -q 'target floor:  3 (raw 0x0007)' "$run_dir/dry3.txt"
grep -q 'new bits:      0x0004' "$run_dir/dry3.txt"
grep -q 'device write:  no' "$run_dir/dry3.txt"

$tool security-version --virt-file "$efuse" --target 3 --expect-current 2 --apply >"$run_dir/apply3.txt"
python -m espefuse --chip esp32s3 --virt --path-efuse-file "$efuse" \
    summary SECURE_VERSION --format value_only >"$run_dir/value3.txt"
[[ "$(tail -n 1 "$run_dir/value3.txt")" == 7 ]] || fail 'floor3 raw value is not 0x0007'

before="$(sha256sum "$efuse" | awk '{print $1}')"
set +e
$tool security-version --virt-file "$efuse" --target 4 --expect-current 3 \
    --expect-mac 11:22:33:44:55:66 --apply >"$run_dir/wrong-mac.txt" 2>&1
wrong_mac_rc=$?
set -e
[[ "$wrong_mac_rc" -ne 0 ]] || fail 'wrong MAC guard unexpectedly succeeded'
after="$(sha256sum "$efuse" | awk '{print $1}')"
[[ "$before" == "$after" ]] || fail 'wrong MAC guard modified virtual eFuse'
grep -q 'expected MAC 11:22:33:44:55:66, device reports 00:00:00:00:00:00' "$run_dir/wrong-mac.txt"

before="$(sha256sum "$efuse" | awk '{print $1}')"
set +e
$tool security-version --virt-file "$efuse" --target 4 --apply >"$run_dir/missing-guard.txt" 2>&1
missing_guard_rc=$?
set -e
[[ "$missing_guard_rc" -ne 0 ]] || fail 'unguarded --apply unexpectedly succeeded'
after="$(sha256sum "$efuse" | awk '{print $1}')"
[[ "$before" == "$after" ]] || fail 'unguarded --apply modified virtual eFuse'
grep -q -- '--apply requires --expect-current' "$run_dir/missing-guard.txt"

before="$(sha256sum "$efuse" | awk '{print $1}')"
set +e
$tool security-version --virt-file "$efuse" --target 2 --expect-current 3 --apply >"$run_dir/rollback.txt" 2>&1
rollback_rc=$?
set -e
[[ "$rollback_rc" -ne 0 ]] || fail 'rollback floor application unexpectedly succeeded'
after="$(sha256sum "$efuse" | awk '{print $1}')"
[[ "$before" == "$after" ]] || fail 'rollback attempt modified virtual eFuse'
grep -q 'cannot lower security floor' "$run_dir/rollback.txt"

set +e
$tool security-version --virt-file "$efuse" --target 4 --expect-current 2 --apply >"$run_dir/wrong-current.txt" 2>&1
wrong_current_rc=$?
set -e
[[ "$wrong_current_rc" -ne 0 ]] || fail 'wrong current-floor guard unexpectedly succeeded'
after="$(sha256sum "$efuse" | awk '{print $1}')"
[[ "$before" == "$after" ]] || fail 'wrong current-floor attempt modified virtual eFuse'
grep -q 'expected current floor 2, device reports 3' "$run_dir/wrong-current.txt"

bad="$run_dir/noncanonical.bin"
python -m espefuse --chip esp32s3 --virt --path-efuse-file "$bad" --do-not-confirm \
    burn_efuse SECURE_VERSION 0x0005 >/dev/null
set +e
$tool security-version --virt-file "$bad" --target 3 >"$run_dir/noncanonical.txt" 2>&1
noncanonical_rc=$?
set -e
[[ "$noncanonical_rc" -ne 0 ]] || fail 'non-canonical SECURE_VERSION was accepted'
grep -q 'non-canonical SECURE_VERSION raw value 0x0005' "$run_dir/noncanonical.txt"

printf 'ESP32-S3 security floor gate: PASS\n'
printf '0 -> 2 -> 3 unary progression: PASS\n'
printf 'dry-run no-write: PASS\n'
printf 'rollback rejection: PASS\n'
printf 'real-device MAC guard: PASS\n'
printf 'MAC mismatch guard: PASS\n'
printf 'explicit apply guard: PASS\n'
printf 'expected-current guard: PASS\n'
printf 'non-canonical raw rejection: PASS\n'
printf 'No physical device was accessed.\n'
