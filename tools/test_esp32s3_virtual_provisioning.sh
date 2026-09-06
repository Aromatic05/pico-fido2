#!/usr/bin/env bash
set -euo pipefail

run_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/pico-fido2-virtual-provision-$$"
trap 'rm -rf "$run_dir"' EXIT
mkdir -p "$run_dir"

fail() {
    echo "virtual-provision-test: $*" >&2
    exit 1
}

[[ -n "${IDF_PATH:-}" ]] || fail 'activate ESP-IDF 5.5 first'
tool=./tools/esp32s3_provision.py

$tool generate --output-dir "$run_dir/material" >/dev/null
manifest="$run_dir/material/manifest.json"

init_blank() {
    local efuse=$1
    $tool preflight --virt-file "$efuse" >/dev/null
}

burn_virtual() {
    local efuse=$1
    shift
    python -m espefuse --chip esp32s3 --virt --path-efuse-file "$efuse" \
        --do-not-confirm burn_key "$@" >/dev/null
}

blank="$run_dir/blank.bin"
init_blank "$blank"
before="$(sha256sum "$blank" | awk '{print $1}')"
$tool provision-virtual --virt-file "$blank" --manifest "$manifest" >"$run_dir/dry-run.txt"
after="$(sha256sum "$blank" | awk '{print $1}')"
[[ "$before" == "$after" ]] || fail 'dry-run modified virtual eFuse'
grep -q 'pending blocks:      KEY0, KEY1, KEY3, KEY4' "$run_dir/dry-run.txt"
grep -q 'virtual write:       no (dry-run)' "$run_dir/dry-run.txt"

$tool provision-virtual --virt-file "$blank" --manifest "$manifest" --apply >"$run_dir/apply.txt"
$tool verify-device --virt-file "$blank" --manifest "$manifest" >/dev/null
grep -q 'KEY0/1/3/4 layout:   PASS' "$run_dir/apply.txt"
grep -q 'virtual write:       applied' "$run_dir/apply.txt"

provisioned="$(sha256sum "$blank" | awk '{print $1}')"
$tool provision-virtual --virt-file "$blank" --manifest "$manifest" --apply >"$run_dir/reapply.txt"
reapplied="$(sha256sum "$blank" | awk '{print $1}')"
[[ "$provisioned" == "$reapplied" ]] || fail 'idempotent reapply modified virtual eFuse'
grep -q 'pending blocks:      none' "$run_dir/reapply.txt"
grep -q 'virtual write:       no (already provisioned)' "$run_dir/reapply.txt"

recoverable="$run_dir/recoverable.bin"
init_blank "$recoverable"
burn_virtual "$recoverable" \
    BLOCK_KEY0 "$run_dir/material/secure_boot_digest.bin" SECURE_BOOT_DIGEST0 \
    BLOCK_KEY3 "$run_dir/material/mkek.bin" USER
$tool provision-virtual --virt-file "$recoverable" --manifest "$manifest" --apply \
    >"$run_dir/recoverable.txt"
$tool verify-device --virt-file "$recoverable" --manifest "$manifest" >/dev/null
grep -q 'pending blocks:      KEY1, KEY4' "$run_dir/recoverable.txt"
grep -q 'virtual write:       applied' "$run_dir/recoverable.txt"

unsafe="$run_dir/unsafe-key1.bin"
init_blank "$unsafe"
burn_virtual "$unsafe" \
    BLOCK_KEY1 "$run_dir/material/flash_encryption_key.bin" XTS_AES_128_KEY
unsafe_before="$(sha256sum "$unsafe" | awk '{print $1}')"
set +e
$tool provision-virtual --virt-file "$unsafe" --manifest "$manifest" --apply \
    >"$run_dir/unsafe.txt" 2>&1
unsafe_rc=$?
set -e
[[ "$unsafe_rc" -ne 0 ]] || fail 'partial unreadable KEY1 state was resumed'
unsafe_after="$(sha256sum "$unsafe" | awk '{print $1}')"
[[ "$unsafe_before" == "$unsafe_after" ]] || fail 'unsafe partial state was modified'
grep -q 'partial provisioning cannot be resumed after KEY1 became unreadable' "$run_dir/unsafe.txt"

wrong="$run_dir/wrong-readable-key.bin"
init_blank "$wrong"
python - "$run_dir/wrong-key.bin" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(bytes(range(32)))
PY
burn_virtual "$wrong" BLOCK_KEY0 "$run_dir/wrong-key.bin" SECURE_BOOT_DIGEST0
wrong_before="$(sha256sum "$wrong" | awk '{print $1}')"
set +e
$tool provision-virtual --virt-file "$wrong" --manifest "$manifest" --apply \
    >"$run_dir/wrong.txt" 2>&1
wrong_rc=$?
set -e
[[ "$wrong_rc" -ne 0 ]] || fail 'wrong readable KEY0 material was accepted'
wrong_after="$(sha256sum "$wrong" | awk '{print $1}')"
[[ "$wrong_before" == "$wrong_after" ]] || fail 'wrong readable-key state was modified'
grep -q 'KEY0 is neither blank nor an exact protected match' "$run_dir/wrong.txt"

floor="$run_dir/nonzero-floor.bin"
init_blank "$floor"
python -m espefuse --chip esp32s3 --virt --path-efuse-file "$floor" \
    --do-not-confirm burn_efuse SECURE_VERSION 1 >/dev/null
floor_before="$(sha256sum "$floor" | awk '{print $1}')"
set +e
$tool provision-virtual --virt-file "$floor" --manifest "$manifest" --apply \
    >"$run_dir/floor.txt" 2>&1
floor_rc=$?
set -e
[[ "$floor_rc" -ne 0 ]] || fail 'initial key provisioning accepted nonzero SECURE_VERSION'
floor_after="$(sha256sum "$floor" | awk '{print $1}')"
[[ "$floor_before" == "$floor_after" ]] || fail 'nonzero SECURE_VERSION refusal modified virtual eFuse'
grep -q 'SECURE_VERSION must remain 0 during initial provisioning' "$run_dir/floor.txt"

set +e
$tool provision-virtual --virt-file "$blank" --port /dev/does-not-exist \
    --manifest "$manifest" --apply \
    >"$run_dir/no-port.txt" 2>&1
port_rc=$?
set -e
[[ "$port_rc" -ne 0 ]] || fail 'provision-virtual unexpectedly accepted a hardware port'
grep -q 'unrecognized arguments: --port' "$run_dir/no-port.txt"

printf 'ESP32-S3 virtual KEY0/KEY1/KEY3/KEY4 provisioning rehearsal: PASS\n'
printf 'blank dry-run no-write: PASS\n'
printf 'full virtual burn + verification: PASS\n'
printf 'idempotent fully-provisioned reapply: PASS\n'
printf 'recoverable readable-key partial state: PASS\n'
printf 'unverifiable partial KEY1 refusal: PASS\n'
printf 'wrong readable key refusal: PASS\n'
printf 'nonzero SECURE_VERSION refusal: PASS\n'
printf 'hardware port unavailable by construction: PASS\n'
printf 'provision command never changes SECURE_VERSION: PASS\n'
printf 'No physical device was accessed.\n'
