#!/usr/bin/env bash
set -euo pipefail

run_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/pico-fido2-virtual-activation-$$"
trap 'rm -rf "$run_dir"' EXIT
mkdir -p "$run_dir"

fail() {
    echo "virtual-activation-test: $*" >&2
    exit 1
}

[[ -n "${IDF_PATH:-}" ]] || fail 'activate ESP-IDF 5.5 first'
tool=./tools/esp32s3_provision.py
manifest=build-provisioning/manifest.json
[[ -f "$manifest" ]] || fail "missing $manifest"
target="$run_dir/target.json"
$tool bind-target --manifest "$manifest" --factory-mac 00:00:00:00:00:00 \
    --output "$target" >/dev/null

init_provisioned() {
    local efuse=$1
    $tool preflight --virt-file "$efuse" >/dev/null
    $tool provision-virtual --virt-file "$efuse" --manifest "$manifest" \
        --target-manifest "$target" --apply >/dev/null
    $tool verify-device --virt-file "$efuse" --manifest "$manifest" \
        --target-manifest "$target" >/dev/null
}

burn_field() {
    local efuse=$1 field=$2 value=$3
    python -m espefuse --chip esp32s3 --virt --path-efuse-file "$efuse" \
        --do-not-confirm burn_efuse "$field" "$value" >/dev/null
}

! $tool activate-secure-virtual --help | grep -q -- '--port' \
    || fail 'virtual activation unexpectedly exposes a hardware port'

full="$run_dir/full.bin"
init_provisioned "$full"
before="$(sha256sum "$full" | awk '{print $1}')"
$tool activate-secure-virtual --virt-file "$full" --manifest "$manifest" \
    --target-manifest "$target" >"$run_dir/dry-run.txt"
after="$(sha256sum "$full" | awk '{print $1}')"
[[ "$before" == "$after" ]] || fail 'activation dry-run modified virtual eFuse'
grep -q 'pending steps:       Flash Encryption -> Secure Boot' "$run_dir/dry-run.txt"
grep -q 'virtual write:       no (dry-run)' "$run_dir/dry-run.txt"

$tool activate-secure-virtual --virt-file "$full" --manifest "$manifest" \
    --target-manifest "$target" --apply >"$run_dir/apply.txt"
$tool verify-secure --virt-file "$full" --manifest "$manifest" \
    --target-manifest "$target" >/dev/null
grep -q 'Flash Encryption:    PASS (SPI_BOOT_CRYPT_CNT=0b001)' "$run_dir/apply.txt"
grep -q 'Secure Boot:         PASS' "$run_dir/apply.txt"
grep -q 'SECURE_VERSION:      PASS (still 0)' "$run_dir/apply.txt"

secured="$(sha256sum "$full" | awk '{print $1}')"
$tool activate-secure-virtual --virt-file "$full" --manifest "$manifest" \
    --target-manifest "$target" --apply >"$run_dir/reapply.txt"
secured_again="$(sha256sum "$full" | awk '{print $1}')"
[[ "$secured" == "$secured_again" ]] || fail 'idempotent secured reapply modified virtual eFuse'
grep -q 'pending steps:       none' "$run_dir/reapply.txt"
grep -q 'virtual write:       no (already secured)' "$run_dir/reapply.txt"

partial="$run_dir/partial-flash-encryption.bin"
init_provisioned "$partial"
burn_field "$partial" SPI_BOOT_CRYPT_CNT 0x1
$tool activate-secure-virtual --virt-file "$partial" --manifest "$manifest" \
    --target-manifest "$target" >"$run_dir/partial-dry.txt"
grep -q 'pending steps:       Secure Boot' "$run_dir/partial-dry.txt"
$tool activate-secure-virtual --virt-file "$partial" --manifest "$manifest" \
    --target-manifest "$target" --apply >"$run_dir/partial-apply.txt"
$tool verify-secure --virt-file "$partial" --manifest "$manifest" \
    --target-manifest "$target" >/dev/null

after_secure_boot_first="$run_dir/secure-boot-first.bin"
init_provisioned "$after_secure_boot_first"
burn_field "$after_secure_boot_first" SECURE_BOOT_EN 1
bad_order_before="$(sha256sum "$after_secure_boot_first" | awk '{print $1}')"
set +e
$tool activate-secure-virtual --virt-file "$after_secure_boot_first" --manifest "$manifest" \
    --target-manifest "$target" --apply >"$run_dir/bad-order.txt" 2>&1
bad_order_rc=$?
set -e
[[ "$bad_order_rc" -ne 0 ]] || fail 'Secure Boot before Flash Encryption was accepted'
bad_order_after="$(sha256sum "$after_secure_boot_first" | awk '{print $1}')"
[[ "$bad_order_before" == "$bad_order_after" ]] || fail 'bad-order refusal modified virtual eFuse'
grep -q 'unsafe activation order: Secure Boot is enabled but SPI_BOOT_CRYPT_CNT is not 0b001' "$run_dir/bad-order.txt"

floor="$run_dir/nonzero-floor.bin"
init_provisioned "$floor"
burn_field "$floor" SECURE_VERSION 1
floor_before="$(sha256sum "$floor" | awk '{print $1}')"
set +e
$tool activate-secure-virtual --virt-file "$floor" --manifest "$manifest" \
    --target-manifest "$target" --apply >"$run_dir/floor.txt" 2>&1
floor_rc=$?
set -e
[[ "$floor_rc" -ne 0 ]] || fail 'security activation accepted nonzero SECURE_VERSION'
floor_after="$(sha256sum "$floor" | awk '{print $1}')"
[[ "$floor_before" == "$floor_after" ]] || fail 'nonzero-floor refusal modified virtual eFuse'
grep -q 'SECURE_VERSION must remain 0' "$run_dir/floor.txt"

set +e
$tool activate-secure-virtual --virt-file "$full" --port /dev/does-not-exist \
    --manifest "$manifest" --apply >"$run_dir/no-port.txt" 2>&1
port_rc=$?
set -e
[[ "$port_rc" -ne 0 ]] || fail 'virtual activation unexpectedly accepted hardware port'
grep -q 'unrecognized arguments: --port' "$run_dir/no-port.txt"

printf 'ESP32-S3 virtual security activation transaction: PASS\n'
printf 'dry-run no-write: PASS\n'
printf 'Flash Encryption -> readback -> Secure Boot -> readback: PASS\n'
printf 'secured-state idempotency: PASS\n'
printf 'Flash-Encryption-only partial resume: PASS\n'
printf 'Secure-Boot-before-Flash-Encryption refusal: PASS\n'
printf 'nonzero SECURE_VERSION refusal: PASS\n'
printf 'hardware port unavailable by construction: PASS\n'
printf 'SECURE_VERSION never advanced by activation command: PASS\n'
printf 'No physical device was accessed.\n'
