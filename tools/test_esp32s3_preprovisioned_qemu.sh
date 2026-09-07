#!/usr/bin/env bash
set -euo pipefail

run_dir="${TMPDIR:-/tmp}/pico-fido2-preprovision-qemu-$$"
qemu_pid=""

fail() {
    echo "preprovision-qemu: $*" >&2
    exit 1
}

cleanup() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    rm -rf "$run_dir"
}
trap cleanup EXIT
mkdir -p "$run_dir"

[[ -n "${IDF_PATH:-}" ]] || fail 'activate ESP-IDF 5.5 first'

find_qemu() {
    local q
    q="$(command -v qemu-system-xtensa || true)"
    if [[ -n "$q" ]] && "$q" -machine help 2>/dev/null | grep '^esp32s3 ' >/dev/null; then
        printf '%s\n' "$q"
        return
    fi
    while IFS= read -r q; do
        if "$q" -machine help 2>/dev/null | grep '^esp32s3 ' >/dev/null; then
            printf '%s\n' "$q"
            return
        fi
    done < <(find "${IDF_TOOLS_PATH:-$HOME/.espressif}/tools/qemu-xtensa" \
        -type f -path '*/qemu/bin/qemu-system-xtensa' -perm -111 2>/dev/null | sort -r)
    return 1
}
qemu="$(find_qemu)" || fail 'Espressif ESP32-S3 QEMU not found'

build_image() {
    local build_dir=$1 sdkconfig=$2 defaults=$3 output=$4
    rm -rf "$build_dir"
    rm -f "$sdkconfig" "$sdkconfig.old"
    SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" set-target esp32s3 >/dev/null
    SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" build >/dev/null
    python -m esptool --chip esp32s3 merge_bin --output "$output" --fill-flash-size 4MB \
        --flash_mode dio --flash_freq 40m --flash_size 4MB \
        0x0 "$build_dir/bootloader/bootloader.bin" \
        0x8000 "$build_dir/partition_table/partition-table.bin" \
        0x10000 "$build_dir/pico_fido2.bin" >/dev/null
}

build_image build-qemu-required sdkconfig.qemu-required \
    'sdkconfig.defaults;sdkconfig.qemu.defaults;sdkconfig.preprovisioned-qemu.defaults' "$run_dir/required.bin"
build_image build-qemu-autokeys sdkconfig.qemu-autokeys \
    'sdkconfig.defaults;sdkconfig.qemu.defaults' "$run_dir/autokeys.bin"

grep -qx 'CONFIG_PICOKEYS_ESP32_REQUIRE_PROVISIONED_KEYS=y' sdkconfig.qemu-required \
    || fail 'required-key profile was not enabled'
if grep -q '^CONFIG_PICOKEYS_ESP32_DEV_KEYS=y' sdkconfig.qemu-required; then
    fail 'required-key profile unexpectedly uses development keys'
fi

make_blank_efuse() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys
b = bytearray(1024)
b[38] = 0x0c  # Espressif QEMU ESP32-S3 default: chip revision v0.3.
Path(sys.argv[1]).write_bytes(b)
PY
}

run_until_return() {
    local flash=$1 efuse=$2 log=$3
    "$qemu" -M esp32s3 \
        -drive file="$flash",if=mtd,format=raw \
        -drive file="$efuse",if=none,format=raw,id=efuse \
        -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
        -nic none -nographic -serial mon:stdio >"$log" 2>&1 &
    qemu_pid=$!
    local returned=false
    for _ in $(seq 1 400); do
        if grep -aq 'main_task: Returned from app_main()' "$log"; then
            returned=true
            break
        fi
        if ! kill -0 "$qemu_pid" 2>/dev/null; then
            wait "$qemu_pid" || rc=$?
            cat "$log" >&2
            fail "QEMU exited before app_main returned: ${rc:-0}"
        fi
        sleep 0.05
    done
    [[ "$returned" == true ]] || { tail -120 "$log" >&2; fail 'QEMU app_main did not return'; }
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=""
}

make_blank_efuse "$run_dir/blank-required-efuse.bin"
blank_before="$(sha256sum "$run_dir/blank-required-efuse.bin" | awk '{print $1}')"
run_until_return "$run_dir/required.bin" "$run_dir/blank-required-efuse.bin" "$run_dir/blank-required.log"
blank_after="$(sha256sum "$run_dir/blank-required-efuse.bin" | awk '{print $1}')"
[[ "$blank_before" == "$blank_after" ]] || fail 'required-key failure modified eFuses'
grep -aq 'OTP initialization failed \[-1013\]' "$run_dir/blank-required.log" \
    || fail 'blank required-key profile did not fail closed'

make_blank_efuse "$run_dir/provisioned-efuse.bin"
auto_before="$(sha256sum "$run_dir/provisioned-efuse.bin" | awk '{print $1}')"
run_until_return "$run_dir/autokeys.bin" "$run_dir/provisioned-efuse.bin" "$run_dir/autokeys.log"
auto_after="$(sha256sum "$run_dir/provisioned-efuse.bin" | awk '{print $1}')"
[[ "$auto_before" != "$auto_after" ]] || fail 'legacy virtual key provisioning did not modify eFuses'

required_before="$auto_after"
run_until_return "$run_dir/required.bin" "$run_dir/provisioned-efuse.bin" "$run_dir/provisioned-required.log"
required_after="$(sha256sum "$run_dir/provisioned-efuse.bin" | awk '{print $1}')"
[[ "$required_before" == "$required_after" ]] || fail 'pre-provisioned startup modified eFuses'
if grep -aq 'OTP initialization failed' "$run_dir/provisioned-required.log"; then
    cat "$run_dir/provisioned-required.log" >&2
    fail 'correctly provisioned KEY3/KEY4 were rejected'
fi

echo "Pre-provisioned KEY3/KEY4 gate: PASS ($($qemu --version | head -1))"
echo "Blank required-key eFuse unchanged: $blank_before"
echo "Virtual provisioning transition: $auto_before -> $auto_after"
echo "Provisioned required-key eFuse unchanged: $required_after"
