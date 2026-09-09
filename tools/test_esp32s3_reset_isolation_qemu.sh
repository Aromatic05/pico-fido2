#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

run_dir="$(mktemp -d "${TMPDIR:-/tmp}/pico-fido2-reset-isolation-qemu.XXXXXX")"
qemu_pid=""

cleanup() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    if [[ "${KEEP_RESET_QEMU_ARTIFACTS:-0}" == 1 ]]; then
        echo "reset-isolation-qemu: retained $run_dir" >&2
    else
        rm -rf "$run_dir"
    fi
}
trap cleanup EXIT

if [[ -z "${IDF_PATH:-}" ]] || ! command -v idf.py >/dev/null 2>&1; then
    echo 'ESP-IDF environment is not active' >&2
    exit 2
fi

find_esp_qemu() {
    local candidate
    candidate="$(command -v qemu-system-xtensa || true)"
    if [[ -n "$candidate" ]] && "$candidate" -machine help 2>/dev/null | grep '^esp32s3 ' >/dev/null; then
        printf '%s\n' "$candidate"
        return
    fi
    while IFS= read -r candidate; do
        if "$candidate" -machine help 2>/dev/null | grep '^esp32s3 ' >/dev/null; then
            printf '%s\n' "$candidate"
            return
        fi
    done < <(find "${IDF_TOOLS_PATH:-$HOME/.espressif}/tools/qemu-xtensa" \
        -type f -path '*/qemu/bin/qemu-system-xtensa' -perm -111 2>/dev/null | sort -r)
    return 1
}

qemu="$(find_esp_qemu)" || {
    echo 'Espressif QEMU with esp32s3 machine support was not found' >&2
    exit 2
}

cat >"$run_dir/reset-selftest.defaults" <<'EOF'
CONFIG_PICO_FIDO2_QEMU_RESET_SELFTEST=y
# Espressif QEMU's ESP32-S3 SHA/GDMA model can abort the host process under
# the repeated crypto initialization exercised by this test. Keep the test on
# the same mbedTLS algorithms but use software implementations in QEMU only.
# CONFIG_MBEDTLS_HARDWARE_SHA is not set
# CONFIG_MBEDTLS_HARDWARE_AES is not set
# CONFIG_MBEDTLS_HARDWARE_GCM is not set
EOF

defaults="$root/sdkconfig.defaults;$root/sdkconfig.bringup.defaults;$root/sdkconfig.qemu.defaults;$run_dir/reset-selftest.defaults"
build="$run_dir/build"
sdkconfig="$run_dir/sdkconfig"

SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build" -DSDKCONFIG="$sdkconfig" set-target esp32s3 >/dev/null
SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build" -DSDKCONFIG="$sdkconfig" build >/dev/null

grep -qx 'CONFIG_PICO_FIDO2_QEMU=y' "$sdkconfig" || {
    echo 'reset-isolation build is not in QEMU mode' >&2
    exit 3
}
grep -qx 'CONFIG_PICO_FIDO2_QEMU_RESET_SELFTEST=y' "$sdkconfig" || {
    echo 'reset-isolation self-test was not enabled' >&2
    exit 3
}
if grep -qx 'CONFIG_SECURE_BOOT=y' "$sdkconfig" || \
   grep -qx 'CONFIG_SECURE_FLASH_ENC_ENABLED=y' "$sdkconfig"; then
    echo 'reset-isolation QEMU profile unexpectedly enables irreversible security settings' >&2
    exit 3
fi

python -m esptool --chip esp32s3 merge_bin \
    --output "$run_dir/flash.bin" --fill-flash-size 4MB \
    --flash_mode dio --flash_freq 40m --flash_size 4MB \
    0x0 "$build/bootloader/bootloader.bin" \
    0x8000 "$build/partition_table/partition-table.bin" \
    0x10000 "$build/pico_fido2.bin" >/dev/null

dd if=/dev/zero of="$run_dir/efuse.bin" bs=1024 count=1 status=none
efuse_before="$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')"

"$qemu" -M esp32s3 \
    -drive file="$run_dir/flash.bin",if=mtd,format=raw \
    -drive file="$run_dir/efuse.bin",if=none,format=raw,id=efuse \
    -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
    -nic none -nographic -serial mon:stdio \
    >"$run_dir/qemu.log" 2>&1 &
qemu_pid=$!

result=""
for _ in $(seq 1 2400); do
    if grep -aq 'RESET_ISOLATION_QEMU_PASS' "$run_dir/qemu.log"; then
        result=pass
        break
    fi
    if grep -aq 'RESET_ISOLATION_QEMU_FAIL' "$run_dir/qemu.log"; then
        result=fail
        break
    fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        wait "$qemu_pid" || rc=$?
        tail -200 "$run_dir/qemu.log" >&2
        echo "QEMU exited before reset-isolation result: ${rc:-0}" >&2
        exit 4
    fi
    sleep 0.05
done

if [[ "$result" != pass ]]; then
    tail -240 "$run_dir/qemu.log" >&2
    echo 'ESP32-S3 reset-isolation self-test failed or timed out' >&2
    exit 4
fi

if grep -aqE 'assert failed|Guru Meditation|RESET_ISOLATION_QEMU_FAIL' "$run_dir/qemu.log"; then
    tail -240 "$run_dir/qemu.log" >&2
    echo 'ESP32-S3 reset-isolation self-test crashed' >&2
    exit 4
fi

kill "$qemu_pid" 2>/dev/null || true
wait "$qemu_pid" 2>/dev/null || true
qemu_pid=""

efuse_after="$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')"
[[ "$efuse_before" == "$efuse_after" ]] || {
    echo 'QEMU reset-isolation test modified the eFuse image' >&2
    exit 4
}

echo "RESET ISOLATION QEMU: PASS ($($qemu --version | head -1))"
echo "eFuse unchanged: $efuse_after"
