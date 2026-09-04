#!/usr/bin/env bash
set -euo pipefail

build_dir="${BUILD_DIR:-build-qemu}"
sdkconfig="${SDKCONFIG:-sdkconfig.qemu}"
defaults='sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.qemu.defaults'
run_dir="${TMPDIR:-/tmp}/pico-fido2-qemu-$$"
mkdir -p "$run_dir"
qemu_pid=""
cleanup() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    rm -rf "$run_dir"
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
    done < <(find "${IDF_TOOLS_PATH:-$HOME/.espressif}/tools/qemu-xtensa" -type f -path '*/qemu/bin/qemu-system-xtensa' -perm -111 2>/dev/null | sort -r)
    return 1
}

qemu="$(find_esp_qemu)" || {
    echo 'Espressif QEMU with esp32s3 machine support was not found' >&2
    exit 2
}

# The QEMU gate owns these disposable artifacts. Reusing a generated sdkconfig
# or build tree can leak stale Kconfig state from another ESP32-S3 profile.
rm -rf "$build_dir"
rm -f "$sdkconfig" "$sdkconfig.old"

SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" set-target esp32s3 >/dev/null
SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" build >/dev/null

for expected in \
    CONFIG_PICO_FIDO2_QEMU=y \
    CONFIG_PICOKEYS_ESP32_DEV_KEYS=y \
    CONFIG_ESPTOOLPY_FLASHMODE_DIO=y \
    CONFIG_ESPTOOLPY_FLASHFREQ_40M=y \
    CONFIG_SPI_FLASH_HPM_DIS=y; do
    grep -qx "$expected" "$sdkconfig" || {
        echo "QEMU config missing: $expected" >&2
        exit 3
    }
done

if grep -qx 'CONFIG_SECURE_BOOT=y' "$sdkconfig" || \
   grep -qx 'CONFIG_SECURE_FLASH_ENC_ENABLED=y' "$sdkconfig"; then
    echo 'QEMU bring-up profile must not enable irreversible security features' >&2
    exit 3
fi

python -m esptool --chip esp32s3 merge_bin \
    --output "$build_dir/qemu_flash.bin" --fill-flash-size 4MB \
    --flash_mode dio --flash_freq 40m --flash_size 4MB \
    0x0 "$build_dir/bootloader/bootloader.bin" \
    0x8000 "$build_dir/partition_table/partition-table.bin" \
    0x10000 "$build_dir/pico_fido2.bin" >/dev/null

dd if=/dev/zero of="$run_dir/efuse.bin" bs=1024 count=1 status=none
before="$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')"
"$qemu" -M esp32s3 \
    -drive file="$build_dir/qemu_flash.bin",if=mtd,format=raw \
    -drive file="$run_dir/efuse.bin",if=none,format=raw,id=efuse \
    -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
    -nic user,model=open_eth -nographic -serial mon:stdio \
    >"$run_dir/qemu.log" 2>&1 &
qemu_pid=$!

booted=false
for _ in $(seq 1 400); do
    if grep -aq 'main_task: Returned from app_main()' "$run_dir/qemu.log"; then
        booted=true
        break
    fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        wait "$qemu_pid" || rc=$?
        cat "$run_dir/qemu.log" >&2
        echo "QEMU exited before app_main completed: ${rc:-0}" >&2
        exit 4
    fi
    sleep 0.05
done

if [[ "$booted" != true ]]; then
    tail -120 "$run_dir/qemu.log" >&2
    echo 'QEMU did not complete app_main' >&2
    exit 4
fi

kill "$qemu_pid"
wait "$qemu_pid" 2>/dev/null || true
qemu_pid=""

after="$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')"
[[ "$before" == "$after" ]] || {
    echo 'QEMU modified blank eFuse in reversible bring-up mode' >&2
    exit 4
}

require_log() {
    local pattern="$1"
    local description="$2"
    if ! grep -aq "$pattern" "$run_dir/qemu.log"; then
        tail -120 "$run_dir/qemu.log" >&2
        echo "QEMU boot milestone missing: $description" >&2
        exit 4
    fi
}

require_log 'Project name:     pico_fido2' 'application image'
require_log 'main_task: Calling app_main()' 'app_main entry'
require_log 'main_task: Returned from app_main()' 'app_main return'
if grep -aqE 'assert failed|Guru Meditation|Rebooting' "$run_dir/qemu.log"; then
    tail -120 "$run_dir/qemu.log" >&2
    echo 'QEMU application crashed or rebooted' >&2
    exit 4
fi

echo "QEMU: PASS ($($qemu --version | head -1))"
echo "App: $(stat -c %s "$build_dir/pico_fido2.bin") bytes"
echo "eFuse unchanged: $after"
