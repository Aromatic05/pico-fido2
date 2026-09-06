#!/usr/bin/env bash
set -euo pipefail

run_dir="${TMPDIR:-/tmp}/pico-fido2-ab-ota-qemu-$$"
qemu_pid=""
defaults='sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.qemu.defaults;sdkconfig.wifi.defaults;sdkconfig.secure-ota.defaults'

fail() {
    echo "ab-ota-qemu: $*" >&2
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

[[ -n "${IDF_PATH:-}" ]] || fail 'IDF_PATH is not set; activate ESP-IDF 5.5 first'
command -v idf.py >/dev/null || fail 'idf.py not found'

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

build_version() {
    local name=$1 project_version=$2 epoch=$3
    local build="$run_dir/build-$name"
    local sdkconfig="$run_dir/sdkconfig-$name"
    local epoch_defaults="$run_dir/epoch-$name.defaults"
    printf 'CONFIG_PICO_FIDO2_SECURITY_VERSION=%s\n' "$epoch" >"$epoch_defaults"
    SDKCONFIG_DEFAULTS="${defaults};${epoch_defaults}" \
        idf.py -B "$build" -DSDKCONFIG="$sdkconfig" -DPROJECT_VER="$project_version" \
        set-target esp32s3 >/dev/null
    SDKCONFIG_DEFAULTS="${defaults};${epoch_defaults}" \
        idf.py -B "$build" -DSDKCONFIG="$sdkconfig" -DPROJECT_VER="$project_version" \
        build >/dev/null

    for expected in \
        CONFIG_PICO_FIDO2_QEMU=y \
        CONFIG_PICOKEYS_ESP32_DEV_KEYS=y \
        CONFIG_PICO_FIDO2_WIFI_COMMISSIONING=y \
        CONFIG_PICO_FIDO2_AB_OTA=y \
        CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y \
        CONFIG_PARTITION_TABLE_OFFSET=0x10000 \
        CONFIG_PICO_FIDO2_SECURITY_VERSION=${epoch}; do
        grep -qx "$expected" "$sdkconfig" || fail "$name: missing config $expected"
    done
    grep -qx 'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="pico-keys-sdk/config/esp32/partitions-secure-ota.csv"' "$sdkconfig" \
        || fail "$name: wrong A/B partition table"
    if grep -qx 'CONFIG_SECURE_BOOT=y' "$sdkconfig" || \
       grep -qx 'CONFIG_SECURE_FLASH_ENC_ENABLED=y' "$sdkconfig" || \
       grep -qx 'CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y' "$sdkconfig" || \
       grep -qx 'CONFIG_PICO_FIDO2_SINGLE_SLOT_ANTI_ROLLBACK=y' "$sdkconfig"; then
        fail "$name: QEMU A/B state test must not enable hardware security/eFuse anti-rollback"
    fi
}

build_version base 7.4.0 0
build_version update 7.4.1 1

python -m esptool --chip esp32s3 merge_bin \
    --output "$run_dir/baseline-flash.bin" --fill-flash-size 4MB \
    --flash_mode dio --flash_freq 40m --flash_size 4MB \
    0x0 "$run_dir/build-base/bootloader/bootloader.bin" \
    0x10000 "$run_dir/build-base/partition_table/partition-table.bin" \
    0x20000 "$run_dir/build-base/pico_fido2.bin" \
    0x190000 "$run_dir/build-update/pico_fido2.bin" >/dev/null

dd if=/dev/zero of="$run_dir/efuse-baseline.bin" bs=1024 count=1 status=none
baseline_efuse_sha="$(sha256sum "$run_dir/efuse-baseline.bin" | awk '{print $1}')"

start_qemu() {
    local flash=$1 efuse=$2 log=$3
    : >"$log"
    "$qemu" -M esp32s3 \
        -drive file="$flash",if=mtd,format=raw \
        -drive file="$efuse",if=none,format=raw,id=efuse \
        -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
        -nic user,model=open_eth -nographic -serial mon:stdio >"$log" 2>&1 &
    qemu_pid=$!
}

stop_qemu() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    qemu_pid=""
}

wait_log() {
    local log=$1 pattern=$2 loops=$3 description=$4
    for _ in $(seq 1 "$loops"); do
        if grep -aqE "$pattern" "$log"; then
            return 0
        fi
        if [[ -n "$qemu_pid" ]] && ! kill -0 "$qemu_pid" 2>/dev/null; then
            wait "$qemu_pid" || true
            qemu_pid=""
            tail -160 "$log" >&2
            fail "QEMU exited before $description"
        fi
        sleep 0.05
    done
    tail -160 "$log" >&2
    fail "timed out waiting for $description"
}

assert_otadata() {
    local flash=$1 slot=$2 seq=$3 state=$4
    python3 - "$flash" "$slot" "$seq" "$state" <<'PY'
from pathlib import Path
import binascii, struct, sys
p = Path(sys.argv[1])
slot = int(sys.argv[2])
expected_seq = int(sys.argv[3])
expected_state = int(sys.argv[4])
data = p.read_bytes()
offset = 0x18000 + slot * 0x1000
entry = data[offset:offset + 32]
seq = struct.unpack_from('<I', entry, 0)[0]
state = struct.unpack_from('<I', entry, 24)[0]
crc = struct.unpack_from('<I', entry, 28)[0]
expected_crc = binascii.crc32(struct.pack('<I', seq), 0xFFFFFFFF) & 0xFFFFFFFF
if (seq, state, crc) != (expected_seq, expected_state, expected_crc):
    raise SystemExit(
        f'otadata[{slot}] mismatch: seq={seq} state={state} crc=0x{crc:08x}; '
        f'expected seq={expected_seq} state={expected_state} crc=0x{expected_crc:08x}'
    )
PY
}

select_ota1_new() {
    local flash=$1
    python3 - "$flash" <<'PY'
from pathlib import Path
import binascii, struct, sys
p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
offset = 0x19000
entry = bytearray(b'\xff' * 32)
seq = 2
struct.pack_into('<I', entry, 0, seq)
struct.pack_into('<I', entry, 24, 0)  # ESP_OTA_IMG_NEW
struct.pack_into('<I', entry, 28, binascii.crc32(struct.pack('<I', seq), 0xFFFFFFFF) & 0xFFFFFFFF)
data[offset:offset + 0x1000] = b'\xff' * 0x1000
data[offset:offset + 32] = entry
p.write_bytes(data)
PY
}

# First raw A/B baseline boot: blank otadata must select ota_0 and persist it VALID.
start_qemu "$run_dir/baseline-flash.bin" "$run_dir/efuse-baseline.bin" "$run_dir/baseline.log"
wait_log "$run_dir/baseline.log" 'App version:.*7\.4\.0' 400 'ota_0 baseline image'
wait_log "$run_dir/baseline.log" 'main_task: Returned from app_main\(\)' 400 'baseline app_main completion'
stop_qemu
assert_otadata "$run_dir/baseline-flash.bin" 0 1 2
[[ "$(sha256sum "$run_dir/efuse-baseline.bin" | awk '{print $1}')" == "$baseline_efuse_sha" ]] \
    || fail 'baseline A/B boot modified virtual eFuse state'

cp "$run_dir/baseline-flash.bin" "$run_dir/rollback-flash.bin"
cp "$run_dir/efuse-baseline.bin" "$run_dir/rollback-efuse.bin"
cp "$run_dir/baseline-flash.bin" "$run_dir/confirm-flash.bin"
cp "$run_dir/efuse-baseline.bin" "$run_dir/confirm-efuse.bin"

# Rollback path: NEW -> PENDING_VERIFY, power loss before five-second confirmation,
# then bootloader marks ota_1 ABORTED and returns to ota_0.
select_ota1_new "$run_dir/rollback-flash.bin"
assert_otadata "$run_dir/rollback-flash.bin" 1 2 0
start_qemu "$run_dir/rollback-flash.bin" "$run_dir/rollback-efuse.bin" "$run_dir/rollback-first.log"
wait_log "$run_dir/rollback-first.log" 'App version:.*7\.4\.1' 400 'ota_1 trial image'
wait_log "$run_dir/rollback-first.log" 'OTA image pending verification; delaying confirmation for 5 seconds' 400 'PENDING_VERIFY application state'
stop_qemu
assert_otadata "$run_dir/rollback-flash.bin" 1 2 1

start_qemu "$run_dir/rollback-flash.bin" "$run_dir/rollback-efuse.bin" "$run_dir/rollback-second.log"
wait_log "$run_dir/rollback-second.log" 'App version:.*7\.4\.0' 400 'rollback to ota_0'
wait_log "$run_dir/rollback-second.log" 'main_task: Returned from app_main\(\)' 400 'rolled-back app_main completion'
stop_qemu
assert_otadata "$run_dir/rollback-flash.bin" 0 1 2
assert_otadata "$run_dir/rollback-flash.bin" 1 2 4
[[ "$(sha256sum "$run_dir/rollback-efuse.bin" | awk '{print $1}')" == "$baseline_efuse_sha" ]] \
    || fail 'rollback case modified virtual eFuse state'

# Confirmation path: NEW -> PENDING_VERIFY -> application VALID after five stable seconds.
select_ota1_new "$run_dir/confirm-flash.bin"
start_qemu "$run_dir/confirm-flash.bin" "$run_dir/confirm-efuse.bin" "$run_dir/confirm-first.log"
wait_log "$run_dir/confirm-first.log" 'App version:.*7\.4\.1' 400 'ota_1 confirmation image'
wait_log "$run_dir/confirm-first.log" 'OTA image confirmed after service-loop stability window' 220 'five-second OTA confirmation'
stop_qemu
assert_otadata "$run_dir/confirm-flash.bin" 1 2 2

start_qemu "$run_dir/confirm-flash.bin" "$run_dir/confirm-efuse.bin" "$run_dir/confirm-second.log"
wait_log "$run_dir/confirm-second.log" 'App version:.*7\.4\.1' 400 'confirmed ota_1 reboot'
wait_log "$run_dir/confirm-second.log" 'main_task: Returned from app_main\(\)' 400 'confirmed app_main completion'
stop_qemu
assert_otadata "$run_dir/confirm-flash.bin" 1 2 2
[[ "$(sha256sum "$run_dir/confirm-efuse.bin" | awk '{print $1}')" == "$baseline_efuse_sha" ]] \
    || fail 'confirmation case modified virtual eFuse state'

printf 'ESP32-S3 A/B OTA rollback QEMU: PASS (%s)\n' "$($qemu --version | head -1)"
printf 'blank otadata -> ota_0 VALID: PASS\n'
printf 'ota_1 NEW -> PENDING_VERIFY: PASS\n'
printf 'unconfirmed ota_1 -> ABORTED -> ota_0 rollback: PASS\n'
printf 'confirmed ota_1 -> VALID -> ota_1 reboot: PASS\n'
printf 'virtual eFuse unchanged: %s\n' "$baseline_efuse_sha"
printf 'No physical device was accessed.\n'
