#!/usr/bin/env bash
set -euo pipefail

# QEMU-only rehearsal of the exact high-risk hardware sequence. This script
# deliberately has no serial-port argument and can never address a physical
# device. Safety/recovery is the primary policy: anti-rollback remains off,
# SECURE_VERSION remains zero, and every ROM/JTAG recovery disable bit must stay
# clear before and after security activation and OTA trials.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

run_dir="${TMPDIR:-/tmp}/pico-fido2-hardware-rehearsal-qemu-$$"
qemu_pid=""
qemu_port=""
qemu_url=""
base_build="$run_dir/build-base"
update_build="$run_dir/build-update"
base_sdkconfig="$run_dir/sdkconfig-base"
update_sdkconfig="$run_dir/sdkconfig-update"
base_epoch_defaults="$run_dir/base-epoch.defaults"
update_epoch_defaults="$run_dir/update-epoch.defaults"
defaults='sdkconfig.defaults;sdkconfig.qemu.defaults;sdkconfig.security-preprovisioned.defaults;sdkconfig.secure-ota.defaults'
provision_dir=build-provisioning
signing_key="$provision_dir/secure_boot_signing_key.pem"
xts_key="$provision_dir/flash_encryption_key.bin"

fail() {
    echo "hardware-rehearsal-qemu: $*" >&2
    exit 1
}

cleanup() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    if [[ "${KEEP_REHEARSAL_ARTIFACTS:-0}" == 1 ]]; then
        echo "hardware-rehearsal-qemu: retained $run_dir" >&2
    else
        rm -rf "$run_dir"
    fi
}
trap cleanup EXIT
mkdir -p "$run_dir"

[[ -n "${IDF_PATH:-}" ]] || fail 'IDF_PATH is not set; activate ESP-IDF 5.5 first'
for command in idf.py openssl strings ss; do
    command -v "$command" >/dev/null || fail "$command not found"
done
for file in \
    "$provision_dir/manifest.json" \
    "$provision_dir/secure_boot_digest.bin" \
    "$signing_key" \
    "$xts_key" \
    "$provision_dir/mkek.bin" \
    "$provision_dir/device_key_secp256k1.bin"; do
    [[ -f "$file" ]] || fail "missing provisioning artifact: $file"
done
./tools/esp32s3_provision.py verify "$provision_dir/manifest.json" >/dev/null

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
    local name=$1 build=$2 sdkconfig=$3 version=$4 epoch=$5 epoch_defaults=$6
    printf 'CONFIG_PICO_FIDO2_SECURITY_VERSION=%s\n' "$epoch" >"$epoch_defaults"
    SDKCONFIG_DEFAULTS="${defaults};${epoch_defaults}" \
        idf.py -B "$build" -DSDKCONFIG="$sdkconfig" -DPROJECT_VER="$version" \
        set-target esp32s3 >/dev/null
    SDKCONFIG_DEFAULTS="${defaults};${epoch_defaults}" \
        idf.py -B "$build" -DSDKCONFIG="$sdkconfig" -DPROJECT_VER="$version" \
        build >/dev/null

    for expected in \
        CONFIG_PICO_FIDO2_QEMU=y \
        CONFIG_PICOKEYS_ESP32_REQUIRE_PROVISIONED_KEYS=y \
        CONFIG_PICO_FIDO2_AB_OTA=y \
        CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y \
        CONFIG_SECURE_BOOT=y \
        CONFIG_SECURE_BOOT_V2_ENABLED=y \
        CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y \
        CONFIG_SECURE_FLASH_ENC_ENABLED=y \
        CONFIG_SECURE_FLASH_ENCRYPTION_AES128=y \
        CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y \
        CONFIG_SECURE_FLASH_REQUIRE_ALREADY_ENABLED=y \
        CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC=y \
        CONFIG_SECURE_BOOT_ALLOW_JTAG=y \
        CONFIG_PARTITION_TABLE_OFFSET=0x10000 \
        CONFIG_PICO_FIDO2_SECURITY_VERSION=${epoch}; do
        grep -qx "$expected" "$sdkconfig" || fail "$name missing config: $expected"
    done
    grep -qx 'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="pico-keys-sdk/config/esp32/partitions-secure-ota.csv"' "$sdkconfig" \
        || fail "$name did not select the secure A/B partition table"
    if grep -qx 'CONFIG_PICOKEYS_ESP32_DEV_KEYS=y' "$sdkconfig" || \
       grep -qx 'CONFIG_PICO_FIDO2_BLE=y' "$sdkconfig" || \
       grep -qx 'CONFIG_PICO_FIDO2_WIFI_COMMISSIONING=y' "$sdkconfig" || \
       grep -qx 'CONFIG_NVS_ENCRYPTION=y' "$sdkconfig" || \
       grep -qx 'CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y' "$sdkconfig" || \
       grep -qx 'CONFIG_PICO_FIDO2_SINGLE_SLOT_ANTI_ROLLBACK=y' "$sdkconfig"; then
        fail "$name rehearsal profile leaked dev keys/radio hardware/NVS encryption/anti-rollback"
    fi
    python -m espsecure verify_signature --version 2 --keyfile "$signing_key" \
        "$build/bootloader/bootloader.bin" >/dev/null
    python -m espsecure verify_signature --version 2 --keyfile "$signing_key" \
        "$build/pico_fido2.bin" >/dev/null
}

build_version base "$base_build" "$base_sdkconfig" 7.4.0 0 "$base_epoch_defaults"
build_version update "$update_build" "$update_sdkconfig" 7.4.1 1 "$update_epoch_defaults"

encrypt_region() {
    local address=$1 plain=$2 cipher=$3
    python -m espsecure encrypt_flash_data --aes_xts --keyfile "$xts_key" \
        --address "$address" --output "$cipher" "$plain" >/dev/null
}

python3 - "$run_dir/ota1-plain.bin" "$run_dir/part0-plain.bin" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(b'\xff' * 0x170000)
Path(sys.argv[2]).write_bytes(b'\xff' * 0x100000)
PY

encrypt_region 0x000000 "$base_build/bootloader/bootloader.bin" "$run_dir/bootloader.enc"
encrypt_region 0x010000 "$base_build/partition_table/partition-table.bin" "$run_dir/partition.enc"
encrypt_region 0x018000 "$base_build/ota_data_initial.bin" "$run_dir/otadata.enc"
encrypt_region 0x020000 "$base_build/pico_fido2.bin" "$run_dir/ota0.enc"
encrypt_region 0x190000 "$run_dir/ota1-plain.bin" "$run_dir/ota1.enc"
encrypt_region 0x300000 "$run_dir/part0-plain.bin" "$run_dir/part0.enc"

python3 - "$run_dir/baseline.bin" \
    "$run_dir/bootloader.enc" "$run_dir/partition.enc" "$run_dir/otadata.enc" \
    "$run_dir/ota0.enc" "$run_dir/ota1.enc" "$run_dir/part0.enc" <<'PY'
from pathlib import Path
import sys
out = bytearray(b'\xff' * 0x400000)
regions = [
    (0x000000, Path(sys.argv[2])),
    (0x010000, Path(sys.argv[3])),
    (0x018000, Path(sys.argv[4])),
    (0x020000, Path(sys.argv[5])),
    (0x190000, Path(sys.argv[6])),
    (0x300000, Path(sys.argv[7])),
]
for offset, path in regions:
    data = path.read_bytes()
    out[offset:offset + len(data)] = data
Path(sys.argv[1]).write_bytes(out)
PY
[[ "$(stat -c %s "$run_dir/baseline.bin")" -eq 4194304 ]] || fail 'baseline is not 4 MiB'

python3 - "$run_dir/efuse.bin" "$run_dir/flash.bin" <<'PY'
from pathlib import Path
import sys
b = bytearray(1024)
b[38] = 0x0c
Path(sys.argv[1]).write_bytes(b)
Path(sys.argv[2]).write_bytes(b'\xff' * 0x400000)
PY

free_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
}

start_rom() {
    local flash=$1 efuse=$2 log=$3
    qemu_port="$(free_port)"
    qemu_url="socket://127.0.0.1:${qemu_port}"
    "$qemu" -M esp32s3 \
        -drive file="$flash",if=mtd,format=raw \
        -drive file="$efuse",if=none,format=raw,id=efuse \
        -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
        -global driver=esp32s3.gpio,property=strap_mode,value=0x07 \
        -nographic -serial "tcp::${qemu_port},server,nowait" >"$log" 2>&1 &
    qemu_pid=$!
    local ready=false
    for _ in $(seq 1 300); do
        if ss -ltn | grep -E ":${qemu_port}[[:space:]]" >/dev/null; then
            ready=true
            break
        fi
        sleep 0.02
    done
    [[ "$ready" == true ]] || fail 'QEMU ROM serial socket did not open'
}

start_boot() {
    local flash=$1 efuse=$2 log=$3
    "$qemu" -M esp32s3 \
        -drive file="$flash",if=mtd,format=raw \
        -drive file="$efuse",if=none,format=raw,id=efuse \
        -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
        -nic none -nographic -serial mon:stdio >"$log" 2>&1 &
    qemu_pid=$!
}

stop_qemu() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    qemu_pid=""
}

wait_strings() {
    local log=$1 pattern=$2 loops=$3 description=$4
    for _ in $(seq 1 "$loops"); do
        if strings -a "$log" | grep -qE "$pattern"; then
            return 0
        fi
        if [[ -n "$qemu_pid" ]] && ! kill -0 "$qemu_pid" 2>/dev/null; then
            wait "$qemu_pid" || true
            qemu_pid=""
            strings -a "$log" | tail -120 >&2 || true
            fail "QEMU exited before $description"
        fi
        sleep 0.05
    done
    strings -a "$log" | grep -E 'App version:|OTA image|secure|flash|assert|panic|abort|Required ESP32' | tail -120 >&2 || true
    fail "timed out waiting for $description"
}

assert_recovery_summary() {
    local summary=$1 stage=$2
    grep -Fq 'Set this bit to disable download mode (boot_mode[3 = False' "$summary" \
        || fail "$stage disabled ROM download mode"
    grep -Fq 'Set this bit to disable UART download mode through = False' "$summary" \
        || fail "$stage disabled USB Serial/JTAG ROM download mode"
    grep -Fq 'Set this bit to disable JTAG in the hard way. JTAG = False' "$summary" \
        || fail "$stage disabled pad JTAG"
    grep -Fq 'Set this bit to disable function of usb switch to  = False' "$summary" \
        || fail "$stage disabled USB JTAG"
    grep -Fq 'Secure version (used by ESP-IDF anti-rollback feat = 0' "$summary" \
        || fail "$stage changed SECURE_VERSION"
}

assert_key_layout() {
    local summary=$1
    grep -Fq 'Purpose of Key0                                    = SECURE_BOOT_DIGEST0' "$summary" || fail 'KEY0 purpose mismatch'
    grep -Fq 'Purpose of Key1                                    = XTS_AES_128_KEY' "$summary" || fail 'KEY1 purpose mismatch'
    grep -Fq 'Purpose of Key3                                    = USER' "$summary" || fail 'KEY3 purpose mismatch'
    grep -Fq 'Purpose of Key4                                    = USER' "$summary" || fail 'KEY4 purpose mismatch'
}

assert_otadata() {
    local flash=$1 slot=$2 seq=$3 state=$4
    dd if="$flash" of="$run_dir/otadata-check.enc" bs=1 skip=$((0x18000)) count=$((0x2000)) status=none
    python -m espsecure decrypt_flash_data --aes_xts --keyfile "$xts_key" \
        --address 0x18000 --output "$run_dir/otadata-check.plain" "$run_dir/otadata-check.enc" >/dev/null
    python3 - "$run_dir/otadata-check.plain" "$slot" "$seq" "$state" <<'PY'
from pathlib import Path
import binascii, struct, sys
data = Path(sys.argv[1]).read_bytes()
slot = int(sys.argv[2])
expected_seq = int(sys.argv[3])
expected_state = int(sys.argv[4])
entry = data[slot * 0x1000:slot * 0x1000 + 32]
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

make_trial_flash() {
    local source=$1 output=$2
    cp "$source" "$output"
    encrypt_region 0x190000 "$update_build/pico_fido2.bin" "$run_dir/update.enc"
    dd if="$run_dir/update.enc" of="$output" bs=1 seek=$((0x190000)) conv=notrunc status=none

    dd if="$source" of="$run_dir/otadata-current.enc" bs=1 skip=$((0x18000)) count=$((0x2000)) status=none
    python -m espsecure decrypt_flash_data --aes_xts --keyfile "$xts_key" \
        --address 0x18000 --output "$run_dir/otadata-new.plain" "$run_dir/otadata-current.enc" >/dev/null
    python3 - "$run_dir/otadata-new.plain" <<'PY'
from pathlib import Path
import binascii, struct, sys
p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
offset = 0x1000
data[offset:offset + 0x1000] = b'\xff' * 0x1000
entry = bytearray(b'\xff' * 32)
seq = 2
struct.pack_into('<I', entry, 0, seq)
struct.pack_into('<I', entry, 24, 0)
struct.pack_into('<I', entry, 28, binascii.crc32(struct.pack('<I', seq), 0xFFFFFFFF) & 0xFFFFFFFF)
data[offset:offset + 32] = entry
p.write_bytes(data)
PY
    encrypt_region 0x18000 "$run_dir/otadata-new.plain" "$run_dir/otadata-new.enc"
    dd if="$run_dir/otadata-new.enc" of="$output" bs=1 seek=$((0x18000)) conv=notrunc status=none
}

start_rom "$run_dir/flash.bin" "$run_dir/efuse.bin" "$run_dir/preflight-rom.log"
python -m esptool --chip esp32s3 --port "$qemu_url" --before no_reset --after no_reset --no-stub chip_id \
    >"$run_dir/chip-id.txt"
grep -Fq 'MAC: 00:00:00:00:00:00' "$run_dir/chip-id.txt" || fail 'unexpected QEMU factory MAC'
python -m espefuse --chip esp32s3 --port "$qemu_url" --before no_reset summary >"$run_dir/preflight.txt"
assert_recovery_summary "$run_dir/preflight.txt" preflight
grep -Fq 'Enables flash encryption when 1 or 3 bits are set  = Disable' "$run_dir/preflight.txt" || fail 'Flash Encryption already enabled at preflight'
grep -Fq 'Set this bit to enable secure boot                 = False' "$run_dir/preflight.txt" || fail 'Secure Boot already enabled at preflight'

python -m espefuse --chip esp32s3 --port "$qemu_url" --before no_reset --do-not-confirm burn_key \
    BLOCK_KEY0 "$provision_dir/secure_boot_digest.bin" SECURE_BOOT_DIGEST0 \
    BLOCK_KEY1 "$xts_key" XTS_AES_128_KEY \
    BLOCK_KEY3 "$provision_dir/mkek.bin" USER \
    BLOCK_KEY4 "$provision_dir/device_key_secp256k1.bin" USER >/dev/null
python -m espefuse --chip esp32s3 --port "$qemu_url" --before no_reset summary >"$run_dir/keys.txt"
assert_recovery_summary "$run_dir/keys.txt" key-provisioning
assert_key_layout "$run_dir/keys.txt"

# QEMU's flasher stub drops large transfers and ROM no-stub full-flash writes
# are prohibitively slow. Exercise a real ROM write/readback on one 4 KiB
# chunk, then stage the complete already-verified 4 MiB backing file directly.
head -c 4096 "$run_dir/bootloader.enc" >"$run_dir/rom-write-probe.bin"
python -m esptool --chip esp32s3 --port "$qemu_url" --before no_reset --after no_reset \
    --no-stub write_flash 0x0 "$run_dir/rom-write-probe.bin" >/dev/null
python -m esptool --chip esp32s3 --port "$qemu_url" --before no_reset --after no_reset \
    --no-stub read_flash 0x0 0x1000 "$run_dir/rom-read-probe.bin" >/dev/null
cmp "$run_dir/rom-write-probe.bin" "$run_dir/rom-read-probe.bin" || fail 'ROM write/readback probe mismatch'
stop_qemu

cp "$run_dir/baseline.bin" "$run_dir/flash.bin"
cmp "$run_dir/baseline.bin" "$run_dir/flash.bin" || fail 'QEMU baseline staging mismatch'

start_rom "$run_dir/flash.bin" "$run_dir/efuse.bin" "$run_dir/activate-rom.log"
python -m espefuse --chip esp32s3 --port "$qemu_url" --before no_reset --do-not-confirm \
    burn_efuse SPI_BOOT_CRYPT_CNT 0x1 >/dev/null
python -m espefuse --chip esp32s3 --port "$qemu_url" --before no_reset summary >"$run_dir/after-flash-encryption.txt"
assert_recovery_summary "$run_dir/after-flash-encryption.txt" flash-encryption
assert_key_layout "$run_dir/after-flash-encryption.txt"
grep -Fq 'Enables flash encryption when 1 or 3 bits are set  = Enable' "$run_dir/after-flash-encryption.txt" || fail 'Flash Encryption activation failed'
grep -Fq 'Set this bit to enable secure boot                 = False' "$run_dir/after-flash-encryption.txt" || fail 'Secure Boot changed before its final step'

python -m espefuse --chip esp32s3 --port "$qemu_url" --before no_reset --do-not-confirm \
    burn_efuse SECURE_BOOT_EN 1 >/dev/null
python -m espefuse --chip esp32s3 --port "$qemu_url" --before no_reset summary >"$run_dir/secured.txt"
assert_recovery_summary "$run_dir/secured.txt" secure-boot
assert_key_layout "$run_dir/secured.txt"
grep -Fq 'Set this bit to enable secure boot                 = True' "$run_dir/secured.txt" || fail 'Secure Boot activation failed'
grep -Fq 'Enables flash encryption when 1 or 3 bits are set  = Enable' "$run_dir/secured.txt" || fail 'Flash Encryption did not remain enabled'
stop_qemu

secured_efuse_sha="$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')"

start_boot "$run_dir/flash.bin" "$run_dir/efuse.bin" "$run_dir/baseline-boot.log"
wait_strings "$run_dir/baseline-boot.log" 'App version:.*7\.4\.0' 800 'secured ota_0 baseline'
wait_strings "$run_dir/baseline-boot.log" 'main_task: Returned from app_main\(\)' 800 'secured baseline app_main completion'
stop_qemu
[[ "$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')" == "$secured_efuse_sha" ]] || fail 'baseline boot changed eFuses'
assert_otadata "$run_dir/flash.bin" 0 1 2

make_trial_flash "$run_dir/flash.bin" "$run_dir/trial-template.bin"
assert_otadata "$run_dir/trial-template.bin" 1 2 0

cp "$run_dir/trial-template.bin" "$run_dir/rollback.bin"
cp "$run_dir/efuse.bin" "$run_dir/rollback-efuse.bin"
start_boot "$run_dir/rollback.bin" "$run_dir/rollback-efuse.bin" "$run_dir/rollback-first.log"
wait_strings "$run_dir/rollback-first.log" 'App version:.*7\.4\.1' 800 'secured ota_1 trial'
wait_strings "$run_dir/rollback-first.log" 'OTA image pending verification; delaying confirmation for 5 seconds' 800 'secured PENDING_VERIFY state'
stop_qemu
assert_otadata "$run_dir/rollback.bin" 1 2 1

start_boot "$run_dir/rollback.bin" "$run_dir/rollback-efuse.bin" "$run_dir/rollback-second.log"
wait_strings "$run_dir/rollback-second.log" 'App version:.*7\.4\.0' 800 'secured rollback to ota_0'
wait_strings "$run_dir/rollback-second.log" 'main_task: Returned from app_main\(\)' 800 'rolled-back app completion'
stop_qemu
assert_otadata "$run_dir/rollback.bin" 0 1 2
assert_otadata "$run_dir/rollback.bin" 1 2 4
[[ "$(sha256sum "$run_dir/rollback-efuse.bin" | awk '{print $1}')" == "$secured_efuse_sha" ]] || fail 'rollback changed eFuses'

cp "$run_dir/trial-template.bin" "$run_dir/confirm.bin"
cp "$run_dir/efuse.bin" "$run_dir/confirm-efuse.bin"
start_boot "$run_dir/confirm.bin" "$run_dir/confirm-efuse.bin" "$run_dir/confirm-first.log"
wait_strings "$run_dir/confirm-first.log" 'App version:.*7\.4\.1' 800 'secured ota_1 confirmation trial'
wait_strings "$run_dir/confirm-first.log" 'OTA image confirmed after service-loop stability window' 260 'secured ota_1 confirmation'
stop_qemu
assert_otadata "$run_dir/confirm.bin" 1 2 2

start_boot "$run_dir/confirm.bin" "$run_dir/confirm-efuse.bin" "$run_dir/confirm-second.log"
wait_strings "$run_dir/confirm-second.log" 'App version:.*7\.4\.1' 800 'confirmed secured ota_1 reboot'
wait_strings "$run_dir/confirm-second.log" 'main_task: Returned from app_main\(\)' 800 'confirmed ota_1 app completion'
stop_qemu
assert_otadata "$run_dir/confirm.bin" 1 2 2
[[ "$(sha256sum "$run_dir/confirm-efuse.bin" | awk '{print $1}')" == "$secured_efuse_sha" ]] || fail 'confirmed OTA changed eFuses'

cp "$run_dir/flash.bin" "$run_dir/rom-rescue.bin"
cp "$run_dir/efuse.bin" "$run_dir/rom-rescue-efuse.bin"
start_rom "$run_dir/rom-rescue.bin" "$run_dir/rom-rescue-efuse.bin" "$run_dir/recovery-write-rom.log"
python -m esptool --chip esp32s3 --port "$qemu_url" --before no_reset --after no_reset \
    --no-stub get_security_info >"$run_dir/security-info.txt"
python -m espefuse --chip esp32s3 --port "$qemu_url" --before no_reset summary >"$run_dir/recovery-summary.txt"
assert_recovery_summary "$run_dir/recovery-summary.txt" final-recovery
grep -Fq 'Set this bit to enable secure boot                 = True' "$run_dir/recovery-summary.txt" || fail 'Secure Boot not enabled during recovery drill'
grep -Fq 'Enables flash encryption when 1 or 3 bits are set  = Enable' "$run_dir/recovery-summary.txt" || fail 'Flash Encryption not enabled during recovery drill'
recovery_efuse_before="$(sha256sum "$run_dir/rom-rescue-efuse.bin" | awk '{print $1}')"
encrypt_region 0x20000 "$update_build/pico_fido2.bin" "$run_dir/recovery-update.enc"
python -m esptool --chip esp32s3 --port "$qemu_url" --before no_reset --after no_reset \
    --no-stub write_flash --force 0x20000 "$run_dir/recovery-update.enc" \
    >"$run_dir/recovery-write.txt"
[[ "$(sha256sum "$run_dir/rom-rescue-efuse.bin" | awk '{print $1}')" == "$recovery_efuse_before" ]] \
    || fail 'ROM rescue write changed eFuses'
stop_qemu

dd if="$run_dir/rom-rescue.bin" of="$run_dir/recovery-update-readback.enc" \
    bs=1 skip=$((0x20000)) count="$(stat -c %s "$run_dir/recovery-update.enc")" status=none
cmp "$run_dir/recovery-update.enc" "$run_dir/recovery-update-readback.enc" \
    || fail 'ROM rescue ciphertext readback mismatch'
python -m espsecure decrypt_flash_data --aes_xts --keyfile "$xts_key" --address 0x20000 \
    --output "$run_dir/recovery-update-readback.plain" "$run_dir/recovery-update-readback.enc" >/dev/null
cmp "$update_build/pico_fido2.bin" "$run_dir/recovery-update-readback.plain" \
    || fail 'ROM rescue ciphertext does not decrypt to the signed update'

start_boot "$run_dir/rom-rescue.bin" "$run_dir/rom-rescue-efuse.bin" "$run_dir/recovery-boot.log"
wait_strings "$run_dir/recovery-boot.log" 'App version:.*7\.4\.1' 800 'ROM-rescued signed ota_0 image'
wait_strings "$run_dir/recovery-boot.log" 'main_task: Returned from app_main\(\)' 800 'ROM-rescued app completion'
stop_qemu
[[ "$(sha256sum "$run_dir/rom-rescue-efuse.bin" | awk '{print $1}')" == "$secured_efuse_sha" ]] \
    || fail 'ROM rescue boot changed eFuses'

printf 'ESP32-S3 hardware-operation rehearsal in QEMU: PASS (%s)\n' "$($qemu --version | head -1)"
printf 'physical-device access path in this script: NONE\n'
printf 'blank ROM preflight + factory MAC read: PASS\n'
printf 'KEY0/KEY1/KEY3/KEY4 burn through real ROM protocol: PASS\n'
printf 'QEMU ROM write/readback probe: PASS\n'
printf 'pre-encrypted 4 MiB baseline staging/equality: PASS (QEMU backing-file workaround)\n'
printf 'Flash Encryption -> readback checkpoint -> Secure Boot: PASS\n'
printf 'ROM download recovery preserved: PASS\n'
printf 'USB Serial/JTAG ROM recovery preserved: PASS\n'
printf 'pad/USB JTAG preserved: PASS\n'
printf 'SECURE_VERSION remained 0: PASS\n'
printf 'provisioned KEY3/KEY4 root-key application boot: PASS\n'
printf 'secured ota_0 baseline -> VALID: PASS\n'
printf 'secured ota_1 NEW -> PENDING_VERIFY: PASS\n'
printf 'power loss -> ABORTED -> ota_0 rollback: PASS\n'
printf 'stable trial -> VALID -> ota_1 reboot: PASS\n'
printf 'eFuse unchanged across both OTA paths: %s\n' "$secured_efuse_sha"
printf 'post-security ROM recovery read/control plane: PASS\n'
printf 'post-security host-preencrypted ROM signed-app rescue write + boot: PASS\n'
printf 'anti-rollback eFuse touched: NO\n'
printf 'No physical device was accessed.\n'
