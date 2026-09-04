#!/usr/bin/env bash
set -euo pipefail

base_build=build-security-rom-base
update_build=build-security-rom-update
base_sdkconfig=sdkconfig.security-rom-base
update_sdkconfig=sdkconfig.security-rom-update
secrets_dir=build-security-secrets
defaults='sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.qemu.defaults;sdkconfig.security-qemu.defaults'
run_dir="${TMPDIR:-/tmp}/pico-fido2-rom-update-qemu-$$"
qemu_pid=""

fail() {
    echo "rom-update-qemu: $*" >&2
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
command -v openssl >/dev/null || fail 'openssl not found'

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

rm -rf "$base_build" "$update_build" "$secrets_dir"
rm -f "$base_sdkconfig" "$base_sdkconfig.old" "$update_sdkconfig" "$update_sdkconfig.old"
mkdir -p "$secrets_dir"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$secrets_dir/secure_boot_signing_key.pem" >/dev/null 2>&1

build_version() {
    local build_dir=$1 sdkconfig=$2 version=$3
    SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" \
        -DPROJECT_VER="$version" set-target esp32s3 >/dev/null
    SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" \
        -DPROJECT_VER="$version" build >/dev/null
    grep -qx 'CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC=y' "$sdkconfig" \
        || fail 'encrypted ROM download is not enabled'
    grep -qx 'CONFIG_SECURE_BOOT_V2_ENABLED=y' "$sdkconfig" || fail 'Secure Boot v2 missing'
    python -m espsecure verify_signature --version 2 \
        --keyfile "$secrets_dir/secure_boot_signing_key.pem" "$build_dir/pico_fido2.bin" >/dev/null
}

build_version "$base_build" "$base_sdkconfig" 7.4.0
build_version "$update_build" "$update_sdkconfig" 7.4.1

base_sha="$(sha256sum "$base_build/pico_fido2.bin" | awk '{print $1}')"
update_sha="$(sha256sum "$update_build/pico_fido2.bin" | awk '{print $1}')"
[[ "$base_sha" != "$update_sha" ]] || fail 'base and update app images are identical'

python -m esptool --chip esp32s3 merge_bin \
    --output "$run_dir/flash.bin" --fill-flash-size 4MB \
    --flash_mode dio --flash_freq 40m --flash_size 4MB \
    0x0 "$base_build/bootloader/bootloader.bin" \
    0x10000 "$base_build/partition_table/partition-table.bin" \
    0x20000 "$base_build/pico_fido2.bin" >/dev/null
python3 - "$run_dir/efuse.bin" <<'PY'
from pathlib import Path
import sys
b = bytearray(1024)
b[38] = 0x0c
Path(sys.argv[1]).write_bytes(b)
PY

"$qemu" -M esp32s3 \
    -drive file="$run_dir/flash.bin",if=mtd,format=raw \
    -drive file="$run_dir/efuse.bin",if=none,format=raw,id=efuse \
    -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
    -nic none -nographic -serial mon:stdio >"$run_dir/transition.log" 2>&1 &
qemu_pid=$!

transitioned=false
for _ in $(seq 1 1200); do
    if grep -aq 'Resetting with flash encryption enabled' "$run_dir/transition.log"; then
        transitioned=true
        break
    fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        wait "$qemu_pid" || rc=$?
        tail -160 "$run_dir/transition.log" >&2
        fail "QEMU exited before security transition: ${rc:-0}"
    fi
    sleep 0.05
done
[[ "$transitioned" == true ]] || { tail -160 "$run_dir/transition.log" >&2; fail 'security transition timed out'; }
kill "$qemu_pid" 2>/dev/null || true
wait "$qemu_pid" 2>/dev/null || true
qemu_pid=""

for marker in \
    'Secure boot permanently enabled' \
    'Generating new flash encryption key' \
    'Flash encryption completed'; do
    grep -aq "$marker" "$run_dir/transition.log" || fail "missing transition marker: $marker"
done

port="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
)"
"$qemu" -M esp32s3 \
    -drive file="$run_dir/flash.bin",if=mtd,format=raw \
    -drive file="$run_dir/efuse.bin",if=none,format=raw,id=efuse \
    -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
    -global driver=esp32s3.gpio,property=strap_mode,value=0x07 \
    -nographic -serial "tcp::${port},server,nowait" >"$run_dir/download.log" 2>&1 &
qemu_pid=$!

ready=false
for _ in $(seq 1 200); do
    if ss -ltn | grep -E ":${port}[[:space:]]" >/dev/null; then
        ready=true
        break
    fi
    sleep 0.02
done
[[ "$ready" == true ]] || fail 'ROM download serial port did not open after security transition'
port_url="socket://127.0.0.1:${port}"

python -m esptool --chip esp32s3 --port "$port_url" --before no_reset --after no_reset \
    --no-stub get_security_info >"$run_dir/security-before.txt"
python -m espefuse --chip esp32s3 --port "$port_url" --before no_reset summary \
    >"$run_dir/efuse-before.txt"

grep -Fq 'Set this bit to enable secure boot                 = True' "$run_dir/efuse-before.txt" \
    || fail 'Secure Boot is not enabled before update'
grep -Fq 'Enables flash encryption when 1 or 3 bits are set  = Enable' "$run_dir/efuse-before.txt" \
    || fail 'Flash Encryption is not enabled before update'
grep -Fq 'Set this bit to disable UART download mode through = False' "$run_dir/efuse-before.txt" \
    || fail 'USB Serial/JTAG download mode was disabled'

efuse_before="$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')"
flash_before="$(sha256sum "$run_dir/flash.bin" | awk '{print $1}')"
python3 - "$run_dir/flash.bin" "$run_dir/regions-before.json" <<'PYREGION'
from pathlib import Path
import hashlib, json, sys
image = Path(sys.argv[1]).read_bytes()
regions = {
    'bootloader': (0x000000, 0x010000),
    'partition': (0x010000, 0x020000),
    'part0': (0x200000, 0x300000),
}
out = {name: hashlib.sha256(image[start:end]).hexdigest() for name, (start, end) in regions.items()}
Path(sys.argv[2]).write_text(json.dumps(out, sort_keys=True) + '\n')
PYREGION

python -m esptool --chip esp32s3 --port "$port_url" --before no_reset --after no_reset \
    --no-stub write_flash --encrypt 0x20000 "$update_build/pico_fido2.bin" \
    >"$run_dir/write-update.txt"

efuse_after="$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')"
flash_after="$(sha256sum "$run_dir/flash.bin" | awk '{print $1}')"
[[ "$efuse_before" == "$efuse_after" ]] || fail 'ROM update unexpectedly changed eFuses'
[[ "$flash_before" != "$flash_after" ]] || fail 'ROM update did not change flash'
python3 - "$run_dir/flash.bin" "$run_dir/regions-before.json" <<'PYREGION'
from pathlib import Path
import hashlib, json, sys
image = Path(sys.argv[1]).read_bytes()
before = json.loads(Path(sys.argv[2]).read_text())
regions = {
    'bootloader': (0x000000, 0x010000),
    'partition': (0x010000, 0x020000),
    'part0': (0x200000, 0x300000),
}
for name, (start, end) in regions.items():
    after = hashlib.sha256(image[start:end]).hexdigest()
    if after != before[name]:
        raise SystemExit(f'{name} changed across app-only update')
print('bootloader/partition/part0 unchanged across update')
PYREGION

python -m espefuse --chip esp32s3 --port "$port_url" --before no_reset summary \
    >"$run_dir/efuse-after.txt"
cmp "$run_dir/efuse-before.txt" "$run_dir/efuse-after.txt" >/dev/null \
    || fail 'eFuse summary changed across app update'

# The encrypted write must not leave the signed plaintext image directly in flash.
python3 - "$run_dir/flash.bin" "$update_build/pico_fido2.bin" <<'PY'
from pathlib import Path
import sys
flash = Path(sys.argv[1]).read_bytes()
plain = Path(sys.argv[2]).read_bytes()
offset = 0x20000
if flash[offset:offset + len(plain)] == plain:
    raise SystemExit('update was written as plaintext')
print(f'encrypted ROM write changed app region: {len(plain)} bytes')
PY

printf 'ESP32-S3 secured ROM update: PASS (%s)\n' "$($qemu --version | head -1)"
printf 'Base app: %s\n' "$base_sha"
printf 'Update app: %s\n' "$update_sha"
printf 'Flash changed: %s -> %s\n' "$flash_before" "$flash_after"
printf 'eFuse unchanged: %s\n' "$efuse_after"
printf 'Secure Boot remained enabled: PASS\n'
printf 'Flash Encryption remained enabled: PASS\n'
printf 'USB Serial/JTAG download-disable eFuse remained clear: PASS\n'
printf 'No physical device was accessed.\n'
