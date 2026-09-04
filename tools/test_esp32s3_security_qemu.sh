#!/usr/bin/env bash
set -euo pipefail

build_dir=build-security-qemu
secrets_dir=build-security-secrets
sdkconfig=sdkconfig.security-qemu
defaults='sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.qemu.defaults;sdkconfig.security-qemu.defaults'
run_dir="${TMPDIR:-/tmp}/pico-fido2-security-qemu-$$"
qemu_pid=""

die() {
    echo "security-qemu: $*" >&2
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

[[ -n "${IDF_PATH:-}" ]] || die 'IDF_PATH is not set; activate ESP-IDF 5.5 first'
command -v idf.py >/dev/null || die 'idf.py not found'
command -v openssl >/dev/null || die 'openssl not found'

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

qemu="$(find_esp_qemu)" || die 'Espressif QEMU with esp32s3 machine support was not found'

rm -rf "$build_dir" "$secrets_dir"
rm -f "$sdkconfig" "$sdkconfig.old"
mkdir -p "$secrets_dir"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$secrets_dir/secure_boot_signing_key.pem" >/dev/null 2>&1

SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" set-target esp32s3 >/dev/null
SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" build >/dev/null

for expected in \
    CONFIG_PICO_FIDO2_QEMU=y \
    CONFIG_PICOKEYS_ESP32_DEV_KEYS=y \
    CONFIG_SECURE_BOOT=y \
    CONFIG_SECURE_BOOT_V2_ENABLED=y \
    CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y \
    CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y \
    CONFIG_SECURE_FLASH_ENC_ENABLED=y \
    CONFIG_SECURE_FLASH_ENCRYPTION_AES128=y \
    CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y \
    CONFIG_SECURE_BOOT_ALLOW_JTAG=y \
    CONFIG_PARTITION_TABLE_OFFSET=0x10000; do
    grep -qx "$expected" "$sdkconfig" || die "missing config: $expected"
done

grep -qx 'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="pico-keys-sdk/config/esp32/partitions-secure.csv"' "$sdkconfig" \
    || die 'secure partition table is not selected'

key="$secrets_dir/secure_boot_signing_key.pem"
python -m espsecure verify_signature --version 2 --keyfile "$key" "$build_dir/bootloader/bootloader.bin" >/dev/null
python -m espsecure verify_signature --version 2 --keyfile "$key" "$build_dir/pico_fido2.bin" >/dev/null

cp "$build_dir/pico_fido2.bin" "$run_dir/tampered-app.bin"
python3 - "$run_dir/tampered-app.bin" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
data[0x100] ^= 1
p.write_bytes(data)
PY
if python -m espsecure verify_signature --version 2 --keyfile "$key" "$run_dir/tampered-app.bin" >/dev/null 2>&1; then
    die 'tampered signed application still verifies'
fi

python -m esptool --chip esp32s3 merge_bin \
    --output "$run_dir/flash.bin" --fill-flash-size 4MB \
    --flash_mode dio --flash_freq 40m --flash_size 4MB \
    0x0 "$build_dir/bootloader/bootloader.bin" \
    0x10000 "$build_dir/partition_table/partition-table.bin" \
    0x20000 "$build_dir/pico_fido2.bin" >/dev/null

# Espressif's QEMU default ESP32-S3 eFuse image is otherwise blank and carries
# revision v0.3 in byte 38. Secure Boot is not reliable in the rev0.0 QEMU ROM.
python3 - "$run_dir/efuse.bin" <<'PY'
from pathlib import Path
import sys
data = bytearray(1024)
data[38] = 0x0c
Path(sys.argv[1]).write_bytes(data)
PY

flash_before="$(sha256sum "$run_dir/flash.bin" | awk '{print $1}')"
efuse_before="$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')"

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
        die "QEMU exited before security transition completed: ${rc:-0}"
    fi
    sleep 0.05
done
[[ "$transitioned" == true ]] || { tail -160 "$run_dir/transition.log" >&2; die 'security transition timed out'; }

for marker in \
    'Signature verified successfully' \
    'Secure boot permanently enabled' \
    'Generating new flash encryption key' \
    'bootloader encrypted successfully' \
    'partition table encrypted and loaded successfully' \
    'Encrypting partition 3 at offset 0x200000' \
    'Flash encryption completed'; do
    grep -aq "$marker" "$run_dir/transition.log" || die "missing transition marker: $marker"
done

kill "$qemu_pid" 2>/dev/null || true
wait "$qemu_pid" 2>/dev/null || true
qemu_pid=""

flash_after="$(sha256sum "$run_dir/flash.bin" | awk '{print $1}')"
efuse_after="$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')"
[[ "$flash_before" != "$flash_after" ]] || die 'flash image did not change during encryption'
[[ "$efuse_before" != "$efuse_after" ]] || die 'eFuse image did not change during security transition'

# part0 starts as erased flash. The encrypted partition must not remain all FF.
python3 - "$run_dir/flash.bin" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
data = p.read_bytes()[0x200000:0x300000]
if len(data) != 0x100000 or all(b == 0xFF for b in data):
    raise SystemExit('part0 was not encrypted')
PY

# Read the mutated eFuses through the emulated ROM. This validates QEMU's 1 KiB
# backing format rather than trying to decode it as espefuse --virt storage.
port="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
)"
"$qemu" -M esp32s3 \
    -drive file="$run_dir/efuse.bin",if=none,format=raw,id=efuse \
    -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
    -global driver=esp32s3.gpio,property=strap_mode,value=0x07 \
    -nographic -serial "tcp::${port},server,nowait" >"$run_dir/efuse-rom.log" 2>&1 &
qemu_pid=$!

serial_ready=false
for _ in $(seq 1 200); do
    if ss -ltn | grep -E ":${port}[[:space:]]" >/dev/null; then
        serial_ready=true
        break
    fi
    sleep 0.02
done
[[ "$serial_ready" == true ]] || die 'virtual ROM serial port did not open'

python -m espefuse --chip esp32s3 --port "socket://127.0.0.1:${port}" --before no_reset summary \
    >"$run_dir/efuse-summary.txt"
kill "$qemu_pid" 2>/dev/null || true
wait "$qemu_pid" 2>/dev/null || true
qemu_pid=""

for marker in \
    'Purpose of Key0                                    = SECURE_BOOT_DIGEST0' \
    'Purpose of Key1                                    = XTS_AES_128_KEY' \
    'Enables flash encryption when 1 or 3 bits are set  = Enable' \
    'Set this bit to enable secure boot                 = True'; do
    grep -Fq "$marker" "$run_dir/efuse-summary.txt" || { cat "$run_dir/efuse-summary.txt" >&2; die "missing eFuse state: $marker"; }
done

python -m espsecure digest_sbv2_public_key --keyfile "$key" --output "$run_dir/expected-digest.bin" >/dev/null
expected_digest="$(xxd -p -c 32 "$run_dir/expected-digest.bin")"
summary_digest="$(python3 - "$run_dir/efuse-summary.txt" <<'PY'
import re, sys
text = open(sys.argv[1], errors='replace').read()
m = re.search(r'BLOCK_KEY0.*?= ((?:[0-9a-f]{2} ){31}[0-9a-f]{2}) R/-', text, re.I | re.S)
if not m:
    raise SystemExit(1)
print(m.group(1).replace(' ', '').lower())
PY
)"
[[ "$summary_digest" == "$expected_digest" ]] || die 'KEY0 digest does not match the signing key'

echo "Security QEMU transition: PASS ($($qemu --version | head -1))"
echo "Signed bootloader: $(stat -c %s "$build_dir/bootloader/bootloader.bin") bytes"
echo "Signed app: $(stat -c %s "$build_dir/pico_fido2.bin") bytes"
echo "Secure Boot digest: $expected_digest"
echo "Flash encrypted: $flash_before -> $flash_after"
echo "eFuse transitioned: $efuse_before -> $efuse_after"
echo 'Post-reset ROM Secure Boot is intentionally not asserted: Espressif ESP32-S3 QEMU does not support Secure Boot yet.'
