#!/usr/bin/env bash
set -euo pipefail

provision_dir="${1:-build-provisioning}"
out_dir="${2:-build-ab-security-bundle}"
security_version="${3:-0}"
build_dir=build-security-ab-initial
sdkconfig=sdkconfig.security-ab-initial
defaults='sdkconfig.defaults;sdkconfig.ble.defaults;sdkconfig.wifi.defaults;sdkconfig.development-maintenance.defaults;sdkconfig.security-preprovisioned.defaults;sdkconfig.secure-ota.defaults'

fail() {
    echo "ab-security-bundle: $*" >&2
    exit 1
}

[[ -n "${IDF_PATH:-}" ]] || fail 'IDF_PATH is not set; activate ESP-IDF 5.5 first'
command -v idf.py >/dev/null || fail 'idf.py not found'
command -v openssl >/dev/null || fail 'openssl not found'
[[ "$provision_dir" == "build-provisioning" ]] \
    || fail 'current security profile expects provisioning material in build-provisioning'
[[ -f "$provision_dir/manifest.json" ]] || fail "missing $provision_dir/manifest.json"
[[ "$security_version" =~ ^[0-9]+$ ]] && (( security_version >= 0 && security_version <= 16 )) \
    || fail 'security version must be an integer from 0 to 16'

./tools/esp32s3_provision.py verify "$provision_dir/manifest.json" >/dev/null

rm -rf "$build_dir" "$out_dir"
rm -f "$sdkconfig" "$sdkconfig.old"
mkdir -p "$out_dir/encrypted" "$out_dir/decrypted-check"
version_defaults="$out_dir/.security-version.defaults"
printf 'CONFIG_PICO_FIDO2_SECURITY_VERSION=%s\n' "$security_version" >"$version_defaults"
build_defaults="${defaults};${version_defaults}"

SDKCONFIG_DEFAULTS="$build_defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" set-target esp32s3 >/dev/null
SDKCONFIG_DEFAULTS="$build_defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" build >/dev/null

for expected in \
    CONFIG_PICOKEYS_ESP32_REQUIRE_PROVISIONED_KEYS=y \
    CONFIG_PICO_FIDO2_BLE=y \
    CONFIG_PICO_FIDO2_WIFI_COMMISSIONING=y \
    CONFIG_PICO_FIDO2_DEVELOPMENT_MAINTENANCE_OPEN=y \
    CONFIG_PICO_FIDO2_AB_OTA=y \
    CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y \
    CONFIG_PM_ENABLE=y \
    CONFIG_BT_CTRL_MODEM_SLEEP=y \
    CONFIG_BT_CTRL_DFT_TX_POWER_LEVEL_N0=y \
    CONFIG_SECURE_BOOT=y \
    CONFIG_SECURE_BOOT_V2_ENABLED=y \
    CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y \
    CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y \
    CONFIG_SECURE_FLASH_ENC_ENABLED=y \
    CONFIG_SECURE_FLASH_ENCRYPTION_AES128=y \
    CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y \
    CONFIG_SECURE_FLASH_REQUIRE_ALREADY_ENABLED=y \
    CONFIG_SECURE_BOOT_ALLOW_JTAG=y \
    CONFIG_PARTITION_TABLE_OFFSET=0x10000 \
    CONFIG_PICO_FIDO2_SECURITY_VERSION=${security_version}; do
    grep -qx "$expected" "$sdkconfig" || fail "missing config: $expected"
done
if grep -qx 'CONFIG_PICO_FIDO2_SINGLE_SLOT_ANTI_ROLLBACK=y' "$sdkconfig"; then
    fail 'A/B initial bundle unexpectedly enables the single-slot anti-rollback wrapper'
fi
if grep -qx 'CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y' "$sdkconfig"; then
    fail 'A/B initial bundle unexpectedly enables irreversible ESP-IDF eFuse anti-rollback'
fi
if grep -qx 'CONFIG_PICOKEYS_ESP32_DEV_KEYS=y' "$sdkconfig"; then
    fail 'A/B initial bundle unexpectedly uses development root keys'
fi
if grep -qx 'CONFIG_PICO_FIDO2_QEMU=y' "$sdkconfig"; then
    fail 'A/B initial bundle unexpectedly uses QEMU platform mode'
fi

grep -qx 'CONFIG_SECURE_BOOT_SIGNING_KEY="build-provisioning/secure_boot_signing_key.pem"' "$sdkconfig" \
    || fail 'unexpected Secure Boot signing key path'
grep -qx 'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="pico-keys-sdk/config/esp32/partitions-secure-ota.csv"' "$sdkconfig" \
    || fail 'secure A/B partition table is not selected'

signing_key="$provision_dir/secure_boot_signing_key.pem"
xts_key="$provision_dir/flash_encryption_key.bin"
bootloader="$build_dir/bootloader/bootloader.bin"
partition="$build_dir/partition_table/partition-table.bin"
otadata="$build_dir/ota_data_initial.bin"
app="$build_dir/pico_fido2.bin"

if xtensa-esp32s3-elf-nm "$build_dir/bootloader/bootloader.elf" \
    | grep -q '__wrap_bootloader_utility_load_boot_image'; then
    fail 'single-slot anti-rollback wrapper leaked into the A/B bootloader'
fi

python -m espsecure verify_signature --version 2 --keyfile "$signing_key" "$bootloader" >/dev/null
python -m espsecure verify_signature --version 2 --keyfile "$signing_key" "$app" >/dev/null
[[ "$(stat -c %s "$app")" -le $((0x170000)) ]] || fail 'signed app does not fit ota_0'
[[ "$(stat -c %s "$otadata")" -eq $((0x2000)) ]] || fail 'initial otadata is not 8 KiB'
python3 - "$otadata" <<'PY'
from pathlib import Path
import sys
data = Path(sys.argv[1]).read_bytes()
if len(data) != 0x2000 or any(b != 0xFF for b in data):
    raise SystemExit('initial otadata must be erased 0xFF')
PY

cp "$app" "$out_dir/tampered-app.bin"
python3 - "$out_dir/tampered-app.bin" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
data[0x100] ^= 1
p.write_bytes(data)
PY
if python -m espsecure verify_signature --version 2 --keyfile "$signing_key" "$out_dir/tampered-app.bin" >/dev/null 2>&1; then
    fail 'tampered signed application still verifies'
fi
rm -f "$out_dir/tampered-app.bin"

python3 - "$out_dir/ota1-plain.bin" "$out_dir/part0-plain.bin" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(b'\xff' * 0x170000)
Path(sys.argv[2]).write_bytes(b'\xff' * 0x100000)
PY

names=(bootloader partition otadata ota0 ota1 part0)
addresses=(0x0 0x10000 0x18000 0x20000 0x190000 0x300000)
plain_files=("$bootloader" "$partition" "$otadata" "$app" "$out_dir/ota1-plain.bin" "$out_dir/part0-plain.bin")

for i in "${!names[@]}"; do
    name="${names[$i]}"
    address="${addresses[$i]}"
    plain="${plain_files[$i]}"
    encrypted="$out_dir/encrypted/${name}.bin"
    decrypted="$out_dir/decrypted-check/${name}.bin"
    python -m espsecure encrypt_flash_data --aes_xts \
        --keyfile "$xts_key" --address "$address" --output "$encrypted" "$plain" >/dev/null
    python -m espsecure decrypt_flash_data --aes_xts \
        --keyfile "$xts_key" --address "$address" --output "$decrypted" "$encrypted" >/dev/null
    cmp "$plain" "$decrypted" >/dev/null || fail "XTS round-trip mismatch: $name"
done

python3 - "$out_dir/esp32s3-ab-security-bundle.bin" \
    "$out_dir/encrypted/bootloader.bin" "$out_dir/encrypted/partition.bin" \
    "$out_dir/encrypted/otadata.bin" "$out_dir/encrypted/ota0.bin" \
    "$out_dir/encrypted/ota1.bin" "$out_dir/encrypted/part0.bin" <<'PY'
from pathlib import Path
import sys

out = Path(sys.argv[1])
regions = [
    (0x000000, Path(sys.argv[2]), 'bootloader'),
    (0x010000, Path(sys.argv[3]), 'partition'),
    (0x018000, Path(sys.argv[4]), 'otadata'),
    (0x020000, Path(sys.argv[5]), 'ota0'),
    (0x190000, Path(sys.argv[6]), 'ota1'),
    (0x300000, Path(sys.argv[7]), 'part0'),
]
image = bytearray(b'\xff' * 0x400000)
used = []
for offset, path, name in regions:
    data = path.read_bytes()
    end = offset + len(data)
    if end > len(image):
        raise SystemExit(f'{name} exceeds 4 MiB flash')
    for prev_start, prev_end, prev_name in used:
        if offset < prev_end and prev_start < end:
            raise SystemExit(f'{name} overlaps {prev_name}')
    image[offset:end] = data
    used.append((offset, end, name))
out.write_bytes(image)
PY

python3 - "$out_dir/manifest.json" "$provision_dir/manifest.json" \
    "$out_dir/esp32s3-ab-security-bundle.bin" \
    "$bootloader" "$partition" "$otadata" "$app" "$out_dir/ota1-plain.bin" "$out_dir/part0-plain.bin" \
    "$out_dir/encrypted/bootloader.bin" "$out_dir/encrypted/partition.bin" \
    "$out_dir/encrypted/otadata.bin" "$out_dir/encrypted/ota0.bin" \
    "$out_dir/encrypted/ota1.bin" "$out_dir/encrypted/part0.bin" "$security_version" <<'PY'
from pathlib import Path
import hashlib, json, sys

manifest_path = Path(sys.argv[1])
provision_manifest = Path(sys.argv[2])
bundle = Path(sys.argv[3])
plain = [Path(p) for p in sys.argv[4:10]]
encrypted = [Path(p) for p in sys.argv[10:16]]
security_version = int(sys.argv[16])
names = ['bootloader', 'partition', 'otadata', 'ota0', 'ota1', 'part0']
offsets = [0x000000, 0x010000, 0x018000, 0x020000, 0x190000, 0x300000]

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

image = bundle.read_bytes()
regions = []
for name, offset, source, cipher in zip(names, offsets, plain, encrypted):
    cipher_bytes = cipher.read_bytes()
    if image[offset:offset + len(cipher_bytes)] != cipher_bytes:
        raise SystemExit(f'bundle slice mismatch: {name}')
    regions.append({
        'name': name,
        'offset': f'0x{offset:06x}',
        'bytes': len(cipher_bytes),
        'plaintext_sha256': sha(source),
        'encrypted_sha256': sha(cipher),
    })

pmanifest = json.loads(provision_manifest.read_text())
out = {
    'schema': 1,
    'kind': 'esp32s3-ab-security-bundle',
    'chip': 'esp32s3',
    'flash_bytes': len(image),
    'bundle': {'file': bundle.name, 'sha256': sha(bundle)},
    'provisioning_manifest_sha256': sha(provision_manifest),
    'secure_boot_digest_hex': pmanifest['secure_boot_digest_hex'],
    'security_version': security_version,
    'security_policy': {
        'secure_boot': 'v2/RSA-3072/host-key',
        'flash_encryption': 'XTS-AES-128/host-key',
        'software_rollback': 'ESP-IDF A/B rollback; initial ota_0 baseline is bootloader-marked VALID',
        'software_downgrade': 'portal rejects signed image epochs below the running image epoch',
        'efuse_anti_rollback': False,
        'secure_version_floor_expected_before_boot': 0,
        'spi_boot_crypt_cnt_expected_before_boot': '0b001',
        'required_root_keys': ['KEY3:USER:MKEK', 'KEY4:USER:secp256k1-device-key'],
        'secure_boot_enable': 'must-be-enabled-before-first-boot-of-this-bundle',
        'jtag': 'kept-enabled-for-experiment',
        'rom_download': 'kept-enabled-for-experiment',
    },
    'ota_layout': {
        'otadata': '0x018000+0x002000',
        'ota_0': '0x020000+0x170000',
        'ota_1': '0x190000+0x170000',
        'part0': '0x300000+0x100000',
    },
    'regions': regions,
}
manifest_path.write_text(json.dumps(out, indent=2, sort_keys=True) + '\n')
PY

rm -rf "$out_dir/decrypted-check"
rm -f "$out_dir/ota1-plain.bin" "$out_dir/part0-plain.bin" "$version_defaults"
[[ "$(stat -c %s "$out_dir/esp32s3-ab-security-bundle.bin")" -eq 4194304 ]] \
    || fail 'bundle size is not 4 MiB'

./tools/verify_esp32s3_ab_security_bundle.py "$out_dir" "$provision_dir" >/dev/null

printf 'A/B security bundle: PASS\n'
printf 'Bundle: %s\n' "$(sha256sum "$out_dir/esp32s3-ab-security-bundle.bin" | awk '{print $1}')"
printf 'Signed bootloader: %s bytes\n' "$(stat -c %s "$bootloader")"
printf 'Signed ota_0 app: %s bytes\n' "$(stat -c %s "$app")"
printf 'Security version: %s\n' "$security_version"
printf 'Software rollback: enabled\n'
printf 'eFuse anti-rollback: disabled\n'
printf 'No device write was performed.\n'
