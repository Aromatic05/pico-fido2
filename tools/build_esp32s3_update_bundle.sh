#!/usr/bin/env bash
set -euo pipefail

provision_dir="${1:-build-provisioning}"
out_dir="${2:-build-update-bundle}"
project_ver="${3:-7.4.1}"
build_dir=build-security-update
sdkconfig=sdkconfig.security-update
defaults='sdkconfig.defaults;sdkconfig.security-preprovisioned.defaults'
app_offset=0x20000

fail() {
    echo "update-bundle: $*" >&2
    exit 1
}

[[ -n "${IDF_PATH:-}" ]] || fail 'IDF_PATH is not set; activate ESP-IDF 5.5 first'
command -v idf.py >/dev/null || fail 'idf.py not found'
[[ "$provision_dir" == "build-provisioning" ]] \
    || fail 'current secure build profile expects provisioning material in build-provisioning'
[[ -f "$provision_dir/manifest.json" ]] || fail "missing $provision_dir/manifest.json"
[[ -n "$project_ver" && ${#project_ver} -le 31 ]] || fail 'project version must be 1..31 characters'

./tools/esp32s3_provision.py verify "$provision_dir/manifest.json" >/dev/null

rm -rf "$build_dir" "$out_dir"
rm -f "$sdkconfig" "$sdkconfig.old"
mkdir -p "$out_dir"

SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" \
    -DPROJECT_VER="$project_ver" set-target esp32s3 >/dev/null
SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" \
    -DPROJECT_VER="$project_ver" build >/dev/null

for expected in \
    CONFIG_PICOKEYS_ESP32_REQUIRE_PROVISIONED_KEYS=y \
    CONFIG_SECURE_BOOT=y \
    CONFIG_SECURE_BOOT_V2_ENABLED=y \
    CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y \
    CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y \
    CONFIG_SECURE_FLASH_ENC_ENABLED=y \
    CONFIG_SECURE_FLASH_ENCRYPTION_AES128=y \
    CONFIG_SECURE_FLASH_REQUIRE_ALREADY_ENABLED=y; do
    grep -qx "$expected" "$sdkconfig" || fail "missing config: $expected"
done
if grep -qx 'CONFIG_PICOKEYS_ESP32_DEV_KEYS=y' "$sdkconfig"; then
    fail 'update build unexpectedly uses development root keys'
fi
if grep -qx 'CONFIG_PICO_FIDO2_QEMU=y' "$sdkconfig"; then
    fail 'update build unexpectedly uses QEMU platform mode'
fi

grep -qx 'CONFIG_SECURE_BOOT_SIGNING_KEY="build-provisioning/secure_boot_signing_key.pem"' "$sdkconfig" \
    || fail 'unexpected Secure Boot signing key path'

signing_key="$provision_dir/secure_boot_signing_key.pem"
xts_key="$provision_dir/flash_encryption_key.bin"
app="$build_dir/pico_fido2.bin"
encrypted="$out_dir/pico_fido2-update-encrypted.bin"
check_plain="$out_dir/.decrypted-check.bin"

python -m espsecure verify_signature --version 2 --keyfile "$signing_key" "$app" >/dev/null
python -m espsecure encrypt_flash_data --aes_xts \
    --keyfile "$xts_key" --address "$app_offset" --output "$encrypted" "$app" >/dev/null
python -m espsecure decrypt_flash_data --aes_xts \
    --keyfile "$xts_key" --address "$app_offset" --output "$check_plain" "$encrypted" >/dev/null
cmp "$app" "$check_plain" >/dev/null || fail 'XTS update round-trip mismatch'
rm -f "$check_plain"

python3 - "$out_dir/manifest.json" "$provision_dir/manifest.json" "$encrypted" "$app" "$project_ver" <<'PY'
from pathlib import Path
import hashlib
import json
import sys

manifest_path = Path(sys.argv[1])
provision_manifest_path = Path(sys.argv[2])
encrypted_path = Path(sys.argv[3])
app_path = Path(sys.argv[4])
project_ver = sys.argv[5]

sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
provision = json.loads(provision_manifest_path.read_text())
manifest = {
    'schema': 1,
    'kind': 'esp32s3-app-update',
    'chip': 'esp32s3',
    'project_version': project_ver,
    'app_offset': '0x020000',
    'provisioning_manifest_sha256': sha(provision_manifest_path),
    'secure_boot_digest_hex': provision['secure_boot_digest_hex'],
    'plaintext': {
        'bytes': app_path.stat().st_size,
        'sha256': sha(app_path),
    },
    'encrypted': {
        'file': encrypted_path.name,
        'bytes': encrypted_path.stat().st_size,
        'sha256': sha(encrypted_path),
    },
    'update_contract': {
        'secure_boot': 'must match existing KEY0 digest',
        'flash_encryption': 'must use existing KEY1 XTS-AES-128 key',
        'efuse_changes': 'none',
        'write_offset': '0x020000',
        'artifact_format': 'pre-encrypted-ciphertext',
        'esptool_write_mode': 'raw-no-encrypt',
        'esptool_encrypt_flag': False,
        'rom_download': 'must remain enabled',
        'usb_serial_jtag_download': 'must remain enabled when used as the physical download transport',
    },
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
PY

./tools/verify_esp32s3_update_bundle.py "$out_dir" "$provision_dir" >/dev/null

printf 'Update bundle: PASS\n'
printf 'Version: %s\n' "$project_ver"
printf 'Offset: %s\n' "$app_offset"
printf 'Signed plaintext: %s bytes\n' "$(stat -c %s "$app")"
printf 'Encrypted update: %s\n' "$(sha256sum "$encrypted" | awk '{print $1}')"
printf 'Flash mode: raw ciphertext write at 0x20000; DO NOT pass --encrypt\n'
printf 'eFuse changes required: none\n'
printf 'No device write was performed.\n'
