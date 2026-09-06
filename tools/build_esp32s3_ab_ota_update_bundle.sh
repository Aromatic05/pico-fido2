#!/usr/bin/env bash
set -euo pipefail

provision_dir="${1:-build-provisioning}"
out_dir="${2:-build-ab-ota-update}"
project_ver="${3:-7.4.1}"
security_version="${4:-0}"
build_dir=build-security-ab-ota-update
sdkconfig=sdkconfig.security-ab-ota-update
defaults='sdkconfig.defaults;sdkconfig.ble.defaults;sdkconfig.wifi.defaults;sdkconfig.development-maintenance.defaults;sdkconfig.security-preprovisioned.defaults;sdkconfig.secure-ota.defaults'
slot_capacity=$((0x170000))

fail() {
    echo "ab-ota-update: $*" >&2
    exit 1
}

[[ -n "${IDF_PATH:-}" ]] || fail 'IDF_PATH is not set; activate ESP-IDF 5.5 first'
command -v idf.py >/dev/null || fail 'idf.py not found'
[[ "$provision_dir" == "build-provisioning" ]] \
    || fail 'current secure build profile expects provisioning material in build-provisioning'
[[ -f "$provision_dir/manifest.json" ]] || fail "missing $provision_dir/manifest.json"
[[ -n "$project_ver" && ${#project_ver} -le 31 ]] || fail 'project version must be 1..31 characters'
[[ "$security_version" =~ ^[0-9]+$ ]] && (( security_version >= 0 && security_version <= 16 )) \
    || fail 'security version must be an integer from 0 to 16'

./tools/esp32s3_provision.py verify "$provision_dir/manifest.json" >/dev/null

rm -rf "$build_dir" "$out_dir"
rm -f "$sdkconfig" "$sdkconfig.old"
mkdir -p "$out_dir"
version_defaults="$out_dir/.security-version.defaults"
printf 'CONFIG_PICO_FIDO2_SECURITY_VERSION=%s\n' "$security_version" >"$version_defaults"
build_defaults="${defaults};${version_defaults}"

SDKCONFIG_DEFAULTS="$build_defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" \
    -DPROJECT_VER="$project_ver" set-target esp32s3 >/dev/null
SDKCONFIG_DEFAULTS="$build_defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" \
    -DPROJECT_VER="$project_ver" build >/dev/null

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
    CONFIG_SECURE_FLASH_REQUIRE_ALREADY_ENABLED=y \
    CONFIG_PARTITION_TABLE_OFFSET=0x10000 \
    CONFIG_PICO_FIDO2_SECURITY_VERSION=${security_version}; do
    grep -qx "$expected" "$sdkconfig" || fail "missing config: $expected"
done
if grep -qx 'CONFIG_PICO_FIDO2_SINGLE_SLOT_ANTI_ROLLBACK=y' "$sdkconfig"; then
    fail 'A/B OTA update build unexpectedly enables the single-slot anti-rollback wrapper'
fi
if grep -qx 'CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y' "$sdkconfig"; then
    fail 'A/B OTA update build unexpectedly enables irreversible ESP-IDF eFuse anti-rollback'
fi
if grep -qx 'CONFIG_PICOKEYS_ESP32_DEV_KEYS=y' "$sdkconfig"; then
    fail 'A/B OTA update build unexpectedly uses development root keys'
fi
if grep -qx 'CONFIG_NVS_ENCRYPTION=y' "$sdkconfig"; then
    fail 'A/B OTA update build enables NVS Encryption without an nvs_keys partition'
fi
if grep -qx 'CONFIG_PICO_FIDO2_QEMU=y' "$sdkconfig"; then
    fail 'A/B OTA update build unexpectedly uses QEMU platform mode'
fi

grep -qx 'CONFIG_SECURE_BOOT_SIGNING_KEY="build-provisioning/secure_boot_signing_key.pem"' "$sdkconfig" \
    || fail 'unexpected Secure Boot signing key path'
grep -qx 'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="pico-keys-sdk/config/esp32/partitions-secure-ota.csv"' "$sdkconfig" \
    || fail 'secure A/B partition table is not selected'

signing_key="$provision_dir/secure_boot_signing_key.pem"
app="$build_dir/pico_fido2.bin"
artifact="$out_dir/pico_fido2-ota-signed.bin"
[[ -f "$app" ]] || fail 'signed application image is missing'
(( $(stat -c %s "$app") <= slot_capacity )) || fail 'signed application does not fit one A/B OTA slot'
python -m espsecure verify_signature --version 2 --keyfile "$signing_key" "$app" >/dev/null
cp "$app" "$artifact"
rm -f "$version_defaults"

python3 - "$out_dir/manifest.json" "$provision_dir/manifest.json" "$artifact" "$project_ver" "$security_version" "$slot_capacity" <<'PY'
from pathlib import Path
import hashlib
import json
import sys

manifest_path = Path(sys.argv[1])
provision_manifest_path = Path(sys.argv[2])
artifact = Path(sys.argv[3])
project_ver = sys.argv[4]
security_version = int(sys.argv[5])
slot_capacity = int(sys.argv[6])
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
provision = json.loads(provision_manifest_path.read_text())
manifest = {
    'schema': 1,
    'kind': 'esp32s3-ab-ota-update',
    'chip': 'esp32s3',
    'project_name': 'pico_fido2',
    'project_version': project_ver,
    'security_version': security_version,
    'slot_capacity': slot_capacity,
    'provisioning_manifest_sha256': sha(provision_manifest_path),
    'secure_boot_digest_hex': provision['secure_boot_digest_hex'],
    'artifact': {
        'file': artifact.name,
        'bytes': artifact.stat().st_size,
        'sha256': sha(artifact),
    },
    'update_contract': {
        'artifact_format': 'secure-boot-signed-plaintext-app',
        'device_writer': 'esp_ota_write',
        'flash_encryption': 'device-local KEY1 encrypts the inactive app partition during esp_ota_write',
        'secure_boot': 'esp_ota_end verifies the existing KEY0 trust anchor before boot selection',
        'software_rollback': 'new slot remains PENDING_VERIFY until the service-loop confirmation delay expires',
        'software_downgrade': 'candidate image security_version must be at or above the currently running image epoch',
        'efuse_changes': 'none',
        'efuse_anti_rollback': False,
        'host_flash_encryption_key_required': False,
        'target': 'inactive OTA app partition selected by esp_ota_get_next_update_partition',
    },
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
PY

./tools/verify_esp32s3_ab_ota_update_bundle.py "$out_dir" "$provision_dir" >/dev/null

printf 'A/B OTA update bundle: PASS\n'
printf 'Version: %s\n' "$project_ver"
printf 'Security version: %s\n' "$security_version"
printf 'Signed plaintext: %s bytes\n' "$(stat -c %s "$artifact")"
printf 'Slot capacity: %s bytes\n' "$slot_capacity"
printf 'Artifact SHA256: %s\n' "$(sha256sum "$artifact" | awk '{print $1}')"
printf 'Flash encryption key required by update client: no\n'
printf 'eFuse changes required: none\n'
printf 'No device write was performed.\n'
