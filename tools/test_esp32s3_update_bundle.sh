#!/usr/bin/env bash
set -euo pipefail

provision_dir="${1:-build-provisioning}"
run_dir="${TMPDIR:-/tmp}/pico-fido2-update-test-$$"
out_dir="$run_dir/update"
version="7.4.1"
security_version=3
security_floor=2

fail() {
    echo "update-test: $*" >&2
    exit 1
}
trap 'rm -rf "$run_dir"' EXIT
mkdir -p "$run_dir"

[[ -n "${IDF_PATH:-}" ]] || fail 'IDF_PATH is not set; activate ESP-IDF 5.5 first'
[[ -f "$provision_dir/manifest.json" ]] || fail "missing $provision_dir/manifest.json"

python3 tests/esp32s3_update_tool_test.py >/dev/null
./tools/build_esp32s3_update_bundle.sh "$provision_dir" "$out_dir" "$version" "$security_version" >/dev/null
./tools/verify_esp32s3_update_bundle.py "$out_dir" "$provision_dir" --security-floor "$security_floor" >/dev/null
./tools/esp32s3_update.py verify "$out_dir" "$provision_dir" --security-floor "$security_floor" >/dev/null

manifest="$out_dir/manifest.json"
encrypted="$out_dir/$(python3 - "$manifest" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))['encrypted']['file'])
PY
)"
plain_hash="$(python3 - "$manifest" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))['plaintext']['sha256'])
PY
)"
xts_key="$provision_dir/flash_encryption_key.bin"
signing_key="$provision_dir/secure_boot_signing_key.pem"

manifest_security_version="$(python3 - "$manifest" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))['security_version'])
PY
)"
[[ "$manifest_security_version" == "$security_version" ]] || fail 'manifest security_version mismatch'

# Host preflight must reject a correctly signed/encrypted image below the requested floor.
if ./tools/verify_esp32s3_update_bundle.py "$out_dir" "$provision_dir" \
    --security-floor "$((security_version + 1))" >/dev/null 2>&1; then
    fail 'update below requested security floor was accepted'
fi

# The manifest cannot lie about the embedded esp_app_desc security version.
cp -a "$out_dir" "$run_dir/wrong-version-manifest"
python3 - "$run_dir/wrong-version-manifest/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]
data = json.load(open(p))
data['security_version'] -= 1
open(p, 'w').write(json.dumps(data, indent=2, sort_keys=True) + '\n')
PY
if ./tools/verify_esp32s3_update_bundle.py "$run_dir/wrong-version-manifest" "$provision_dir" >/dev/null 2>&1; then
    fail 'manifest/image security_version mismatch was accepted'
fi

# Wrong XTS key must not recover the signed plaintext.
python3 - "$run_dir/wrong-xts.bin" <<'PY'
from pathlib import Path
import os, sys
Path(sys.argv[1]).write_bytes(os.urandom(32))
PY
python -m espsecure decrypt_flash_data --aes_xts --keyfile "$run_dir/wrong-xts.bin" \
    --address 0x20000 --output "$run_dir/wrong-key.bin" "$encrypted" >/dev/null
[[ "$(sha256sum "$run_dir/wrong-key.bin" | awk '{print $1}')" != "$plain_hash" ]] \
    || fail 'wrong XTS key recovered expected plaintext'
python3 - "$run_dir/wrong-key.bin" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, 'tools')
import esp32s3_update
try:
    esp32s3_update.validate_decrypted_app_prefix(Path(sys.argv[1]).read_bytes()[:0x1000])
except esp32s3_update.UpdateError:
    pass
else:
    raise SystemExit('updater KEY1 preflight accepted wrong-key plaintext')
PY

# XTS is address-tweaked: the correct key at the wrong offset must also fail.
python -m espsecure decrypt_flash_data --aes_xts --keyfile "$xts_key" \
    --address 0x30000 --output "$run_dir/wrong-offset.bin" "$encrypted" >/dev/null
[[ "$(sha256sum "$run_dir/wrong-offset.bin" | awk '{print $1}')" != "$plain_hash" ]] \
    || fail 'wrong flash offset recovered expected plaintext'

# A ciphertext mutation must fail the bundle verifier.
cp -a "$out_dir" "$run_dir/tampered"
python3 - "$run_dir/tampered/pico_fido2-update-encrypted.bin" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
data[len(data) // 2] ^= 1
p.write_bytes(data)
PY
if ./tools/verify_esp32s3_update_bundle.py "$run_dir/tampered" "$provision_dir" >/dev/null 2>&1; then
    fail 'tampered update bundle still verifies'
fi

# A different Secure Boot signing key must not validate the signed app.
python -m espsecure decrypt_flash_data --aes_xts --keyfile "$xts_key" \
    --address 0x20000 --output "$run_dir/plain.bin" "$encrypted" >/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$run_dir/wrong-signing.pem" >/dev/null 2>&1
if python -m espsecure verify_signature --version 2 --keyfile "$run_dir/wrong-signing.pem" \
    "$run_dir/plain.bin" >/dev/null 2>&1; then
    fail 'wrong Secure Boot key verified the update'
fi
python -m espsecure verify_signature --version 2 --keyfile "$signing_key" "$run_dir/plain.bin" >/dev/null

printf 'ESP32-S3 update bundle gate: PASS\n'
printf 'same KEY0 signing trust: PASS\n'
printf 'security version %s >= floor %s: PASS\n' "$security_version" "$security_floor"
printf 'security floor negative test: PASS\n'
printf 'manifest/image security version binding: PASS\n'
printf 'same KEY1 XTS encryption: PASS\n'
printf 'updater KEY1 device-binding preflight: PASS\n'
printf 'wrong key negative test: PASS\n'
printf 'wrong offset negative test: PASS\n'
printf 'tamper negative test: PASS\n'
printf 'eFuse changes required: none\n'
