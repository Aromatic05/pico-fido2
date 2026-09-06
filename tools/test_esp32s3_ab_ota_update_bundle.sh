#!/usr/bin/env bash
set -euo pipefail

provision_dir="${1:-build-provisioning}"
run_dir="${TMPDIR:-/tmp}/pico-fido2-ab-ota-test-$$"
out_dir="$run_dir/update"
version="7.4.2"
security_version=3
running_epoch=2

fail() {
    echo "ab-ota-test: $*" >&2
    exit 1
}
trap 'rm -rf "$run_dir"' EXIT
mkdir -p "$run_dir"

[[ -n "${IDF_PATH:-}" ]] || fail 'IDF_PATH is not set; activate ESP-IDF 5.5 first'
[[ -f "$provision_dir/manifest.json" ]] || fail "missing $provision_dir/manifest.json"

./tools/build_esp32s3_ab_ota_update_bundle.sh "$provision_dir" "$out_dir" "$version" "$security_version" >/dev/null
./tools/verify_esp32s3_ab_ota_update_bundle.py "$out_dir" "$provision_dir" \
    --minimum-running-epoch "$running_epoch" >/dev/null

manifest="$out_dir/manifest.json"
artifact="$out_dir/$(python3 - "$manifest" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))['artifact']['file'])
PY
)"

if ./tools/verify_esp32s3_ab_ota_update_bundle.py "$out_dir" "$provision_dir" \
    --minimum-running-epoch "$((security_version + 1))" >/dev/null 2>&1; then
    fail 'signed OTA image older than the requested running epoch was accepted'
fi

cp -a "$out_dir" "$run_dir/wrong-epoch"
python3 - "$run_dir/wrong-epoch/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]
data = json.load(open(p))
data['security_version'] -= 1
open(p, 'w').write(json.dumps(data, indent=2, sort_keys=True) + '\n')
PY
if ./tools/verify_esp32s3_ab_ota_update_bundle.py "$run_dir/wrong-epoch" "$provision_dir" >/dev/null 2>&1; then
    fail 'manifest/image security version mismatch was accepted'
fi

cp -a "$out_dir" "$run_dir/wrong-project"
python3 - "$run_dir/wrong-project/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]
data = json.load(open(p))
data['project_name'] = 'other'
open(p, 'w').write(json.dumps(data, indent=2, sort_keys=True) + '\n')
PY
if ./tools/verify_esp32s3_ab_ota_update_bundle.py "$run_dir/wrong-project" "$provision_dir" >/dev/null 2>&1; then
    fail 'wrong project manifest was accepted'
fi

cp -a "$out_dir" "$run_dir/tampered"
python3 - "$run_dir/tampered/$(basename "$artifact")" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
data[len(data) // 2] ^= 1
p.write_bytes(data)
PY
if ./tools/verify_esp32s3_ab_ota_update_bundle.py "$run_dir/tampered" "$provision_dir" >/dev/null 2>&1; then
    fail 'tampered signed plaintext OTA artifact was accepted'
fi

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$run_dir/wrong-signing.pem" >/dev/null 2>&1
if python -m espsecure verify_signature --version 2 --keyfile "$run_dir/wrong-signing.pem" \
    "$artifact" >/dev/null 2>&1; then
    fail 'wrong Secure Boot key verified the OTA artifact'
fi
python -m espsecure verify_signature --version 2 \
    --keyfile "$provision_dir/secure_boot_signing_key.pem" "$artifact" >/dev/null

printf 'ESP32-S3 A/B OTA update bundle gate: PASS\n'
printf 'signed plaintext artifact: PASS\n'
printf 'same KEY0 signing trust: PASS\n'
printf 'device-local KEY1 only: PASS\n'
printf 'software epoch downgrade negative test: PASS\n'
printf 'manifest/image identity binding: PASS\n'
printf 'wrong signing key negative test: PASS\n'
printf 'tamper negative test: PASS\n'
printf 'eFuse changes required: none\n'
