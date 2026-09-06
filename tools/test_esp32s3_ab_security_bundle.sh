#!/usr/bin/env bash
set -euo pipefail

provision_dir="${1:-build-provisioning}"
run_dir="${TMPDIR:-/tmp}/pico-fido2-ab-security-test-$$"
out_dir="$run_dir/bundle"

fail() {
    echo "ab-security-test: $*" >&2
    exit 1
}
trap 'rm -rf "$run_dir"' EXIT
mkdir -p "$run_dir"

[[ -n "${IDF_PATH:-}" ]] || fail 'IDF_PATH is not set; activate ESP-IDF 5.5 first'
[[ -f "$provision_dir/manifest.json" ]] || fail "missing $provision_dir/manifest.json"

./tools/build_esp32s3_ab_security_bundle.sh "$provision_dir" "$out_dir" 0 >/dev/null
./tools/verify_esp32s3_ab_security_bundle.py "$out_dir" "$provision_dir" >/dev/null

cp -a "$out_dir" "$run_dir/tampered"
python3 - "$run_dir/tampered/esp32s3-ab-security-bundle.bin" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
data[0x20000 + 0x100] ^= 1
p.write_bytes(data)
PY
if ./tools/verify_esp32s3_ab_security_bundle.py "$run_dir/tampered" "$provision_dir" >/dev/null 2>&1; then
    fail 'tampered encrypted A/B baseline was accepted'
fi

cp -a "$out_dir" "$run_dir/efuse-policy"
python3 - "$run_dir/efuse-policy/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]
data = json.load(open(p))
data['security_policy']['efuse_anti_rollback'] = True
open(p, 'w').write(json.dumps(data, indent=2, sort_keys=True) + '\n')
PY
if ./tools/verify_esp32s3_ab_security_bundle.py "$run_dir/efuse-policy" "$provision_dir" >/dev/null 2>&1; then
    fail 'manifest enabling irreversible eFuse anti-rollback was accepted'
fi

cp -a "$out_dir" "$run_dir/layout"
python3 - "$run_dir/layout/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]
data = json.load(open(p))
data['ota_layout']['ota_1'] = '0x1a0000+0x160000'
open(p, 'w').write(json.dumps(data, indent=2, sort_keys=True) + '\n')
PY
if ./tools/verify_esp32s3_ab_security_bundle.py "$run_dir/layout" "$provision_dir" >/dev/null 2>&1; then
    fail 'mutated A/B layout contract was accepted'
fi

printf 'ESP32-S3 A/B security baseline gate: PASS\n'
printf 'encrypted bundle integrity negative test: PASS\n'
printf 'A/B layout contract negative test: PASS\n'
printf 'eFuse anti-rollback remains disabled: PASS\n'
printf 'eFuse changes required: none\n'
