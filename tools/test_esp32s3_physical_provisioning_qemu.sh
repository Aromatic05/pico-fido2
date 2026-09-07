#!/usr/bin/env bash
set -euo pipefail

# Exercise the real provision-device CLI against an ESP32-S3 QEMU ROM socket.
# This script has no physical serial-port argument and can never select hardware.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

provision_dir="${1:-build-provisioning}"
run_dir="${TMPDIR:-/tmp}/pico-fido2-physical-provision-qemu-$$"
qemu_pid=""
qemu_port=""
qemu_url=""

fail() {
    echo "physical-provision-qemu: $*" >&2
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
for command in ss sha256sum; do
    command -v "$command" >/dev/null || fail "$command not found"
done
[[ -f "$provision_dir/manifest.json" ]] || fail "missing $provision_dir/manifest.json"
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

free_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
}

python3 - "$run_dir/efuse.bin" "$run_dir/flash.bin" <<'PY'
from pathlib import Path
import sys
b = bytearray(1024)
b[38] = 0x0c
Path(sys.argv[1]).write_bytes(b)
Path(sys.argv[2]).write_bytes(b'\xff' * 0x400000)
PY

qemu_port="$(free_port)"
qemu_url="socket://127.0.0.1:${qemu_port}"
"$qemu" -M esp32s3 \
    -drive file="$run_dir/flash.bin",if=mtd,format=raw \
    -drive file="$run_dir/efuse.bin",if=none,format=raw,id=efuse \
    -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
    -global driver=esp32s3.gpio,property=strap_mode,value=0x07 \
    -nographic -serial "tcp::${qemu_port},server,nowait" >"$run_dir/qemu.log" 2>&1 &
qemu_pid=$!
for _ in $(seq 1 300); do
    if ss -ltn | grep -E ":${qemu_port}[[:space:]]" >/dev/null; then break; fi
    sleep 0.02
done
ss -ltn | grep -E ":${qemu_port}[[:space:]]" >/dev/null \
    || fail 'QEMU ROM serial socket did not open'

./tools/esp32s3_provision.py bind-target \
    --manifest "$provision_dir/manifest.json" \
    --factory-mac 00:00:00:00:00:00 \
    --output "$run_dir/target.json" >/dev/null

before="$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')"
./tools/esp32s3_provision.py provision-device \
    --port "$qemu_url" \
    --manifest "$provision_dir/manifest.json" \
    --target-manifest "$run_dir/target.json" >"$run_dir/dry-run.txt"
after="$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')"
[[ "$before" == "$after" ]] || fail 'physical-command dry-run modified QEMU eFuse state'
grep -q 'pending blocks:      KEY0, KEY1, KEY3, KEY4' "$run_dir/dry-run.txt"
grep -q 'guarded burn order:  KEY0 -> KEY3 -> KEY4 -> KEY1' "$run_dir/dry-run.txt"
grep -q 'device write:        no (dry-run)' "$run_dir/dry-run.txt"

set +e
./tools/esp32s3_provision.py provision-device \
    --port "$qemu_url" \
    --manifest "$provision_dir/manifest.json" \
    --target-manifest "$run_dir/target.json" --apply \
    >"$run_dir/missing-mac.txt" 2>&1
missing_mac_rc=$?
set -e
[[ "$missing_mac_rc" -ne 0 ]] || fail '--apply unexpectedly accepted no explicit MAC guard'
grep -q 'requires an explicit --expect-mac guard' "$run_dir/missing-mac.txt"
[[ "$before" == "$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')" ]] \
    || fail 'missing-MAC refusal modified QEMU eFuse state'

set +e
./tools/esp32s3_provision.py provision-device \
    --port "$qemu_url" \
    --manifest "$provision_dir/manifest.json" \
    --target-manifest "$run_dir/target.json" \
    --expect-mac 11:22:33:44:55:66 --apply \
    >"$run_dir/wrong-mac.txt" 2>&1
wrong_mac_rc=$?
set -e
[[ "$wrong_mac_rc" -ne 0 ]] || fail '--apply unexpectedly accepted a MAC conflicting with target manifest'
grep -q 'disagrees with target manifest' "$run_dir/wrong-mac.txt"
[[ "$before" == "$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')" ]] \
    || fail 'wrong-MAC refusal modified QEMU eFuse state'

./tools/esp32s3_provision.py provision-device \
    --port "$qemu_url" \
    --manifest "$provision_dir/manifest.json" \
    --target-manifest "$run_dir/target.json" \
    --expect-mac 00:00:00:00:00:00 --apply \
    >"$run_dir/apply.txt"

for marker in \
    'KEY0 burn/readback: PASS' \
    'KEY3 burn/readback: PASS' \
    'KEY4 burn/readback: PASS' \
    'KEY1 burn/readback: PASS' \
    'KEY0/1/3/4 layout:   PASS' \
    'KEY1 read protect:   PASS' \
    'SECURE_VERSION:      PASS (still 0)' \
    'recovery paths:      PASS (still enabled)' \
    'device write:        applied'; do
    grep -Fq "$marker" "$run_dir/apply.txt" || fail "missing apply marker: $marker"
done

./tools/esp32s3_provision.py verify-device \
    --port "$qemu_url" \
    --manifest "$provision_dir/manifest.json" \
    --target-manifest "$run_dir/target.json" >/dev/null

provisioned="$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')"
./tools/esp32s3_provision.py provision-device \
    --port "$qemu_url" \
    --manifest "$provision_dir/manifest.json" \
    --target-manifest "$run_dir/target.json" \
    --expect-mac 00:00:00:00:00:00 --apply \
    >"$run_dir/reapply.txt"
[[ "$provisioned" == "$(sha256sum "$run_dir/efuse.bin" | awk '{print $1}')" ]] \
    || fail 'idempotent physical-command reapply modified QEMU eFuse state'
grep -q 'device write:        no (already provisioned)' "$run_dir/reapply.txt"

printf 'ESP32-S3 guarded physical provisioning via QEMU ROM: PASS\n'
printf 'dry-run no-write: PASS\n'
printf 'explicit MAC guard: PASS\n'
printf 'burn/readback order KEY0 -> KEY3 -> KEY4 -> KEY1: PASS\n'
printf 'KEY1 last/read-protected: PASS\n'
printf 'SECURE_VERSION unchanged: PASS\n'
printf 'recovery paths preserved: PASS\n'
printf 'idempotent completed-state reapply: PASS\n'
printf 'No physical device was accessed.\n'
