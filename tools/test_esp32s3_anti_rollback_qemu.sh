#!/usr/bin/env bash
set -euo pipefail

run_dir="${TMPDIR:-/tmp}/pico-fido2-anti-rollback-qemu-$$"
qemu_pid=""

fail() {
    echo "anti-rollback-qemu: $*" >&2
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
command -v python >/dev/null || fail 'python not found'

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

qemu="$(find_esp_qemu)" || fail 'Espressif QEMU with esp32s3 machine support was not found'
base_defaults='sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.qemu.defaults;sdkconfig.anti-rollback-qemu.defaults'

build_version() {
    local version="$1"
    local build="$run_dir/build-v${version}"
    local sdkconfig="$run_dir/sdkconfig-v${version}"
    local version_defaults="$run_dir/version-v${version}.defaults"

    printf 'CONFIG_PICO_FIDO2_SECURITY_VERSION=%s\n' "$version" >"$version_defaults"
    SDKCONFIG_DEFAULTS="${base_defaults};${version_defaults}" \
        idf.py -B "$build" -DSDKCONFIG="$sdkconfig" set-target esp32s3 >/dev/null
    SDKCONFIG_DEFAULTS="${base_defaults};${version_defaults}" \
        idf.py -B "$build" -DSDKCONFIG="$sdkconfig" build >/dev/null

    grep -qx 'CONFIG_PICO_FIDO2_QEMU=y' "$sdkconfig" || fail "v${version}: QEMU mode is not enabled"
    grep -qx 'CONFIG_PICO_FIDO2_SINGLE_SLOT_ANTI_ROLLBACK=y' "$sdkconfig" \
        || fail "v${version}: anti-rollback is not enabled"
    grep -qx "CONFIG_PICO_FIDO2_SECURITY_VERSION=${version}" "$sdkconfig" \
        || fail "v${version}: wrong security version"
    grep -qx '# CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP is not set' "$sdkconfig" \
        || fail "v${version}: deep-sleep validation bypass is enabled"
    if grep -qx 'CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y' "$sdkconfig"; then
        fail "v${version}: stock OTA anti-rollback must remain disabled"
    fi
    if grep -qx 'CONFIG_SECURE_BOOT=y' "$sdkconfig"; then
        fail "v${version}: policy-only QEMU gate must not enable Secure Boot"
    fi

    grep -q '#define CONFIG_PICO_FIDO2_SINGLE_SLOT_ANTI_ROLLBACK 1' \
        "$build/bootloader/config/sdkconfig.h" || fail "v${version}: bootloader lacks anti-rollback config"
    grep -q "#define CONFIG_PICO_FIDO2_SECURITY_VERSION ${version}" \
        "$build/bootloader/config/sdkconfig.h" || fail "v${version}: bootloader sees wrong version"

    python3 - "$build/pico_fido2.bin" "$version" <<'PY'
from pathlib import Path
import struct
import sys
image = Path(sys.argv[1]).read_bytes()
expected = int(sys.argv[2])
magic, version = struct.unpack_from('<II', image, 24 + 8)
if magic != 0xABCD5432 or version != expected:
    raise SystemExit(f'bad app descriptor: magic=0x{magic:08x} version={version}, expected={expected}')
PY
}

make_floor2_efuse() {
    local output="$1"
    python3 - "$output" <<'PY'
from pathlib import Path
import sys
b = bytearray(1024)
b[38] = 0x0c  # QEMU ESP32-S3 rev v0.3 convention used by the security gates.
for bit in (142, 143):  # SECURE_VERSION raw field = 0b11, popcount floor = 2.
    b[bit // 8] |= 1 << (bit % 8)
Path(sys.argv[1]).write_bytes(b)
PY
}

run_version() {
    local version="$1"
    local expect="$2"
    local build="$run_dir/build-v${version}"
    local case_dir="$run_dir/run-v${version}"
    mkdir -p "$case_dir"

    python -m esptool --chip esp32s3 merge_bin \
        --output "$case_dir/flash.bin" --fill-flash-size 4MB \
        --flash_mode dio --flash_freq 40m --flash_size 4MB \
        0x0 "$build/bootloader/bootloader.bin" \
        0x8000 "$build/partition_table/partition-table.bin" \
        0x10000 "$build/pico_fido2.bin" >/dev/null
    make_floor2_efuse "$case_dir/efuse.bin"
    local before after
    before="$(sha256sum "$case_dir/efuse.bin" | awk '{print $1}')"

    "$qemu" -M esp32s3 \
        -drive file="$case_dir/flash.bin",if=mtd,format=raw \
        -drive file="$case_dir/efuse.bin",if=none,format=raw,id=efuse \
        -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
        -nic user,model=open_eth -nographic -serial mon:stdio \
        >"$case_dir/qemu.log" 2>&1 &
    qemu_pid=$!

    local done=false
    for _ in $(seq 1 500); do
        if [[ "$expect" == accept ]] && grep -aq 'main_task: Returned from app_main()' "$case_dir/qemu.log"; then
            done=true
            break
        fi
        if [[ "$expect" == reject ]] && grep -aq 'rejecting rolled-back factory image' "$case_dir/qemu.log"; then
            done=true
            break
        fi
        if ! kill -0 "$qemu_pid" 2>/dev/null; then
            break
        fi
        sleep 0.02
    done

    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=""
    after="$(sha256sum "$case_dir/efuse.bin" | awk '{print $1}')"

    [[ "$done" == true ]] || { tail -120 "$case_dir/qemu.log" >&2; fail "v${version}: expected ${expect} marker not observed"; }
    grep -aq "security floor=2, image=${version}" "$case_dir/qemu.log" \
        || { tail -120 "$case_dir/qemu.log" >&2; fail "v${version}: floor/image log missing"; }
    [[ "$before" == "$after" ]] || fail "v${version}: boot changed virtual SECURE_VERSION/eFuse state"

    if [[ "$expect" == accept ]]; then
        grep -aq 'main_task: Returned from app_main()' "$case_dir/qemu.log" \
            || fail "v${version}: accepted image did not reach app_main"
        if grep -aq 'rejecting rolled-back factory image' "$case_dir/qemu.log"; then
            fail "v${version}: accepted image was also rejected"
        fi
    else
        grep -aq 'rejecting rolled-back factory image' "$case_dir/qemu.log" \
            || fail "v${version}: rolled-back image was not rejected"
        if grep -aq 'main_task: Returned from app_main()' "$case_dir/qemu.log"; then
            fail "v${version}: rolled-back image reached app_main"
        fi
    fi

    echo "v${version} / floor2: ${expect^^} (eFuse unchanged)"
}

for version in 1 2 3; do
    build_version "$version"
done

run_version 1 reject
run_version 2 accept
run_version 3 accept

# The deep-sleep fast path bypasses normal boot image validation before the
# wrapped loader is reached, so anti-rollback builds must reject this option.
bypass_defaults="$run_dir/deep-sleep-bypass.defaults"
cat >"$bypass_defaults" <<'EOF'
CONFIG_PICO_FIDO2_SECURITY_VERSION=2
CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP=y
EOF
set +e
SDKCONFIG_DEFAULTS="${base_defaults};${bypass_defaults}" \
    idf.py -B "$run_dir/build-bypass" -DSDKCONFIG="$run_dir/sdkconfig-bypass" \
    set-target esp32s3 >"$run_dir/bypass-build.log" 2>&1
bypass_rc=$?
set -e
[[ "$bypass_rc" -ne 0 ]] || fail 'deep-sleep validation bypass build unexpectedly succeeded'
grep -q 'Single-slot anti-rollback forbids BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP' \
    "$run_dir/bypass-build.log" || { cat "$run_dir/bypass-build.log" >&2; fail 'deep-sleep bypass was rejected for the wrong reason'; }
echo 'deep-sleep validation bypass: REJECT'

echo "Single-slot anti-rollback QEMU: PASS ($($qemu --version | head -1))"
echo 'No real eFuse was written; the SECURE_VERSION floor existed only in disposable QEMU backing files.'
