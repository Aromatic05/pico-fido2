#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_dir="$(mktemp -d "${TMPDIR:-/tmp}/aromatic-ed25519-qemu.XXXXXX")"
qemu_pid=""

cleanup() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    rm -rf "$run_dir"
}
trap cleanup EXIT

[[ -n "${IDF_PATH:-}" ]] || {
    echo 'IDF_PATH is not set; activate ESP-IDF 5.5 first' >&2
    exit 2
}
command -v idf.py >/dev/null 2>&1 || {
    echo 'idf.py is not available; activate ESP-IDF 5.5 first' >&2
    exit 2
}
[[ -f "$IDF_PATH/components/mbedtls/mbedtls/include/mbedtls/eddsa.h" ]] || {
    echo "Ed25519 backend is missing; run $root/tools/prepare_esp32s3_ed25519.sh" >&2
    exit 2
}

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

qemu="$(find_esp_qemu)" || {
    echo 'Espressif QEMU with esp32s3 machine support was not found' >&2
    exit 2
}

mkdir -p "$run_dir/main"
cat > "$run_dir/CMakeLists.txt" <<'CMAKE'
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(aromatic_ed25519_runtime)
CMAKE
cat > "$run_dir/main/CMakeLists.txt" <<'CMAKE'
idf_component_register(SRCS "main.c" INCLUDE_DIRS "." REQUIRES mbedtls esp_hw_support)
CMAKE
cat > "$run_dir/main/main.c" <<'C'
#include <stdio.h>
#include "esp_random.h"
#include "mbedtls/ecp.h"
#include "mbedtls/eddsa.h"

static int test_rng(void *ctx, unsigned char *buf, size_t len)
{
    (void) ctx;
    esp_fill_random(buf, len);
    return 0;
}

void app_main(void)
{
    static const unsigned char msg[] = "aromatic-key-ed25519-esp32s3";
    unsigned char sig[64];
    size_t sig_len = 0;
    mbedtls_ecp_keypair key;
    int rc;

    mbedtls_ecp_keypair_init(&key);
    rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_ED25519, &key, test_rng, NULL);
    if (rc != 0) {
        printf("ED25519_RUNTIME_FAIL keygen=%d\n", rc);
        goto out;
    }

    rc = mbedtls_eddsa_write_signature(&key, msg, sizeof(msg) - 1,
                                       sig, sizeof(sig), &sig_len,
                                       MBEDTLS_EDDSA_PURE, NULL, 0,
                                       test_rng, NULL);
    if (rc != 0) {
        printf("ED25519_RUNTIME_FAIL sign=%d\n", rc);
        goto out;
    }
    if (sig_len != sizeof(sig)) {
        printf("ED25519_RUNTIME_FAIL sig_len=%u\n", (unsigned) sig_len);
        goto out;
    }

    rc = mbedtls_eddsa_read_signature(&key, msg, sizeof(msg) - 1,
                                      sig, sig_len,
                                      MBEDTLS_EDDSA_PURE, NULL, 0);
    if (rc != 0) {
        printf("ED25519_RUNTIME_FAIL verify=%d\n", rc);
        goto out;
    }

    sig[0] ^= 0x01;
    rc = mbedtls_eddsa_read_signature(&key, msg, sizeof(msg) - 1,
                                      sig, sig_len,
                                      MBEDTLS_EDDSA_PURE, NULL, 0);
    if (rc == 0) {
        printf("ED25519_RUNTIME_FAIL tamper-accepted\n");
        goto out;
    }

    printf("ED25519_RUNTIME_PASS sig_len=%u tamper_rc=%d\n",
           (unsigned) sig_len, rc);
out:
    mbedtls_ecp_keypair_free(&key);
}
C
cat > "$run_dir/sdkconfig.defaults" <<'EOF_CONFIG'
CONFIG_ESPTOOLPY_FLASHMODE_DIO=y
CONFIG_ESPTOOLPY_FLASHFREQ_40M=y
CONFIG_SPI_FLASH_HPM_DIS=y
CONFIG_MBEDTLS_SHA512_C=y
CONFIG_MBEDTLS_ECP_C=y
CONFIG_MBEDTLS_ECP_DP_ED25519_ENABLED=y
CONFIG_MBEDTLS_EDDSA_C=y
EOF_CONFIG

idf.py -C "$run_dir" -B "$run_dir/build" set-target esp32s3 >/dev/null
idf.py -C "$run_dir" -B "$run_dir/build" build >/dev/null

for expected in \
    CONFIG_MBEDTLS_ECP_DP_ED25519_ENABLED=y \
    CONFIG_MBEDTLS_EDDSA_C=y; do
    grep -qx "$expected" "$run_dir/sdkconfig" || {
        echo "Ed25519 QEMU config missing: $expected" >&2
        exit 3
    }
done

python -m esptool --chip esp32s3 merge_bin \
    --output "$run_dir/build/qemu_flash.bin" --fill-flash-size 4MB \
    --flash_mode dio --flash_freq 40m --flash_size 4MB \
    0x0 "$run_dir/build/bootloader/bootloader.bin" \
    0x8000 "$run_dir/build/partition_table/partition-table.bin" \
    0x10000 "$run_dir/build/aromatic_ed25519_runtime.bin" >/dev/null

dd if=/dev/zero of="$run_dir/efuse.bin" bs=1024 count=1 status=none
"$qemu" -M esp32s3 \
    -drive file="$run_dir/build/qemu_flash.bin",if=mtd,format=raw \
    -drive file="$run_dir/efuse.bin",if=none,format=raw,id=efuse \
    -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
    -nic user,model=open_eth -nographic -serial mon:stdio \
    >"$run_dir/qemu.log" 2>&1 &
qemu_pid=$!

for _ in $(seq 1 800); do
    if grep -aq 'ED25519_RUNTIME_PASS\|ED25519_RUNTIME_FAIL' "$run_dir/qemu.log"; then
        break
    fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
done

kill "$qemu_pid" 2>/dev/null || true
wait "$qemu_pid" 2>/dev/null || true
qemu_pid=""

if ! grep -aq 'ED25519_RUNTIME_PASS' "$run_dir/qemu.log"; then
    tail -120 "$run_dir/qemu.log" >&2
    echo 'ESP32-S3 Ed25519 runtime test failed' >&2
    exit 4
fi
if grep -aqE 'ED25519_RUNTIME_FAIL|assert failed|Guru Meditation|Rebooting' "$run_dir/qemu.log"; then
    tail -120 "$run_dir/qemu.log" >&2
    echo 'ESP32-S3 Ed25519 runtime test reported a failure' >&2
    exit 4
fi

grep -a 'ED25519_RUNTIME_PASS' "$run_dir/qemu.log"
echo "Ed25519 QEMU: PASS ($($qemu --version | head -1))"
