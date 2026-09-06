#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python tests/formal_state_model.py
python tests/source_ownership_contracts.py
python tests/yubikey_profile_contracts.py
python tests/sdkconfig_contracts.py
git diff --check

cmake -S . -B build-host -DENABLE_EMULATION=1 -DCMAKE_BUILD_TYPE=Debug
cmake --build build-host -j2
python tests/host_protocol_smoke.py build-host/pico_fido2
python tests/host_transport_contention.py build-host/pico_fido2 --iterations 50

cmake -S . -B build-host-analyzer \
    -DENABLE_EMULATION=1 \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS='-fanalyzer -Wno-analyzer-too-complex' \
    -DCMAKE_CXX_FLAGS='-fanalyzer -Wno-analyzer-too-complex'
cmake --build build-host-analyzer -j2

cmake -S . -B build-host-frame \
    -DENABLE_EMULATION=1 \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS='-Wframe-larger-than=8192 -Werror=frame-larger-than=8192' \
    -DCMAKE_CXX_FLAGS='-Wframe-larger-than=8192 -Werror=frame-larger-than=8192'
cmake --build build-host-frame -j2

cmake -S . -B build-host-asan \
    -DENABLE_EMULATION=1 \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -O1 -g' \
    -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -O1 -g' \
    -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-host-asan -j2
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
    python tests/host_protocol_smoke.py build-host-asan/pico_fido2
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
    python tests/host_transport_contention.py build-host-asan/pico_fido2 --iterations 30
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
    python tests/host_powercycle_durability.py build-host-asan/pico_fido2 --iterations 3

cc -std=c11 -Wall -Wextra -Werror \
    -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I src/fido2 tests/ble_fido_frame_test.c src/fido2/ble_fido_frame.c \
    -o build-host-asan/ble_fido_frame_test
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
    build-host-asan/ble_fido_frame_test

cmake -S . -B build-host-tsan \
    -DENABLE_EMULATION=1 \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS='-fsanitize=thread -fno-omit-frame-pointer -O1 -g' \
    -DCMAKE_CXX_FLAGS='-fsanitize=thread -fno-omit-frame-pointer -O1 -g' \
    -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=thread'
cmake --build build-host-tsan -j2
TSAN_OPTIONS=halt_on_error=1 \
    python tests/host_protocol_smoke.py build-host-tsan/pico_fido2
TSAN_OPTIONS=halt_on_error=1 \
    python tests/host_transport_contention.py build-host-tsan/pico_fido2 --iterations 30
TSAN_OPTIONS=halt_on_error=1 \
    python tests/host_powercycle_durability.py build-host-tsan/pico_fido2 --iterations 2

if [[ -z "${IDF_PATH:-}" ]]; then
    DEFAULT_IDF="$ROOT/../esp-idf-v5.5"
    if [[ ! -f "$DEFAULT_IDF/export.sh" ]]; then
        echo "IDF_PATH is unset and $DEFAULT_IDF/export.sh does not exist" >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    source "$DEFAULT_IDF/export.sh" >/dev/null 2>&1
else
    # shellcheck disable=SC1090
    source "$IDF_PATH/export.sh" >/dev/null 2>&1
fi

idf.py -B build-bringup-wireless reconfigure
idf.py -B build-bringup-wireless build
sha256sum build-bringup-wireless/pico_fido2.bin

echo "transport ownership software gate: PASS"
