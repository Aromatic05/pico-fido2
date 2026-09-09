#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
idf="${IDF_PATH:-$root/../esp-idf-v5.5}"
component_patch="$root/patches/esp-idf-v5.5/mbedtls-component-ed25519.patch"
core_patch="$root/patches/esp-idf-v5.5/mbedtls-core-ed25519.patch"
expected_idf='8c750b088c7cd857d079c0eeb495da199b359461'
expected_core='98ae8db06b8acc1dc1c6b1f78c2719cb776f4147'

fail() {
    echo "prepare Ed25519: $*" >&2
    exit 2
}

[[ -d "$idf/.git" ]] || fail "ESP-IDF checkout not found at $idf"
core="$idf/components/mbedtls/mbedtls"
[[ -d "$core" ]] || fail "ESP-IDF mbedTLS submodule not found at $core"
[[ -f "$component_patch" && -f "$core_patch" ]] || fail 'source patches are missing'

idf_head="$(git -C "$idf" rev-parse HEAD)"
core_head="$(git -C "$core" rev-parse HEAD)"
[[ "$idf_head" == "$expected_idf" ]] || fail "expected ESP-IDF v5.5 $expected_idf, found $idf_head"
[[ "$core_head" == "$expected_core" ]] || fail "expected Espressif mbedTLS $expected_core, found $core_head"

patch_state() {
    local repo="$1"
    local patch="$2"
    if git -C "$repo" apply --unidiff-zero --reverse --check "$patch" >/dev/null 2>&1; then
        printf '%s\n' applied
    elif git -C "$repo" apply --unidiff-zero --check "$patch" >/dev/null 2>&1; then
        printf '%s\n' pending
    else
        printf '%s\n' conflict
    fi
}

component_state="$(patch_state "$idf" "$component_patch")"
core_state="$(patch_state "$core" "$core_patch")"
[[ "$component_state" != conflict ]] || fail 'ESP-IDF mbedTLS component has incompatible local changes'
[[ "$core_state" != conflict ]] || fail 'ESP-IDF mbedTLS core has incompatible local changes'

if [[ "$component_state" == pending ]]; then
    git -C "$idf" apply --unidiff-zero "$component_patch"
    component_state='applied now'
else
    component_state='already applied'
fi
if [[ "$core_state" == pending ]]; then
    git -C "$core" apply --unidiff-zero "$core_patch"
    core_state='applied now'
else
    core_state='already applied'
fi

printf 'ESP-IDF Ed25519 component: %s\n' "$component_state"
printf 'ESP-IDF Ed25519 core: %s\n' "$core_state"
printf 'Ed25519 backend ready: %s\n' "$idf"
