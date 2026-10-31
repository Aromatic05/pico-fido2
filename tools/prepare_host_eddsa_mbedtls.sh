#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_tree="$root/pico-keys-sdk/mbedtls"
patch="$root/patches/mbedtls-v3.6.5/eddsa.patch"
security_patch="$root/patches/mbedtls-cve-2026-34874.patch"
expected_base='e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df'
target="${1:-}"

fail() {
    echo "prepare host EdDSA: $*" >&2
    exit 1
}

[[ -n "$target" ]] || fail 'usage: prepare_host_eddsa_mbedtls.sh TARGET_DIR'
[[ -d "$source_tree/.git" || -f "$source_tree/.git" ]] || fail 'pico-keys-sdk/mbedtls submodule is missing'
[[ -f "$patch" && -f "$security_patch" ]] || fail 'host EdDSA or security patch is missing'
actual="$(git -C "$source_tree" rev-parse HEAD)"
[[ "$actual" == "$expected_base" ]] || fail "unexpected mbedTLS base: $actual"

rm -rf "$target"
git clone --quiet --local --no-hardlinks "$source_tree" "$target"
git -C "$target" checkout --quiet -b mbedtls-3.6-eddsa
git -C "$target" apply --unidiff-zero --check "$patch"
git -C "$target" apply --unidiff-zero "$patch"
git -C "$target" apply --unidiff-zero --check "$security_patch"
git -C "$target" apply --unidiff-zero "$security_patch"
[[ -f "$target/include/mbedtls/eddsa.h" && -f "$target/library/eddsa.c" ]] \
    || fail 'EdDSA sources were not produced'
