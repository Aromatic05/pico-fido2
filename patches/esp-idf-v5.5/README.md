# ESP-IDF v5.5 Ed25519 backport

Aromatic Key uses Ed25519 for the OpenPGP signature and authentication slots. Stock ESP-IDF v5.5 enables Curve25519 but does not provide the EdDSA/Ed25519 implementation required by `pico-openpgp`; without this backport the card can accept an Ed25519 algorithm attribute and then fail `GENERATE ASYMMETRIC KEY PAIR` with `6A81`.

The backport is intentionally limited to Ed25519. CV25519 remains provided by the stock ESP-IDF mbedTLS implementation; Ed448/SHA3 are not enabled by this patch.

Pinned bases:

- ESP-IDF v5.5: `8c750b088c7cd857d079c0eeb495da199b359461`
- Espressif mbedTLS submodule: `98ae8db06b8acc1dc1c6b1f78c2719cb776f4147` (mbedTLS 3.6.3 based)
- EdDSA feature source: `librekeys/mbedtls`, branch `mbedtls-3.6-eddsa`; the port was derived from the EdDSA-only delta of merge head `32604790a0433470ac1836be4faa1e0793035673` against its upstream 3.6 parent `14ada7f73c71f4207dfe15c86d6585647ca35237`.

`mbedtls-component-ed25519.patch` adds the ESP-IDF Kconfig/config mapping. `mbedtls-core-ed25519.patch` ports the Ed25519/EdDSA implementation onto Espressif's 3.6.3 mbedTLS while preserving ESP-IDF's legacy `mbedtls_ecp_set_zero()` / `mbedtls_ecp_is_zero()` API used by components such as `wpa_supplicant`. It also classifies Ed25519 as an RFC 8410 key and adds the Ed25519 AlgorithmIdentifier mapping needed to emit PIV attestation certificates.

Apply with `tools/prepare_esp32s3_ed25519.sh`; do not apply either patch manually in production workflows. The script validates the exact base revisions and is idempotent.

The same preparation script also applies `patches/mbedtls-cve-2026-34874.patch`, the upstream Mbed TLS allocation-failure fix (commit `bfaf4a47fd33da860796feaba6235847acb71127`) to the pinned ESP-IDF Mbed TLS source. This does not change the Ed25519 backport or the ESP-IDF base revision.
