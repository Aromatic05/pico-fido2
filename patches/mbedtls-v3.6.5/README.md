# Host mbedTLS EdDSA patch

The native emulator is pinned to upstream mbedTLS v3.6.5 at `e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df`. Stock mbedTLS 3.6.5 does not provide the LibreKeys Ed25519/Ed448 EdDSA extension used by Pico OpenPGP and Pico FIDO when `ENABLE_EDDSA=1`.

`eddsa.patch` is based on the EdDSA-only delta from `librekeys/mbedtls` branch `mbedtls-3.6-eddsa`, merge head `32604790a0433470ac1836be4faa1e0793035673`, relative to its upstream parent `14ada7f73c71f4207dfe15c86d6585647ca35237`. The project patch additionally supplies the Ed25519 RFC 8410 AlgorithmIdentifier mapping required by PIV attestation. It applies cleanly to the pinned v3.6.5 submodule.

The host compatibility tests apply this patch to a disposable clone and mount that clone over `/src/pico-keys-sdk/mbedtls` inside the isolated test container. The project submodule itself is never modified.
