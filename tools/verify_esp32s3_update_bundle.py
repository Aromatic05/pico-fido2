#!/usr/bin/env python3
"""Offline verification for an ESP32-S3 signed, pre-encrypted app update."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

EXPECTED_OFFSET = 0x20000
APP_DESC_OFFSET = 24 + 8
APP_DESC_MAGIC = 0xABCD5432
MAX_SECURITY_VERSION = 16


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def die(message: str) -> None:
    raise SystemExit(f"update-bundle verify: {message}")


def run(args: list[str]) -> None:
    try:
        subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        die(f"command failed: {' '.join(args[:4])}")


def app_security_version(path: Path) -> int:
    data = path.read_bytes()
    if len(data) < APP_DESC_OFFSET + 8:
        die("application is too small for esp_app_desc")
    magic, version = struct.unpack_from("<II", data, APP_DESC_OFFSET)
    if magic != APP_DESC_MAGIC:
        die("application descriptor magic mismatch")
    return version


def verify(bundle_dir: Path, provision_dir: Path, security_floor: int = 0) -> None:
    manifest_path = bundle_dir / "manifest.json"
    provision_manifest_path = provision_dir / "manifest.json"
    if not manifest_path.is_file() or not provision_manifest_path.is_file():
        die("update or provisioning manifest is missing")

    manifest = json.loads(manifest_path.read_text())
    provision = json.loads(provision_manifest_path.read_text())
    if manifest.get("schema") != 1 or manifest.get("kind") != "esp32s3-app-update":
        die("unexpected update manifest schema/kind")
    if manifest.get("chip") != "esp32s3" or provision.get("chip") != "esp32s3":
        die("unexpected chip")
    if int(manifest.get("app_offset", "0"), 0) != EXPECTED_OFFSET:
        die("unexpected app offset")
    if manifest.get("provisioning_manifest_sha256") != sha256(provision_manifest_path):
        die("provisioning manifest hash mismatch")
    if manifest.get("secure_boot_digest_hex") != provision.get("secure_boot_digest_hex"):
        die("Secure Boot digest mismatch")
    security_version = manifest.get("security_version")
    if not isinstance(security_version, int) or not 0 <= security_version <= MAX_SECURITY_VERSION:
        die("invalid security_version")
    if not 0 <= security_floor <= MAX_SECURITY_VERSION:
        die("security floor must be from 0 to 16")
    if security_version < security_floor:
        die(f"security_version {security_version} is below device floor {security_floor}")

    encrypted_meta = manifest.get("encrypted", {})
    plain_meta = manifest.get("plaintext", {})
    encrypted = bundle_dir / encrypted_meta.get("file", "")
    if not encrypted.is_file():
        die("encrypted update is missing")
    if encrypted.stat().st_size != encrypted_meta.get("bytes") or sha256(encrypted) != encrypted_meta.get("sha256"):
        die("encrypted update hash/size mismatch")

    xts_key = provision_dir / "flash_encryption_key.bin"
    signing_key = provision_dir / "secure_boot_signing_key.pem"
    if not xts_key.is_file() or xts_key.stat().st_size != 32 or not signing_key.is_file():
        die("required provisioning key material is missing")

    with tempfile.TemporaryDirectory(prefix="pico-update-verify-") as tmp:
        plain = Path(tmp) / "app.bin"
        run([
            sys.executable, "-m", "espsecure", "decrypt_flash_data", "--aes_xts",
            "--keyfile", str(xts_key), "--address", hex(EXPECTED_OFFSET),
            "--output", str(plain), str(encrypted),
        ])
        if plain.stat().st_size != plain_meta.get("bytes") or sha256(plain) != plain_meta.get("sha256"):
            die("decrypted plaintext hash/size mismatch")
        image_security_version = app_security_version(plain)
        if image_security_version != security_version:
            die(f"manifest/image security_version mismatch: {security_version} != {image_security_version}")
        run([
            sys.executable, "-m", "espsecure", "verify_signature", "--version", "2",
            "--keyfile", str(signing_key), str(plain),
        ])

    contract = manifest.get("update_contract", {})
    expected_contract = {
        "efuse_changes": "none",
        "anti_rollback": "image security_version must be at or above the device SECURE_VERSION floor",
        "write_offset": "0x020000",
        "artifact_format": "pre-encrypted-ciphertext",
        "esptool_write_mode": "raw-no-encrypt",
        "esptool_encrypt_flag": False,
    }
    for key, value in expected_contract.items():
        if contract.get(key) != value:
            die(f"unexpected update contract: {key}")

    print(f"update: PASS ({encrypted})")
    print(f"version: {manifest.get('project_version')}")
    print(f"security version: {security_version} (floor {security_floor})")
    print(f"offset: 0x{EXPECTED_OFFSET:06x}")
    print(f"encrypted sha256: {encrypted_meta['sha256']}")
    print("RSA-PSS signature: PASS")
    print("XTS-AES-128 decrypt/plaintext hash: PASS")
    print("flash mode: raw ciphertext write; no --encrypt flag")
    print("eFuse changes required: none")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle_dir", type=Path, nargs="?", default=Path("build-update-bundle"))
    parser.add_argument("provision_dir", type=Path, nargs="?", default=Path("build-provisioning"))
    parser.add_argument("--security-floor", type=int, default=0, help="minimum accepted SECURE_VERSION floor (0..16)")
    args = parser.parse_args()
    verify(args.bundle_dir, args.provision_dir, args.security_floor)


if __name__ == "__main__":
    main()
