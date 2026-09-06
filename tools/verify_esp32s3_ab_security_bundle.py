#!/usr/bin/env python3
"""Offline integrity/crypto verification for the ESP32-S3 A/B security baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

APP_DESC_OFFSET = 24 + 8
APP_DESC_MAGIC = 0xABCD5432
MAX_SECURITY_VERSION = 16
EXPECTED_OFFSETS = {
    "bootloader": 0x000000,
    "partition": 0x010000,
    "otadata": 0x018000,
    "ota0": 0x020000,
    "ota1": 0x190000,
    "part0": 0x300000,
}
EXPECTED_ERASED = {"otadata": 0x2000, "ota1": 0x170000, "part0": 0x100000}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def die(message: str) -> None:
    raise SystemExit(f"ab-security-bundle verify: {message}")


def run(args: list[str]) -> None:
    try:
        subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        die(f"command failed: {' '.join(args[:4])}")


def parse_offset(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise SystemExit(f"invalid region offset: {value}") from exc


def verify(bundle_dir: Path, provision_dir: Path) -> None:
    probe = subprocess.run([sys.executable, "-m", "espsecure", "--help"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if probe.returncode != 0:
        die("espsecure is unavailable; activate ESP-IDF 5.5 before verification")

    manifest_path = bundle_dir / "manifest.json"
    provision_manifest_path = provision_dir / "manifest.json"
    if not manifest_path.is_file() or not provision_manifest_path.is_file():
        die("bundle or provisioning manifest is missing")
    manifest = json.loads(manifest_path.read_text())
    provision = json.loads(provision_manifest_path.read_text())
    if manifest.get("schema") != 1 or manifest.get("kind") != "esp32s3-ab-security-bundle":
        die("unexpected A/B security manifest schema/kind")
    if manifest.get("chip") != "esp32s3" or provision.get("chip") != "esp32s3":
        die("unexpected chip")
    if manifest.get("flash_bytes") != 0x400000:
        die("bundle manifest is not 4 MiB")
    if manifest.get("provisioning_manifest_sha256") != sha256_file(provision_manifest_path):
        die("provisioning manifest hash mismatch")
    if manifest.get("secure_boot_digest_hex") != provision.get("secure_boot_digest_hex"):
        die("Secure Boot digest mismatch")
    security_version = manifest.get("security_version")
    if not isinstance(security_version, int) or not 0 <= security_version <= MAX_SECURITY_VERSION:
        die("invalid security_version")

    policy = manifest.get("security_policy", {})
    if policy.get("efuse_anti_rollback") is not False:
        die("A/B baseline must not enable irreversible eFuse anti-rollback")
    if policy.get("secure_version_floor_expected_before_boot") != 0:
        die("A/B baseline must expect SECURE_VERSION eFuse floor 0")
    expected_layout = {
        "otadata": "0x018000+0x002000",
        "ota_0": "0x020000+0x170000",
        "ota_1": "0x190000+0x170000",
        "part0": "0x300000+0x100000",
    }
    if manifest.get("ota_layout") != expected_layout:
        die("unexpected A/B OTA layout contract")

    bundle = bundle_dir / manifest["bundle"]["file"]
    if not bundle.is_file() or bundle.stat().st_size != 0x400000:
        die("bundle file is missing or not 4 MiB")
    if sha256_file(bundle) != manifest["bundle"]["sha256"]:
        die("bundle SHA-256 mismatch")

    regions = manifest.get("regions")
    if not isinstance(regions, list) or {r.get("name") for r in regions} != set(EXPECTED_OFFSETS):
        die("unexpected region set")
    image = bundle.read_bytes()
    xts_key = provision_dir / "flash_encryption_key.bin"
    signing_key = provision_dir / "secure_boot_signing_key.pem"
    if not xts_key.is_file() or xts_key.stat().st_size != 32 or not signing_key.is_file():
        die("required provisioning key material is missing")

    with tempfile.TemporaryDirectory(prefix="pico-ab-security-verify-") as tmp:
        tmpdir = Path(tmp)
        decrypted_paths: dict[str, Path] = {}
        spans: list[tuple[int, int, str]] = []
        for region in regions:
            name = region["name"]
            offset = parse_offset(region["offset"])
            size = int(region["bytes"])
            if offset != EXPECTED_OFFSETS[name] or size <= 0 or offset + size > len(image):
                die(f"invalid geometry for region {name}")
            for start, end, other in spans:
                if offset < end and start < offset + size:
                    die(f"region overlap: {name}/{other}")
            spans.append((offset, offset + size, name))
            encrypted = image[offset:offset + size]
            if sha256_bytes(encrypted) != region["encrypted_sha256"]:
                die(f"encrypted SHA-256 mismatch: {name}")
            cipher_path = tmpdir / f"{name}.encrypted.bin"
            plain_path = tmpdir / f"{name}.plain.bin"
            cipher_path.write_bytes(encrypted)
            run([sys.executable, "-m", "espsecure", "decrypt_flash_data", "--aes_xts",
                 "--keyfile", str(xts_key), "--address", hex(offset),
                 "--output", str(plain_path), str(cipher_path)])
            if sha256_file(plain_path) != region["plaintext_sha256"]:
                die(f"decrypted plaintext SHA-256 mismatch: {name}")
            decrypted_paths[name] = plain_path

        app_bytes = decrypted_paths["ota0"].read_bytes()
        if len(app_bytes) < APP_DESC_OFFSET + 8:
            die("ota_0 application is too small for esp_app_desc")
        app_magic, image_security_version = struct.unpack_from("<II", app_bytes, APP_DESC_OFFSET)
        if app_magic != APP_DESC_MAGIC:
            die("ota_0 application descriptor magic mismatch")
        if image_security_version != security_version:
            die(f"manifest/image security_version mismatch: {security_version} != {image_security_version}")
        for name in ("bootloader", "ota0"):
            run([sys.executable, "-m", "espsecure", "verify_signature", "--version", "2",
                 "--keyfile", str(signing_key), str(decrypted_paths[name])])
        for name, expected_size in EXPECTED_ERASED.items():
            data = decrypted_paths[name].read_bytes()
            if len(data) != expected_size or any(b != 0xFF for b in data):
                die(f"decrypted initial {name} is not erased plaintext flash")

    print(f"A/B bundle: PASS ({bundle})")
    print(f"sha256: {manifest['bundle']['sha256']}")
    print(f"security version: {security_version} (eFuse floor remains 0)")
    print("XTS decrypt/plaintext hashes: PASS")
    print("RSA-PSS bootloader/ota_0 signatures: PASS")
    print("otadata/ota_1/part0 erased plaintext: PASS")
    print("eFuse anti-rollback: disabled")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle_dir", type=Path, nargs="?", default=Path("build-ab-security-bundle"))
    parser.add_argument("provision_dir", type=Path, nargs="?", default=Path("build-provisioning"))
    args = parser.parse_args()
    verify(args.bundle_dir, args.provision_dir)


if __name__ == "__main__":
    main()
