#!/usr/bin/env python3
"""Offline integrity/crypto verification for an ESP32-S3 security bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

EXPECTED_OFFSETS = {
    "bootloader": 0x000000,
    "partition": 0x010000,
    "app": 0x020000,
    "part0": 0x200000,
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def die(message: str) -> None:
    raise SystemExit(f"security-bundle verify: {message}")


def parse_offset(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise SystemExit(f"invalid region offset: {value}") from exc


def run(args: list[str]) -> None:
    try:
        subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as exc:
        die(f"command failed: {' '.join(args[:4])}")


def verify(bundle_dir: Path, provision_dir: Path) -> None:
    probe = subprocess.run(
        [sys.executable, "-m", "espsecure", "--help"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if probe.returncode != 0:
        die("espsecure is unavailable; activate ESP-IDF 5.5 before verification")

    manifest_path = bundle_dir / "manifest.json"
    provision_manifest_path = provision_dir / "manifest.json"
    if not manifest_path.is_file() or not provision_manifest_path.is_file():
        die("bundle or provisioning manifest is missing")

    manifest = json.loads(manifest_path.read_text())
    provision_manifest = json.loads(provision_manifest_path.read_text())
    if manifest.get("chip") != "esp32s3" or provision_manifest.get("chip") != "esp32s3":
        die("unexpected chip in manifest")
    if manifest.get("flash_bytes") != 0x400000:
        die("bundle manifest is not 4 MiB")
    if manifest.get("provisioning_manifest_sha256") != sha256_file(provision_manifest_path):
        die("provisioning manifest hash mismatch")
    if manifest.get("secure_boot_digest_hex") != provision_manifest.get("secure_boot_digest_hex"):
        die("Secure Boot digest manifest mismatch")

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

    with tempfile.TemporaryDirectory(prefix="pico-security-bundle-verify-") as tmp:
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
            run(
                [
                    sys.executable,
                    "-m",
                    "espsecure",
                    "decrypt_flash_data",
                    "--aes_xts",
                    "--keyfile",
                    str(xts_key),
                    "--address",
                    hex(offset),
                    "--output",
                    str(plain_path),
                    str(cipher_path),
                ]
            )
            if sha256_file(plain_path) != region["plaintext_sha256"]:
                die(f"decrypted plaintext SHA-256 mismatch: {name}")
            decrypted_paths[name] = plain_path

        for name in ("bootloader", "app"):
            run(
                [
                    sys.executable,
                    "-m",
                    "espsecure",
                    "verify_signature",
                    "--version",
                    "2",
                    "--keyfile",
                    str(signing_key),
                    str(decrypted_paths[name]),
                ]
            )

        part0 = decrypted_paths["part0"].read_bytes()
        if len(part0) != 0x100000 or any(b != 0xFF for b in part0):
            die("decrypted initial part0 is not erased flash")

    print(f"bundle: PASS ({bundle})")
    print(f"sha256: {manifest['bundle']['sha256']}")
    print(f"secure boot digest: {manifest['secure_boot_digest_hex']}")
    print("XTS decrypt/plaintext hashes: PASS")
    print("RSA-PSS bootloader/app signatures: PASS")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle_dir", type=Path, nargs="?", default=Path("build-security-bundle"))
    parser.add_argument("provision_dir", type=Path, nargs="?", default=Path("build-provisioning"))
    args = parser.parse_args()
    verify(args.bundle_dir, args.provision_dir)


if __name__ == "__main__":
    main()
