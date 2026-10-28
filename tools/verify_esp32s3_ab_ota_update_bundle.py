#!/usr/bin/env python3
"""Offline verification for an ESP32-S3 Secure Boot signed A/B OTA application."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

APP_DESC_OFFSET = 24 + 8
APP_DESC_MAGIC = 0xABCD5432
APP_DESC_VERSION_OFFSET = 16
APP_DESC_PROJECT_OFFSET = 48
APP_DESC_STRING_LEN = 32
MAX_SECURITY_VERSION = 16
EXPECTED_SLOT_CAPACITY = 0x170000
EXPECTED_PROJECT = "pico_fido2"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def die(message: str) -> None:
    raise SystemExit(f"ab-ota-update verify: {message}")


def run(args: list[str]) -> None:
    try:
        subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        die(f"command failed: {' '.join(args[:4])}")


def c_string(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("utf-8", errors="strict")


def app_identity(path: Path) -> tuple[int, str, str]:
    data = path.read_bytes()
    required = APP_DESC_OFFSET + APP_DESC_PROJECT_OFFSET + APP_DESC_STRING_LEN
    if len(data) < required:
        die("application is too small for esp_app_desc")
    base = APP_DESC_OFFSET
    magic, security_version = struct.unpack_from("<II", data, base)
    if magic != APP_DESC_MAGIC:
        die("application descriptor magic mismatch")
    version = c_string(data[base + APP_DESC_VERSION_OFFSET:base + APP_DESC_VERSION_OFFSET + APP_DESC_STRING_LEN])
    project = c_string(data[base + APP_DESC_PROJECT_OFFSET:base + APP_DESC_PROJECT_OFFSET + APP_DESC_STRING_LEN])
    return security_version, version, project


def verify(bundle_dir: Path, provision_dir: Path, minimum_running_epoch: int = 0) -> None:
    manifest_path = bundle_dir / "manifest.json"
    provision_manifest_path = provision_dir / "manifest.json"
    if not manifest_path.is_file() or not provision_manifest_path.is_file():
        die("OTA or provisioning manifest is missing")

    manifest = json.loads(manifest_path.read_text())
    provision = json.loads(provision_manifest_path.read_text())
    if manifest.get("schema") != 1 or manifest.get("kind") != "esp32s3-ab-ota-update":
        die("unexpected OTA manifest schema/kind")
    if manifest.get("chip") != "esp32s3" or provision.get("chip") != "esp32s3":
        die("unexpected chip")
    if manifest.get("project_name") != EXPECTED_PROJECT:
        die("unexpected project name")
    if manifest.get("slot_capacity") != EXPECTED_SLOT_CAPACITY:
        die("unexpected A/B slot capacity")
    if manifest.get("provisioning_manifest_sha256") != sha256(provision_manifest_path):
        die("provisioning manifest hash mismatch")
    if manifest.get("secure_boot_digest_hex") != provision.get("secure_boot_digest_hex"):
        die("Secure Boot digest mismatch")

    security_version = manifest.get("security_version")
    if not isinstance(security_version, int) or not 0 <= security_version <= MAX_SECURITY_VERSION:
        die("invalid security_version")
    if not 0 <= minimum_running_epoch <= MAX_SECURITY_VERSION:
        die("minimum running epoch must be from 0 to 16")
    if security_version < minimum_running_epoch:
        die(f"security_version {security_version} is below running image epoch {minimum_running_epoch}")

    artifact_meta = manifest.get("artifact", {})
    artifact = bundle_dir / artifact_meta.get("file", "")
    if not artifact.is_file():
        die("signed plaintext OTA application is missing")
    if artifact.stat().st_size != artifact_meta.get("bytes") or sha256(artifact) != artifact_meta.get("sha256"):
        die("OTA artifact hash/size mismatch")
    if artifact.stat().st_size > EXPECTED_SLOT_CAPACITY:
        die("OTA artifact does not fit one A/B slot")

    image_epoch, image_version, image_project = app_identity(artifact)
    if image_epoch != security_version:
        die(f"manifest/image security_version mismatch: {security_version} != {image_epoch}")
    if image_version != manifest.get("project_version"):
        die("manifest/image project version mismatch")
    if image_project != manifest.get("project_name"):
        die("manifest/image project name mismatch")

    signing_key = provision_dir / "secure_boot_signing_key.pem"
    if not signing_key.is_file():
        die("Secure Boot signing key is missing")
    run([
        sys.executable, "-m", "espsecure", "verify_signature", "--version", "2",
        "--keyfile", str(signing_key), str(artifact),
    ])

    contract = manifest.get("update_contract", {})
    expected_contract = {
        "artifact_format": "secure-boot-signed-plaintext-app",
        "device_writer": "esp_ota_write",
        "efuse_changes": "none",
        "efuse_anti_rollback": False,
        "host_flash_encryption_key_required": False,
        "target": "inactive OTA app partition selected by esp_ota_get_next_update_partition",
    }
    for key, value in expected_contract.items():
        if contract.get(key) != value:
            die(f"unexpected OTA update contract: {key}")

    print(f"A/B OTA update: PASS ({artifact})")
    print(f"version: {image_version}")
    print(f"security version: {image_epoch} (running epoch floor {minimum_running_epoch})")
    print(f"signed plaintext sha256: {artifact_meta['sha256']}")
    print("RSA-PSS signature: PASS")
    print("host KEY1 required: no")
    print("eFuse changes required: none")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle_dir", type=Path, nargs="?", default=Path("build-ab-ota-update"))
    parser.add_argument("provision_dir", type=Path, nargs="?", default=Path("build-provisioning"))
    parser.add_argument("--minimum-running-epoch", type=int, default=0,
                        help="minimum currently running signed image epoch (0..16)")
    args = parser.parse_args()
    verify(args.bundle_dir, args.provision_dir, args.minimum_running_epoch)


if __name__ == "__main__":
    main()
