#!/usr/bin/env python3
"""Generate and describe deterministic ESP32-S3 Pico FIDO2 provisioning material.

This tool intentionally has no device-write command. It is safe to use before a
hardware provisioning backend exists: it generates host secrets and a manifest,
and prints the exact eFuse ownership/policy expected by the firmware.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
from pathlib import Path

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

LAYOUT = [
    {
        "block": "KEY0",
        "purpose": "SECURE_BOOT_DIGEST0",
        "source": "secure_boot_signing_key.pem public-key digest",
        "readable": True,
    },
    {
        "block": "KEY1",
        "purpose": "XTS_AES_128_KEY",
        "source": "flash_encryption_key.bin",
        "readable": False,
    },
    {"block": "KEY2", "purpose": "FREE", "source": None, "readable": None},
    {
        "block": "KEY3",
        "purpose": "USER",
        "source": "mkek.bin",
        "readable": True,
    },
    {
        "block": "KEY4",
        "purpose": "USER",
        "source": "device_key_secp256k1.bin",
        "readable": True,
    },
    {"block": "KEY5", "purpose": "FREE", "source": None, "readable": None},
]

FILES = {
    "secure_boot_private": "secure_boot_signing_key.pem",
    "secure_boot_public": "secure_boot_signing_key.pub.pem",
    "secure_boot_digest": "secure_boot_digest.bin",
    "flash_encryption_key": "flash_encryption_key.bin",
    "mkek": "mkek.bin",
    "device_key": "device_key_secp256k1.bin",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_secret(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def run(args: list[str], *, quiet: bool = False) -> None:
    kwargs: dict[str, object] = {"check": True}
    if quiet:
        kwargs.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(args, **kwargs)


def require_empty_output_dir(out: Path) -> None:
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"output directory is not empty: {out}")
    out.mkdir(parents=True, exist_ok=True)


def generate(out: Path) -> Path:
    require_empty_output_dir(out)

    private = out / FILES["secure_boot_private"]
    public = out / FILES["secure_boot_public"]
    digest = out / FILES["secure_boot_digest"]
    flash_key = out / FILES["flash_encryption_key"]
    mkek = out / FILES["mkek"]
    device_key = out / FILES["device_key"]

    run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:3072",
            "-out",
            str(private),
        ],
        quiet=True,
    )
    os.chmod(private, stat.S_IRUSR | stat.S_IWUSR)
    run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], quiet=True)
    os.chmod(public, 0o600)

    try:
        run(
            [
                sys.executable,
                "-m",
                "espsecure",
                "digest_sbv2_public_key",
                "--keyfile",
                str(private),
                "--output",
                str(digest),
            ],
            quiet=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise SystemExit(
            "espsecure is required to generate the ESP32-S3 Secure Boot v2 digest; activate ESP-IDF 5.5 first"
        ) from exc
    os.chmod(digest, 0o600)

    write_secret(flash_key, os.urandom(32))
    write_secret(mkek, os.urandom(32))
    scalar = secrets.randbelow(SECP256K1_ORDER - 1) + 1
    write_secret(device_key, scalar.to_bytes(32, "big"))

    if len(digest.read_bytes()) != 32:
        raise SystemExit("unexpected Secure Boot digest length")
    if len(flash_key.read_bytes()) != 32 or len(mkek.read_bytes()) != 32:
        raise SystemExit("unexpected 256-bit key length")
    d = int.from_bytes(device_key.read_bytes(), "big")
    if not 1 <= d < SECP256K1_ORDER:
        raise SystemExit("invalid secp256k1 private scalar")

    manifest = {
        "schema": 1,
        "chip": "esp32s3",
        "policy": {
            "flash_encryption": "XTS-AES-128",
            "flash_encryption_development_crypt_count": "0b001",
            "flash_encryption_production_crypt_count": "0b111",
            "secure_boot": "v2/RSA-3072",
            "secure_boot_enable": "host-controlled-final-step",
            "jtag": "leave-enabled-during-experiment",
            "rom_download": "leave-enabled-during-experiment",
        },
        "layout": LAYOUT,
        "artifacts": {
            name: {
                "file": filename,
                "bytes": (out / filename).stat().st_size,
                "sha256": sha256(out / filename),
            }
            for name, filename in FILES.items()
        },
        "secure_boot_digest_hex": digest.read_bytes().hex(),
    }
    manifest_path = out / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    os.chmod(manifest_path, 0o600)
    return manifest_path


def print_plan() -> None:
    print("ESP32-S3 Pico FIDO2 deterministic provisioning plan")
    print()
    for item in LAYOUT:
        src = item["source"] or "-"
        readable = item["readable"]
        access = "free" if item["purpose"] == "FREE" else ("software-readable" if readable else "hardware-only")
        print(f"{item['block']}: {item['purpose']:<20} {access:<17} source={src}")
    print()
    print("Activation policy:")
    print("1. Verify target eFuse baseline and exact empty key blocks.")
    print("2. Generate RSA-3072, XTS-AES-128, MKEK, and secp256k1 material off-device.")
    print("3. Build signed firmware and host-encrypt all flash regions that require encryption.")
    print("4. Provision KEY0/KEY1/KEY3/KEY4 with the purposes above; keep KEY2/KEY5 free.")
    print("5. Program the encrypted, signed flash image while security enable bits are still off.")
    print("6. Experimental mode: set SPI_BOOT_CRYPT_CNT=0b001; leave JTAG/ROM download available.")
    print("7. Enable SECURE_BOOT_EN last, after image/key verification.")
    print("8. Production hardening, if wanted later, is a separate irreversible policy step.")
    print()
    print("This program has no eFuse burn or flash-write command.")


def verify_manifest(path: Path) -> None:
    manifest = json.loads(path.read_text())
    root = path.parent
    if manifest.get("chip") != "esp32s3" or manifest.get("layout") != LAYOUT:
        raise SystemExit("manifest chip/layout mismatch")
    for entry in manifest["artifacts"].values():
        p = root / entry["file"]
        if not p.is_file() or p.stat().st_size != entry["bytes"] or sha256(p) != entry["sha256"]:
            raise SystemExit(f"artifact integrity mismatch: {p}")
    device = root / FILES["device_key"]
    d = int.from_bytes(device.read_bytes(), "big")
    if not 1 <= d < SECP256K1_ORDER:
        raise SystemExit("invalid secp256k1 private scalar")
    if (root / FILES["secure_boot_digest"]).read_bytes().hex() != manifest["secure_boot_digest_hex"]:
        raise SystemExit("secure boot digest mismatch")
    print(f"manifest: PASS ({path})")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="show the deterministic key/eFuse ownership plan")
    gen = sub.add_parser("generate", help="generate host-only provisioning material")
    gen.add_argument("--output-dir", type=Path, default=Path("build-provisioning"))
    verify = sub.add_parser("verify", help="verify a generated manifest and artifacts")
    verify.add_argument("manifest", type=Path)
    args = parser.parse_args()

    if args.command == "plan":
        print_plan()
    elif args.command == "generate":
        manifest = generate(args.output_dir)
        print(f"generated: {manifest}")
        print(f"secure boot digest: {json.loads(manifest.read_text())['secure_boot_digest_hex']}")
    else:
        verify_manifest(args.manifest)


if __name__ == "__main__":
    main()
