#!/usr/bin/env python3
"""Generate and describe deterministic ESP32-S3 Pico FIDO2 provisioning material.

Key provisioning stays host-only. The only device-write path is the explicit
``security-version --apply`` command, which advances the ESP32-S3 anti-rollback
SECURE_VERSION floor after checking the current canonical unary value.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import secrets
import stat
import subprocess
import sys
from pathlib import Path

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MAX_SECURITY_VERSION = 16

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


def capture(args: list[str]) -> str:
    try:
        result = subprocess.run(args, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "espefuse command failed").strip()
        raise SystemExit(detail) from exc
    return result.stdout


def security_version_mask(floor: int) -> int:
    if not 0 <= floor <= MAX_SECURITY_VERSION:
        raise SystemExit(f"security floor must be from 0 to {MAX_SECURITY_VERSION}")
    return (1 << floor) - 1 if floor else 0


def security_version_floor(raw: int) -> int:
    if not 0 <= raw <= 0xFFFF:
        raise SystemExit(f"SECURE_VERSION raw value is out of range: 0x{raw:x}")
    floor = raw.bit_count()
    if raw != security_version_mask(floor):
        raise SystemExit(f"non-canonical SECURE_VERSION raw value 0x{raw:04x}")
    return floor


def normalize_mac(value: str) -> str:
    candidate = value.strip().split()[0].replace("-", ":").lower()
    parts = candidate.split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        raise ValueError(f"invalid MAC address: {value}")
    try:
        parsed = [int(part, 16) for part in parts]
    except ValueError as exc:
        raise ValueError(f"invalid MAC address: {value}") from exc
    return ":".join(f"{part:02x}" for part in parsed)


def mac_argument(value: str) -> str:
    try:
        return normalize_mac(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def espefuse_base(*, port: str | None = None, virt_file: Path | None = None) -> list[str]:
    args = [sys.executable, "-m", "espefuse", "--chip", "esp32s3"]
    if port is not None:
        args.extend(["--port", port])
    elif virt_file is not None:
        args.extend(["--virt", "--path-efuse-file", str(virt_file)])
    else:
        raise SystemExit("espefuse source is required")
    return args


def read_security_state(
    *, port: str | None = None, virt_file: Path | None = None
) -> tuple[int, bool, str]:
    output = capture(espefuse_base(port=port, virt_file=virt_file) + [
        "summary", "SECURE_VERSION", "MAC", "--format", "json"
    ])
    start = output.find("{")
    if start < 0:
        raise SystemExit("espefuse security-state JSON was not found")
    try:
        data = json.loads(output[start:])
        entry = data["SECURE_VERSION"]
        raw = int(entry["raw_value"], 0)
        writeable = bool(entry["writeable"])
        mac = normalize_mac(str(data["MAC"]["value"]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit("invalid espefuse security-state JSON") from exc
    if entry.get("bit_len") != MAX_SECURITY_VERSION:
        raise SystemExit(f"unexpected SECURE_VERSION width: {entry.get('bit_len')}")
    security_version_floor(raw)
    return raw, writeable, mac


def security_version_command(args: argparse.Namespace) -> None:
    if args.apply and args.expect_current is None:
        raise SystemExit("--apply requires --expect-current")
    if args.apply and args.port is not None and args.expect_mac is None:
        raise SystemExit("--apply on a real device requires --expect-mac")

    if args.current is not None:
        if args.apply:
            raise SystemExit("--apply requires --port or --virt-file, not --current")
        if args.expect_current is not None or args.expect_mac is not None:
            raise SystemExit("expected device guards are only valid with --port or --virt-file")
        current_raw = security_version_mask(args.current)
        current_floor = args.current
        writeable = False
        device_mac = None
        source = "offline"
        base = None
    else:
        current_raw, writeable, device_mac = read_security_state(
            port=args.port, virt_file=args.virt_file
        )
        current_floor = security_version_floor(current_raw)
        source = "virtual" if args.virt_file is not None else args.port
        base = espefuse_base(port=args.port, virt_file=args.virt_file)

    if args.target < current_floor:
        raise SystemExit(f"cannot lower security floor from {current_floor} to {args.target}")
    if args.expect_current is not None and args.expect_current != current_floor:
        raise SystemExit(
            f"expected current floor {args.expect_current}, device reports {current_floor}"
        )
    if args.expect_mac is not None and args.expect_mac != device_mac:
        raise SystemExit(f"expected MAC {args.expect_mac}, device reports {device_mac}")

    target_raw = security_version_mask(args.target)
    new_bits = target_raw & ~current_raw
    print("ESP32-S3 SECURE_VERSION plan")
    print(f"source:        {source}")
    if device_mac is not None:
        print(f"device MAC:    {device_mac}")
    print(f"current floor: {current_floor} (raw 0x{current_raw:04x})")
    print(f"target floor:  {args.target} (raw 0x{target_raw:04x})")
    print(f"new bits:      0x{new_bits:04x}")

    if base is not None:
        burn = base + [
            "--do-not-confirm", "burn_efuse", "SECURE_VERSION", f"0x{target_raw:04x}"
        ]
        print(f"burn command:  {shlex.join(burn)}")

    if not args.apply:
        print("device write:  no")
        return
    if new_bits == 0:
        print("device write:  no (already at target)")
        return
    if not writeable:
        raise SystemExit("SECURE_VERSION is write-protected")

    assert base is not None
    fresh_raw, fresh_writeable, fresh_mac = read_security_state(
        port=args.port, virt_file=args.virt_file
    )
    if fresh_raw != current_raw or fresh_mac != device_mac:
        raise SystemExit("device security state changed between plan and apply")
    if not fresh_writeable:
        raise SystemExit("SECURE_VERSION became write-protected before apply")
    capture(burn)
    final_raw, _, final_mac = read_security_state(port=args.port, virt_file=args.virt_file)
    if final_mac != device_mac:
        raise SystemExit("device MAC changed during SECURE_VERSION apply")
    if final_raw != target_raw:
        raise SystemExit(
            f"SECURE_VERSION verification failed: 0x{final_raw:04x} != 0x{target_raw:04x}"
        )
    if args.virt_file is not None:
        print("device write:  virtual eFuse applied")
    else:
        print("device write:  applied")
    print(f"verified raw:  0x{final_raw:04x}")


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
    print("Key provisioning commands never write a device.")
    print("Only 'security-version --apply' can burn SECURE_VERSION; real hardware also requires current-floor and MAC guards.")


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
    secver = sub.add_parser("security-version", help="plan or apply the anti-rollback SECURE_VERSION floor")
    source = secver.add_mutually_exclusive_group(required=True)
    source.add_argument("--current", type=int, help="offline current floor (0..16)")
    source.add_argument("--port", help="ESP32-S3 serial port to inspect")
    source.add_argument("--virt-file", type=Path, help="espefuse virtual backing file for host tests")
    secver.add_argument("--target", type=int, required=True, help="target floor (0..16)")
    secver.add_argument("--expect-current", type=int, help="required current floor guard for --apply")
    secver.add_argument("--expect-mac", type=mac_argument, help="required factory MAC guard for real-device --apply")
    secver.add_argument("--apply", action="store_true", help="irreversibly burn the target floor")
    args = parser.parse_args()

    for name in ("current", "target", "expect_current"):
        value = getattr(args, name, None)
        if value is not None and not 0 <= value <= MAX_SECURITY_VERSION:
            parser.error(f"--{name.replace('_', '-')} must be from 0 to {MAX_SECURITY_VERSION}")

    if args.command == "plan":
        print_plan()
    elif args.command == "generate":
        manifest = generate(args.output_dir)
        print(f"generated: {manifest}")
        print(f"secure boot digest: {json.loads(manifest.read_text())['secure_boot_digest_hex']}")
    elif args.command == "verify":
        verify_manifest(args.manifest)
    else:
        security_version_command(args)


if __name__ == "__main__":
    main()
