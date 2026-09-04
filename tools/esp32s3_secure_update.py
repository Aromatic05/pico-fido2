#!/usr/bin/env python3
"""Verify and physically reflash ESP32-S3 Secure Boot v2 images."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str], *, dry_run: bool = False) -> None:
    print("+", shlex.join(cmd))
    if not dry_run:
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as exc:
            raise SystemExit(exc.returncode) from None


def load_flasher_args(build_dir: Path) -> dict:
    path = build_dir / "flasher_args.json"
    if not path.is_file():
        raise SystemExit(f"missing ESP-IDF flash manifest: {path}")
    return json.loads(path.read_text())


def image_path(build_dir: Path, entry: dict) -> Path:
    path = build_dir / entry["file"]
    if not path.is_file():
        raise SystemExit(f"missing build artifact: {path}")
    return path


def verify_image(path: Path, keyfile: Path) -> None:
    run([
        sys.executable,
        "-m",
        "espsecure",
        "verify_signature",
        "--version",
        "2",
        "--keyfile",
        str(keyfile),
        str(path),
    ])


def verify(build_dir: Path, keyfile: Path, *, full: bool) -> dict:
    manifest = load_flasher_args(build_dir)
    if not keyfile.is_file():
        raise SystemExit(f"missing trusted Secure Boot key: {keyfile}")

    app = image_path(build_dir, manifest["app"])
    print(f"verify app: {app}")
    verify_image(app, keyfile)

    if full:
        bootloader = image_path(build_dir, manifest["bootloader"])
        print(f"verify bootloader: {bootloader}")
        verify_image(bootloader, keyfile)

    return manifest


def esptool_base(manifest: dict, port: str) -> list[str]:
    extra = manifest.get("extra_esptool_args", {})
    if extra.get("stub", True):
        raise SystemExit("refusing Secure Boot flash: ESP-IDF manifest does not disable the flasher stub")

    chip = extra.get("chip", "esp32s3")
    before = extra.get("before", "default_reset")
    after = extra.get("after", "no_reset")
    return [
        sys.executable,
        "-m",
        "esptool",
        "--chip",
        chip,
        "--port",
        port,
        "--before",
        before,
        "--after",
        after,
        "--no-stub",
    ]


def flash_args(
    manifest: dict,
    build_dir: Path,
    *,
    mode: str,
    include_bootloader: bool = False,
) -> list[str]:
    args = ["write_flash", *manifest.get("write_flash_args", [])]
    app = manifest["app"]
    if mode == "flash":
        entries = [(app["offset"], app["file"])]
    elif mode == "recover":
        partition = manifest["partition-table"]
        entries = [
            (partition["offset"], partition["file"]),
            (app["offset"], app["file"]),
        ]
        if include_bootloader:
            bootloader = manifest["bootloader"]
            entries.append((bootloader["offset"], bootloader["file"]))
            args.append("--force")
    else:
        raise ValueError(f"unsupported flash mode: {mode}")

    for offset, filename in sorted(entries, key=lambda item: int(item[0], 0)):
        path = build_dir / filename
        if not path.is_file():
            raise SystemExit(f"missing build artifact: {path}")
        args.extend([offset, str(path)])
    return args


def probe(port: str) -> None:
    run([
        sys.executable,
        "-m",
        "esptool",
        "--chip",
        "esp32s3",
        "--port",
        port,
        "--no-stub",
        "get_security_info",
    ])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify and physically reflash signed ESP32-S3 pico-fido2 firmware.",
    )
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--keyfile", type=Path, default=Path("secure_boot_signing_key.pem"))

    sub = parser.add_subparsers(dest="command", required=True)

    verify_parser = sub.add_parser("verify", help="verify signed app and bootloader")
    verify_parser.add_argument("--app-only", action="store_true")

    probe_parser = sub.add_parser("probe", help="read ROM security state")
    probe_parser.add_argument("--port", required=True)

    flash_parser = sub.add_parser("flash", help="update only the signed application image")
    flash_parser.add_argument("--port", required=True)
    flash_parser.add_argument("--dry-run", action="store_true")

    recover_parser = sub.add_parser(
        "recover",
        help="rewrite partition table and signed app while preserving the trusted bootloader",
    )
    recover_parser.add_argument("--port", required=True)
    recover_parser.add_argument("--dry-run", action="store_true")
    recover_parser.add_argument(
        "--include-bootloader",
        action="store_true",
        help="also rewrite the signed bootloader; requires esptool --force under Secure Boot",
    )

    args = parser.parse_args()
    build_dir = args.build_dir.resolve()
    keyfile = args.keyfile.resolve()

    if args.command == "probe":
        probe(args.port)
        return

    full = (
        (args.command == "verify" and not getattr(args, "app_only", False))
        or (args.command == "recover" and getattr(args, "include_bootloader", False))
    )
    manifest = verify(build_dir, keyfile, full=full)
    if args.command == "verify":
        return

    cmd = esptool_base(manifest, args.port)
    cmd += flash_args(
        manifest,
        build_dir,
        mode=args.command,
        include_bootloader=getattr(args, "include_bootloader", False),
    )
    run(cmd, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
