#!/usr/bin/env python3
"""Safely inspect and apply an ESP32-S3 pre-encrypted app-only update.

This tool never writes eFuses.  The apply path is intentionally restricted to
one raw ciphertext write at the fixed factory-app offset (0x20000), after
verifying the bundle and binding the operation to both the device MAC and the
ciphertext SHA-256 supplied by the operator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import string
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from esp32s3_provision import normalize_mac, security_version_floor

APP_OFFSET = 0x20000
APP_PREFIX_BYTES = 0x1000
APP_DESC_OFFSET = 32
APP_DESC_MAGIC = 0xABCD5432
EXPECTED_PROJECT_NAME = "pico_fido2"
EFUSE_FIELDS = (
    "SECURE_BOOT_EN",
    "SPI_BOOT_CRYPT_CNT",
    "DIS_DOWNLOAD_MODE",
    "DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE",
    "SECURE_VERSION",
    "MAC",
    "KEY_PURPOSE_0",
    "BLOCK_KEY0",
)


class UpdateError(RuntimeError):
    pass


@dataclass(frozen=True)
class DeviceSecurityState:
    mac: str
    secure_boot: bool
    flash_encryption: bool
    flash_encryption_raw: int
    download_mode_enabled: bool
    usb_download_mode_enabled: bool
    security_version_raw: int
    security_floor: int
    key0_purpose: str
    key0_digest_hex: str | None


@dataclass(frozen=True)
class UpdateBundle:
    directory: Path
    manifest_path: Path
    encrypted_path: Path
    encrypted_sha256: str
    security_version: int
    project_version: str
    secure_boot_digest_hex: str


@dataclass(frozen=True)
class CurrentAppIdentity:
    project_name: str
    project_version: str
    security_version: int


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def capture(args: list[str]) -> str:
    try:
        result = subprocess.run(args, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "command failed").strip()
        raise UpdateError(detail) from exc
    return result.stdout


def run(args: list[str]) -> None:
    try:
        subprocess.run(args, check=True)
    except subprocess.CalledProcessError as exc:
        raise UpdateError(f"command failed with exit code {exc.returncode}: {shlex.join(args)}") from exc


def _json_from_output(output: str) -> dict[str, object]:
    start = output.find("{")
    if start < 0:
        raise UpdateError("espefuse JSON output was not found")
    try:
        data = json.loads(output[start:])
    except json.JSONDecodeError as exc:
        raise UpdateError("invalid espefuse JSON output") from exc
    if not isinstance(data, dict):
        raise UpdateError("unexpected espefuse JSON root")
    return data


def _field(data: dict[str, object], name: str) -> dict[str, object]:
    value = data.get(name)
    if not isinstance(value, dict):
        raise UpdateError(f"missing eFuse field: {name}")
    return value


def _raw_int(entry: dict[str, object], name: str) -> int:
    try:
        return int(str(entry["raw_value"]), 0)
    except (KeyError, TypeError, ValueError) as exc:
        raise UpdateError(f"invalid raw eFuse value: {name}") from exc


def _bool_value(entry: dict[str, object], name: str) -> bool:
    value = entry.get("value")
    if not isinstance(value, bool):
        raise UpdateError(f"invalid boolean eFuse value: {name}")
    return value


def _digest_value(entry: dict[str, object]) -> str | None:
    if entry.get("readable") is not True:
        return None
    value = entry.get("value")
    if not isinstance(value, str):
        raise UpdateError("invalid readable KEY0 digest")
    compact = "".join(value.split()).lower()
    if len(compact) != 64 or any(c not in string.hexdigits.lower() for c in compact):
        raise UpdateError("invalid readable KEY0 digest")
    return compact


def parse_device_state(data: dict[str, object]) -> DeviceSecurityState:
    secure_version = _field(data, "SECURE_VERSION")
    if secure_version.get("bit_len") != 16:
        raise UpdateError(f"unexpected SECURE_VERSION width: {secure_version.get('bit_len')}")
    security_raw = _raw_int(secure_version, "SECURE_VERSION")
    try:
        floor = security_version_floor(security_raw)
    except SystemExit as exc:
        raise UpdateError(str(exc)) from exc

    crypt_raw = _raw_int(_field(data, "SPI_BOOT_CRYPT_CNT"), "SPI_BOOT_CRYPT_CNT")
    if not 0 <= crypt_raw <= 0x7:
        raise UpdateError(f"invalid SPI_BOOT_CRYPT_CNT raw value: 0x{crypt_raw:x}")

    mac_entry = _field(data, "MAC")
    try:
        mac = normalize_mac(str(mac_entry["value"]))
    except (KeyError, ValueError) as exc:
        raise UpdateError("invalid device MAC") from exc

    purpose = str(_field(data, "KEY_PURPOSE_0").get("value", ""))
    return DeviceSecurityState(
        mac=mac,
        secure_boot=_bool_value(_field(data, "SECURE_BOOT_EN"), "SECURE_BOOT_EN"),
        flash_encryption=(crypt_raw.bit_count() % 2) == 1,
        flash_encryption_raw=crypt_raw,
        download_mode_enabled=not _bool_value(_field(data, "DIS_DOWNLOAD_MODE"), "DIS_DOWNLOAD_MODE"),
        usb_download_mode_enabled=not _bool_value(
            _field(data, "DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE"),
            "DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE",
        ),
        security_version_raw=security_raw,
        security_floor=floor,
        key0_purpose=purpose,
        key0_digest_hex=_digest_value(_field(data, "BLOCK_KEY0")),
    )


def read_device_state(port: str) -> DeviceSecurityState:
    output = capture([
        sys.executable,
        "-m",
        "espefuse",
        "--chip",
        "esp32s3",
        "--port",
        port,
        "--before",
        "no_reset",
        "summary",
        *EFUSE_FIELDS,
        "--format",
        "json",
    ])
    return parse_device_state(_json_from_output(output))


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise UpdateError(f"cannot read JSON: {path}") from exc
    if not isinstance(value, dict):
        raise UpdateError(f"unexpected JSON root: {path}")
    return value


def load_bundle(bundle_dir: Path) -> UpdateBundle:
    manifest_path = bundle_dir / "manifest.json"
    manifest = _load_json(manifest_path)
    if manifest.get("schema") != 1 or manifest.get("kind") != "esp32s3-app-update":
        raise UpdateError("unexpected update manifest schema/kind")
    if manifest.get("chip") != "esp32s3":
        raise UpdateError("update bundle is not for ESP32-S3")
    try:
        offset = int(str(manifest["app_offset"]), 0)
        security_version = int(manifest["security_version"])
        project_version = str(manifest["project_version"])
        digest = str(manifest["secure_boot_digest_hex"]).lower()
        encrypted_meta = manifest["encrypted"]
        if not isinstance(encrypted_meta, dict):
            raise TypeError
        encrypted_path = bundle_dir / str(encrypted_meta["file"])
        expected_hash = str(encrypted_meta["sha256"]).lower()
        expected_bytes = int(encrypted_meta["bytes"])
    except (KeyError, TypeError, ValueError) as exc:
        raise UpdateError("invalid update manifest") from exc
    if offset != APP_OFFSET:
        raise UpdateError(f"unexpected app offset 0x{offset:x}")
    if len(digest) != 64 or any(c not in string.hexdigits.lower() for c in digest):
        raise UpdateError("invalid Secure Boot digest in update manifest")
    if not encrypted_path.is_file():
        raise UpdateError(f"encrypted update is missing: {encrypted_path}")
    actual_hash = sha256(encrypted_path)
    if actual_hash != expected_hash or encrypted_path.stat().st_size != expected_bytes:
        raise UpdateError("encrypted update hash/size mismatch")
    return UpdateBundle(
        directory=bundle_dir,
        manifest_path=manifest_path,
        encrypted_path=encrypted_path,
        encrypted_sha256=actual_hash,
        security_version=security_version,
        project_version=project_version,
        secure_boot_digest_hex=digest,
    )


def verify_bundle(bundle_dir: Path, provision_dir: Path, security_floor: int) -> UpdateBundle:
    verifier = Path(__file__).with_name("verify_esp32s3_update_bundle.py")
    try:
        subprocess.run([
            sys.executable,
            str(verifier),
            str(bundle_dir),
            str(provision_dir),
            "--security-floor",
            str(security_floor),
        ], check=True, stdout=subprocess.DEVNULL)
    except subprocess.CalledProcessError as exc:
        raise UpdateError("update bundle verification failed") from exc
    return load_bundle(bundle_dir)


def validate_device_for_update(state: DeviceSecurityState, bundle: UpdateBundle) -> None:
    if not state.secure_boot:
        raise UpdateError("device Secure Boot is not enabled")
    if not state.flash_encryption:
        raise UpdateError("device Flash Encryption is not enabled")
    if not state.download_mode_enabled:
        raise UpdateError("ROM download mode is disabled")
    if not state.usb_download_mode_enabled:
        raise UpdateError("USB Serial/JTAG ROM download mode is disabled")
    if state.key0_purpose != "SECURE_BOOT_DIGEST0":
        raise UpdateError(f"KEY0 purpose is {state.key0_purpose!r}, expected SECURE_BOOT_DIGEST0")
    if state.key0_digest_hex is None:
        raise UpdateError("KEY0 Secure Boot digest is not readable; refusing unbound update")
    if state.key0_digest_hex != bundle.secure_boot_digest_hex:
        raise UpdateError("update Secure Boot trust anchor does not match device KEY0")
    if bundle.security_version < state.security_floor:
        raise UpdateError(
            f"update security_version {bundle.security_version} is below device floor {state.security_floor}"
        )


def validate_decrypted_app_prefix(data: bytes) -> CurrentAppIdentity:
    if len(data) < APP_DESC_OFFSET + 256:
        raise UpdateError("decrypted current app prefix is too short")
    if data[0] != 0xE9 or not 1 <= data[1] <= 16:
        raise UpdateError("candidate KEY1 did not recover a valid ESP32-S3 image header")
    magic, security_version = struct.unpack_from("<II", data, APP_DESC_OFFSET)
    if magic != APP_DESC_MAGIC:
        raise UpdateError("candidate KEY1 did not recover a valid esp_app_desc")

    def fixed_string(start: int, size: int, label: str) -> str:
        raw = data[start:start + size].split(b"\0", 1)[0]
        try:
            value = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise UpdateError(f"candidate KEY1 produced invalid {label}") from exc
        if not value or any(ord(c) < 0x20 or ord(c) > 0x7E for c in value):
            raise UpdateError(f"candidate KEY1 produced invalid {label}")
        return value

    version = fixed_string(APP_DESC_OFFSET + 16, 32, "project version")
    project = fixed_string(APP_DESC_OFFSET + 48, 32, "project name")
    if project != EXPECTED_PROJECT_NAME:
        raise UpdateError(
            f"candidate KEY1 decrypted project {project!r}, expected {EXPECTED_PROJECT_NAME!r}"
        )
    return CurrentAppIdentity(project, version, security_version)


def verify_device_xts_key(port: str, provision_dir: Path) -> CurrentAppIdentity:
    xts_key = provision_dir / "flash_encryption_key.bin"
    if not xts_key.is_file() or xts_key.stat().st_size != 32:
        raise UpdateError("candidate KEY1 flash encryption key is missing or malformed")

    with tempfile.TemporaryDirectory(prefix="pico-update-key1-") as td:
        raw = Path(td) / "current-app-encrypted.bin"
        plain = Path(td) / "current-app-prefix.bin"
        capture([
            sys.executable,
            "-m",
            "esptool",
            "--chip",
            "esp32s3",
            "--port",
            port,
            "--before",
            "no_reset",
            "--after",
            "no_reset",
            "--no-stub",
            "read_flash",
            hex(APP_OFFSET),
            hex(APP_PREFIX_BYTES),
            str(raw),
        ])
        capture([
            sys.executable,
            "-m",
            "espsecure",
            "decrypt_flash_data",
            "--aes_xts",
            "--keyfile",
            str(xts_key),
            "--address",
            hex(APP_OFFSET),
            "--output",
            str(plain),
            str(raw),
        ])
        return validate_decrypted_app_prefix(plain.read_bytes())


def build_write_command(port: str, encrypted_path: Path) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "esptool",
        "--chip",
        "esp32s3",
        "--port",
        port,
        "--before",
        "no_reset",
        "--after",
        "no_reset",
        "--no-stub",
        "write_flash",
        hex(APP_OFFSET),
        str(encrypted_path),
    ]
    if "--encrypt" in command:
        raise AssertionError("pre-encrypted update must never use esptool --encrypt")
    return command


def build_read_command(port: str, offset: int, size: int, output_path: Path) -> list[str]:
    if offset < 0 or size <= 0:
        raise UpdateError("invalid flash read range")
    return [
        sys.executable,
        "-m",
        "esptool",
        "--chip",
        "esp32s3",
        "--port",
        port,
        "--before",
        "no_reset",
        "--after",
        "no_reset",
        "--no-stub",
        "read_flash",
        hex(offset),
        hex(size),
        str(output_path),
    ]


def read_raw_flash(port: str, offset: int, size: int, output_path: Path) -> None:
    capture(build_read_command(port, offset, size, output_path))


def verify_written_ciphertext(port: str, bundle: UpdateBundle) -> str:
    expected_size = bundle.encrypted_path.stat().st_size
    with tempfile.TemporaryDirectory(prefix="pico-update-readback-") as td:
        readback = Path(td) / "app-ciphertext.bin"
        read_raw_flash(port, APP_OFFSET, expected_size, readback)
        if readback.stat().st_size != expected_size:
            raise UpdateError(
                f"post-write ciphertext size {readback.stat().st_size} != expected {expected_size}"
            )
        actual_hash = sha256(readback)
    if actual_hash != bundle.encrypted_sha256:
        raise UpdateError(
            f"post-write ciphertext SHA256 {actual_hash} != expected {bundle.encrypted_sha256}"
        )
    return actual_hash


def print_plan(
    state: DeviceSecurityState,
    bundle: UpdateBundle,
    current_app: CurrentAppIdentity,
    port: str,
) -> None:
    print("ESP32-S3 app-only secure update plan")
    print(f"device:              {port}")
    print(f"device MAC:          {state.mac}")
    print(f"Secure Boot:         enabled")
    print(f"Flash Encryption:    enabled (SPI_BOOT_CRYPT_CNT=0x{state.flash_encryption_raw:x})")
    print(f"security floor:      {state.security_floor} (raw 0x{state.security_version_raw:04x})")
    print(f"KEY0 trust anchor:   {state.key0_digest_hex}")
    print(f"KEY1 binding:        PASS (current app {current_app.project_version})")
    print(f"update version:      {bundle.project_version}")
    print(f"update sec version:  {bundle.security_version}")
    print(f"ciphertext SHA256:   {bundle.encrypted_sha256}")
    print(f"write offset:        0x{APP_OFFSET:06x}")
    print("write format:        raw pre-encrypted ciphertext")
    print("eFuse writes:        none")
    print(f"write command:       {shlex.join(build_write_command(port, bundle.encrypted_path))}")


def inspect_command(args: argparse.Namespace) -> None:
    state = read_device_state(args.port)
    bundle = verify_bundle(args.bundle_dir, args.provision_dir, state.security_floor)
    validate_device_for_update(state, bundle)
    current_app = verify_device_xts_key(args.port, args.provision_dir)
    print_plan(state, bundle, current_app, args.port)
    print("device write:        no")


def apply_command(args: argparse.Namespace) -> None:
    expected_mac = normalize_mac(args.expect_mac)
    expected_hash = args.expect_update_sha256.lower()
    if len(expected_hash) != 64 or any(c not in string.hexdigits.lower() for c in expected_hash):
        raise UpdateError("--expect-update-sha256 must be 64 hexadecimal characters")

    planned_state = read_device_state(args.port)
    bundle = verify_bundle(args.bundle_dir, args.provision_dir, planned_state.security_floor)
    validate_device_for_update(planned_state, bundle)
    planned_app = verify_device_xts_key(args.port, args.provision_dir)
    if planned_state.mac != expected_mac:
        raise UpdateError(f"expected MAC {expected_mac}, device reports {planned_state.mac}")
    if bundle.encrypted_sha256 != expected_hash:
        raise UpdateError(
            f"expected update SHA256 {expected_hash}, bundle reports {bundle.encrypted_sha256}"
        )
    print_plan(planned_state, bundle, planned_app, args.port)

    fresh_state = read_device_state(args.port)
    fresh_bundle = verify_bundle(args.bundle_dir, args.provision_dir, fresh_state.security_floor)
    validate_device_for_update(fresh_state, fresh_bundle)
    fresh_app = verify_device_xts_key(args.port, args.provision_dir)
    if fresh_state != planned_state:
        raise UpdateError("device security state changed between plan and apply")
    if fresh_bundle.encrypted_sha256 != bundle.encrypted_sha256:
        raise UpdateError("update ciphertext changed between plan and apply")
    if fresh_app != planned_app:
        raise UpdateError("current encrypted app changed between plan and apply")

    command = build_write_command(args.port, fresh_bundle.encrypted_path)
    print("device write:        applying app ciphertext only")
    sys.stdout.flush()
    run(command)

    final_state = read_device_state(args.port)
    if final_state != fresh_state:
        raise UpdateError("CRITICAL: device eFuse/security state changed across app-only update")
    final_app = verify_device_xts_key(args.port, args.provision_dir)
    if final_app.project_version != fresh_bundle.project_version:
        raise UpdateError(
            f"post-write app version {final_app.project_version!r} != {fresh_bundle.project_version!r}"
        )
    if final_app.security_version != fresh_bundle.security_version:
        raise UpdateError(
            f"post-write app security_version {final_app.security_version} != {fresh_bundle.security_version}"
        )
    print("device write:        PASS")
    print(f"post-write app:      {final_app.project_version} / security_version {final_app.security_version}")
    print("eFuse state:         unchanged")
    print("device reset:        not performed; device remains in ROM download mode")


def verify_command(args: argparse.Namespace) -> None:
    bundle = verify_bundle(args.bundle_dir, args.provision_dir, args.security_floor)
    print(f"update bundle:       PASS ({bundle.project_version})")
    print(f"ciphertext SHA256:   {bundle.encrypted_sha256}")
    print(f"write offset:        0x{APP_OFFSET:06x}")
    print("device/eFuse write:  none")


def mac_argument(value: str) -> str:
    try:
        return normalize_mac(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    verify_parser = sub.add_parser("verify", help="offline bundle verification; no device access")
    verify_parser.add_argument("bundle_dir", type=Path)
    verify_parser.add_argument("provision_dir", type=Path)
    verify_parser.add_argument("--security-floor", type=int, default=0)
    verify_parser.set_defaults(func=verify_command)

    inspect_parser = sub.add_parser("inspect", help="verify bundle and inspect a connected device; no writes")
    inspect_parser.add_argument("bundle_dir", type=Path)
    inspect_parser.add_argument("provision_dir", type=Path)
    inspect_parser.add_argument("--port", required=True)
    inspect_parser.set_defaults(func=inspect_command)

    apply_parser = sub.add_parser("apply", help="write only the verified pre-encrypted app ciphertext")
    apply_parser.add_argument("bundle_dir", type=Path)
    apply_parser.add_argument("provision_dir", type=Path)
    apply_parser.add_argument("--port", required=True)
    apply_parser.add_argument("--expect-mac", required=True, type=mac_argument)
    apply_parser.add_argument("--expect-update-sha256", required=True)
    apply_parser.set_defaults(func=apply_command)

    args = parser.parse_args()
    try:
        args.func(args)
    except (UpdateError, ValueError) as exc:
        raise SystemExit(f"esp32s3-update: {exc}") from exc


if __name__ == "__main__":
    main()
