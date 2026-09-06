#!/usr/bin/env python3
"""Generate and validate ESP32-S3 Pico FIDO2 provisioning material.

KEY0/KEY1/KEY3/KEY4 provisioning has a virtual-eFuse rehearsal path only. It
cannot address a serial port or write physical hardware. The separate explicit
``security-version --apply`` command is the only real-device write path in this
tool and is intentionally independent from initial key provisioning.
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
from dataclasses import dataclass
from pathlib import Path

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MAX_SECURITY_VERSION = 16
PROVISION_KEY_BLOCKS = (0, 1, 3, 4)
PROVISION_FIELDS = (
    "SECURE_BOOT_EN",
    "SPI_BOOT_CRYPT_CNT",
    "DIS_DOWNLOAD_MODE",
    "DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE",
    "SECURE_VERSION",
    "MAC",
    "KEY_PURPOSE_0",
    "KEY_PURPOSE_1",
    "KEY_PURPOSE_3",
    "KEY_PURPOSE_4",
    "BLOCK_KEY0",
    "BLOCK_KEY1",
    "BLOCK_KEY3",
    "BLOCK_KEY4",
)

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

PROVISION_BURN = {
    0: (FILES["secure_boot_digest"], "SECURE_BOOT_DIGEST0"),
    1: (FILES["flash_encryption_key"], "XTS_AES_128_KEY"),
    3: (FILES["mkek"], "USER"),
    4: (FILES["device_key"], "USER"),
}


@dataclass(frozen=True)
class KeyBlockState:
    purpose: str
    purpose_writeable: bool
    readable: bool
    writeable: bool
    value: bytes | None
    raw_value: int


@dataclass(frozen=True)
class ProvisioningDeviceState:
    mac: str
    secure_boot: bool
    flash_encryption_raw: int
    security_version_raw: int
    security_floor: int
    download_mode_enabled: bool
    usb_download_mode_enabled: bool
    keys: dict[int, KeyBlockState]


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


def bind_target_manifest(provision_manifest: Path, factory_mac: str, output: Path) -> Path:
    verify_manifest(provision_manifest, quiet=True)
    provision = json.loads(provision_manifest.read_text())
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise SystemExit(f"target manifest already exists: {output}")
    target = {
        "schema": 1,
        "kind": "esp32s3-provisioning-target",
        "chip": "esp32s3",
        "factory_mac": normalize_mac(factory_mac),
        "provisioning_manifest_sha256": sha256(provision_manifest),
        "secure_boot_digest_hex": provision["secure_boot_digest_hex"],
    }
    write_secret(output, (json.dumps(target, indent=2, sort_keys=True) + "\n").encode())
    return output


def verify_target_manifest(target_path: Path, provision_manifest: Path) -> str:
    verify_manifest(provision_manifest, quiet=True)
    try:
        target = json.loads(target_path.read_text())
        provision = json.loads(provision_manifest.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid provisioning target manifest: {target_path}") from exc
    if target.get("schema") != 1 or target.get("kind") != "esp32s3-provisioning-target":
        raise SystemExit("unexpected provisioning target schema/kind")
    if target.get("chip") != "esp32s3":
        raise SystemExit("provisioning target is not for ESP32-S3")
    try:
        factory_mac = normalize_mac(str(target["factory_mac"]))
    except (KeyError, ValueError) as exc:
        raise SystemExit("invalid factory MAC in provisioning target") from exc
    if target.get("provisioning_manifest_sha256") != sha256(provision_manifest):
        raise SystemExit("target provisioning manifest hash mismatch")
    if target.get("secure_boot_digest_hex") != provision.get("secure_boot_digest_hex"):
        raise SystemExit("target Secure Boot digest mismatch")
    return factory_mac


def expected_mac_guard(args: argparse.Namespace, provision_manifest: Path | None = None) -> str | None:
    manual = getattr(args, "expect_mac", None)
    target_path = getattr(args, "target_manifest", None)
    target_mac = None
    if target_path is not None:
        if provision_manifest is None:
            raise SystemExit("--target-manifest requires --manifest")
        target_mac = verify_target_manifest(target_path, provision_manifest)
    if manual is not None and target_mac is not None and manual != target_mac:
        raise SystemExit(f"manual expected MAC {manual} disagrees with target manifest {target_mac}")
    return target_mac or manual


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


def read_efuse_json(
    fields: tuple[str, ...], *, port: str | None = None, virt_file: Path | None = None
) -> dict[str, object]:
    output = capture(espefuse_base(port=port, virt_file=virt_file) + [
        "summary", *fields, "--format", "json"
    ])
    start = output.find("{")
    if start < 0:
        raise SystemExit("espefuse JSON was not found")
    try:
        value = json.loads(output[start:])
    except json.JSONDecodeError as exc:
        raise SystemExit("invalid espefuse JSON") from exc
    if not isinstance(value, dict):
        raise SystemExit("unexpected espefuse JSON root")
    return value


def _efuse_entry(data: dict[str, object], name: str) -> dict[str, object]:
    value = data.get(name)
    if not isinstance(value, dict):
        raise SystemExit(f"missing eFuse field: {name}")
    return value


def _efuse_bool(data: dict[str, object], name: str) -> bool:
    value = _efuse_entry(data, name).get("value")
    if not isinstance(value, bool):
        raise SystemExit(f"invalid boolean eFuse field: {name}")
    return value


def _efuse_raw(data: dict[str, object], name: str) -> int:
    try:
        return int(str(_efuse_entry(data, name)["raw_value"]), 0)
    except (KeyError, TypeError, ValueError) as exc:
        raise SystemExit(f"invalid raw eFuse field: {name}") from exc


def _efuse_bytes(entry: dict[str, object], name: str) -> bytes | None:
    if entry.get("readable") is not True:
        return None
    value = entry.get("value")
    if not isinstance(value, str):
        raise SystemExit(f"invalid readable key block: {name}")
    compact = "".join(value.split())
    if len(compact) != 64:
        raise SystemExit(f"unexpected readable key length: {name}")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise SystemExit(f"invalid readable key block: {name}") from exc


def parse_provisioning_state(data: dict[str, object]) -> ProvisioningDeviceState:
    sec = _efuse_entry(data, "SECURE_VERSION")
    if sec.get("bit_len") != MAX_SECURITY_VERSION:
        raise SystemExit(f"unexpected SECURE_VERSION width: {sec.get('bit_len')}")
    sec_raw = _efuse_raw(data, "SECURE_VERSION")
    floor = security_version_floor(sec_raw)
    crypt_raw = _efuse_raw(data, "SPI_BOOT_CRYPT_CNT")
    if not 0 <= crypt_raw <= 0x7:
        raise SystemExit(f"invalid SPI_BOOT_CRYPT_CNT raw value: 0x{crypt_raw:x}")

    try:
        mac = normalize_mac(str(_efuse_entry(data, "MAC")["value"]))
    except (KeyError, ValueError) as exc:
        raise SystemExit("invalid factory MAC") from exc

    keys: dict[int, KeyBlockState] = {}
    for index in PROVISION_KEY_BLOCKS:
        purpose_name = f"KEY_PURPOSE_{index}"
        block_name = f"BLOCK_KEY{index}"
        purpose = _efuse_entry(data, purpose_name)
        block = _efuse_entry(data, block_name)
        keys[index] = KeyBlockState(
            purpose=str(purpose.get("value", "")),
            purpose_writeable=bool(purpose.get("writeable")),
            readable=bool(block.get("readable")),
            writeable=bool(block.get("writeable")),
            value=_efuse_bytes(block, block_name),
            raw_value=_efuse_raw(data, block_name),
        )

    return ProvisioningDeviceState(
        mac=mac,
        secure_boot=_efuse_bool(data, "SECURE_BOOT_EN"),
        flash_encryption_raw=crypt_raw,
        security_version_raw=sec_raw,
        security_floor=floor,
        download_mode_enabled=not _efuse_bool(data, "DIS_DOWNLOAD_MODE"),
        usb_download_mode_enabled=not _efuse_bool(data, "DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE"),
        keys=keys,
    )


def read_provisioning_state(
    *, port: str | None = None, virt_file: Path | None = None
) -> ProvisioningDeviceState:
    return parse_provisioning_state(
        read_efuse_json(PROVISION_FIELDS, port=port, virt_file=virt_file)
    )


def validate_pre_enable_state(state: ProvisioningDeviceState) -> None:
    if state.secure_boot:
        raise SystemExit("Secure Boot is already enabled")
    if state.flash_encryption_raw != 0:
        raise SystemExit(
            f"Flash Encryption enable count is already nonzero: 0x{state.flash_encryption_raw:x}"
        )
    if state.security_floor != 0:
        raise SystemExit(
            f"SECURE_VERSION must remain 0 during initial provisioning, found {state.security_floor}"
        )
    if not state.download_mode_enabled:
        raise SystemExit("ROM download mode is already disabled")
    if not state.usb_download_mode_enabled:
        raise SystemExit("USB Serial/JTAG ROM download mode is already disabled")


def validate_blank_provisioning_state(state: ProvisioningDeviceState) -> None:
    validate_pre_enable_state(state)
    for index in PROVISION_KEY_BLOCKS:
        key = state.keys[index]
        if key.purpose != "USER" or not key.purpose_writeable:
            raise SystemExit(f"KEY{index} purpose is not blank/writeable")
        if not key.readable or not key.writeable:
            raise SystemExit(f"KEY{index} block is not blank/readable/writeable")
        if key.raw_value != 0 or key.value != bytes(32):
            raise SystemExit(f"KEY{index} block is not empty")


def expected_provisioning_material(manifest_path: Path) -> dict[int, tuple[str, bool, bytes | None]]:
    manifest = json.loads(manifest_path.read_text())
    root = manifest_path.parent
    if manifest.get("chip") != "esp32s3" or manifest.get("layout") != LAYOUT:
        raise SystemExit("manifest chip/layout mismatch")
    digest = (root / FILES["secure_boot_digest"]).read_bytes()
    flash_key = (root / FILES["flash_encryption_key"]).read_bytes()
    mkek = (root / FILES["mkek"]).read_bytes()
    device_key = (root / FILES["device_key"]).read_bytes()
    if (
        len(digest) != 32
        or len(flash_key) != 32
        or len(mkek) != 32
        or len(device_key) != 32
    ):
        raise SystemExit("unexpected provisioning key length")
    return {
        0: ("SECURE_BOOT_DIGEST0", True, digest),
        1: ("XTS_AES_128_KEY", False, None),
        3: ("USER", True, mkek),
        4: ("USER", True, device_key),
    }


def key_block_is_blank(key: KeyBlockState) -> bool:
    return (
        key.purpose == "USER"
        and key.purpose_writeable
        and key.readable
        and key.writeable
        and key.raw_value == 0
        and key.value == bytes(32)
    )


def key_block_matches_expected(
    key: KeyBlockState,
    expected: tuple[str, bool, bytes | None],
) -> bool:
    purpose, readable, value = expected
    return (
        key.purpose == purpose
        and not key.purpose_writeable
        and not key.writeable
        and key.readable == readable
        and (not readable or key.value == value)
    )


def virtual_provisioning_pending_blocks(
    state: ProvisioningDeviceState,
    expected: dict[int, tuple[str, bool, bytes | None]],
) -> list[int]:
    validate_pre_enable_state(state)
    pending: list[int] = []
    provisioned: set[int] = set()
    for index in PROVISION_KEY_BLOCKS:
        key = state.keys[index]
        if key_block_matches_expected(key, expected[index]):
            provisioned.add(index)
        elif key_block_is_blank(key):
            pending.append(index)
        else:
            raise SystemExit(
                f"KEY{index} is neither blank nor an exact protected match for the provisioning manifest"
            )

    if 1 in provisioned and pending:
        raise SystemExit(
            "partial provisioning cannot be resumed after KEY1 became unreadable; "
            "refusing to assume Flash Encryption key material"
        )
    return pending


def virtual_provision_command(args: argparse.Namespace) -> None:
    if not args.virt_file.is_file():
        raise SystemExit(
            "--virt-file must already exist; initialize/inspect a blank virtual eFuse with preflight first"
        )
    verify_manifest(args.manifest, quiet=True)
    expected_mac = expected_mac_guard(args, args.manifest)
    expected = expected_provisioning_material(args.manifest)
    state = read_provisioning_state(virt_file=args.virt_file)
    if expected_mac is not None and expected_mac != state.mac:
        raise SystemExit(f"expected MAC {expected_mac}, device reports {state.mac}")
    pending = virtual_provisioning_pending_blocks(state, expected)

    print("ESP32-S3 virtual key provisioning rehearsal")
    print(f"source:              {args.virt_file}")
    print(f"manifest:            {args.manifest}")
    print(f"device MAC:          {state.mac}")
    print("SECURE_VERSION:      0")
    print("Secure Boot:         disabled")
    print("Flash Encryption:    disabled")
    print(
        "pending blocks:      "
        + (", ".join(f"KEY{index}" for index in pending) if pending else "none")
    )

    if not pending:
        validate_provisioned_device_state(state, expected)
        print("virtual write:       no (already provisioned)")
        return
    if not args.apply:
        print("virtual write:       no (dry-run)")
        return

    root = args.manifest.parent
    command = espefuse_base(virt_file=args.virt_file) + ["--do-not-confirm", "burn_key"]
    for index in pending:
        filename, purpose = PROVISION_BURN[index]
        command.extend([f"BLOCK_KEY{index}", str(root / filename), purpose])
    run(command, quiet=True)

    after = read_provisioning_state(virt_file=args.virt_file)
    if after.mac != state.mac:
        raise SystemExit("device MAC changed during virtual provisioning")
    validate_provisioned_device_state(after, expected)
    print("KEY0/1/3/4 layout:   PASS")
    print("KEY1 read protect:   PASS")
    print("virtual write:       applied")


def validate_provisioned_device_state(
    state: ProvisioningDeviceState,
    expected: dict[int, tuple[str, bool, bytes | None]],
) -> None:
    validate_pre_enable_state(state)
    validate_provisioned_key_layout(state, expected)


def validate_flash_encryption_pre_secure_state(
    state: ProvisioningDeviceState,
    expected: dict[int, tuple[str, bool, bytes | None]],
) -> None:
    if state.secure_boot:
        raise SystemExit("Secure Boot is already enabled before activation verification")
    if state.flash_encryption_raw != 0x1:
        raise SystemExit(
            "Flash Encryption activation checkpoint requires SPI_BOOT_CRYPT_CNT=0b001, "
            f"found 0x{state.flash_encryption_raw:x}"
        )
    if state.security_floor != 0:
        raise SystemExit(
            f"SECURE_VERSION must remain 0 in the current safe provisioning phase, found {state.security_floor}"
        )
    if not state.download_mode_enabled:
        raise SystemExit("ROM download recovery is disabled")
    if not state.usb_download_mode_enabled:
        raise SystemExit("USB Serial/JTAG ROM download recovery is disabled")
    validate_provisioned_key_layout(state, expected)


def activate_secure_virtual_command(args: argparse.Namespace) -> None:
    if not args.virt_file.is_file():
        raise SystemExit("--virt-file must already exist and contain provisioned KEY0/1/3/4")
    verify_manifest(args.manifest, quiet=True)
    expected_mac = expected_mac_guard(args, args.manifest)
    expected = expected_provisioning_material(args.manifest)
    state = read_provisioning_state(virt_file=args.virt_file)
    if expected_mac is not None and expected_mac != state.mac:
        raise SystemExit(f"expected MAC {expected_mac}, device reports {state.mac}")

    if state.secure_boot and state.flash_encryption_raw != 0x1:
        raise SystemExit(
            "unsafe activation order: Secure Boot is enabled but SPI_BOOT_CRYPT_CNT is not 0b001"
        )
    if state.secure_boot:
        validate_secure_device_state(state, expected)
        pending: list[str] = []
    elif state.flash_encryption_raw == 0:
        validate_provisioned_device_state(state, expected)
        pending = ["Flash Encryption", "Secure Boot"]
    elif state.flash_encryption_raw == 0x1:
        validate_flash_encryption_pre_secure_state(state, expected)
        pending = ["Secure Boot"]
    else:
        raise SystemExit(
            "experimental activation accepts only SPI_BOOT_CRYPT_CNT=0b000 or 0b001, "
            f"found 0b{state.flash_encryption_raw:03b}"
        )

    print("ESP32-S3 virtual security activation rehearsal")
    print(f"source:              {args.virt_file}")
    print(f"manifest:            {args.manifest}")
    if args.target_manifest is not None:
        print(f"target:              {args.target_manifest}")
    print(f"device MAC:          {state.mac}")
    print("SECURE_VERSION:      0")
    print("ROM recovery:        enabled")
    print("pending steps:       " + (" -> ".join(pending) if pending else "none"))

    if not pending:
        print("virtual write:       no (already secured)")
        return
    if not args.apply:
        print("virtual write:       no (dry-run)")
        return

    if state.flash_encryption_raw == 0:
        run(
            espefuse_base(virt_file=args.virt_file)
            + ["--do-not-confirm", "burn_efuse", "SPI_BOOT_CRYPT_CNT", "0x1"],
            quiet=True,
        )
        flash_state = read_provisioning_state(virt_file=args.virt_file)
        if flash_state.mac != state.mac:
            raise SystemExit("device MAC changed during Flash Encryption activation")
        validate_flash_encryption_pre_secure_state(flash_state, expected)
        state = flash_state
        print("Flash Encryption:    PASS (SPI_BOOT_CRYPT_CNT=0b001)")

    run(
        espefuse_base(virt_file=args.virt_file)
        + ["--do-not-confirm", "burn_efuse", "SECURE_BOOT_EN", "1"],
        quiet=True,
    )
    final = read_provisioning_state(virt_file=args.virt_file)
    if final.mac != state.mac:
        raise SystemExit("device MAC changed during Secure Boot activation")
    validate_secure_device_state(final, expected)
    print("Secure Boot:         PASS")
    print("SECURE_VERSION:      PASS (still 0)")
    print("virtual write:       applied")


def validate_provisioned_key_layout(
    state: ProvisioningDeviceState,
    expected: dict[int, tuple[str, bool, bytes | None]],
) -> None:
    for index in PROVISION_KEY_BLOCKS:
        key = state.keys[index]
        purpose, readable, value = expected[index]
        if key.purpose != purpose:
            raise SystemExit(f"KEY{index} purpose mismatch: {key.purpose!r} != {purpose!r}")
        if key.purpose_writeable:
            raise SystemExit(f"KEY{index} purpose is not write-protected")
        if key.writeable:
            raise SystemExit(f"KEY{index} block is not write-protected")
        if key.readable != readable:
            raise SystemExit(
                f"KEY{index} readability mismatch: {key.readable} != {readable}"
            )
        if readable and key.value != value:
            raise SystemExit(f"KEY{index} readable key material does not match provisioning manifest")


def validate_secure_device_state(
    state: ProvisioningDeviceState,
    expected: dict[int, tuple[str, bool, bytes | None]],
) -> None:
    if not state.secure_boot:
        raise SystemExit("Secure Boot is not enabled")
    if state.flash_encryption_raw != 0x1:
        raise SystemExit(
            "experimental secure state requires SPI_BOOT_CRYPT_CNT=0b001, "
            f"found 0x{state.flash_encryption_raw:x}"
        )
    if state.security_floor != 0:
        raise SystemExit(
            f"SECURE_VERSION must remain 0 in the current safe provisioning phase, found {state.security_floor}"
        )
    if not state.download_mode_enabled:
        raise SystemExit("ROM download recovery is disabled")
    if not state.usb_download_mode_enabled:
        raise SystemExit("USB Serial/JTAG ROM download recovery is disabled")
    validate_provisioned_key_layout(state, expected)


def guarded_provisioning_state(args: argparse.Namespace) -> ProvisioningDeviceState:
    manifest = getattr(args, "manifest", None)
    expected_mac = expected_mac_guard(args, manifest)
    if args.port is not None and expected_mac is None:
        raise SystemExit("real-device provisioning inspection requires --target-manifest or --expect-mac")
    state = read_provisioning_state(port=args.port, virt_file=args.virt_file)
    if expected_mac is not None and expected_mac != state.mac:
        raise SystemExit(f"expected MAC {expected_mac}, device reports {state.mac}")
    return state


def provisioning_state_command(args: argparse.Namespace, *, provisioned: bool) -> None:
    state = guarded_provisioning_state(args)

    if provisioned:
        verify_manifest(args.manifest, quiet=True)
        expected = expected_provisioning_material(args.manifest)
        validate_provisioned_device_state(state, expected)
        phase = "provisioned-key verification"
    else:
        validate_blank_provisioning_state(state)
        phase = "blank-device preflight"

    source = str(args.virt_file) if args.virt_file is not None else args.port
    print(f"ESP32-S3 {phase}: PASS")
    print(f"source:              {source}")
    print(f"device MAC:          {state.mac}")
    print("Secure Boot:         disabled")
    print("Flash Encryption:    disabled")
    print("SECURE_VERSION:      0")
    print("ROM recovery:        enabled")
    if provisioned:
        print("KEY0/1/3/4 layout:   PASS")
        print("readable key checks: PASS (KEY0/KEY3/KEY4)")
        print("KEY1 read protect:   PASS")
    else:
        print("KEY0/1/3/4 empty:    PASS")
        print("key blocks writeable: PASS")
    print("device write:        no")


def secure_state_command(args: argparse.Namespace) -> None:
    state = guarded_provisioning_state(args)
    verify_manifest(args.manifest, quiet=True)
    expected = expected_provisioning_material(args.manifest)
    validate_secure_device_state(state, expected)

    source = str(args.virt_file) if args.virt_file is not None else args.port
    print("ESP32-S3 secured-device verification: PASS")
    print(f"source:              {source}")
    print(f"device MAC:          {state.mac}")
    print("Secure Boot:         enabled")
    print("Flash Encryption:    enabled (SPI_BOOT_CRYPT_CNT=0b001)")
    print("SECURE_VERSION:      0")
    print("ROM recovery:        enabled")
    print("KEY0/1/3/4 layout:   PASS")
    print("readable key checks: PASS (KEY0/KEY3/KEY4)")
    print("KEY1 read protect:   PASS")
    print("device write:        no")


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
    print("KEY0/1/3/4 writes are available only against an espefuse --virt backing file.")
    print("There is no physical-device KEY0/KEY1/KEY3/KEY4 burn command.")
    print("Flash Encryption/Secure Boot enable-bit writes can likewise be rehearsed only with activate-secure-virtual.")
    print("There is no physical-device security activation command in this tool.")
    print("Only 'security-version --apply' can burn SECURE_VERSION; real hardware also requires current-floor and MAC guards.")


def verify_manifest(path: Path, *, quiet: bool = False) -> None:
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
    if not quiet:
        print(f"manifest: PASS ({path})")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="show the deterministic key/eFuse ownership plan")
    gen = sub.add_parser("generate", help="generate host-only provisioning material")
    gen.add_argument("--output-dir", type=Path, default=Path("build-provisioning"))
    bind_target = sub.add_parser("bind-target", help="bind provisioning material to one exact factory MAC")
    bind_target.add_argument("--manifest", type=Path, default=Path("build-provisioning/manifest.json"))
    bind_target.add_argument("--factory-mac", type=mac_argument, required=True)
    bind_target.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify", help="verify a generated manifest and artifacts")
    verify.add_argument("manifest", type=Path)
    preflight = sub.add_parser("preflight", help="read-only blank-device provisioning preflight")
    preflight_source = preflight.add_mutually_exclusive_group(required=True)
    preflight_source.add_argument("--port", help="ESP32-S3 serial port to inspect")
    preflight_source.add_argument("--virt-file", type=Path, help="espefuse virtual backing file for host tests")
    preflight.add_argument("--manifest", type=Path, default=Path("build-provisioning/manifest.json"))
    preflight.add_argument("--target-manifest", type=Path, help="device binding: exact factory MAC plus provisioning-manifest hash")
    preflight.add_argument("--expect-mac", type=mac_argument, help="manual factory MAC guard; target manifest is preferred")
    verify_device = sub.add_parser("verify-device", help="read-only verification after KEY0/1/3/4 provisioning")
    verify_source = verify_device.add_mutually_exclusive_group(required=True)
    verify_source.add_argument("--port", help="ESP32-S3 serial port to inspect")
    verify_source.add_argument("--virt-file", type=Path, help="espefuse virtual backing file for host tests")
    verify_device.add_argument("--manifest", type=Path, default=Path("build-provisioning/manifest.json"))
    verify_device.add_argument("--target-manifest", type=Path, help="device binding: exact factory MAC plus provisioning-manifest hash")
    verify_device.add_argument("--expect-mac", type=mac_argument, help="manual factory MAC guard; target manifest is preferred")
    verify_secure = sub.add_parser("verify-secure", help="read-only verification after Flash Encryption and Secure Boot enablement")
    verify_secure_source = verify_secure.add_mutually_exclusive_group(required=True)
    verify_secure_source.add_argument("--port", help="ESP32-S3 serial port to inspect")
    verify_secure_source.add_argument("--virt-file", type=Path, help="espefuse virtual backing file for host tests")
    verify_secure.add_argument("--manifest", type=Path, default=Path("build-provisioning/manifest.json"))
    verify_secure.add_argument("--target-manifest", type=Path, help="device binding: exact factory MAC plus provisioning-manifest hash")
    verify_secure.add_argument("--expect-mac", type=mac_argument, help="manual factory MAC guard; target manifest is preferred")
    provision_virtual = sub.add_parser(
        "provision-virtual",
        help="rehearse KEY0/1/3/4 provisioning against an espefuse virtual backing file only",
    )
    provision_virtual.add_argument("--virt-file", type=Path, required=True)
    provision_virtual.add_argument("--manifest", type=Path, default=Path("build-provisioning/manifest.json"))
    provision_virtual.add_argument("--target-manifest", type=Path, help="device binding checked before any virtual burn")
    provision_virtual.add_argument("--apply", action="store_true", help="write the virtual eFuse backing file")
    activate_virtual = sub.add_parser(
        "activate-secure-virtual",
        help="rehearse Flash Encryption then Secure Boot activation on a virtual eFuse only",
    )
    activate_virtual.add_argument("--virt-file", type=Path, required=True)
    activate_virtual.add_argument("--manifest", type=Path, default=Path("build-provisioning/manifest.json"))
    activate_virtual.add_argument("--target-manifest", type=Path, help="device binding checked before any virtual eFuse activation")
    activate_virtual.add_argument("--apply", action="store_true", help="write only the virtual eFuse backing file")
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
    elif args.command == "bind-target":
        target = bind_target_manifest(args.manifest, args.factory_mac, args.output)
        print(f"target: {target}")
        print(f"factory MAC: {args.factory_mac}")
        print(f"provisioning manifest SHA256: {sha256(args.manifest)}")
    elif args.command == "verify":
        verify_manifest(args.manifest)
    elif args.command == "preflight":
        provisioning_state_command(args, provisioned=False)
    elif args.command == "verify-device":
        provisioning_state_command(args, provisioned=True)
    elif args.command == "verify-secure":
        secure_state_command(args)
    elif args.command == "provision-virtual":
        virtual_provision_command(args)
    elif args.command == "activate-secure-virtual":
        activate_secure_virtual_command(args)
    else:
        security_version_command(args)


if __name__ == "__main__":
    main()
