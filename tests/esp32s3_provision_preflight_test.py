#!/usr/bin/env python3
"""Pure contracts for read-only ESP32-S3 provisioning inspection."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import esp32s3_provision as provision


def entry(value, raw: str, *, bit_len: int = 1, readable: bool = True, writeable: bool = True):
    return {
        "value": value,
        "raw_value": raw,
        "bit_len": bit_len,
        "readable": readable,
        "writeable": writeable,
    }


def blank_json() -> dict[str, object]:
    data: dict[str, object] = {
        "SECURE_BOOT_EN": entry(False, "0x0"),
        "SPI_BOOT_CRYPT_CNT": entry("Disable", "0x0", bit_len=3),
        "DIS_DOWNLOAD_MODE": entry(False, "0x0"),
        "DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE": entry(False, "0x0"),
        "SECURE_VERSION": entry(0, "0x0000", bit_len=16),
        "MAC": entry("12:34:56:78:9a:bc (OK)", "0x123456789abc", bit_len=48),
    }
    for index in provision.PROVISION_KEY_BLOCKS:
        data[f"KEY_PURPOSE_{index}"] = entry("USER", "0x0", bit_len=4)
        data[f"BLOCK_KEY{index}"] = entry(" ".join(["00"] * 32), "0x0", bit_len=256)
    return data


def expect_reject(func, needle: str) -> None:
    try:
        func()
    except SystemExit as exc:
        assert needle in str(exc), (needle, str(exc))
        return
    raise AssertionError(f"expected rejection containing {needle!r}")


def provisioned_state(expected: dict[int, tuple[str, bool, bytes | None]]) -> provision.ProvisioningDeviceState:
    keys = {
        index: provision.KeyBlockState(
            purpose=purpose,
            purpose_writeable=False,
            readable=readable,
            writeable=False,
            value=value if readable else None,
            raw_value=int.from_bytes(value, "big") if value is not None else 1,
        )
        for index, (purpose, readable, value) in expected.items()
    }
    return provision.ProvisioningDeviceState(
        mac="12:34:56:78:9a:bc",
        secure_boot=False,
        flash_encryption_raw=0,
        security_version_raw=0,
        security_floor=0,
        download_mode_enabled=True,
        usb_download_mode_enabled=True,
        keys=keys,
    )


def main() -> None:
    blank = provision.parse_provisioning_state(blank_json())
    provision.validate_blank_provisioning_state(blank)
    assert blank.mac == "12:34:56:78:9a:bc"
    assert blank.security_floor == 0

    expect_reject(
        lambda: provision.validate_blank_provisioning_state(replace(blank, secure_boot=True)),
        "Secure Boot",
    )
    expect_reject(
        lambda: provision.validate_blank_provisioning_state(replace(blank, flash_encryption_raw=1)),
        "Flash Encryption",
    )
    expect_reject(
        lambda: provision.validate_blank_provisioning_state(
            replace(blank, security_version_raw=1, security_floor=1)
        ),
        "SECURE_VERSION",
    )
    expect_reject(
        lambda: provision.validate_blank_provisioning_state(replace(blank, download_mode_enabled=False)),
        "ROM download",
    )
    expect_reject(
        lambda: provision.validate_blank_provisioning_state(replace(blank, usb_download_mode_enabled=False)),
        "USB Serial/JTAG",
    )

    bad_keys = dict(blank.keys)
    bad_keys[0] = replace(bad_keys[0], purpose="SECURE_BOOT_DIGEST0")
    expect_reject(
        lambda: provision.validate_blank_provisioning_state(replace(blank, keys=bad_keys)),
        "KEY0 purpose",
    )
    bad_keys = dict(blank.keys)
    bad_keys[1] = replace(bad_keys[1], raw_value=1, value=b"\0" * 31 + b"\1")
    expect_reject(
        lambda: provision.validate_blank_provisioning_state(replace(blank, keys=bad_keys)),
        "KEY1 block is not empty",
    )
    bad_keys = dict(blank.keys)
    bad_keys[3] = replace(bad_keys[3], writeable=False)
    expect_reject(
        lambda: provision.validate_blank_provisioning_state(replace(blank, keys=bad_keys)),
        "KEY3 block is not blank/readable/writeable",
    )

    expected = {
        0: ("SECURE_BOOT_DIGEST0", True, b"\x11" * 32),
        1: ("XTS_AES_128_KEY", False, None),
        3: ("USER", True, b"\x33" * 32),
        4: ("USER", True, b"\x44" * 32),
    }
    configured = provisioned_state(expected)
    provision.validate_provisioned_device_state(configured, expected)

    bad = dict(configured.keys)
    bad[0] = replace(bad[0], value=b"\x22" * 32)
    expect_reject(
        lambda: provision.validate_provisioned_device_state(replace(configured, keys=bad), expected),
        "KEY0 readable key material",
    )
    bad = dict(configured.keys)
    bad[1] = replace(bad[1], readable=True, value=b"\x55" * 32)
    expect_reject(
        lambda: provision.validate_provisioned_device_state(replace(configured, keys=bad), expected),
        "KEY1 readability mismatch",
    )
    bad = dict(configured.keys)
    bad[3] = replace(bad[3], purpose_writeable=True)
    expect_reject(
        lambda: provision.validate_provisioned_device_state(replace(configured, keys=bad), expected),
        "KEY3 purpose is not write-protected",
    )
    bad = dict(configured.keys)
    bad[4] = replace(bad[4], purpose="RESERVED")
    expect_reject(
        lambda: provision.validate_provisioned_device_state(replace(configured, keys=bad), expected),
        "KEY4 purpose mismatch",
    )
    expect_reject(
        lambda: provision.validate_provisioned_device_state(replace(configured, secure_boot=True), expected),
        "Secure Boot",
    )

    secured = replace(configured, secure_boot=True, flash_encryption_raw=0x1)
    provision.validate_secure_device_state(secured, expected)
    expect_reject(
        lambda: provision.validate_secure_device_state(replace(secured, secure_boot=False), expected),
        "Secure Boot is not enabled",
    )
    expect_reject(
        lambda: provision.validate_secure_device_state(replace(secured, flash_encryption_raw=0x0), expected),
        "SPI_BOOT_CRYPT_CNT=0b001",
    )
    expect_reject(
        lambda: provision.validate_secure_device_state(replace(secured, flash_encryption_raw=0x3), expected),
        "SPI_BOOT_CRYPT_CNT=0b001",
    )
    expect_reject(
        lambda: provision.validate_secure_device_state(
            replace(secured, security_version_raw=1, security_floor=1), expected
        ),
        "SECURE_VERSION must remain 0",
    )
    expect_reject(
        lambda: provision.validate_secure_device_state(
            replace(secured, download_mode_enabled=False), expected
        ),
        "ROM download recovery",
    )
    expect_reject(
        lambda: provision.validate_secure_device_state(
            replace(secured, usb_download_mode_enabled=False), expected
        ),
        "USB Serial/JTAG ROM download recovery",
    )
    secure_bad_keys = dict(secured.keys)
    secure_bad_keys[4] = replace(secure_bad_keys[4], value=b"\x55" * 32)
    expect_reject(
        lambda: provision.validate_secure_device_state(
            replace(secured, keys=secure_bad_keys), expected
        ),
        "KEY4 readable key material",
    )

    print("ESP32-S3 provisioning preflight contracts: PASS")


if __name__ == "__main__":
    main()
