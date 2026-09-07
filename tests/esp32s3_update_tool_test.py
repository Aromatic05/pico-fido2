#!/usr/bin/env python3
"""Pure safety contracts for tools/esp32s3_update.py."""

from __future__ import annotations

import json
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import esp32s3_update as update


DIGEST = "12" * 32


def entry(value, raw: str, *, bit_len: int = 1, readable: bool = True):
    return {
        "value": value,
        "raw_value": raw,
        "bit_len": bit_len,
        "readable": readable,
    }


def good_state_json() -> dict[str, object]:
    return {
        "SECURE_BOOT_EN": entry(True, "0x1"),
        "SPI_BOOT_CRYPT_CNT": entry("Enable", "0x1", bit_len=3),
        "DIS_DOWNLOAD_MODE": entry(False, "0x0"),
        "DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE": entry(False, "0x0"),
        "SECURE_VERSION": entry(0, "0x0000", bit_len=16),
        "MAC": entry("12:34:56:78:9a:bc (OK)", "0x123456789abc", bit_len=48),
        "KEY_PURPOSE_0": entry("SECURE_BOOT_DIGEST0", "0x9", bit_len=4),
        "BLOCK_KEY0": entry(" ".join(["12"] * 32), "0x" + DIGEST, bit_len=256),
    }


def bundle_fixture(tmp: Path) -> update.UpdateBundle:
    encrypted = tmp / "update.bin"
    encrypted.write_bytes(b"ciphertext")
    return update.UpdateBundle(
        directory=tmp,
        manifest_path=tmp / "manifest.json",
        encrypted_path=encrypted,
        encrypted_sha256=update.sha256(encrypted),
        security_version=0,
        project_version="7.4.1",
        secure_boot_digest_hex=DIGEST,
    )


def expect_reject(state: update.DeviceSecurityState, bundle: update.UpdateBundle, needle: str) -> None:
    try:
        update.validate_device_for_update(state, bundle)
    except update.UpdateError as exc:
        assert needle in str(exc), (needle, str(exc))
        return
    raise AssertionError(f"expected rejection containing {needle!r}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="pico-update-tool-test-") as td:
        tmp = Path(td)
        raw = good_state_json()
        state = update.parse_device_state(raw)
        bundle = bundle_fixture(tmp)
        update.validate_device_for_update(state, bundle)
        assert state.mac == "12:34:56:78:9a:bc"
        assert state.flash_encryption
        assert state.security_floor == 0
        assert state.key0_digest_hex == DIGEST

        command = update.build_write_command("socket://127.0.0.1:1234", bundle.encrypted_path)
        assert "--encrypt" not in command
        assert command[-2:] == [hex(update.APP_OFFSET), str(bundle.encrypted_path)]
        assert command.count("write_flash") == 1
        assert "--no-stub" in command
        assert command[command.index("--before") + 1] == "no_reset"
        assert command[command.index("--after") + 1] == "no_reset"

        prefix = bytearray(b"\xff" * update.APP_PREFIX_BYTES)
        prefix[0] = 0xE9
        prefix[1] = 7
        struct.pack_into("<II", prefix, update.APP_DESC_OFFSET, update.APP_DESC_MAGIC, 3)
        prefix[update.APP_DESC_OFFSET + 16:update.APP_DESC_OFFSET + 48] = b"\0" * 32
        prefix[update.APP_DESC_OFFSET + 48:update.APP_DESC_OFFSET + 80] = b"\0" * 32
        prefix[update.APP_DESC_OFFSET + 16:update.APP_DESC_OFFSET + 16 + len(b"7.4.2")] = b"7.4.2"
        prefix[update.APP_DESC_OFFSET + 48:update.APP_DESC_OFFSET + 48 + len(b"pico_fido2")] = b"pico_fido2"
        identity = update.validate_decrypted_app_prefix(bytes(prefix))
        assert identity == update.CurrentAppIdentity("pico_fido2", "7.4.2", 3)

        wrong_project = bytearray(prefix)
        wrong_project[update.APP_DESC_OFFSET + 48:update.APP_DESC_OFFSET + 48 + 32] = b"other\0" + b"\0" * 26
        try:
            update.validate_decrypted_app_prefix(bytes(wrong_project))
        except update.UpdateError as exc:
            assert "expected 'pico_fido2'" in str(exc)
        else:
            raise AssertionError("wrong decrypted project identity was accepted")

        wrong_magic = bytearray(prefix)
        struct.pack_into("<I", wrong_magic, update.APP_DESC_OFFSET, 0)
        try:
            update.validate_decrypted_app_prefix(bytes(wrong_magic))
        except update.UpdateError as exc:
            assert "esp_app_desc" in str(exc)
        else:
            raise AssertionError("wrong decrypted app descriptor was accepted")

        cases = [
            ("secure_boot", False, "Secure Boot"),
            ("flash_encryption", False, "Flash Encryption"),
            ("download_mode_enabled", False, "ROM download mode"),
            ("usb_download_mode_enabled", False, "USB Serial/JTAG"),
            ("key0_purpose", "USER", "KEY0 purpose"),
            ("key0_digest_hex", None, "not readable"),
            ("key0_digest_hex", "34" * 32, "trust anchor"),
        ]
        for field, value, needle in cases:
            changed = update.DeviceSecurityState(**{
                **state.__dict__,
                field: value,
            })
            expect_reject(changed, bundle, needle)

        high_floor = update.DeviceSecurityState(**{
            **state.__dict__,
            "security_version_raw": 0x0003,
            "security_floor": 2,
        })
        expect_reject(high_floor, bundle, "below device floor")

        malformed = good_state_json()
        malformed["SECURE_VERSION"] = entry(2, "0x0002", bit_len=16)
        try:
            update.parse_device_state(malformed)
        except update.UpdateError as exc:
            assert "non-canonical" in str(exc)
        else:
            raise AssertionError("non-canonical SECURE_VERSION was accepted")

        unreadable = good_state_json()
        unreadable["BLOCK_KEY0"] = entry(None, "0x0", bit_len=256, readable=False)
        assert update.parse_device_state(unreadable).key0_digest_hex is None

        print("ESP32-S3 update tool safety contracts: PASS")


if __name__ == "__main__":
    main()
