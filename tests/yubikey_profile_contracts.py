#!/usr/bin/env python3
"""Structural contracts for the YubiKey-compatible advertised device profile."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def macro_hex(text: str, name: str) -> int:
    match = re.search(rf"^#define\s+{re.escape(name)}\s+0x([0-9A-Fa-f]+)\s*$", text, re.MULTILINE)
    if not match:
        raise AssertionError(f"missing literal macro {name}")
    return int(match.group(1), 16)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    cmake = read("CMakeLists.txt")
    fido_version = read("pico-fido/src/fido/version.h")
    openpgp_version = read("pico-openpgp/src/openpgp/version.h")
    usb_policy = read("src/fido2/usb_policy.c")
    usb_core = read("pico-keys-sdk/src/usb/usb.c")
    hid = read("pico-keys-sdk/src/usb/hid/hid.c")

    internal = macro_hex(fido_version, "PICO_FIDO_VERSION")
    require(internal == 0x0704, "internal product release version unexpectedly changed")

    match = re.search(r"add_compile_definitions\(PICO_FIDO_DEVICE_VERSION=0x([0-9A-Fa-f]+)\)", cmake)
    require(match is not None, "product must define one advertised device version")
    advertised = int(match.group(1), 16)
    require(advertised == 0x0507, "YubiKey compatibility profile must remain 5.7.0")

    require(macro_hex(openpgp_version, "PIV_VERSION") == advertised,
            "PIV firmware version must match the advertised YubiKey profile")
    require(macro_hex(openpgp_version, "OPGP_VERSION") == 0x0304,
            "OpenPGP 3.4 is an application version and must not be rewritten as firmware version")

    major = advertised >> 8
    minor = advertised & 0xFF
    expected_bcd = (major << 8) | (minor << 4)
    require(expected_bcd == 0x0570, "unexpected BCD encoding for YubiKey 5.7.0")
    require("PICO_FIDO_DEVICE_VERSION_MAJOR << 8" in usb_policy and
            "PICO_FIDO_DEVICE_VERSION_MINOR << 4" in usb_policy,
            "USB bcdDevice must derive from the advertised device version")
    require("desc_device.bcdDevice = picokey_usb_device_version_policy" in usb_core,
            "USB core must apply the product bcdDevice policy")

    outward = {
        "FIDO HID": "pico-fido/src/fido/fido.c",
        "management": "pico-fido/src/fido/management.c",
        "OATH": "pico-fido/src/fido/oath.c",
        "OTP": "pico-fido/src/fido/otp.c",
        "CTAP GetInfo": "pico-fido/src/fido/cbor_get_info.c",
        "BLE DIS": "src/fido2/ble_fido.c",
    }
    for label, path in outward.items():
        source = read(path)
        require("PICO_FIDO_DEVICE_VERSION" in source,
                f"{label} must use the advertised device version")

    for path in (
        "pico-fido/src/fido/fido.c",
        "pico-fido/src/fido/management.c",
        "pico-fido/src/fido/oath.c",
        "pico-fido/src/fido/otp.c",
        "src/fido2/ble_fido.c",
    ):
        source = read(path)
        require("PICO_FIDO_VERSION_MAJOR" not in source and "PICO_FIDO_VERSION_MINOR" not in source,
                f"{path} leaked the internal project version onto a YubiKey-facing protocol")

    version_block = hid[hid.index("else if (ctap_req->init.cmd == CTAPHID_VERSION)"):]
    version_block = version_block[:version_block.index("last_packet_time = 0;")]
    require("get_version_major ? get_version_major()" in version_block and
            "get_version_minor ? get_version_minor()" in version_block,
            "CTAPHID VERSION must use the same product version provider as CTAPHID INIT")

    print("YubiKey advertised profile: PASS (internal 7.4, advertised 5.7.0, OpenPGP 3.4, USB bcd 0x0570)")


if __name__ == "__main__":
    main()
