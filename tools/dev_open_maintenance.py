#!/usr/bin/env python3
"""Open ESP32-S3 development maintenance mode through the USB FIDO transport."""

from __future__ import annotations

import argparse

from fido2 import cbor
from fido2.hid import CTAPHID, CtapHidDevice

YUBIKEY_VID = 0x1050
YUBIKEY_OTP_FIDO_CCID_PID = 0x0407
CTAPHID_VENDOR_CBOR = int(CTAPHID.VENDOR_FIRST) + 1
VENDOR_MAINTENANCE = 0x07
SUBCOMMAND_OPEN = 0x01


def select_device(serial: str | None) -> CtapHidDevice:
    candidates = [
        dev
        for dev in CtapHidDevice.list_devices()
        if dev.descriptor.vid == YUBIKEY_VID
        and dev.descriptor.pid == YUBIKEY_OTP_FIDO_CCID_PID
        and (serial is None or dev.descriptor.serial_number == serial)
    ]
    if len(candidates) != 1:
        details = ", ".join(
            f"serial={dev.descriptor.serial_number!r} path={dev.descriptor.path!r}"
            for dev in candidates
        ) or "none"
        for dev in candidates:
            dev.close()
        raise SystemExit(
            f"expected exactly one 1050:0407 development device, found {len(candidates)}: {details}"
        )
    return candidates[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", help="select one 1050:0407 device by USB serial")
    args = parser.parse_args()

    dev = select_device(args.serial)
    try:
        payload = bytes([VENDOR_MAINTENANCE]) + cbor.encode({1: SUBCOMMAND_OPEN})
        response = dev.call(CTAPHID_VENDOR_CBOR, payload)
    finally:
        dev.close()

    if not response:
        raise SystemExit("device returned an empty maintenance response")
    if response[0] != 0:
        raise SystemExit(f"maintenance request rejected with CTAP status 0x{response[0]:02x}")
    result = cbor.decode(response[1:])
    if result != {1: True}:
        raise SystemExit(f"unexpected maintenance response: {result!r}")
    print("development maintenance requested over USB")


if __name__ == "__main__":
    main()
