#!/usr/bin/env python3
"""Owner-confirmed Aromatic Key application-data factory reset over USB CCID.

Without --reset, perform only the read-only management SELECT preflight.
Never retry the destructive APDU: a transport error can leave its result unknown.
"""

import argparse

from smartcard.Exceptions import CardConnectionException
from smartcard.System import readers


# The YubiKey-compatible management AID is not an identity check: genuine
# YubiKeys also answer it. Use the project's registered Pico FIDO AID instead.
SELECT_MANAGEMENT = bytes.fromhex("00A4040008A000000527471117")
# CMakeLists.txt exposes 5.7.0 to YubiKey-compatible clients, independently
# of the 7.4.x upstream/project version shown by other status interfaces.
EXPECTED_MANAGEMENT_VERSION = b"5.7.0"
RESET_DEVICE = bytes.fromhex("001E0000")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="request one owner-confirmed factory reset")
    args = parser.parse_args()

    devices = readers()
    if len(devices) != 1:
        raise SystemExit(f"Expected one PC/SC reader for Aromatic Key; found {len(devices)}")

    card = devices[0].createConnection()
    try:
        card.connect()
    except CardConnectionException as exc:
        raise SystemExit(f"PC/SC connect failed; no Reset sent: {exc}") from exc

    try:
        try:
            response, sw1, sw2 = card.transmit(list(SELECT_MANAGEMENT))
        except CardConnectionException as exc:
            raise SystemExit(f"Management SELECT failed; no Reset sent: {exc}") from exc

        if (sw1, sw2) != (0x90, 0x00):
            raise SystemExit(f"Management SELECT returned {sw1:02X}{sw2:02X}; no Reset sent")

        version = bytes(response)
        if version != EXPECTED_MANAGEMENT_VERSION:
            raise SystemExit(
                f"Unexpected project management version {version!r} "
                f"(expected {EXPECTED_MANAGEMENT_VERSION!r}); no Reset sent"
            )

        print(f"Reader: {devices[0]}")
        print(f"Pico FIDO management applet: {version.decode('ascii')}")
        if not args.reset:
            print("SELECT preflight successful. No Reset sent.")
            return

        print("AUTHORIZATION: Full application-data factory reset on this disposable Aromatic Key.")
        print("This deletes stored FIDO/PIV/OpenPGP/OTP/OATH/HSM Auth user data and PINs.")
        print("PIV factory attestation identity and firmware/eFuse configuration are preserved.")
        if input("Type RESET to authorize exactly one device Reset: ") != "RESET":
            raise SystemExit("Cancelled; no Reset sent")

        try:
            _, sw1, sw2 = card.transmit(list(RESET_DEVICE))
        except CardConnectionException as exc:
            raise SystemExit(
                f"Reset transport failed; result UNKNOWN. Do not retry before inspecting device: {exc}"
            ) from exc

        if (sw1, sw2) != (0x90, 0x00):
            raise SystemExit(f"Reset returned {sw1:02X}{sw2:02X}; inspect device before retry")
        print("Device accepted Reset. Replug USB and verify each applet's factory state.")
    finally:
        card.disconnect()


if __name__ == "__main__":
    main()
