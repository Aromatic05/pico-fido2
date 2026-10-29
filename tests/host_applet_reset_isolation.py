#!/usr/bin/env python3
"""Protocol-level OpenPGP/PIV reset isolation on disposable Host emulator flash.

Both resets exercise their real ISO-7816 APDU command paths after a FIDO2
resident credential has authenticated. No physical device is contacted.
"""
from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

import host_cross_applet_longevity as cross


def reset_applet(module, sock, applet: str) -> None:
    if applet == "openpgp":
        cross.select(module, sock, cross.OPENPGP_AID)
        for reference, wrong in ((0x81, b"000000"), (0x83, b"00000000")):
            for _ in range(3):
                _, sw = module.transmit(sock, module.apdu(0x20, 0, reference, wrong))
                assert sw != 0x9000, (applet, reference, sw)
        for ins in (0xE6, 0x44):  # TERMINATE DF / ACTIVATE FILE
            _, sw = module.transmit(sock, module.apdu(ins))
            assert sw == 0x9000, (applet, ins, sw)
        return

    if applet == "piv":
        cross.select(module, sock, cross.PIV_AID)
        for _ in range(3):
            _, sw = module.transmit(sock, module.apdu(0x20, 0, 0x80, b"000000\xff\xff"))
            assert sw != 0x9000, (applet, "PIN", sw)
        for _ in range(3):
            _, sw = module.transmit(sock, module.apdu(0x2C, 0, 0x80, b"00000000" + b"654321\xff\xff"))
            assert sw != 0x9000, (applet, "PUK", sw)
        _, sw = module.transmit(sock, module.apdu(0xFB))
        assert sw == 0x9000, (applet, "RESET", sw)
        return

    raise ValueError(applet)


def run_case(binary: Path, applet: str) -> None:
    module = cross.load_module(cross.DURABILITY, "host_powercycle_durability")
    hsm = cross.load_module(cross.HSM_TEST, "host_hsmauth")
    otp = cross.load_module(cross.OTP_TEST, "otp_sector_powercut_matrix")

    with tempfile.TemporaryDirectory(prefix=f"pico-reset-{applet}-") as work:
        run_dir = Path(work)
        original_id, original_key, counter, _ = cross.establish_state(
            module, hsm, otp, binary, run_dir
        )

        emulator = module.Emulator(binary, run_dir)
        emulator.start()
        try:
            assert emulator.ccid is not None
            counter = cross.verify_fido(module, original_id, original_key, counter)
            reset_applet(module, emulator.ccid, applet)
            if applet == "openpgp":
                cross.verify_piv(module, emulator.ccid)
            elif applet == "piv":
                cross.verify_openpgp(module, emulator.ccid)
            counter = cross.verify_fido(module, original_id, original_key, counter)
        finally:
            emulator.stop()

        # Persisted values, not merely cached FIDO authentication state.
        emulator = module.Emulator(binary, run_dir)
        emulator.start()
        try:
            cross.verify_fido(module, original_id, original_key, counter)
        finally:
            emulator.stop()
        print(f"{applet.upper()} reset preserves FIDO resident/PIN/signatures after restart: PASS")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    if not args.binary.is_file():
        raise SystemExit("Host emulator executable not found")
    for applet in ("openpgp", "piv"):
        run_case(args.binary.resolve(), applet)


if __name__ == "__main__":
    main()
