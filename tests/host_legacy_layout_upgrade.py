#!/usr/bin/env python3
"""Verify compatibility with the pre-journal local persistent layout.

The legacy binary creates one shared emulator flash image containing FIDO,
PIV, OpenPGP, OATH, OTP and HSM Auth state. The current binary then opens the
same image, exercises every sentinel, persists current-format journal updates,
and reopens it once more. This is a local-emulator regression only.
"""

from __future__ import annotations

import argparse
import importlib.util
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DURABILITY = ROOT / "tests" / "host_powercycle_durability.py"
CROSS_APPLET = ROOT / "tests" / "host_cross_applet_longevity.py"
HSM_TEST = ROOT / "tests" / "host_hsmauth.py"
OTP_TEST = ROOT / "tests" / "otp_sector_powercut_matrix.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load local test helper: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_current_cycle(cross, dur, hsm, otp, current: Path, run_dir: Path,
                         credential_id: bytes, public_key: dict[int, object],
                         counter: int, otp_key: bytes, hard_stop: bool) -> int:
    emu = dur.Emulator(current, run_dir)
    emu.start()
    try:
        assert emu.ccid is not None
        counter = cross.verify_fido(dur, credential_id, public_key, counter)
        cross.verify_piv(dur, emu.ccid)
        cross.verify_openpgp(dur, emu.ccid)
        cross.verify_oath(dur, emu.ccid)
        cross.verify_otp(dur, otp, emu.ccid, otp_key)
        cross.verify_hsm(hsm, emu.ccid)
        if hard_stop:
            emu.hard_kill()
        return counter
    finally:
        emu.stop()


def run(legacy: Path, current: Path) -> None:
    cross = load_module(CROSS_APPLET, "host_cross_applet_longevity")
    dur = load_module(DURABILITY, "host_powercycle_durability")
    hsm = load_module(HSM_TEST, "host_hsmauth")
    otp = load_module(OTP_TEST, "otp_sector_powercut_matrix")

    with tempfile.TemporaryDirectory(prefix="pico-legacy-layout-upgrade-") as tmp:
        run_dir = Path(tmp)
        credential_id, public_key, counter, otp_key = cross.establish_state(
            dur, hsm, otp, legacy, run_dir
        )

        counter = verify_current_cycle(
            cross, dur, hsm, otp, current, run_dir,
            credential_id, public_key, counter, otp_key, True,
        )
        verify_current_cycle(
            cross, dur, hsm, otp, current, run_dir,
            credential_id, public_key, counter, otp_key, False,
        )

    print(
        "legacy-layout local upgrade: PASS "
        "(FIDO/PIV/OpenPGP/OATH/OTP/HSM Auth + current journal reboot)"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("legacy_binary", type=Path)
    parser.add_argument("current_binary", type=Path)
    args = parser.parse_args()
    legacy = args.legacy_binary.resolve()
    current = args.current_binary.resolve()
    if not legacy.is_file():
        raise SystemExit(f"legacy emulator binary not found: {legacy}")
    if not current.is_file():
        raise SystemExit(f"current emulator binary not found: {current}")
    run(legacy, current)


if __name__ == "__main__":
    main()
