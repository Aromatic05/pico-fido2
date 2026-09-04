#!/usr/bin/env python3
"""Fault-injection probes for smartcard durability gaps.

These scenarios are investigation tests.  They preserve one emulator flash image
across process restarts, inject exactly one file_put_data() failure after normal
initialization, then reboot and verify the old durable state is still usable.
They do not touch a physical device.
"""

from __future__ import annotations

import argparse
import importlib.util
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DURABILITY = ROOT / "tests" / "host_powercycle_durability.py"
PIV_AID = bytes.fromhex("A000000308")
OPENPGP_AID = bytes.fromhex("D27600012401")

EF_PW_PRIV = 0x10C4
EF_DEK = 0x1099
EF_PIV_PIN = 0x1184
EF_PIV_PUK = 0x1185
EF_PW3 = 0x1083
EF_RC = 0x1082

PIV_PIN_DEFAULT = b"123456\xff\xff"
PIV_PIN_NEW = b"654321\xff\xff"
PIV_PUK_DEFAULT = b"12345678"
PIV_PUK_NEW = b"87654321"
OPENPGP_PW3_DEFAULT = b"12345678"
OPENPGP_PW3_NEW = b"87654321"
OPENPGP_RC = b"87654321"
OPENPGP_PW1_DEFAULT = b"123456"
OPENPGP_PW1_NEW = b"654321"


def load_harness():
    spec = importlib.util.spec_from_file_location("host_powercycle_durability", DURABILITY)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load host durability harness")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def select(module, sock, aid: bytes) -> int:
    _, sw = module.transmit(sock, module.apdu(0xA4, 0x04, 0x00, aid))
    while (sw >> 8) == 0x61:
        le = sw & 0xFF
        _, sw = module.transmit(sock, bytes((0x00, 0xC0, 0x00, 0x00, le)))
    return sw


def piv_verify(module, sock, pin: bytes) -> int:
    _, sw = module.transmit(sock, module.apdu(0x20, 0x00, 0x80, pin))
    return sw


def piv_change(module, sock, ref: int, old: bytes, new: bytes) -> int:
    _, sw = module.transmit(sock, module.apdu(0x24, 0x00, ref, old + new))
    return sw


def piv_reset_retry(module, sock, puk: bytes, new_pin: bytes) -> int:
    _, sw = module.transmit(sock, module.apdu(0x2C, 0x00, 0x80, puk + new_pin))
    return sw


def openpgp_verify(module, sock, ref: int, value: bytes) -> int:
    _, sw = module.transmit(sock, module.apdu(0x20, 0x00, ref, value))
    return sw


def openpgp_change(module, sock, ref: int, old: bytes, new: bytes) -> int:
    _, sw = module.transmit(sock, module.apdu(0x24, 0x00, ref, old + new))
    return sw


def openpgp_set_rc(module, sock, rc: bytes) -> int:
    _, sw = module.transmit(sock, module.apdu(0xDA, 0x00, 0xD3, rc))
    return sw


def openpgp_reset_by_rc(module, sock, rc: bytes, new_pw1: bytes) -> int:
    _, sw = module.transmit(sock, module.apdu(0x2C, 0x00, 0x81, rc + new_pw1))
    return sw


def initialized_flash(module, binary: Path, run_dir: Path, aid: bytes) -> None:
    emu = module.Emulator(binary, run_dir)
    try:
        emu.start()
        assert emu.ccid is not None
        sw = select(module, emu.ccid, aid)
        if sw != 0x9000:
            raise RuntimeError(f"initial SELECT failed: {sw:04x}")
    finally:
        emu.stop()


def fault_env(fid: int, nth: int = 1) -> dict[str, str]:
    return {
        "PICO_KEYS_EMU_FAIL_FILE_PUT_FID_ONCE": hex(fid),
        "PICO_KEYS_EMU_FAIL_FILE_PUT_NTH": str(nth),
    }


def reboot_and_verify_piv_old_pin(module, binary: Path, run_dir: Path) -> None:
    emu = module.Emulator(binary, run_dir)
    try:
        emu.start()
        assert emu.ccid is not None
        if select(module, emu.ccid, PIV_AID) != 0x9000:
            raise RuntimeError("PIV SELECT failed after reboot")
        sw = piv_verify(module, emu.ccid, PIV_PIN_DEFAULT)
        if sw != 0x9000:
            raise RuntimeError(f"PIV old PIN lost after failed transaction: {sw:04x}")
    finally:
        emu.stop()


def run_piv_fault_matrix(binary: Path) -> None:
    module = load_harness()

    # Direct PIN update: failed verifier write must leave the old PIN durable.
    with tempfile.TemporaryDirectory(prefix="pico-piv-pin-fault-") as tmp:
        run_dir = Path(tmp)
        initialized_flash(module, binary, run_dir, PIV_AID)
        emu = module.Emulator(binary, run_dir, fault_env(EF_PIV_PIN))
        try:
            emu.start()
            assert emu.ccid is not None
            assert select(module, emu.ccid, PIV_AID) == 0x9000
            sw = piv_change(module, emu.ccid, 0x80, PIV_PIN_DEFAULT, PIV_PIN_NEW)
            if sw == 0x9000:
                raise RuntimeError("PIV PIN change reported success after injected verifier-write failure")
        finally:
            emu.hard_kill()
        reboot_and_verify_piv_old_pin(module, binary, run_dir)

    # Direct PUK update: after a failed PUK write the old PUK must still authorize
    # a later PUK change.  This probe is disposable and may mutate the final image.
    with tempfile.TemporaryDirectory(prefix="pico-piv-puk-fault-") as tmp:
        run_dir = Path(tmp)
        initialized_flash(module, binary, run_dir, PIV_AID)
        emu = module.Emulator(binary, run_dir, fault_env(EF_PIV_PUK))
        try:
            emu.start()
            assert emu.ccid is not None
            assert select(module, emu.ccid, PIV_AID) == 0x9000
            sw = piv_change(module, emu.ccid, 0x81, PIV_PUK_DEFAULT, PIV_PUK_NEW)
            if sw == 0x9000:
                raise RuntimeError("PIV PUK change reported success after injected verifier-write failure")
        finally:
            emu.hard_kill()
        emu = module.Emulator(binary, run_dir)
        try:
            emu.start()
            assert emu.ccid is not None
            assert select(module, emu.ccid, PIV_AID) == 0x9000
            sw = piv_change(module, emu.ccid, 0x81, PIV_PUK_DEFAULT, PIV_PUK_NEW)
            if sw != 0x9000:
                raise RuntimeError(f"PIV old PUK lost after failed transaction: {sw:04x}")
        finally:
            emu.stop()

    # RESET RETRY is multi-record.  Probe both the first PIN write and the later
    # shared retry/status write; neither failure may publish the new PIN.
    for fid, label in ((EF_PIV_PIN, "pin"), (EF_PW_PRIV, "retry-status")):
        with tempfile.TemporaryDirectory(prefix=f"pico-piv-reset-retry-{label}-") as tmp:
            run_dir = Path(tmp)
            initialized_flash(module, binary, run_dir, PIV_AID)
            emu = module.Emulator(binary, run_dir, fault_env(fid))
            try:
                emu.start()
                assert emu.ccid is not None
                assert select(module, emu.ccid, PIV_AID) == 0x9000
                sw = piv_reset_retry(module, emu.ccid, PIV_PUK_DEFAULT, PIV_PIN_NEW)
                if sw == 0x9000:
                    raise RuntimeError(
                        f"PIV RESET RETRY reported success after injected {label} write failure"
                    )
            finally:
                emu.hard_kill()
            reboot_and_verify_piv_old_pin(module, binary, run_dir)

    print("PIV PIN/PUK partial-write fault matrix: PASS")


def reboot_and_verify_openpgp_pw3(module, binary: Path, run_dir: Path, expected: bytes) -> None:
    emu = module.Emulator(binary, run_dir)
    try:
        emu.start()
        assert emu.ccid is not None
        if select(module, emu.ccid, OPENPGP_AID) != 0x9000:
            raise RuntimeError("OpenPGP SELECT failed after reboot")
        sw = openpgp_verify(module, emu.ccid, 0x83, expected)
        if sw != 0x9000:
            raise RuntimeError(f"OpenPGP old PW3 lost after failed transaction: {sw:04x}")
    finally:
        emu.stop()


def run_openpgp_pw3_fault_matrix(binary: Path) -> None:
    module = load_harness()

    for fid, label in ((EF_PW3, "pw3-verifier"), (EF_DEK, "pw3-wrapper")):
        with tempfile.TemporaryDirectory(prefix=f"pico-openpgp-pw3-{label}-") as tmp:
            run_dir = Path(tmp)
            initialized_flash(module, binary, run_dir, OPENPGP_AID)
            emu = module.Emulator(binary, run_dir, fault_env(fid))
            try:
                emu.start()
                assert emu.ccid is not None
                assert select(module, emu.ccid, OPENPGP_AID) == 0x9000
                sw = openpgp_change(
                    module, emu.ccid, 0x83, OPENPGP_PW3_DEFAULT, OPENPGP_PW3_NEW
                )
                if sw == 0x9000:
                    raise RuntimeError(
                        f"OpenPGP PW3 change reported success after injected {label} failure"
                    )
            finally:
                emu.hard_kill()
            reboot_and_verify_openpgp_pw3(module, binary, run_dir, OPENPGP_PW3_DEFAULT)

    print("OpenPGP PW3 partial-write fault matrix: PASS")


def run_openpgp_rc_fault_case(binary: Path, fid: int, label: str, nth: int = 1) -> None:
    """incomplete Reset Code persistence must remain fail-closed."""
    module = load_harness()

    # RC setup writes the RC verifier, DEK wrapper and retry/status record.  A
    # failed later write must not leave a usable half-installed reset code.
    with tempfile.TemporaryDirectory(prefix=f"pico-openpgp-rc-{label}-") as tmp:
        run_dir = Path(tmp)
        initialized_flash(module, binary, run_dir, OPENPGP_AID)
        emu = module.Emulator(binary, run_dir, fault_env(fid, nth))
        try:
            emu.start()
            assert emu.ccid is not None
            assert select(module, emu.ccid, OPENPGP_AID) == 0x9000
            assert openpgp_verify(module, emu.ccid, 0x83, OPENPGP_PW3_DEFAULT) == 0x9000
            sw = openpgp_set_rc(module, emu.ccid, OPENPGP_RC)
            if sw == 0x9000:
                raise RuntimeError(
                    f"OpenPGP RC setup reported success after injected {label} failure"
                )
        finally:
            emu.hard_kill()

        emu = module.Emulator(binary, run_dir)
        try:
            emu.start()
            assert emu.ccid is not None
            assert select(module, emu.ccid, OPENPGP_AID) == 0x9000
            sw = openpgp_reset_by_rc(module, emu.ccid, OPENPGP_RC, OPENPGP_PW1_NEW)
            if sw == 0x9000:
                raise RuntimeError(
                    f"OpenPGP half-installed Reset Code survived {label} failure"
                )
            # Old PW1 must still be valid regardless of the failed RC setup.
            sw = openpgp_verify(module, emu.ccid, 0x81, OPENPGP_PW1_DEFAULT)
            if sw != 0x9000:
                raise RuntimeError(
                    f"OpenPGP PW1 damaged by failed RC setup ({label}): {sw:04x}"
                )
        finally:
            emu.stop()

    print(f"OpenPGP RC partial-write case {label}: PASS")


def run_openpgp_fault_matrix(binary: Path) -> None:
    run_openpgp_pw3_fault_matrix(binary)
    for fid, label, nth in (
        (EF_RC, "rc-verifier", 1),
        (EF_DEK, "rc-wrapper", 1),
        # Successful VERIFY PW3 resets its retry counter first, so RC setup is
        # the second EF_PW_PRIV write in this process.
        (EF_PW_PRIV, "rc-retry", 2),
    ):
        run_openpgp_rc_fault_case(binary, fid, label, nth)

    print("OpenPGP PW3/Reset-Code partial-write fault matrix: PASS")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument(
        "scenario",
        choices=(
            "piv",
            "openpgp",
            "openpgp-pw3",
            "openpgp-rc-verifier",
            "openpgp-rc-wrapper",
            "openpgp-rc-retry",
            "all",
        ),
        default="all",
        nargs="?",
    )
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"emulator binary not found: {binary}")
    if args.scenario in ("piv", "all"):
        run_piv_fault_matrix(binary)
    if args.scenario in ("openpgp", "all"):
        run_openpgp_fault_matrix(binary)
    elif args.scenario == "openpgp-pw3":
        run_openpgp_pw3_fault_matrix(binary)
    elif args.scenario == "openpgp-rc-verifier":
        run_openpgp_rc_fault_case(binary, EF_RC, "rc-verifier")
    elif args.scenario == "openpgp-rc-wrapper":
        run_openpgp_rc_fault_case(binary, EF_DEK, "rc-wrapper")
    elif args.scenario == "openpgp-rc-retry":
        run_openpgp_rc_fault_case(binary, EF_PW_PRIV, "rc-retry", 2)


if __name__ == "__main__":
    main()
