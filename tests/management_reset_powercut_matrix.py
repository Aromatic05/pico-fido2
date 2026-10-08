#!/usr/bin/env python3
"""Crash-consistency probes for the management whole-device reset.

A disposable emulator is populated with independent FIDO, PIV, OpenPGP and
OATH state.  The real management INS_RESET path is then cut at flash journal
phases.  After recovery all applets must describe the same generation: either
all old state or all factory state.  Mixed generations are a durability bug.
"""

from __future__ import annotations

import argparse
import importlib.util
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from fido2.ctap2.pin import ClientPin


ROOT = Path(__file__).resolve().parents[1]
DURABILITY = ROOT / "tests" / "host_powercycle_durability.py"
MAN_AID = bytes.fromhex("D2760000850101")
PIV_AID = bytes.fromhex("A000000308")
OPENPGP_AID = bytes.fromhex("D27600012401")
OATH_AID = bytes.fromhex("A0000005272101")

PIV_DEFAULT = b"123456\xff\xff"
PIV_OLD = b"654321\xff\xff"
OPENPGP_DEFAULT_PW3 = b"12345678"
OPENPGP_OLD_PW3 = b"87654321"
FIDO_OLD_PIN = "DurableReset42"
OATH_NAME = b"reset-old"
OATH_SECRET = bytes([0x5A]) * 20


@dataclass(frozen=True)
class Generation:
    fido: str
    piv: str
    openpgp: str
    oath: str


def load_harness():
    spec = importlib.util.spec_from_file_location("host_powercycle_durability", DURABILITY)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load host durability harness")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def select(module, sock, aid: bytes) -> bytes:
    body, sw = module.transmit(sock, module.apdu(0xA4, 0x04, 0x00, aid))
    out = bytearray(body)
    while (sw >> 8) == 0x61:
        body, sw = module.transmit(
            sock, bytes((0x00, 0xC0, 0x00, 0x00, sw & 0xFF))
        )
        out.extend(body)
    if sw != 0x9000:
        raise RuntimeError(f"SELECT {aid.hex()} failed: {sw:04x}")
    return bytes(out)


def establish_old_state(module, binary: Path, run_dir: Path) -> None:
    emu = module.Emulator(binary, run_dir)
    dev = None
    try:
        emu.start()
        assert emu.ccid is not None

        dev, ctap2 = module.open_fido()
        ClientPin(ctap2).set_pin(FIDO_OLD_PIN)
        if not ctap2.get_info().options.get("clientPin", False):
            raise RuntimeError("failed to establish FIDO PIN sentinel")
        dev.close()
        dev = None

        select(module, emu.ccid, PIV_AID)
        _, sw = module.transmit(
            emu.ccid, module.apdu(0x24, 0x00, 0x80, PIV_DEFAULT + PIV_OLD)
        )
        if sw != 0x9000:
            raise RuntimeError(f"failed to establish PIV sentinel: {sw:04x}")

        select(module, emu.ccid, OPENPGP_AID)
        _, sw = module.transmit(
            emu.ccid,
            module.apdu(0x24, 0x00, 0x83, OPENPGP_DEFAULT_PW3 + OPENPGP_OLD_PW3),
        )
        if sw != 0x9000:
            raise RuntimeError(f"failed to establish OpenPGP sentinel: {sw:04x}")

        select(module, emu.ccid, OATH_AID)
        put = (
            bytes((0x71, len(OATH_NAME))) + OATH_NAME
            + bytes((0x73, len(OATH_SECRET) + 2, 0x21, 6)) + OATH_SECRET
        )
        _, sw = module.transmit(emu.ccid, module.apdu(0x01, data=put))
        if sw != 0x9000:
            raise RuntimeError(f"failed to establish OATH sentinel: {sw:04x}")
    finally:
        if dev is not None:
            try:
                dev.close()
            except OSError:
                pass
        emu.stop()


def classify_fido(module) -> str:
    dev = None
    try:
        dev, ctap2 = module.open_fido()
        return "old" if ctap2.get_info().options.get("clientPin", False) else "factory"
    finally:
        if dev is not None:
            dev.close()


def classify_pin(module, sock, aid: bytes, ref: int, old: bytes, default: bytes, label: str) -> str:
    select(module, sock, aid)
    _, sw_old = module.transmit(sock, module.apdu(0x20, 0x00, ref, old))
    if sw_old == 0x9000:
        return "old"
    _, sw_default = module.transmit(sock, module.apdu(0x20, 0x00, ref, default))
    if sw_default == 0x9000:
        return "factory"
    raise RuntimeError(
        f"{label} is neither old nor factory after recovery: "
        f"old={sw_old:04x} default={sw_default:04x}"
    )


def classify_oath(module, sock) -> str:
    select(module, sock, OATH_AID)
    body, sw = module.transmit(sock, module.apdu(0xA1))
    if sw != 0x9000:
        raise RuntimeError(f"OATH LIST failed after reset recovery: {sw:04x}")
    return "old" if OATH_NAME in body else "factory"


def classify_generation(module, binary: Path, run_dir: Path) -> Generation:
    emu = module.Emulator(binary, run_dir)
    try:
        emu.start()
        assert emu.ccid is not None
        fido = classify_fido(module)
        piv = classify_pin(module, emu.ccid, PIV_AID, 0x80, PIV_OLD, PIV_DEFAULT, "PIV")
        openpgp = classify_pin(
            module,
            emu.ccid,
            OPENPGP_AID,
            0x83,
            OPENPGP_OLD_PW3,
            OPENPGP_DEFAULT_PW3,
            "OpenPGP",
        )
        oath = classify_oath(module, emu.ccid)
        return Generation(fido, piv, openpgp, oath)
    finally:
        emu.stop()


def cut_cases() -> tuple[tuple[str, int], ...]:
    phases = (
        "journal-after-meta-erase",
        "journal-after-data-erase",
        "journal-mid-data",
        "journal-before-commit",
        "journal-after-meta",
        "after-erase",
        "mid-program",
    )
    return tuple((phase, 1) for phase in phases)


def run(binary: Path) -> None:
    module = load_harness()
    old_generation = Generation("old", "old", "old", "old")
    factory_generation = Generation("factory", "factory", "factory", "factory")

    for phase, page in cut_cases():
        label = phase
        with tempfile.TemporaryDirectory(prefix=f"pico-device-reset-{label}-") as tmp:
            run_dir = Path(tmp)
            establish_old_state(module, binary, run_dir)
            if classify_generation(module, binary, run_dir) != old_generation:
                raise RuntimeError(f"{label}: pre-reset sentinel generation is inconsistent")

            arm = run_dir / "reset-cut.arm"
            env = {
                "PICO_KEYS_EMU_COMMIT_CUT_ARM_FILE": str(arm),
                "PICO_KEYS_EMU_COMMIT_CUT_AFTER_PAGES": str(page),
            }
            env["PICO_KEYS_EMU_COMMIT_CUT_PHASE"] = phase
            env["PICO_KEYS_EMU_COMMIT_CUT_PROGRAM_BYTES"] = "256"

            emu = module.Emulator(binary, run_dir, env)
            emu.start()
            try:
                assert emu.ccid is not None
                select(module, emu.ccid, MAN_AID)
                arm.touch()
                try:
                    module.transmit(emu.ccid, module.apdu(0x1E))
                except (OSError, RuntimeError):
                    pass
                for _ in range(150):
                    if emu.process is not None and emu.process.poll() is not None:
                        break
                    time.sleep(0.01)
                if emu.process is None or emu.process.poll() != 97:
                    raise RuntimeError(
                        f"{label}: expected reset power-cut exit 97, "
                        f"got {None if emu.process is None else emu.process.poll()}"
                    )
            finally:
                emu.stop()
                arm.unlink(missing_ok=True)

            recovered = classify_generation(module, binary, run_dir)
            if recovered not in (old_generation, factory_generation):
                raise RuntimeError(
                    f"{label}: mixed device-reset generation after reboot: {recovered}"
                )

    print(f"Management whole-device reset power-cut consistency: PASS x{len(cut_cases())}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"emulator binary not found: {binary}")
    run(binary)


if __name__ == "__main__":
    main()
