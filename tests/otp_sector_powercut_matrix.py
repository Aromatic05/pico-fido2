#!/usr/bin/env python3
"""Sector-level crash probes for YubiOTP slot configuration.

The test arms the host flash journal only after normal initialization, cuts the
emulator at one commit phase, then reboots the same flash image.  The recovered
slot must be either the complete old state (absent) or the complete new state
(functional HMAC-SHA1 configuration), never a torn third state.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DURABILITY = ROOT / "tests" / "host_powercycle_durability.py"
OTP_AID = bytes.fromhex("A0000005272001")
CONFIG1_VALID = 0x01
EF_OTP_SLOT1 = 0xBB00
HOST_FLASH_BYTES = 8 * 1024 * 1024
FLASH_SECTOR_SIZE = 4096
FLASH_JOURNAL_SECTORS = 16


def load_harness():
    spec = importlib.util.spec_from_file_location("host_powercycle_durability", DURABILITY)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load host durability harness")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def hmac_slot_payload() -> tuple[bytes, bytes]:
    # Packed otp_config_t: fixed[16], uid[6], aes[16], access[6], four flag
    # bytes, rfu[2], crc[2].  The implementation forms the HMAC key as
    # aes_key || uid, so keep both non-zero to detect torn field recovery.
    uid = b"UID123"
    aes_key = b"0123456789ABCDEF"
    cfg = bytearray(52)
    cfg[16:22] = uid
    cfg[22:38] = aes_key
    cfg[46] = 0x40  # CHAL_RESP
    cfg[47] = 0x22  # CHAL_HMAC
    checksum = (~crc16(cfg[:50])) & 0xFFFF
    cfg[50:52] = checksum.to_bytes(2, "little")
    if crc16(cfg) != 0xF0B8:
        raise RuntimeError("synthetic OTP configuration CRC is invalid")
    # Firmware reserves eight persistent bytes after the 52-byte config.
    return bytes(cfg) + bytes(8), aes_key + uid


def yubiotp_slot_payload() -> bytes:
    cfg = bytearray(52)
    cfg[:6] = b"cccccc"
    cfg[16:22] = b"UID123"
    cfg[22:38] = b"0123456789ABCDEF"
    cfg[44] = 6  # fixed_size
    checksum = (~crc16(cfg[:50])) & 0xFFFF
    cfg[50:52] = checksum.to_bytes(2, "little")
    if crc16(cfg) != 0xF0B8:
        raise RuntimeError("synthetic YubiOTP configuration CRC is invalid")
    return bytes(cfg) + bytes(8)


def read_live_dynamic_record(flash_path: Path, fid: int) -> bytes:
    """Traverse the same dynamic linked list used by scan_region(false)."""
    image = flash_path.read_bytes()
    if len(image) != HOST_FLASH_BYTES:
        raise RuntimeError(f"unexpected host flash size: {len(image)}")
    ptr_size = 8  # host test binary is x86_64
    flash_data_header_size = ptr_size + 4
    end_rom_pool = len(image) - flash_data_header_size - 4
    start_rom_pool = end_rom_pool - 4 * FLASH_SECTOR_SIZE
    end_data_pool = start_rom_pool - flash_data_header_size
    data_start_pool = FLASH_JOURNAL_SECTORS * FLASH_SECTOR_SIZE

    base = int.from_bytes(image[end_data_pool:end_data_pool + ptr_size], "little")
    visited: set[int] = set()
    while base:
        if base in visited:
            raise RuntimeError(f"dynamic flash list loop at {base:#x}")
        visited.add(base)
        if not (data_start_pool <= base < end_data_pool):
            raise RuntimeError(f"dynamic flash list pointer out of range: {base:#x}")
        next_addr = int.from_bytes(image[base:base + ptr_size], "little")
        record_fid = int.from_bytes(
            image[base + 2 * ptr_size:base + 2 * ptr_size + 2], "little"
        )
        length_off = base + 2 * ptr_size + 2
        length = int.from_bytes(image[length_off:length_off + 2], "little")
        payload_off = length_off + 2
        if length > FLASH_SECTOR_SIZE or payload_off + length > len(image):
            raise RuntimeError(
                f"invalid live record fid={record_fid:#x} len={length} at {base:#x}"
            )
        if record_fid == fid:
            return image[payload_off:payload_off + length]
        base = next_addr
    raise RuntimeError(f"live dynamic record {fid:#x} not found")


def select_otp(module, sock) -> bytes:
    body, sw = module.transmit(sock, module.apdu(0xA4, 0x04, 0x00, OTP_AID))
    out = bytearray(body)
    while (sw >> 8) == 0x61:
        le = sw & 0xFF
        body, sw = module.transmit(sock, bytes((0x00, 0xC0, 0x00, 0x00, le)))
        out.extend(body)
    if sw != 0x9000:
        raise RuntimeError(f"OTP SELECT failed: {sw:04x}")
    if len(out) < 5:
        raise RuntimeError(f"OTP SELECT returned short status: {out.hex()}")
    return bytes(out)


def slot1_configured(status: bytes) -> bool:
    return bool(status[4] & CONFIG1_VALID)


def validate_recovered_new_state(module, sock, key: bytes) -> None:
    challenge = bytes(range(64))
    body, sw = module.transmit(sock, module.apdu(0x01, 0x30, 0x00, challenge))
    full = bytearray(body)
    while (sw >> 8) == 0x61:
        le = sw & 0xFF
        body, sw = module.transmit(sock, bytes((0x00, 0xC0, 0x00, 0x00, le)))
        full.extend(body)
    if sw != 0x9000:
        raise RuntimeError(f"recovered OTP slot cannot calculate HMAC: {sw:04x}")
    expected = hmac.new(key, challenge, hashlib.sha1).digest()
    if bytes(full) != expected:
        raise RuntimeError(
            "torn OTP configuration after reboot: "
            f"expected_hmac={expected.hex()} actual={bytes(full).hex()}"
        )


def cut_phases() -> tuple[str, ...]:
    return (
        "journal-after-meta-erase",
        "journal-after-data-erase",
        "journal-mid-data",
        "journal-before-commit",
        "journal-after-meta",
        "after-erase",
        "mid-program",
    )


def cut_env(arm: Path, phase: str) -> dict[str, str]:
    return {
        "PICO_KEYS_EMU_COMMIT_CUT_ARM_FILE": str(arm),
        "PICO_KEYS_EMU_COMMIT_CUT_AFTER_PAGES": "1",
        "PICO_KEYS_EMU_COMMIT_CUT_PHASE": phase,
        "PICO_KEYS_EMU_COMMIT_CUT_PROGRAM_BYTES": "256",
    }


def wait_for_power_cut(emulator, phase: str) -> None:
    for _ in range(100):
        if emulator.process is not None and emulator.process.poll() is not None:
            break
        time.sleep(0.01)
    if emulator.process is None or emulator.process.poll() != 97:
        raise RuntimeError(
            f"{phase}: expected emulator power-cut exit 97, "
            f"got {None if emulator.process is None else emulator.process.poll()}"
        )


def run_config(binary: Path) -> None:
    module = load_harness()
    payload, key = hmac_slot_payload()
    phases = cut_phases()

    for phase in phases:
        with tempfile.TemporaryDirectory(prefix=f"pico-otp-sector-{phase}-") as tmp:
            run_dir = Path(tmp)
            arm = run_dir / "commit-cut.arm"
            env = cut_env(arm, phase)
            first = module.Emulator(binary, run_dir, env)
            first.start()
            try:
                assert first.ccid is not None
                before = select_otp(module, first.ccid)
                if slot1_configured(before):
                    raise RuntimeError(f"{phase}: slot unexpectedly configured before mutation")
                arm.touch()
                try:
                    module.transmit(first.ccid, module.apdu(0x01, 0x01, 0x00, payload))
                except (OSError, RuntimeError):
                    pass
                wait_for_power_cut(first, phase)
            finally:
                first.stop()
                arm.unlink(missing_ok=True)

            second = module.Emulator(binary, run_dir)
            second.start()
            try:
                assert second.ccid is not None
                after = select_otp(module, second.ccid)
                if slot1_configured(after):
                    validate_recovered_new_state(module, second.ccid, key)
                # Unconfigured is the complete old state and is also valid.
            finally:
                second.stop()

    print(f"OTP slot sector power-cut recovery: PASS x{len(phases)}")


def run_counter(binary: Path) -> None:
    module = load_harness()
    payload = yubiotp_slot_payload()
    phases = cut_phases()

    for phase in phases:
        with tempfile.TemporaryDirectory(prefix=f"pico-otp-counter-{phase}-") as tmp:
            run_dir = Path(tmp)

            # Establish a fully committed slot with counter 0 without ever
            # invoking CTAPHID_INIT, which is what calls init_fido/init_otp.
            setup = module.Emulator(binary, run_dir)
            setup.start()
            try:
                assert setup.ccid is not None
                before = select_otp(module, setup.ccid)
                if slot1_configured(before):
                    raise RuntimeError(f"{phase}: slot unexpectedly exists before setup")
                _, sw = module.transmit(
                    setup.ccid, module.apdu(0x01, 0x01, 0x00, payload)
                )
                if sw != 0x9000:
                    raise RuntimeError(f"{phase}: OTP slot setup failed: {sw:04x}")
            finally:
                setup.stop()

            baseline = read_live_dynamic_record(run_dir / "memory.flash", EF_OTP_SLOT1)
            if len(baseline) != len(payload):
                raise RuntimeError(f"{phase}: unexpected baseline OTP length {len(baseline)}")
            if int.from_bytes(baseline[52:54], "big") != 0:
                raise RuntimeError(f"{phase}: baseline OTP counter is not zero")

            arm = run_dir / "commit-cut.arm"
            first = module.Emulator(binary, run_dir, cut_env(arm, phase))
            first.start()
            dev = None
            try:
                arm.touch()
                try:
                    # python-fido2 performs CTAPHID_INIT while opening the
                    # device.  That calls init_fido(), which in turn invokes
                    # init_otp() and persists the YubiOTP power-cycle counter.
                    dev, _ = module.open_fido()
                    raise RuntimeError(f"{phase}: OTP counter power cut did not trigger")
                except (OSError, RuntimeError):
                    pass
                wait_for_power_cut(first, phase)
            finally:
                if dev is not None:
                    try:
                        dev.close()
                    except OSError:
                        pass
                first.stop()
                arm.unlink(missing_ok=True)

            # Starting the emulator performs journal recovery but selecting
            # OTP does not call init_otp(), so it cannot advance the counter
            # again before we inspect the active record.
            second = module.Emulator(binary, run_dir)
            second.start()
            try:
                assert second.ccid is not None
                status = select_otp(module, second.ccid)
                if not slot1_configured(status):
                    raise RuntimeError(f"{phase}: OTP slot disappeared after counter cut")
                recovered = read_live_dynamic_record(run_dir / "memory.flash", EF_OTP_SLOT1)
                if len(recovered) != len(baseline):
                    raise RuntimeError(
                        f"{phase}: OTP slot length changed {len(baseline)}->{len(recovered)}"
                    )
                counter = int.from_bytes(recovered[52:54], "big")
                if counter not in (0, 1):
                    raise RuntimeError(f"{phase}: torn OTP counter value {counter}")
                normalized = bytearray(recovered)
                normalized[52:54] = baseline[52:54]
                if bytes(normalized) != baseline:
                    raise RuntimeError(
                        f"{phase}: OTP slot bytes changed outside counter field"
                    )
            finally:
                second.stop()

    print(f"OTP counter sector power-cut recovery: PASS x{len(phases)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("scenario", choices=("config", "counter", "all"), nargs="?", default="all")
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"emulator binary not found: {binary}")
    if args.scenario in ("config", "all"):
        run_config(binary)
    if args.scenario in ("counter", "all"):
        run_counter(binary)


if __name__ == "__main__":
    main()
