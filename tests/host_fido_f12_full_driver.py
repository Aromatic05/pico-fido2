#!/usr/bin/env python3
"""Test the physical F12 acceptance driver's real CTAP methods on virtual Flash.

This is a software-card-only driver regression, not physical BOOT evidence.
The emulator supplies synthetic UP and is restarted between full/overflow.
"""

import argparse
import json
from pathlib import Path

from fido2.ctap2 import Ctap2, ClientPin
from fido2.hid import CtapHidDevice

from hil import fido_capacity as driver


PIN = "F12VirtualFullDriver42"
JOURNAL = Path("f12-virtual-full-driver.json")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("fill", "after-restart"))
    opts = parser.parse_args()
    print(f"F12_VIRTUAL_DRIVER_PHASE: {opts.stage}; synthetic UP, not real hardware", flush=True)
    def virtual_message(value):
        value = value.replace("F12_PHYSICAL_", "F12_VIRTUAL_DRIVER_")
        value = value.replace("F12_TOUCH_BOOT:", "F12_VIRTUAL_SYNTHETIC_UP:")
        value = value.replace("press once when yellow", "emulator supplies synthetic UP")
        value = value.replace("touch BOOT if yellow", "emulator supplies synthetic UP")
        value = value.replace("REAL_BOOT_REQUIRED", "SYNTHETIC_UP")
        print(value, flush=True)

    driver.EVIDENCE_DIR = Path(".")
    driver.message = virtual_message
    devices = list(CtapHidDevice.list_devices())
    assert len(devices) == 1
    device = devices[0]
    try:
        ctap = Ctap2(device)
        if opts.stage == "fill":
            ClientPin(ctap).set_pin(PIN)
            state = {
                "phase": "fill", "ids": {}, "attestation_failures": [],
                "unconfirmed_writes": [], "initial_existing": 0,
            }
            driver.usb_number = lambda: "VIRTUAL-USB-NOT-PHYSICAL"
            driver.fill(ctap, PIN, state, JOURNAL, Path("."))
            assert state["phase"] == "await-real-usb-replug"
            assert len(state["ids"]) == 256
            assert not state["attestation_failures"]
            print("F12_VIRTUAL_FULL_DRIVER_256_REGISTERED: PASS", flush=True)
        else:
            state = json.loads(JOURNAL.read_text())
            assert state["phase"] == "await-real-usb-replug"
            assert driver.read_full_snapshot(ctap, PIN) == state["full_snapshot"]
            driver.verify_resident_signature(ctap, PIN, 0)
            driver.verify_resident_signature(ctap, PIN, 255)
            print("F12_VIRTUAL_FULL_DRIVER_256_PRESERVED_AFTER_EMULATOR_RESTART: PASS", flush=True)
            state["phase"] = "overflow"
            driver.atomic_json(JOURNAL, state)
            driver.overflow(ctap, PIN, state, JOURNAL)
            driver.delete_one(ctap, PIN, state, JOURNAL)
            driver.refill(ctap, PIN, state, JOURNAL, Path("."))
            driver.cleanup(ctap, PIN, state, JOURNAL)
            assert state["phase"] == "done"
            assert not state["attestation_failures"]
            print("F12_VIRTUAL_FULL_DRIVER_OVERFLOW_DELETE_REFILL_CLEANUP: PASS", flush=True)
    finally:
        device.close()


if __name__ == "__main__":
    main()
