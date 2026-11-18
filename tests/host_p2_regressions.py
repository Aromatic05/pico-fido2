#!/usr/bin/env python3
"""P2 regressions against the product Host emulator, never physical devices."""

import argparse
from pathlib import Path
from tempfile import TemporaryDirectory

from host_p1_regressions import command, running
from host_protocol_smoke import tlv_value


def r5_07(binary):
    from host_hsmauth import TcpSmartCardConnection
    from yubikit.piv import DEFAULT_MANAGEMENT_KEY, MANAGEMENT_KEY_TYPE, PivSession

    with TemporaryDirectory(prefix="p2-piv-metadata-") as tmp:
        directory = Path(tmp)
        key = DEFAULT_MANAGEMENT_KEY + bytes(8)
        with running(binary, directory) as emulator:
            piv = PivSession(TcpSmartCardConnection(emulator.ccid))
            assert tlv_value(command(emulator, 0xF7, p2=0x9B), 5) == b"\x01"
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.set_management_key(MANAGEMENT_KEY_TYPE.AES256, key)
            metadata = command(emulator, 0xF7, p2=0x9B)
            assert tlv_value(metadata, 1) == b"\x0c"
            assert tlv_value(metadata, 5) == b"\x00"
        with running(binary, directory) as emulator:
            piv = PivSession(TcpSmartCardConnection(emulator.ccid))
            piv.authenticate(key)
            assert tlv_value(command(emulator, 0xF7, p2=0x9B), 5) == b"\x00"


CASES = {
    "r5-07": r5_07,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("case", choices=[*CASES, "all"])
    args = parser.parse_args()
    cases = CASES if args.case == "all" else (args.case,)
    for case in cases:
        CASES[case](args.binary.resolve())
        print(f"PASS {case}")


if __name__ == "__main__":
    main()
