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




import argparse
import hashlib
import os
import tempfile
from pathlib import Path

from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin, PinProtocolV2

import host_cross_applet_longevity as cross


def fido_verify_siblings(module, hsm, otp, emulator, otp_key: bytes, phase: str) -> None:
    if emulator.ccid is None:
        raise RuntimeError("CCID emulator is not connected")
    sock = emulator.ccid
    cross.verify_piv(module, sock)
    print(f"F11_{phase}_PIV_PIN: PASS", flush=True)
    cross.verify_openpgp(module, sock)
    print(f"F11_{phase}_OPENPGP_PW3: PASS", flush=True)
    cross.verify_oath(module, sock)
    print(f"F11_{phase}_OATH_CREDENTIAL: PASS", flush=True)
    cross.verify_otp(module, otp, sock, otp_key)
    print(f"F11_{phase}_OTP_HMAC_SLOT: PASS", flush=True)
    cross.verify_hsm(hsm, sock)
    print(f"F11_{phase}_HSM_AUTH_SESSION_KEYS: PASS", flush=True)


def fido_verify_old_fido_invalid(module, credential_id: bytes, phase: str) -> None:
    device, ctap2 = module.open_fido()
    try:
        if ctap2.get_info().options.get("clientPin", False):
            raise AssertionError("FIDO-only reset retained the old PIN")
        try:
            ctap2.get_assertion(
                rp_id=cross.FIDO_RP["id"],
                client_data_hash=hashlib.sha256(b"f11-old-credential-check").digest(),
                allow_list=[{"type": "public-key", "id": credential_id}],
            )
        except CtapError as exc:
            if exc.code not in (
                CtapError.ERR.NO_CREDENTIALS,
                CtapError.ERR.INVALID_CREDENTIAL,
            ):
                raise
        else:
            raise AssertionError("old FIDO resident still authorizes after reset")
        print(f"F11_{phase}_OLD_FIDO_PIN_AND_CREDENTIAL_REMOVED: PASS", flush=True)
    finally:
        device.close()


def fido_provision_new_fido(module) -> tuple[bytes, dict, int]:
    device, ctap2 = module.open_fido()
    try:
        client_pin = ClientPin(ctap2)
        client_pin.set_pin(cross.FIDO_PIN)
        client_hash = os.urandom(32)
        protocol = PinProtocolV2()
        token = client_pin.get_pin_token(
            cross.FIDO_PIN,
            permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
            permissions_rpid=cross.FIDO_RP["id"],
        )
        made = ctap2.make_credential(
            client_data_hash=client_hash,
            rp=cross.FIDO_RP,
            user=cross.FIDO_USER,
            key_params=[{"type": "public-key", "alg": -7}],
            options={"rk": True},
            pin_uv_param=protocol.authenticate(token, client_hash),
            pin_uv_protocol=protocol.VERSION,
        )
        data = made.auth_data.credential_data
        if data is None:
            raise AssertionError("new FIDO resident not created")
        return data.credential_id, dict(data.public_key), made.auth_data.counter
    finally:
        device.close()


def fido_run_round(binary: Path, round_number: int) -> None:
    module = cross.load_module(cross.DURABILITY, "host_powercycle_durability")
    hsm = cross.load_module(cross.HSM_TEST, "host_hsmauth")
    otp = cross.load_module(cross.OTP_TEST, "otp_sector_powercut_matrix")

    # Temporary memory.flash is separate from all physical-device storage.
    with tempfile.TemporaryDirectory(prefix=f"aromatic-authorized-f11-{round_number}-") as tmp:
        flash_dir = Path(tmp)
        original_id, original_pub, original_counter, otp_key = cross.establish_state(
            module, hsm, otp, binary, flash_dir
        )
        print(f"F11_ROUND_{round_number}_SIX_APPLETS_SEEDED: PASS", flush=True)

        emulator = module.Emulator(binary, flash_dir)
        emulator.start()
        try:
            cross.verify_fido(module, original_id, original_pub, original_counter)
            fido_verify_siblings(module, hsm, otp, emulator, otp_key, "BEFORE")
            print("F11_BEFORE_ALL_SIX_USABLE: PASS", flush=True)

            # This CTAP2 Reset is sent only through the local TCP emulator.
            device, ctap2 = module.open_fido()
            try:
                ctap2.reset()
            finally:
                device.close()
            print("F11_CTAP2_FIDO_ONLY_RESET_COMPLETED: PASS", flush=True)

            fido_verify_old_fido_invalid(module, original_id, "IMMEDIATE")
            fido_verify_siblings(module, hsm, otp, emulator, otp_key, "IMMEDIATE")
        finally:
            emulator.stop()

        emulator = module.Emulator(binary, flash_dir)
        emulator.start()
        try:
            fido_verify_old_fido_invalid(module, original_id, "RESTARTED")
            fido_verify_siblings(module, hsm, otp, emulator, otp_key, "RESTARTED")

            new_id, new_pub, new_counter = fido_provision_new_fido(module)
            if new_id == original_id or new_pub == original_pub:
                raise AssertionError("FIDO reset did not rotate resident identity")
            new_counter = cross.verify_fido(module, new_id, new_pub, new_counter)
            print("F11_POST_RESET_NEW_FIDO_CREDENTIAL_SIGN_VERIFY: PASS", flush=True)
            fido_verify_siblings(module, hsm, otp, emulator, otp_key, "REPROVISIONED")
        finally:
            emulator.stop()

        emulator = module.Emulator(binary, flash_dir)
        emulator.start()
        try:
            cross.verify_fido(module, new_id, new_pub, new_counter)
            fido_verify_siblings(module, hsm, otp, emulator, otp_key, "FINAL_RESTART")
        finally:
            emulator.stop()

    print(f"F11_ROUND_{round_number}_DISPOSABLE_SOFTWARE_FULL_CHAIN: PASS", flush=True)






import argparse
import tempfile
from pathlib import Path

from yubikit.hsmauth import HsmAuthSession
from yubikit.oath import OathSession
from yubikit.yubiotp import SLOT, YubiOtpSession

import host_cross_applet_longevity as cross
import host_applet_reset_isolation as apdu_reset


def other_verify_other_five(module, hsm, otp, emu, target, credential_id, public_key,
                      previous_counter, otp_key, stage):
    if emu.ccid is None:
        raise RuntimeError("virtual PCSC test card missing")
    counter = cross.verify_fido(module, credential_id, public_key, previous_counter)
    print(f"A12_SOFTWARE_{target.upper()}_{stage}_FIDO_RESIDENT_SIGNATURE: PASS", flush=True)
    if target != "piv":
        cross.verify_piv(module, emu.ccid)
        print(f"A12_SOFTWARE_{target.upper()}_{stage}_PIV_PIN: PASS", flush=True)
    if target != "openpgp":
        cross.verify_openpgp(module, emu.ccid)
        print(f"A12_SOFTWARE_{target.upper()}_{stage}_OPENPGP_ADMIN_PIN: PASS", flush=True)
    if target != "oath":
        cross.verify_oath(module, emu.ccid)
        print(f"A12_SOFTWARE_{target.upper()}_{stage}_OATH_CREDENTIAL: PASS", flush=True)
    if target != "otp":
        cross.verify_otp(module, otp, emu.ccid, otp_key)
        print(f"A12_SOFTWARE_{target.upper()}_{stage}_OTP_HMAC: PASS", flush=True)
    if target != "hsm":
        cross.verify_hsm(hsm, emu.ccid)
        print(f"A12_SOFTWARE_{target.upper()}_{stage}_HSM_SESSION_KEYS: PASS", flush=True)
    return counter


def other_clear_target(module, hsm, emu, target):
    assert emu.ccid is not None
    conn = hsm.TcpSmartCardConnection(emu.ccid)
    if target in ("piv", "openpgp"):
        apdu_reset.reset_applet(module, emu.ccid, target)
    elif target == "oath":
        OathSession(conn).reset()
    elif target == "hsm":
        HsmAuthSession(conn).reset()
    elif target == "otp":
        YubiOtpSession(conn).delete_slot(SLOT.ONE)
    else:
        raise ValueError(target)
    print(f"A12_SOFTWARE_{target.upper()}_DEDICATED_CLEAR_COMMAND: PASS", flush=True)


def other_verify_target_cleared(module, hsm, otp, emu, target, stage):
    assert emu.ccid is not None
    if target == "oath":
        cross.select(module, emu.ccid, cross.OATH_AID)
        body, sw = module.transmit(emu.ccid, module.apdu(0xA1))
        assert sw == 0x9000 and cross.OATH_NAME not in body, (sw, body)
    elif target == "hsm":
        assert not any(item.label == cross.HSM_LABEL for item in HsmAuthSession(
            hsm.TcpSmartCardConnection(emu.ccid)).list_credentials())
    elif target == "otp":
        status = otp.select_otp(module, emu.ccid)
        assert not otp.slot1_configured(status)
    elif target == "piv":
        cross.select(module, emu.ccid, cross.PIV_AID)
        _, old_sw = module.transmit(emu.ccid, module.apdu(0x20, 0, 0x80, cross.PIV_PIN))
        _, default_sw = module.transmit(emu.ccid, module.apdu(0x20, 0, 0x80, cross.PIV_PIN_DEFAULT))
        assert old_sw != 0x9000 and default_sw == 0x9000, (old_sw, default_sw)
    elif target == "openpgp":
        cross.select(module, emu.ccid, cross.OPENPGP_AID)
        _, old_sw = module.transmit(emu.ccid, module.apdu(0x20, 0, 0x83, cross.OPENPGP_PW3))
        _, default_sw = module.transmit(emu.ccid, module.apdu(0x20, 0, 0x83, cross.OPENPGP_PW3_DEFAULT))
        assert old_sw != 0x9000 and default_sw == 0x9000, (old_sw, default_sw)
    else:
        raise ValueError(target)
    if target in ("piv", "openpgp"):
        print(f"A12_SOFTWARE_{target.upper()}_{stage}_TARGET_PIN_RESET_TO_DEFAULT: PASS", flush=True)
    else:
        print(f"A12_SOFTWARE_{target.upper()}_{stage}_TARGET_CREDENTIAL_EMPTY: PASS", flush=True)


def other_run_case(binary, target):
    module = cross.load_module(cross.DURABILITY, "host_powercycle_durability")
    hsm = cross.load_module(cross.HSM_TEST, "host_hsmauth")
    otp = cross.load_module(cross.OTP_TEST, "otp_sector_powercut_matrix")

    with tempfile.TemporaryDirectory(prefix=f"aromatic-a12-{target}-") as directory:
        work = Path(directory)
        credential_id, public_key, counter, otp_key = cross.establish_state(
            module, hsm, otp, binary, work,
        )
        emu = module.Emulator(binary, work)
        emu.start()
        try:
            assert emu.ccid is not None
            counter = other_verify_other_five(
                module, hsm, otp, emu, "baseline", credential_id, public_key,
                counter, otp_key, "BEFORE",
            )
            # Initial target must be usable before it is cleared.
            if target == "piv":
                cross.verify_piv(module, emu.ccid)
            elif target == "openpgp":
                cross.verify_openpgp(module, emu.ccid)
            elif target == "oath":
                cross.verify_oath(module, emu.ccid)
            elif target == "otp":
                cross.verify_otp(module, otp, emu.ccid, otp_key)
            else:
                cross.verify_hsm(hsm, emu.ccid)
            print(f"A12_SOFTWARE_{target.upper()}_BUSINESS_BEFORE_CLEAR: PASS", flush=True)

            other_clear_target(module, hsm, emu, target)
            other_verify_target_cleared(module, hsm, otp, emu, target, "IMMEDIATE")
            counter = other_verify_other_five(
                module, hsm, otp, emu, target, credential_id, public_key,
                counter, otp_key, "IMMEDIATE",
            )
        finally:
            emu.stop()

        emu = module.Emulator(binary, work)
        emu.start()
        try:
            other_verify_target_cleared(module, hsm, otp, emu, target, "RESTARTED")
            other_verify_other_five(
                module, hsm, otp, emu, target, credential_id, public_key,
                counter, otp_key, "RESTARTED",
            )
        finally:
            emu.stop()
    print(f"A12_SOFTWARE_{target.upper()}_ISOLATION_AND_DURABILITY: PASS", flush=True)






def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--case", choices=("smartcard", "fido", "other", "all"), default="all")
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    assert args.rounds > 0
    if args.case in ("smartcard", "all"):
        for applet in ("openpgp", "piv"):
            run_case(binary, applet)
    if args.case in ("fido", "all"):
        for index in range(1, args.rounds + 1):
            fido_run_round(binary, index)
    if args.case in ("other", "all"):
        for applet in ("piv", "openpgp", "oath", "hsm", "otp"):
            other_run_case(binary, applet)


if __name__ == "__main__":
    main()
