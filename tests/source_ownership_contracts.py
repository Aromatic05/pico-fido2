#!/usr/bin/env python3
"""Static source contracts connecting the ownership model to product C code."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT / "pico-keys-sdk" / "src"
HID = SDK / "usb" / "hid" / "hid.c"
CCID = SDK / "usb" / "ccid" / "ccid.c"
USB = SDK / "usb" / "usb.c"
USB_H = SDK / "usb" / "usb.h"
MAIN = SDK / "main.c"
APDU = SDK / "apdu.c"
HWRNG = SDK / "rng" / "hwrng.c"
EMULATION = SDK / "usb" / "emulation" / "emulation.c"
LED = SDK / "led" / "led.c"
BLE = ROOT / "src" / "fido2" / "ble_fido.c"
OTP = ROOT / "pico-fido" / "src" / "fido" / "otp.c"
CBOR_CONFIG = ROOT / "pico-fido" / "src" / "fido" / "cbor_config.c"
CREDENTIAL = ROOT / "pico-fido" / "src" / "fido" / "credential.c"
GET_ASSERTION = ROOT / "pico-fido" / "src" / "fido" / "cbor_get_assertion.c"
MAKE_CREDENTIAL = ROOT / "pico-fido" / "src" / "fido" / "cbor_make_credential.c"
CTAP_H = ROOT / "pico-fido" / "src" / "fido" / "ctap.h"
AUTHENTICATE = ROOT / "pico-fido" / "src" / "fido" / "cmd_authenticate.c"
PIV = ROOT / "pico-openpgp" / "src" / "openpgp" / "piv.c"
CMAKE = ROOT / "CMakeLists.txt"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", source, re.S)
    if not match:
        raise AssertionError(f"function not found: {name}")
    start = match.end()
    depth = 1
    pos = start
    while pos < len(source) and depth:
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
        pos += 1
    if depth:
        raise AssertionError(f"unterminated function: {name}")
    return source[start : pos - 1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def before(body: str, first: str, second: str, message: str) -> None:
    a = body.find(first)
    b = body.find(second)
    require(a >= 0, f"missing source marker: {first}")
    require(b >= 0, f"missing source marker: {second}")
    require(a < b, message)


def verify_product_sdk_binding() -> None:
    source = text(CMAKE)
    require("pico-keys-sdk/src" in source, "product ESP32 build no longer binds root pico-keys-sdk")
    require(
        "include(pico-keys-sdk/pico_keys_sdk_import.cmake)" in source,
        "product host build no longer imports root pico-keys-sdk",
    )
    require(
        "pico-fido/pico-keys-sdk" not in source and "pico-openpgp/pico-keys-sdk" not in source,
        "product build must not silently bind a nested SDK copy",
    )


def verify_arbiter() -> None:
    source = text(USB)
    main_source = text(MAIN)
    header = text(USB_H)
    start = function_body(source, "card_start_claimed")
    exit_claimed = function_body(source, "card_exit_claimed")
    try_claim = function_body(source, "card_try_claim")
    release = function_body(source, "card_release")
    status = function_body(source, "card_status")
    core0 = function_body(main_source, "core0_loop")
    require(
        "card_command_is_owned_by(itf)" in start,
        "card_start_claimed must verify the caller owns the card command",
    )
    require("return false" in start, "card_start_claimed must reject non-owner callers")
    require(
        "card_command_is_owned_by(itf)" in exit_claimed and "return false" in exit_claimed,
        "card_exit_claimed must reject non-owner callers",
    )
    require("static bool card_start(" in source, "raw worker start must remain private to the arbiter")
    require("static void card_exit_unchecked(" in source, "raw worker exit must remain private to the arbiter")
    require("extern bool card_start(" not in header, "raw worker start must not be exported")
    require("extern void card_exit(" not in header, "raw worker exit must not be exported")
    require("mutex_enter_blocking(&card_state_mutex)" in try_claim and
            "mutex_exit(&card_state_mutex)" in try_claim,
            "product command claim must serialize cross-task owner changes")
    require("mutex_enter_blocking(&card_state_mutex)" in release and
            "mutex_exit(&card_state_mutex)" in release,
            "product command release must serialize cross-task owner changes")
    require("card_try_claim_maintenance()" in core0,
            "flash/cache maintenance must participate in the global command arbiter")
    before(core0, "low_flash_is_pending()", "card_try_claim_maintenance()",
           "idle maintenance must only contend for the owner when flash work is pending")
    before(core0, "card_try_claim_maintenance()", "do_flash()",
           "main loop must claim maintenance ownership before flash cache reuse")
    before(core0, "do_flash()", "card_release_maintenance()",
           "main loop must retain maintenance ownership until flash work completes")
    finished = status[status.find("m == EV_EXEC_FINISHED") :]
    require(finished, "card_status must handle worker completion")
    before(finished, "low_flash_is_pending()", "do_flash()",
           "worker completion must detect pending flash before owner-local flush")
    before(finished, "do_flash()", "queue_try_add(&card_to_usb_q, &m)",
           "worker completion must try owner-local flush before requeueing completion")
    before(finished, "do_flash()", "return PICOKEY_OK",
           "worker completion must finish pending flash before reporting response ready")


def verify_button_signals() -> None:
    source = text(MAIN)
    wait = function_body(source, "wait_button")
    require("__atomic_store_n(&cancel_button" in source, "cancel request must use atomic stores")
    require("__atomic_load_n(&cancel_button" in source, "cancel request must use atomic loads")
    require("__atomic_store_n(&req_button_pending" in source, "button-pending state must use atomic stores")
    require("__atomic_load_n(&req_button_pending" in source, "button-pending state must use atomic loads")
    require("execute_tasks()" not in wait, "worker-side button wait must not recursively run transport tasks")


def verify_hwrng_state() -> None:
    source = text(HWRNG)
    task = function_body(source, "hwrng_task")
    get = function_body(source, "hwrng_get")
    flush = function_body(source, "hwrng_flush")
    wait_full = function_body(source, "hwrng_wait_full")
    require("static mutex_t hwrng_mutex" in source, "HWRNG shared state must have one ownership mutex")
    for label, body in (("task", task), ("get", get), ("flush", flush), ("wait_full", wait_full)):
        require("mutex_enter_blocking(&hwrng_mutex)" in body, f"HWRNG {label} must acquire the shared-state mutex")
        require("mutex_exit(&hwrng_mutex)" in body, f"HWRNG {label} must release the shared-state mutex")


def verify_emulator_arbiter() -> None:
    source = text(EMULATION)
    read = function_body(source, "emul_read")
    task = function_body(source, "emul_ccid_task")
    require("process_apdu()" not in read,
            "host emulator CCID receive path must not synchronously bypass the product arbiter")
    require("memcpy(emul_ccid_request, emul_rx, len)" in read,
            "host emulator must snapshot CCID request bytes before deferred execution")
    for reset in ("apdu_reset_warm_session(APDU_SESSION_CCID)", "apdu_reset_session(APDU_SESSION_CCID)"):
        reset_pos = read.index(reset)
        claim_pos = read.rfind("card_try_claim(ITF_CCID)", 0, reset_pos)
        release_pos = read.find("card_release(ITF_CCID)", reset_pos)
        require(claim_pos >= 0,
                "host emulator session reset must claim global APDU/application state")
        require(release_pos >= 0,
                "host emulator session reset must release global APDU/application state")
    before(task, "card_try_claim(ITF_CCID)", "apdu_process(APDU_SESSION_CCID",
           "host emulator CCID must claim the same global owner before APDU execution")
    before(task, "card_try_claim(ITF_CCID)", "card_start_claimed(ITF_CCID, apdu_thread)",
           "host emulator CCID worker start must remain owner-checked")
    require("uint16_t ret = finished_data_size" in task,
            "host emulator async completion must use the worker-produced response length")
    require("apdu_next()" not in task,
            "host emulator must not advance an async APDU response a second time")
    require("card_release(ITF_CCID)" in task,
            "host emulator CCID must release the shared owner after response completion")


def verify_runtime_ui_state() -> None:
    led_source = text(LED)
    config_source = text(CBOR_CONFIG)
    set_mode = function_body(led_source, "led_set_mode")
    get_mode = function_body(led_source, "led_get_mode")
    blink = function_body(led_source, "led_blinking_task")
    require("__atomic_store_n(&led_mode" in set_mode,
            "LED mode is written by workers and must use an atomic store")
    require("__atomic_load_n(&led_mode" in get_mode,
            "LED mode is read by the main task and must use an atomic load")
    require("uint32_t mode = led_get_mode()" in blink,
            "LED task must snapshot LED mode once per tick")
    require(re.search(r"\bled_mode\b", blink) is None,
            "LED task must not bypass the atomic led_get_mode snapshot")
    require("__atomic_load_n(&phy_data.opts" in blink,
            "runtime PHY options read by LED task must be atomic")
    require("__atomic_store_n(&phy_data.opts" in config_source,
            "runtime vendor PHY option updates must use an atomic store")


def verify_hid_adapter() -> None:
    source = text(HID)
    init = function_body(source, "driver_init_hid")
    callback = function_body(source, "tud_hid_set_report_cb")
    parser = function_body(source, "driver_process_usb_packet_hid")
    task = function_body(source, "hid_task")
    keepalive = function_body(source, "send_keepalive")
    queue_response = function_body(source, "hid_queue_response")
    async_finish = function_body(source, "driver_exec_finished_hid")
    finish = function_body(source, "driver_exec_finished_cont_hid")

    for forbidden in (
        "ctap_req = (CTAPHID_FRAME *) (hid_rx",
        "apdu.header =",
        "apdu.rdata =",
        "memset(ctap_resp",
        "hid_tx[ITF_HID_CTAP].w_ptr =",
    ):
        require(forbidden not in init, f"HID init mutates shared/response state before claim: {forbidden}")

    require(
        "driver_process_usb_packet_hid" not in callback,
        "TinyUSB RX callback must only enqueue data; it must not enter core parsing directly",
    )
    require(
        "sizeof(hid_rx[itf].buffer)" in callback,
        "HID RX enqueue must bounds-check the ring storage",
    )

    require(
        "card_command_is_owned_by(ITF_HID)" in parser,
        "HID parser must refuse ordinary input while its worker owns the command",
    )
    require("memcpy(&ctap_req_snapshot, rx_req, sizeof(ctap_req_snapshot))" in parser,
            "HID must snapshot each report before releasing reusable RX ring storage")
    before(parser,
           "if (!card_is_idle())",
           "memcpy(&ctap_req_snapshot, rx_req, sizeof(ctap_req_snapshot))",
           "HID must arbitrate an existing owner before overwriting the worker-visible request snapshot")
    require("ctap_error_for_cid(rx_req->cid, CTAP1_ERR_CHANNEL_BUSY)" in parser,
            "HID foreign-owner BUSY response must use the incoming RX CID without borrowing worker snapshot state")
    snapshot_pos = parser.index("memcpy(&ctap_req_snapshot, rx_req, sizeof(ctap_req_snapshot))")
    owner_guard_pos = parser.index("if (!card_is_idle())")
    busy_prefix = parser[owner_guard_pos:snapshot_pos]
    require("ctap_req_snapshot" not in busy_prefix,
            "HID BUSY/CANCEL handling must not overwrite or borrow the active worker snapshot")
    normal_release_pos = parser.find("hid_rx[ITF_HID_CTAP].r_ptr += 64", snapshot_pos)
    require(normal_release_pos > snapshot_pos,
            "HID normal path must snapshot the report before releasing reusable RX ring storage")
    require("ctap_req = &ctap_req_snapshot" in parser,
            "HID parser must read the stable report snapshot, not the RX ring")
    before(parser, "if (!card_is_idle())", "hid_prepare_response()",
           "HID must arbitrate foreign owners before mutating response/transaction state")
    require("static void hid_abort_transaction(void)" in source,
            "HID must have one explicit transaction-abort boundary")
    init_block = parser[parser.find("ctap_req->init.cmd == CTAPHID_INIT") :
                        parser.find("ctap_req->init.cmd == CTAPHID_WINK")]
    before(init_block, "card_try_claim(ITF_HID)", "card_exit_claimed(ITF_HID)",
           "CTAPHID_INIT may replace a parked worker only after acquiring the HID owner")
    before(parser, "if (!card_is_idle())", "card_exit_claimed(ITF_HID)",
           "worker exit must be unreachable while a command/completion still owns the core")
    busy_claims = re.findall(
        r"if \(!card_try_claim\(ITF_HID\)\) \{\s*hid_abort_transaction\(\);\s*return ctap_error\(CTAP1_ERR_CHANNEL_BUSY\);\s*\}",
        parser,
        re.S,
    )
    require(len(busy_claims) == 3,
            "every completed HID request that loses owner arbitration must abort stale transaction state")
    require("hid_tx_idle()" in parser, "HID parser must not reuse response storage while TX is active")
    require("hid_prepare_response()" in parser, "HID response storage must be prepared only at safe parse time")

    require(
        re.search(r"apdu_process\([^;]*msg_packet\.data\s*,\s*msg_packet\.len\s*\)", parser) is not None,
        "HID APDU worker request must use stable msg_packet storage",
    )
    require(
        re.search(r"cbor_process\([^;]*msg_packet\.data\s*,\s*msg_packet\.len\s*\)", parser) is not None,
        "HID CBOR worker request must use stable msg_packet storage",
    )
    require(
        "apdu_process(APDU_SESSION_HID, ITF_HID_CTAP, ctap_req->init.data" not in parser,
        "HID APDU worker must not borrow reusable RX report storage",
    )
    require(
        "cbor_process(last_cmd, ctap_req->init.data" not in parser,
        "HID CBOR worker must not borrow reusable RX report storage",
    )

    before(
        parser,
        "card_try_claim(ITF_HID)",
        "apdu.rdata = ctap_resp->init.data",
        "HID APDU response context must be bound only after claim",
    )
    require("active_cid = last_req.cid" in parser, "HID must snapshot CID for async response")
    require("active_cmd = last_cmd" in parser, "HID must snapshot command for async response")
    require("active_cid" in keepalive and "ctap_req->cid" not in keepalive, "HID keepalive must use snapshotted CID")
    require("ctap_resp->cid = cid" in queue_response and "ctap_resp->init.cmd = cmd" in queue_response,
            "HID response primitive must take header ownership explicitly")
    require("hid_queue_response(ITF_HID_CTAP, active_cid, active_cmd" in async_finish,
            "HID async completion must use the worker response snapshot")
    require("hid_queue_response(itf, active_cid, active_cmd" in finish,
            "HID APDU continuation must use the worker response snapshot")
    require("offset -= 7" not in finish,
            "HID continuation offset must not use the legacy underflow-prone header magic")

    ping_begin = parser.index("else if ((last_cmd == CTAPHID_PING || last_cmd == CTAPHID_SYNC)")
    ping_end = parser.index("else if (ctap_req->init.cmd == CTAPHID_LOCK)", ping_begin)
    ping = parser[ping_begin:ping_end]
    require("hid_queue_response(ITF_HID_CTAP, last_req.cid, last_cmd" in ping,
            "HID synchronous PING/SYNC response must use the current transaction snapshot")
    require("active_cid" not in ping and "active_cmd" not in ping,
            "HID synchronous response must not borrow a stale async worker header")

    before(
        task,
        "card_status(ITF_HID)",
        "driver_process_usb_packet_hid(64)",
        "HID task must collect worker completion before consuming another RX report",
    )
    require(
        "hid_tx_idle()" in task,
        "HID task must wait for transport-owned TX to drain before reusing response storage",
    )


def verify_ccid_adapter() -> None:
    source = text(CCID)
    init = function_body(source, "driver_init_ccid")
    rx_callback = function_body(source, "tud_vendor_rx_cb")
    fast_write = function_body(source, "ccid_write_fast")
    parser = function_body(source, "driver_process_usb_packet_ccid")
    task = function_body(source, "ccid_task")
    timeout = function_body(source, "driver_exec_timeout_ccid")
    finish = function_body(source, "driver_exec_finished_cont_ccid")
    fast_finish = function_body(source, "driver_exec_finished_fast_ccid")

    require(
        "ccid_response[itf] =" not in init,
        "CCID init must not bind mutable response storage before command claim",
    )
    require(
        "sizeof(ccid_rx[itf].buffer) - ccid_rx[itf].w_ptr" in rx_callback,
        "CCID RX callback must cap reads to remaining ring capacity",
    )
    require(
        "driver_process_usb_packet_ccid" not in rx_callback,
        "CCID TinyUSB RX callback must only enqueue bytes; parsing belongs to the main transport task",
    )
    require(
        "driver_process_usb_packet_ccid" in task,
        "CCID main task must be the only runtime consumer of the RX ring",
    )
    before(task,
           "card_command_is_owned_by(sc_itf_to_usb_itf(itf))",
           "driver_process_usb_packet_ccid",
           "CCID must not parse a second request while its worker still owns the active request snapshot")
    owner_guard = task[task.find("card_command_is_owned_by(sc_itf_to_usb_itf(itf))") :
                       task.find("driver_process_usb_packet_ccid")]
    require("continue" in owner_guard,
            "CCID owner guard must stop parsing until the active worker releases request ownership")
    require(
        "driver_write_ccid" not in fast_write,
        "CCID fast scratch packets must not advance the normal TX ring",
    )
    require(
        "ccid_tx[itf].r_ptr" not in fast_write and "ccid_tx[itf].w_ptr" not in fast_write,
        "CCID fast writer must not mutate normal TX ring cursors",
    )

    xfr = parser[parser.find("CCID_XFR_BLOCK") :]
    before(
        xfr,
        "card_try_claim(usb_itf)",
        "ccid_response[itf] =",
        "CCID XFR response storage must be bound only after claim",
    )
    before(
        xfr,
        "card_try_claim(usb_itf)",
        "apdu.rdata =",
        "CCID XFR APDU response pointer must be bound only after claim",
    )
    require("memcpy(ccid_request[itf].buffer, ccid_header[itf], frame_len)" in parser,
            "CCID must snapshot the complete message before releasing RX ring storage")
    release_pos = parser.find("ccid_rx[itf].r_ptr += frame_len")
    require(release_pos >= 0, "CCID parser must explicitly release snapshotted RX storage")
    complete_tail = parser[release_pos:]
    require("ccid_header[itf]" not in complete_tail,
            "CCID parser must not read mutable RX header after releasing ring storage")
    require(
        "ccid_active_seq[itf] = request->bSeq" in xfr,
        "CCID must snapshot bSeq from the stable request copy while it owns the command",
    )
    require(
        "ccid_response[itf]->bSeq = ccid_active_seq[itf]" in xfr,
        "CCID response must bind the snapshotted bSeq",
    )
    require(
        re.search(r"apdu_process\([^;]*&request->apdu\s*,\s*apdu_len\s*\)", xfr) is not None,
        "CCID worker must not borrow the reusable RX ring",
    )
    require(
        "ccid_header[itf]->bSeq" not in finish,
        "CCID async completion must not read the current mutable RX header",
    )
    require("ccid_active_seq[itf]" in finish, "CCID final response must use snapshotted sequence")
    require("ccid_header[itf]->bSeq" not in timeout and "ccid_active_seq[itf]" in timeout,
            "CCID TIMEEXT must use the active command sequence")
    require("ccid_header[itf]->bSeq" not in fast_finish and "ccid_active_seq[itf]" in fast_finish,
            "CCID synchronous continuation must use the active command sequence")

    power_on = parser[parser.find("CCID_POWER_ON") : parser.find("CCID_POWER_OFF")]
    power_off = parser[parser.find("CCID_POWER_OFF") : parser.find("CCID_SET_PARAMS")]
    for label, block in (("POWER_ON", power_on), ("POWER_OFF", power_off)):
        before(
            block,
            "card_try_claim(usb_itf)",
            "apdu_reset_session",
            f"CCID {label} must claim global APDU/application state before session reset",
        )
        require("card_release(usb_itf)" in block, f"CCID {label} must release its claim")


def verify_apdu_sessions() -> None:
    source = text(APDU)
    session_struct = source[source.find("typedef struct apdu_session_state") : source.find("} apdu_session_state_t;")]
    require("response_buf[" in session_struct, "GET RESPONSE cache must be session-owned storage")
    require("uint8_t *response_data" not in session_struct, "GET RESPONSE cache must not borrow transport TX pointers")
    require("uint8_t *response_next" not in session_struct, "GET RESPONSE cursor must be an offset, not a transport pointer")
    require("response_offset" in session_struct, "GET RESPONSE must use session-relative offsets")


def verify_ble_adapter() -> None:
    source = text(BLE)
    dispatch = function_body(source, "fido_ble_dispatch")
    write = function_body(source, "fido_ble_control_point_write")
    gap = function_body(source, "fido_ble_gap_event")
    release = function_body(source, "fido_ble_release_request")
    reducer = function_body(source, "fido_ble_handle_event")
    task = function_body(source, "fido_ble_task")
    queue_event = function_body(source, "fido_ble_queue_event")
    overflow = function_body(source, "fido_ble_recover_event_overflow")

    require("FIDO_BLE_CORE_IDLE" in source and "FIDO_BLE_CORE_RUNNING" in source and "FIDO_BLE_CORE_ABORTED" in source,
            "BLE core lifecycle must use an explicit enum state")
    require(re.search(r"\bprocessing\b", source) is None, "BLE must not regress to an independent processing boolean")
    require(re.search(r"\bprocessing_aborted\b", source) is None, "BLE must not regress to an independent aborted boolean")
    require("__atomic_store_n(&event_overflow" in queue_event,
            "BLE event queue overflow must become a sticky fail-closed fault, not a dropped event")
    require("__atomic_exchange_n(&event_overflow" in overflow,
            "BLE core task must consume the sticky event-overflow fault")
    require("FIDO_BLE_CORE_ABORTED" in overflow and "button_cancel_request()" in overflow,
            "BLE event overflow during execution must abort the owned command")
    require("fido_ble_release_request()" in overflow,
            "BLE event overflow while idle must release any retained RX ownership token")
    before(task, "fido_ble_recover_event_overflow()", "fido_ble_process_events()",
           "BLE must fail closed on queue overflow before consuming later events")

    before(dispatch, "card_try_claim(ble_itf)", "cbor_process_to", "BLE must claim shared CBOR context before binding it")
    require("xQueueCreate(1, sizeof(fido_ble_request_t))" in source,
            "BLE request queue must remain capacity one so its entry is the RX ownership token")
    require("xQueuePeek(request_queue" in task,
            "BLE main task must peek, not consume, the request while worker/TX still owns RX data")
    require("xQueueReceive(request_queue" in release and "fido_ble_rx_reset(&rx)" in release,
            "BLE request release must atomically consume the ownership token and clear RX")
    require("rx_mutex" in release, "BLE RX ownership-token release must synchronize with the GATT task")
    require("fido_ble_request_pending()" in write,
            "BLE GATT writer must reject reuse while a request ownership token exists")
    for forbidden in ("core_state", "card_try_claim", "card_start_claimed", "card_status", "card_release", "tx_active", "tx_waiting"):
        require(forbidden not in write, f"BLE GATT write callback must not enter main/core state: {forbidden}")
        require(forbidden not in gap, f"BLE GAP callback must only publish events, not mutate main/core state: {forbidden}")
    require("fido_ble_queue_event" in gap, "BLE GAP callback must publish lifecycle events to the main reducer")
    require("FIDO_BLE_EVENT_CANCEL" in write, "BLE cancel must be serialized through the event queue")
    require("core_state = FIDO_BLE_CORE_RUNNING" in dispatch,
            "BLE main-thread dispatch must own the RUNNING transition")
    running_tail = dispatch[dispatch.find("core_state = FIDO_BLE_CORE_RUNNING") :]
    require("fido_ble_release_request" not in running_tail,
            "BLE worker-owned RX token must not be released at dispatch time")
    require("FIDO_BLE_CORE_ABORTED" in reducer and "button_cancel_request" in reducer,
            "BLE reducer must serialize disconnect/unsubscribe cancellation")
    require("FIDO_BLE_CORE_ABORTED" in task, "BLE task must explicitly complete aborted workers")
    notify_pos = task.find("fido_ble_notify(FIDO_BLE_CMD_MSG")
    require(notify_pos >= 0, "BLE normal completion must queue the response into private TX storage")
    release_after_notify = task.find("card_release(ble_itf)", notify_pos)
    require(
        release_after_notify > notify_pos,
        "BLE normal completion must copy response into transport-owned TX payload before release",
    )


def verify_otp_hid_adapter() -> None:
    source = text(OTP)
    set_report = function_body(source, "otp_hid_set_report_cb")
    get_report = function_body(source, "otp_hid_get_report_cb")

    before(
        set_report,
        "card_try_claim(ITF_KEYBOARD)",
        "apdu.header = hdr",
        "OTP HID command path must claim shared APDU state before binding request context",
    )
    before(
        set_report,
        "card_try_claim(ITF_KEYBOARD)",
        "otp_process_apdu()",
        "OTP HID command path must claim before synchronous APDU execution",
    )
    require("struct apdu saved_apdu = apdu" in set_report, "OTP HID command must preserve prior APDU context")
    require("apdu = saved_apdu" in set_report, "OTP HID command must restore APDU context before release")
    before(
        set_report,
        "apdu = saved_apdu",
        "card_release(ITF_KEYBOARD)",
        "OTP HID command must restore APDU context before releasing owner",
    )

    before(
        get_report,
        "card_try_claim(ITF_KEYBOARD)",
        "res_APDU = buffer",
        "OTP HID status path must claim shared APDU state before binding response context",
    )
    require("struct apdu saved_apdu = apdu" in get_report, "OTP HID status must preserve prior APDU context")
    require("apdu = saved_apdu" in get_report, "OTP HID status must restore APDU context")
    before(
        get_report,
        "apdu = saved_apdu",
        "card_release(ITF_KEYBOARD)",
        "OTP HID status must restore APDU context before releasing owner",
    )


def verify_piv_slot_storage() -> None:
    source = text(PIV)
    x509_create = function_body(source, "x509_create_cert")
    get_metadata = function_body(source, "cmd_get_metadata")
    authenticate = function_body(source, "cmd_authenticate")
    keygen = function_body(source, "cmd_asym_keygen")
    move_key = function_body(source, "cmd_move_key")
    import_key = function_body(source, "cmd_import_asym")

    require(
        source.count("key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref") == 1,
        "PIV logical slot 0x93 mapping must exist only inside piv_key_storage_fid",
    )
    require("piv_key_storage_fid" in get_metadata,
            "PIV GET_METADATA must resolve the logical slot through storage mapping")
    require("key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK" in get_metadata and
            "? key_ref" in get_metadata,
            "PIV PIN/PUK GET_METADATA must preserve their full 16-bit file identifiers")
    require("while (serial_offset + 1 < sizeof(serial) && serial[serial_offset] == 0)" in x509_create,
            "PIV X.509 serials must strip random leading zero octets before DER INTEGER encoding")
    require("serial[serial_offset] = 1" in x509_create,
            "PIV X.509 serial generation must turn the all-zero value into a positive non-zero INTEGER")
    require("serial + serial_offset" in x509_create and
            "sizeof(serial) - serial_offset" in x509_create,
            "PIV X.509 serial writer must receive the canonicalized serial span")
    require(authenticate.count("piv_key_storage_fid(key_ref)") >= 3,
            "PIV authenticate/ECDH paths must resolve private-key storage through one mapping")
    require("piv_key_storage_fid(key_ref)" in keygen,
            "PIV generated keys must use the logical-to-physical storage mapping")
    require("piv_key_storage_fid(from_ref)" in move_key and
            "piv_key_storage_fid(to_ref)" in move_key,
            "PIV move/delete-key must map both source and destination logical slots")
    require("piv_key_storage_fid(key_ref)" in import_key,
            "PIV imported keys must use the logical-to-physical storage mapping")


def verify_credential_ownership() -> None:
    credential = text(CREDENTIAL)
    assertion = text(GET_ASSERTION)
    make_credential = text(MAKE_CREDENTIAL)
    move = function_body(credential, "credential_move")
    get_assertion = function_body(assertion, "cbor_get_assertion")
    make = function_body(make_credential, "cbor_make_credential")

    before(move, "credential_free(dst)", "*dst = *src",
           "Credential move must release any previous destination ownership before transfer")
    before(move, "*dst = *src", "memset(src, 0, sizeof(*src))",
           "Credential move must clear the source immediately after transferring owned pointers")
    require("creds[numberOfCredentials++] = creds[i]" not in get_assertion,
            "GetAssertion compaction must not shallow-copy owned Credential values")
    require("credsx[i] = creds[i]" not in get_assertion,
            "GetNextAssertion transfer must not duplicate Credential ownership")
    require(get_assertion.count("credential_move(&creds[numberOfCredentials], &creds[i])") == 2,
            "both GetAssertion compaction branches must use explicit Credential move semantics")
    require("credential_move(&credsx[i], &creds[i])" in get_assertion,
            "GetNextAssertion retained credentials must receive ownership through credential_move")

    for label, body in (("GetAssertion", get_assertion), ("MakeCredential", make)):
        cleanup = body.find("err:")
        require(cleanup >= 0, f"{label} must have one common cleanup boundary")
        for ret in re.finditer(r"\breturn\b", body):
            require(ret.start() > cleanup,
                    f"{label} static request-owned storage must not bypass cleanup with an early return")

    require("static PublicKeyCredentialDescriptor allowList" in get_assertion and
            "static Credential creds" in get_assertion,
            "GetAssertion large request-owned arrays must stay outside the worker task stack")
    require("memset(allowList, 0, sizeof(allowList))" in get_assertion and
            "memset(creds, 0, sizeof(creds))" in get_assertion,
            "GetAssertion static owned arrays must be cleared at request boundaries")
    require("static uint8_t aut_data[CTAP_MAX_CBOR_PAYLOAD]" in make and
            "static uint8_t cred_id[MAX_CRED_ID_LENGTH]" in make and
            "static uint8_t cbor_buf[1024]" in make,
            "MakeCredential large request scratch must stay outside the worker task stack")
    require(make.count("mbedtls_platform_zeroize(aut_data, sizeof(aut_data))") >= 2 and
            make.count("mbedtls_platform_zeroize(cred_id, sizeof(cred_id))") >= 2 and
            make.count("mbedtls_platform_zeroize(cbor_buf, sizeof(cbor_buf))") >= 2,
            "MakeCredential static scratch must be zeroized on both entry and cleanup")


def verify_allocation_boundaries() -> None:
    cmake = text(CMAKE)
    usb = text(USB)
    hid = text(HID)
    ccid = text(CCID)
    ble = text(BLE)
    credential = text(CREDENTIAL)

    require("set(DEBUG_APDU 1)" not in cmake,
            "product builds must not enable protocol payload dumps by default")

    for label, source in (("USB core", usb), ("HID", hid), ("CCID", ccid), ("BLE", ble)):
        require(re.search(r"\b(?:malloc|calloc|realloc)\s*\(", source) is None,
                f"{label} runtime transport state must use deterministic static storage, not heap allocation")

    require("CARD_INTERFACE_CAPACITY = 8" in text(USB_H),
            "logical transport registration must have an explicit fixed capacity")
    require("HID_TRANSPORT_CAPACITY = 2" in text(USB_H),
            "HID transport storage capacity must be explicit")
    require("CCID_TRANSPORT_CAPACITY = 2" in text(USB_H),
            "CCID transport storage capacity must be explicit")
    require("if (ITF_TOTAL >= CARD_INTERFACE_CAPACITY)" in function_body(usb, "card_register_interface"),
            "extra transport registration must reject capacity exhaustion")
    require("assert(ble_itf != ITF_INVALID)" in function_body(ble, "fido_ble_init"),
            "BLE initialization must treat interface registration failure as a hard invariant")

    fido_dir = ROOT / "pico-fido" / "src" / "fido"
    allocations: list[tuple[Path, str]] = []
    for path in sorted(fido_dir.glob("*.c")):
        for match in re.finditer(r"\b(?:malloc|calloc|realloc)\s*\([^;]*", text(path)):
            allocations.append((path, match.group(0)))
    require(len(allocations) == 1,
            f"common FIDO protocol code must have exactly one explicit owned allocation, found {allocations}")
    allocation_path, allocation = allocations[0]
    require(allocation_path == CREDENTIAL and "calloc(1, cred_id_len)" in allocation,
            "the only common FIDO heap allocation must be Credential.id owned storage")

    load = function_body(credential, "credential_load")
    before(load, "cred->id.data = (uint8_t *) calloc(1, cred_id_len)",
           "if (cred->id.data == NULL && cred_id_len != 0)",
           "Credential.id allocation must be checked before copying into owned storage")
    before(load, "if (cred->id.data == NULL && cred_id_len != 0)",
           "memcpy(cred->id.data, cred_id, cred_id_len)",
           "Credential.id must never be dereferenced before allocation success")


def verify_protocol_buffer_bounds() -> None:
    assertion = text(GET_ASSERTION)
    ctap_h = text(CTAP_H)
    authenticate = function_body(text(AUTHENTICATE), "cmd_authenticate")

    require("uint8_t datax[CTAP_MAX_CBOR_PAYLOAD]" in assertion,
            "GetNextAssertion must retain the complete negotiated CTAP CBOR payload, not MAX_MSG_SIZE")
    require("#define CTAP_MAX_KH_SIZE         255" in ctap_h,
            "U2F key-handle storage must match the one-byte wire length range")
    require("uint8_t tmp_kh[CTAP_MAX_KH_SIZE]" in authenticate,
            "U2F in-place credential verification must use a full wire-capacity scratch copy")
    require("apdu.nc != CTAP_CHAL_SIZE + CTAP_APPID_SIZE + 1 + req->keyHandleLen" in authenticate,
            "U2F Authenticate must require the actual APDU payload to exactly match keyHandleLen")


def main() -> None:
    checks = (
        ("product SDK binding", verify_product_sdk_binding),
        ("global arbiter", verify_arbiter),
        ("button signals", verify_button_signals),
        ("HWRNG state", verify_hwrng_state),
        ("emulator arbiter", verify_emulator_arbiter),
        ("runtime UI state", verify_runtime_ui_state),
        ("HID ownership", verify_hid_adapter),
        ("CCID ownership", verify_ccid_adapter),
        ("APDU session storage", verify_apdu_sessions),
        ("BLE ownership", verify_ble_adapter),
        ("OTP HID ownership", verify_otp_hid_adapter),
        ("PIV slot storage", verify_piv_slot_storage),
        ("Credential ownership", verify_credential_ownership),
        ("allocation boundaries", verify_allocation_boundaries),
        ("protocol buffer bounds", verify_protocol_buffer_bounds),
    )
    for label, check in checks:
        check()
        print(f"{label}: PASS")


if __name__ == "__main__":
    main()
