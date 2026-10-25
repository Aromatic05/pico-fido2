#!/usr/bin/env python3
"""exercise the real CCID arbitration helper against BLE ownership.

The test compiles ccid_defer_busy_request extracted from the SDK source,
not a reimplementation. It also checks the RX parser does not consume a
pending request before giving the other transport its short grace window.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from ccid_transport_regression import SOURCE, function_body

HEADER = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define CCID_TRANSPORT_CAPACITY 1
#define CCID_BUSY_GRACE_MS 350U
#define CCID_POWER_ON 0x62
#define CCID_POWER_OFF 0x63
#define CCID_XFR_BLOCK 0x6F
static bool ccid_busy_wait_started[CCID_TRANSPORT_CAPACITY];
static uint32_t ccid_busy_wait_since[CCID_TRANSPORT_CAPACITY];
static bool owner_idle;
static uint32_t now_ms;
static bool card_is_idle(void) { return owner_idle; }
static uint32_t board_millis(void) { return now_ms; }
"""

TESTS = r"""
static void reset_test(void) {
    ccid_busy_wait_started[0]=false;
    ccid_busy_wait_since[0]=0;
    owner_idle=true;
    now_ms=100;
}
static void short_ble_contention_preserves_request(void) {
    reset_test();
    owner_idle=false;
    assert(ccid_defer_busy_request(0,CCID_XFR_BLOCK));
    assert(ccid_busy_wait_started[0]);
    now_ms=449;
    assert(ccid_defer_busy_request(0,CCID_XFR_BLOCK));
    owner_idle=true;
    now_ms=449;
    assert(!ccid_defer_busy_request(0,CCID_XFR_BLOCK));
    assert(!ccid_busy_wait_started[0]);
    puts("CCID_RETRY_TRANSIENT_BLE_OWNER_WITHOUT_BUSY: PASS");
}
static void bounded_grace_retains_busy_for_long_owner(void) {
    reset_test();
    owner_idle=false;
    assert(ccid_defer_busy_request(0,CCID_POWER_ON));
    now_ms=449;
    assert(ccid_defer_busy_request(0,CCID_POWER_ON));
    now_ms=450;
    assert(!ccid_defer_busy_request(0,CCID_POWER_ON));
    assert(!ccid_busy_wait_started[0]);
    puts("CCID_RETRY_POWER_ON_350MS_BOUNDARY: PASS");
}
static void power_off_and_unrelated_commands(void) {
    reset_test();
    owner_idle=false;
    assert(ccid_defer_busy_request(0,CCID_POWER_OFF));
    assert(!ccid_defer_busy_request(0,0x65));
    assert(!ccid_busy_wait_started[0]);
    puts("CCID_POWER_OFF_DELAYED_SLOT_STATUS_IMMEDIATE: PASS");
}
static void clock_wrap_and_new_request(void) {
    reset_test();
    owner_idle=false;
    now_ms=UINT32_MAX-100;
    assert(ccid_defer_busy_request(0,CCID_XFR_BLOCK));
    now_ms=50;
    assert(ccid_defer_busy_request(0,CCID_XFR_BLOCK));
    now_ms=250;
    assert(!ccid_defer_busy_request(0,CCID_XFR_BLOCK));
    assert(ccid_defer_busy_request(0,CCID_XFR_BLOCK));
    puts("CCID_RETRY_TIME_WRAP_AND_FRESH_GRACE: PASS");
}
int main(void) {
    short_ble_contention_preserves_request();
    bounded_grace_retains_busy_for_long_owner();
    power_off_and_unrelated_commands();
    clock_wrap_and_new_request();
    return 0;
}
"""


def main() -> None:
    source = SOURCE.read_text()
    parser = function_body(source, "driver_process_usb_packet_ccid")
    defer_call = parser.index("ccid_defer_busy_request(")
    assert defer_call < parser.index("memcpy(ccid_request[itf].buffer,")
    assert defer_call < parser.index("ccid_rx[itf].r_ptr += frame_len")
    assert "memset(ccid_busy_wait_started, 0, sizeof(ccid_busy_wait_started))" in source
    code = HEADER + function_body(source, "ccid_defer_busy_request") + TESTS
    with tempfile.TemporaryDirectory(prefix="ak-ccid-busy-") as directory:
        c = Path(directory) / "test.c"
        exe = Path(directory) / "test"
        c.write_text(code)
        subprocess.run(
            ["cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             "-o", str(exe), str(c)],
            check=True,
        )
        subprocess.run([str(exe)], check=True)
    print("CCID_RX_PARSER_PRESERVES_PENDING_FRAME_UNTIL_RETRY: PASS")


if __name__ == "__main__":
    main()
