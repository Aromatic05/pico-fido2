#!/usr/bin/env python3
"""Exercise actual BLE dispatch under deterministic cross-transport contention."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/fido2/ble_fido.c"


def extract_function(source: str, signature: str) -> str:
    start = source.index(signature)
    depth = 0
    for pos in range(source.index("{", start), len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start : pos + 1]
    raise AssertionError("missing BLE dispatch closing brace")


TEST_HEADER = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>

#define CONFIG_PICO_FIDO2_HIL_DIAG 0
#define FIDO_BLE_CMD_MSG 0x83
#define FIDO_BLE_CMD_PING 0x81
#define FIDO_BLE_CMD_CANCEL 0xBE
#define FIDO_BLE_CMD_ERROR 0xBF
#define FIDO_BLE_ERR_BUSY 0x06
#define FIDO_BLE_ERR_INVALID_CMD 0x01
#define FIDO_BLE_ERR_OTHER 0x7F
#define FIDO_BLE_CORE_IDLE 0
#define FIDO_BLE_CORE_RUNNING 1
#define CTAPHID_CBOR 0x90
#define FIDO_TRANSPORT_BLE 2
#define EV_CMD_AVAILABLE 5

typedef struct { uint8_t command; uint16_t len; } fido_ble_request_t;
typedef struct { uint8_t data[64]; } rx_t;
static rx_t rx;
static uint8_t ble_response[2048];
static uint8_t ble_itf=3;
static int core_state;
static uint32_t rx_fragment_time;
static uint32_t now_ms;
static bool can_claim;
static bool claimed;
static int claim_attempts;
static int notify_count, error_count, last_error, release_count, cancel_count;
static int cbor_count, start_count, card_release_count, usb_event_count;
static bool start_ok;

static uint32_t board_millis(void) { return now_ms; }
static bool card_command_is_owned_by(uint8_t itf) {
    assert(itf==ble_itf); return claimed;
}
static void button_cancel_request(void) { cancel_count++; }
static void fido_ble_release_request(void) { release_count++; }
static int fido_ble_notify(uint8_t cmd, const uint8_t *bytes, uint16_t len) {
    (void)bytes;(void)len;
    notify_count++;
    if(cmd==FIDO_BLE_CMD_ERROR) error_count++;
    return 0;
}
static int fido_ble_error(uint8_t code) {
    last_error=code;
    return fido_ble_notify(FIDO_BLE_CMD_ERROR, &code, 1);
}
static bool card_try_claim(uint8_t itf) {
    assert(itf==ble_itf);
    claim_attempts++;
    claimed=can_claim;
    return can_claim;
}
static void cbor_process_to(uint8_t cmd, const void *in, uint16_t len,
                            uint8_t *out, int transport) {
    (void)in;(void)len;(void)out;
    assert(cmd==CTAPHID_CBOR && transport==FIDO_TRANSPORT_BLE);
    cbor_count++;
}
static void *cbor_thread(void *arg) { return arg; }
static bool card_start_claimed(uint8_t itf, void *(*fn)(void *)) {
    assert(itf==ble_itf && fn==cbor_thread);
    start_count++;
    return start_ok;
}
static void card_release(uint8_t itf) {
    assert(itf==ble_itf);
    card_release_count++;
    claimed=false;
}
static void usb_send_event(uint32_t event) {
    assert(event==EV_CMD_AVAILABLE); usb_event_count++;
}
"""

TEST_CASES = r"""
static void reset(void) {
    now_ms=100;
    rx_fragment_time=100;
    can_claim=false;
    claimed=false;
    start_ok=true;
    core_state=FIDO_BLE_CORE_IDLE;
    claim_attempts=notify_count=error_count=last_error=release_count=cancel_count=0;
    cbor_count=start_count=card_release_count=usb_event_count=0;
}
int main(void) {
    const fido_ble_request_t message={FIDO_BLE_CMD_MSG,1};
    reset();
    for(int i=0;i<35;i++) {
        now_ms=100+(uint32_t)(i*10);
        fido_ble_dispatch(&message);
        assert(error_count==0 && cbor_count==0);
    }
    assert(claim_attempts==35 && release_count==0);
    now_ms=450;
    fido_ble_dispatch(&message);
    assert(error_count==1 && last_error==FIDO_BLE_ERR_BUSY);
    assert(cbor_count==0);
    puts("BLE_350MS_NONBLOCKING_CLAIM_GRACE_BOUNDARY: PASS");

    reset();
    now_ms=119;
    fido_ble_dispatch(&message);
    assert(error_count==0);
    can_claim=true;
    now_ms=180;
    fido_ble_dispatch(&message);
    assert(cbor_count==1 && start_count==1 && usb_event_count==1);
    assert(core_state==FIDO_BLE_CORE_RUNNING);
    assert(error_count==0);
    puts("BLE_SHORT_CCID_CLAIM_RECOVERS_WITHOUT_BUSY: PASS");

    reset();
    const fido_ble_request_t ping={FIDO_BLE_CMD_PING, 2};
    fido_ble_dispatch(&ping);
    assert(notify_count==1 && error_count==0 && claim_attempts==0);
    const fido_ble_request_t cancel={FIDO_BLE_CMD_CANCEL,0};
    fido_ble_dispatch(&cancel);
    assert(release_count==1 && claim_attempts==0);
    puts("BLE_PING_AND_CANCEL_REMAIN_NONBLOCKING: PASS");
    return 0;
}
"""


def main() -> None:
    source = SOURCE.read_text()
    function = extract_function(
        source, "static void fido_ble_dispatch(const fido_ble_request_t *request)"
    )
    with tempfile.TemporaryDirectory(prefix="aromatic-ble-contention-") as d:
        c = Path(d) / "test.c"
        exe = Path(d) / "test"
        c.write_text(TEST_HEADER + function + TEST_CASES)
        subprocess.run(
            ["cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             str(c), "-o", str(exe)],
            check=True,
        )
        subprocess.run([str(exe)], check=True)


if __name__ == "__main__":
    main()
