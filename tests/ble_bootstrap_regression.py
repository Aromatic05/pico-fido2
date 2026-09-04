#!/usr/bin/env python3
"""Exercise the actual core0 BLE startup function without a physical key."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/fido2/esp32_transports.c"


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
    raise AssertionError("missing closing brace")


PRELUDE = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#define PICOKEY_OK 0
#define ESP_LOGE(tag,fmt,...) ((void)0)

static bool fido_ready;
static bool claim_allowed;
static int result_next;
static uint32_t time_ms;
static int init_count, claim_count, release_count;

static bool fido_is_ready(void) { return fido_ready; }
static uint32_t board_millis(void) { return time_ms; }
static bool card_try_claim_maintenance(void) {
    claim_count++;
    return claim_allowed;
}
static void card_release_maintenance(void) { release_count++; }
static int init_fido(void) {
    init_count++;
    if (result_next == PICOKEY_OK) fido_ready = true;
    return result_next;
}

static bool ble_fido_bootstrap_attempted;
static bool ble_fido_bootstrap_failed;
static uint32_t ble_fido_bootstrap_last_ms;
"""
TEST = r"""
static void reset(void) {
    fido_ready = false;
    claim_allowed = true;
    result_next = 0;
    time_ms = 10;
    init_count = claim_count = release_count = 0;
    ble_fido_bootstrap_attempted = false;
    ble_fido_bootstrap_failed = false;
    ble_fido_bootstrap_last_ms = 0;
}
int main(void) {
    reset();
    ble_fido_bootstrap();
    assert(init_count==1 && claim_count==1 && release_count==1);
    assert(fido_ready && ble_fido_bootstrap_attempted);
    for(int n=0;n<10;n++) ble_fido_bootstrap();
    assert(init_count==1);
    puts("BLE_COLD_START_WITHOUT_USB_INIT: PASS");

    reset();
    claim_allowed=false;
    ble_fido_bootstrap();
    assert(init_count==0 && !ble_fido_bootstrap_attempted && release_count==0);
    claim_allowed=true;
    ble_fido_bootstrap();
    assert(init_count==1 && release_count==1);
    puts("BLE_OWNER_CONFLICT_NONBLOCKING_RETRY: PASS");

    reset();
    fido_ready=true; // HID completed initialization first
    ble_fido_bootstrap();
    assert(init_count==0 && claim_count==0 && ble_fido_bootstrap_attempted);
    puts("BLE_USB_FIRST_NO_DOUBLE_INIT: PASS");

    reset();
    result_next=-7;
    ble_fido_bootstrap();
    assert(init_count==1 && ble_fido_bootstrap_failed);
    time_ms=1009;
    ble_fido_bootstrap();
    assert(init_count==1 && claim_count==1);
    time_ms=1010;
    result_next=0;
    ble_fido_bootstrap();
    assert(init_count==2 && release_count==2 && ble_fido_bootstrap_attempted);
    puts("BLE_TRANSIENT_INIT_FAILURE_RATE_LIMITED_RECOVERY: PASS");
    return 0;
}
"""


def main() -> None:
    source = SOURCE.read_text()
    signature = "static void ble_fido_bootstrap(void)"
    function = extract_function(source, signature)
    with tempfile.TemporaryDirectory(prefix="aromatic-ble-bootstrap-") as d:
        path = Path(d)
        c = path / "test.c"
        binary = path / "test"
        c.write_text(PRELUDE + function + TEST)
        subprocess.run(
            ["cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             str(c), "-o", str(binary)],
            check=True,
        )
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
