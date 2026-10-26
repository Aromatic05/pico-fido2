#!/usr/bin/env python3
"""Exercise real SDK CTAPHID TX functions at the cross-core ACK handoff.

TinyUSB's completion callback runs on CPU1 and hid_task on CPU0. Instrument
the source function immediately after publishing WRITE_SUCCESS to schedule
the normal sender at that exact point. The old implementation re-sent the
initial frame, instead of emitting continuation sequence zero.

This is a deterministic host scheduling regression, not a physical USB test.
"""

import subprocess
import tempfile
from pathlib import Path

import hid_tx_completion_regression as sdk


FUNCTIONS = (
    "hid_tx_idle", "hid_prepare_response", "hid_write_offset",
    "hid_queue_response", "tud_hid_report_complete_cb", "driver_write_hid",
)
PUBLISH = "__atomic_store_n(&last_write_result[instance], WRITE_SUCCESS, __ATOMIC_RELEASE);"

TEST = r"""
void ack_observer_hook(void) {
    /* Run one iteration of the actual CPU0 HID sender at the instant
     * WRITE_SUCCESS becomes visible from CPU1. */
    if (hid_tx[0].w_ptr > hid_tx[0].r_ptr &&
        __atomic_load_n(&last_write_result[0], __ATOMIC_ACQUIRE) != WRITE_PENDING) {
        assert(driver_write_hid(0, hid_tx[0].buffer + hid_tx[0].r_ptr, 64) == 64);
    }
}

int main(void) {
    const uint16_t len = 320;
    uint8_t expected[320], actual[320];
    memset(hid_tx, 0, sizeof(hid_tx));
    memset(send_buffer_size, 0, sizeof(send_buffer_size));
    memset(last_write_result, 0, sizeof(last_write_result));
    hid_prepare_response();
    for (unsigned i = 0; i < len; i++) {
        expected[i] = (uint8_t)(i * 57u + 13u);
    }
    memcpy(hid_tx[0].buffer + 7, expected, len);
    capture_frames = true;
    mock_inline = false;
    hid_queue_response(0, 0x11223344, 0x90, len, 0);
    assert(driver_write_hid(0, hid_tx[0].buffer, 64) == 64);
    assert(packet_count == 1);
    unsigned acknowledged = 0;
    while (acknowledged < packet_count) {
        assert(acknowledged < 16);
        assert(last_write_result[0] == WRITE_PENDING);
        tud_hid_report_complete_cb(0, packets[acknowledged], 64);
        acknowledged++;
    }
    assert(hid_tx_idle());
    assert(packet_count == 1u + (len - 57u + 58u) / 59u);
    assert(packets[0][4] == 0x90);
    unsigned copied = 57;
    memcpy(actual, packets[0] + 7, copied);
    for (unsigned i = 1; i < packet_count; i++) {
        if (packets[i][4] != i - 1) {
            fprintf(stderr, "CTAPHID_ACK_PUBLICATION_RACE: expected seq=%u, got header=%u\n", i - 1, packets[i][4]);
            return 2;
        }
        unsigned remaining = len - copied;
        unsigned chunk = remaining < 59u ? remaining : 59u;
        memcpy(actual + copied, packets[i] + 5, chunk);
        copied += chunk;
    }
    assert(copied == len && memcmp(actual, expected, len) == 0);
    puts("HID_ACTUAL_SDK_CROSS_CORE_ACK_PUBLICATION_ORDER: PASS");
    puts("HID_ACTUAL_SDK_CROSS_CORE_MULTIFRAME_REASSEMBLY: PASS");
    return 0;
}
"""


def main():
    source = sdk.SOURCE.read_text()
    funcs = {name: sdk.extract(source, name) for name in FUNCTIONS}
    callback = funcs["tud_hid_report_complete_cb"]
    assert callback.count(PUBLISH) == 1
    funcs["tud_hid_report_complete_cb"] = callback.replace(
        PUBLISH, PUBLISH + "\n            ack_observer_hook();",
    )
    body = "\n\n".join(funcs[name] for name in FUNCTIONS)
    code = sdk.HEADER + "\nvoid ack_observer_hook(void);\n" + body + "\n" + TEST
    with tempfile.TemporaryDirectory(prefix="aromatic-hid-ack-interleaving-") as tmp:
        path = Path(tmp)
        (path / "test.c").write_text(code)
        subprocess.run(
            ["cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             str(path / "test.c"), "-o", str(path / "test")],
            check=True,
        )
        subprocess.run([str(path / "test")], check=True)


if __name__ == "__main__":
    main()
