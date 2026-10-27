#!/usr/bin/env python3
"""Compile the actual CCID functions against a deterministic TinyUSB FIFO.

No device, reader, USB access, key material or mocked replacement CCID code.
Extract functions from the SDK fork so the tests follow the implementation.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "pico-keys-sdk/src/usb/ccid/ccid.c"


def function_body(source: str, name: str) -> str:
    match = re.search(
        r"(?m)^(?:static\s+)?(?:int|void|bool|uint16_t)\s+"
        + re.escape(name)
        + r"\s*\([^;]*?\)\s*\{",
        source,
        re.S,
    )
    if match is None:
        raise AssertionError(f"CCID SDK function missing: {name}")
    depth = 0
    for i in range(match.end() - 1, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start() : i + 1]
    raise AssertionError(f"CCID SDK function unbalanced: {name}")


HEADER = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define DEBUG_PAYLOAD(ptr, size) ((void)0)
#define CCID_TRANSPORT_CAPACITY 1
#define CCID_FAST_FRAME_SIZE 64
#define CCID_TRACE(event,a,b) ((void)0)
#define CCID_DATA_BLOCK_RET 0x80
#define CCID_SLOT_STATUS_RET 0x81
#define CCID_CMD_STATUS_ERROR 0x40
#define CCID_CMD_STATUS_TIMEEXT 0x80
#define CCID_MSG_HEADER_SIZE 10
#define CCID_MSG_DATA_OFFSET 10
#define USB_LL_BUF_SIZE 64
#define tud_vendor_n_flush(idx) tud_vendor_n_write_flush(idx)
#define MAX_CMD_APDU_DATA_SIZE (24 + 4 + 512 * 4)
#define MAX_RES_APDU_DATA_SIZE (5 + 9 + 512 * 4)
#define USB_BUF_SIZE (MAX_CMD_APDU_DATA_SIZE + 20 + 9)
typedef struct {uint8_t buffer[USB_BUF_SIZE]; uint16_t r_ptr,w_ptr;} ccid_tx_buffer_t;
typedef struct __attribute__((packed)) {
    uint8_t bMessageType;
    uint32_t dwLength;
    uint8_t bSlot,bSeq,abRFU0;
    uint16_t abRFU1;
    uint8_t apdu;
} ccid_header_t;
static uint8_t ccid_status;
static ccid_tx_buffer_t ccid_tx[CCID_TRANSPORT_CAPACITY];
static ccid_header_t *ccid_response[CCID_TRANSPORT_CAPACITY];
static uint8_t ccid_active_seq[CCID_TRANSPORT_CAPACITY];
static uint8_t ccid_fast_storage[CCID_TRANSPORT_CAPACITY][CCID_FAST_FRAME_SIZE];
static ccid_header_t *ccid_resp_fast[CCID_TRANSPORT_CAPACITY];
static uint8_t ccid_fast_pending[CCID_TRANSPORT_CAPACITY][CCID_FAST_FRAME_SIZE];
static uint16_t ccid_fast_length[CCID_TRANSPORT_CAPACITY];
static uint16_t ccid_fast_offset[CCID_TRANSPORT_CAPACITY];
static uint16_t ccid_inflight_length[CCID_TRANSPORT_CAPACITY];
static volatile uint32_t ccid_inflight_acked[CCID_TRANSPORT_CAPACITY];
static volatile bool ccid_bus_reset_pending;
static bool ccid_drop_completion[CCID_TRANSPORT_CAPACITY];
static uint8_t itf_num;
static uint8_t ITF_SC_TOTAL=1;
static bool card_work_active;
static int bus_reset_count;
static uint8_t sc_itf_to_usb_itf(uint8_t itf) { return itf; }
static bool card_command_is_owned_by(uint8_t itf) {
    assert(itf==0); return card_work_active;
}
static void ccid_init_buffers(void) {
    memset(ccid_tx, 0, sizeof(ccid_tx));
    memset(ccid_fast_length, 0, sizeof(ccid_fast_length));
    memset(ccid_fast_offset, 0, sizeof(ccid_fast_offset));
    memset(ccid_inflight_length, 0, sizeof(ccid_inflight_length));
    memset((void*)ccid_inflight_acked,0,sizeof(ccid_inflight_acked));
    memset(ccid_drop_completion,0,sizeof(ccid_drop_completion));
}
static void vendord_reset(uint8_t rhport) {
    assert(rhport==0); bus_reset_count++;
}

static uint8_t wire[8192];
static uint16_t accepted_frames[128];
static size_t wire_len, calls;
static uint32_t mock_available;
static uint32_t mock_accept_limit;
static unsigned flushes;
static bool mock_complete_inline;

static uint16_t make_uint16_t_be(uint8_t hi,uint8_t lo) {
    return ((uint16_t)hi<<8)|lo;
}
static void put_uint16_t_be(uint16_t value,uint8_t *out) {
    out[0]=(uint8_t)(value>>8);
    out[1]=(uint8_t)value;
}
static uint32_t tud_vendor_n_write_available(uint8_t itf) {
    assert(itf==0);
    return mock_available;
}
static void tud_vendor_tx_cb(uint8_t itf, uint32_t sent_bytes);
static uint32_t tud_vendor_n_write(uint8_t itf, const void *data, uint32_t len) {
    assert(itf==0);
    uint32_t n = len < mock_accept_limit ? len : mock_accept_limit;
    assert(wire_len + n <= sizeof(wire));
    assert(calls < 128);
    memcpy(wire + wire_len, data, n);
    wire_len += n;
    accepted_frames[calls++] = (uint16_t)n;
    /* TinyUSB may auto-start a full-size packet inside write(); another
     * task can deliver its ACK before this call returns to the producer. */
    if (mock_complete_inline && n != 0) {
        tud_vendor_tx_cb(itf, n);
    }
    return n;
}
static uint32_t tud_vendor_n_write_flush(uint8_t itf) {
    assert(itf==0);
    flushes++;
    return 1;
}
static void tud_vendor_tx_cb(uint8_t itf, uint32_t sent_bytes);
"""

TESTS = r"""
static void reset_test(void) {
    memset(ccid_tx, 0, sizeof(ccid_tx));
    memset(ccid_fast_storage,0,sizeof(ccid_fast_storage));
    memset(ccid_fast_pending,0,sizeof(ccid_fast_pending));
    memset(ccid_fast_length,0,sizeof(ccid_fast_length));
    memset(ccid_fast_offset,0,sizeof(ccid_fast_offset));
    memset(ccid_inflight_length,0,sizeof(ccid_inflight_length));
    ccid_inflight_acked[0] = 0;
    ccid_resp_fast[0] = (ccid_header_t*)ccid_fast_storage[0];
    ccid_active_seq[0] = 7;
    ccid_status = 0;
    memset(wire,0,sizeof(wire));
    memset(accepted_frames,0,sizeof(accepted_frames));
    wire_len = calls = flushes = 0;
    mock_available = 4096;
    mock_accept_limit = 4096;
    mock_complete_inline = false;
    ccid_bus_reset_pending=false;
    ccid_drop_completion[0]=false;
    itf_num=3;
    card_work_active=false;
    bus_reset_count=0;
}
static void acknowledge(void) {
    assert(ccid_inflight_length[0] > 0);
    size_t before = calls;
    tud_vendor_tx_cb(0, ccid_inflight_length[0]);
    /* The last TinyUSB callback still has to process a possible ZLP.
     * No bytes of the next CCID frame may enter the FIFO on that tick. */
    assert(ccid_tx_pump(0));
    assert(calls==before);
}
static void full_frame_backpressure(void) {
    reset_test();
    memset(ccid_tx[0].buffer,0xAC,2048);
    ccid_tx[0].w_ptr=2048;
    mock_available=2038; /* Ten bytes still occupy TinyUSB's 2048 FIFO. */
    assert(ccid_tx_pump(0));
    assert(calls==0 && ccid_tx[0].r_ptr==0);
    mock_available=2048;
    assert(ccid_tx_pump(0));
    assert(calls==1 && accepted_frames[0]==2048);
    assert(ccid_tx[0].r_ptr==2048 && ccid_tx[0].w_ptr==2048);
    assert(ccid_tx_pump(0)); /* Cannot acknowledge before the USB callback. */
    assert(calls==1);
    acknowledge();
    assert(!ccid_tx_pump(0));
    assert(ccid_tx[0].r_ptr==0 && ccid_tx[0].w_ptr==0);
    printf("CCID_FULL_2048_BACKPRESSURE: PASS\n");
}
static void time_extension_before_long_response(void) {
    reset_test();
    uint8_t time_ext[10]={0x80,0,0,0,0,0,7,0x80,0,0};
    assert(ccid_write_fast(0,time_ext,10)==10);
    memset(ccid_tx[0].buffer,0xB5,2048);
    ccid_tx[0].w_ptr=2048;
    assert(ccid_tx_pump(0));
    assert(calls==1 && accepted_frames[0]==10);
    acknowledge();
    mock_available=2038;
    assert(ccid_tx_pump(0)); /* Previous 10 bytes must not coalesce with DataBlock. */
    assert(calls==1 && ccid_fast_length[0]==0);
    mock_available=2048;
    assert(ccid_tx_pump(0));
    assert(calls==2 && accepted_frames[1]==2048 && wire_len==2058);
    assert(memcmp(wire,time_ext,10)==0);
    for (size_t i=10;i<wire_len;i++) assert(wire[i]==0xB5);
    acknowledge();
    assert(!ccid_tx_pump(0));
    printf("CCID_TIME_EXT_BEFORE_2048_DATABLOCK: PASS\n");
}
static void rsa4096_long_operation_many_time_extensions(void) {
    reset_test();
    /* 110 consecutive 1.5-second Time Extensions cover 165 seconds without
     * allowing an interim CCID response to contaminate the final DataBlock.
     * The actual unmodified SDK functions construct and pump every frame. */
    enum { EXTENSIONS = 110, RESPONSE_LEN = 528 };
    const size_t total_extensions = EXTENSIONS * 10U;
    for (size_t i = 0; i < EXTENSIONS; ++i) {
        driver_exec_timeout_ccid(0);
        assert(ccid_fast_length[0] == 10);
        assert(ccid_tx_pump(0));
        assert(calls == i + 1 && accepted_frames[i] == 10);
        assert(wire_len == (i + 1) * 10U);
        assert(wire[10U * i] == 0x80); /* RDR_to_PC_DataBlock */
        for (size_t b = 1; b < 5; ++b) assert(wire[10U * i + b] == 0);
        assert(wire[10U * i + 6] == 7); /* Same original APDU sequence. */
        assert(wire[10U * i + 7] == CCID_CMD_STATUS_TIMEEXT);
        assert(wire[10U * i + 8] == 0 && wire[10U * i + 9] == 0);
        acknowledge();
        assert(!ccid_tx_pump(0));
        assert(ccid_fast_length[0] == 0);
    }
    assert(wire_len == total_extensions);
    /* Follow the same APDU sequence with a real 528-byte PIV response. */
    memset(ccid_tx[0].buffer + CCID_MSG_DATA_OFFSET, 0xA4, RESPONSE_LEN - 2);
    ccid_tx[0].buffer[CCID_MSG_DATA_OFFSET + RESPONSE_LEN - 2] = 0x90;
    ccid_tx[0].buffer[CCID_MSG_DATA_OFFSET + RESPONSE_LEN - 1] = 0;
    driver_exec_finished_cont_ccid(0, RESPONSE_LEN, 0);
    assert(ccid_tx[0].w_ptr == RESPONSE_LEN + CCID_MSG_HEADER_SIZE);
    assert(ccid_tx_pump(0));
    assert(calls == EXTENSIONS + 1 && accepted_frames[EXTENSIONS] == RESPONSE_LEN + 10);
    assert(wire_len == total_extensions + RESPONSE_LEN + 10);
    assert(wire[total_extensions] == 0x80);
    assert(wire[total_extensions + 6] == 7);
    assert(wire[total_extensions + 7] == 0); /* Final normal DataBlock status. */
    assert(wire[total_extensions + 10] == 0xA4);
    assert(wire[wire_len - 2] == 0x90 && wire[wire_len - 1] == 0);
    acknowledge();
    assert(!ccid_tx_pump(0));
    assert(ccid_tx[0].w_ptr == 0 && ccid_fast_length[0] == 0);
    printf("CCID_RSA4096_110_WTX_FRAMES_THEN_FINAL_DATABLOCK: PASS\n");
}
static void unexpected_partial_write_no_byte_loss(void) {
    reset_test();
    for (int i=0;i<20;i++) ccid_tx[0].buffer[i]=(uint8_t)i;
    ccid_tx[0].w_ptr=20;
    mock_accept_limit=7;
    assert(ccid_tx_pump(0));
    assert(ccid_tx[0].r_ptr==7 && ccid_tx[0].w_ptr==20);
    assert(calls==1 && accepted_frames[0]==7);
    acknowledge();
    mock_accept_limit=2048;
    assert(ccid_tx_pump(0));
    assert(ccid_tx[0].r_ptr==20 && calls==2 && accepted_frames[1]==13);
    acknowledge();
    assert(!ccid_tx_pump(0));
    assert(wire_len==20);
    for (int i=0;i<20;i++) assert(wire[i]==i);
    printf("CCID_PARTIAL_ACCEPTANCE_PRESERVES_REMAINDER: PASS\n");
}
static void delayed_fast_response_and_get_response_cursor(void) {
    reset_test();
    uint8_t data[52]; memset(data,0x5A,sizeof(data));
    mock_available=0;
    assert(driver_exec_finished_fast_ccid(0,data,52,0x9000,52)==52);
    assert(ccid_fast_length[0]==64 && calls==0);
    assert(ccid_tx_pump(0));
    assert(calls==0);
    mock_available=64;
    assert(ccid_tx_pump(0));
    assert(calls==1 && accepted_frames[0]==64);
    assert(wire[0]==0x80 && wire[4]==0 && wire[5]==0);
    assert(wire[10]==0x5A && wire[61]==0x5A && wire[62]==0x90 && wire[63]==0);
    acknowledge();
    assert(!ccid_tx_pump(0));
    printf("CCID_GET_RESPONSE_64_BYTES_STAGED_RETRIED: PASS\n");
}
static void busy_reply_types(void) {
    reset_test();
    driver_exec_busy_status_ccid(0,17);
    assert(ccid_fast_pending[0][0]==0x81 && ccid_fast_pending[0][8]==0xE0);
    reset_test();
    driver_exec_busy_ccid(0,18);
    assert(ccid_fast_pending[0][0]==0x80 && ccid_fast_pending[0][8]==0xE0);
    printf("CCID_POWER_OFF_SLOT_STATUS_ERROR_FRAME: PASS\n");
}
static void coalesce_duplicate_time_extension(void) {
    reset_test();
    driver_exec_timeout_ccid(0);
    assert(ccid_fast_length[0]==10);
    driver_exec_timeout_ccid(0);
    assert(ccid_fast_length[0]==10);
    assert(ccid_tx_pump(0));
    assert(calls==1);
    acknowledge();
    assert(!ccid_tx_pump(0));
    driver_exec_timeout_ccid(0);
    assert(ccid_fast_length[0]==10);
    printf("CCID_TIME_EXTENSION_BACKPRESSURE_COALESCED: PASS\n");
}
static void bus_reset_discards_stale_ack_and_data(void) {
    reset_test();
    ccid_tx[0].w_ptr=1024;
    ccid_fast_length[0]=10;
    ccid_inflight_length[0]=64;
    ccid_inflight_acked[0]=12;
    card_work_active=true;
    ccid_reset_cb(0);
    assert(ccid_bus_reset_pending && ccid_tx[0].w_ptr==1024);
    assert(bus_reset_count==1 && itf_num==0);
    ccid_sync_bus_reset();
    assert(!ccid_bus_reset_pending && ccid_tx[0].w_ptr==0);
    assert(ccid_fast_length[0]==0 && ccid_inflight_length[0]==0);
    assert(ccid_inflight_acked[0]==0 && ccid_drop_completion[0]);
    assert(!ccid_tx_pump(0));
    card_work_active=false;
    ccid_drop_completion[0]=false; /* Finishing old APDU discards old result. */
    ccid_reset_cb(0);
    ccid_sync_bus_reset();
    assert(!ccid_drop_completion[0]);
    printf("CCID_BUS_RESET_INVALIDATES_STALE_ACK_AND_FRAME: PASS\n");
}
static void piv_x509_der_tail_never_overwrites_queue_cursors(void) {
    reset_test();
    /* Reproduce the PIV applet's exact 2048-byte DER workspace starting at
     * CCID header +10, and a 608-byte cert written at its very end.
     * The old generic USB buffer put r_ptr and w_ptr inside this region. */
    const size_t workspace = 2048;
    const size_t certificate = 608;
    assert(sizeof(ccid_tx[0].buffer) >= CCID_MSG_HEADER_SIZE + workspace);
    uint8_t *apdu_out = ccid_tx[0].buffer + CCID_MSG_HEADER_SIZE;
    memset(apdu_out + workspace - certificate, 0xA6, certificate);
    assert(ccid_tx[0].r_ptr == 0 && ccid_tx[0].w_ptr == 0);
    memmove(apdu_out, apdu_out + workspace - certificate, certificate);
    apdu_out[certificate] = 0x90;
    apdu_out[certificate + 1] = 0x00;
    driver_exec_finished_cont_ccid(0, certificate + 2, 0);
    assert(ccid_tx[0].w_ptr == certificate + 2 + CCID_MSG_HEADER_SIZE);
    assert(ccid_tx[0].r_ptr == 0);
    assert(ccid_tx[0].buffer[0] == CCID_DATA_BLOCK_RET);
    assert(((ccid_header_t*)ccid_tx[0].buffer)->dwLength == certificate + 2);
    assert(ccid_tx_pump(0) && calls == 1 && accepted_frames[0] == 620);
    assert(wire[10] == 0xA6 && wire[617] == 0xA6);
    assert(wire[618] == 0x90 && wire[619] == 0);
    acknowledge();
    assert(!ccid_tx_pump(0));
    printf("PIV_X509_2048B_DER_TAIL_NO_CCID_CURSOR_CORRUPTION: PASS\n");
}
static void ccid_oversize_and_pending_response_are_bounded(void) {
    reset_test();
    driver_exec_finished_cont_ccid(0, 4842, 0);
    assert(ccid_tx[0].w_ptr == 12);
    assert(ccid_tx[0].buffer[10] == 0x6F && ccid_tx[0].buffer[11] == 0);
    assert(((ccid_header_t*)ccid_tx[0].buffer)->dwLength == 2);
    driver_exec_finished_cont_ccid(0, 610, 0);
    assert(ccid_tx[0].w_ptr == 12); /* Single in-flight frame, no append. */
    assert(ccid_tx_pump(0));
    assert(calls == 1 && accepted_frames[0] == 12);
    acknowledge();
    assert(!ccid_tx_pump(0));
    printf("CCID_OVERSIZE_REJECTED_WITHOUT_OVERFLOW_OR_QUEUED_APPEND: PASS\n");
}
static void ccid_max_frame_with_realistic_usb_ack_chunks(void) {
    reset_test();
    /* A legal frame longer than the old 2048-byte FIFO must be accepted by
     * the new FIFO. Actual USB IN callbacks acknowledge 64-byte packets. */
    const uint16_t size_next = sizeof(ccid_tx[0].buffer) - CCID_MSG_HEADER_SIZE;
    const uint16_t frame_len = sizeof(ccid_tx[0].buffer);
    for (uint16_t i = 0; i < size_next; ++i) {
        ccid_tx[0].buffer[CCID_MSG_DATA_OFFSET + i] = (uint8_t)(i * 13U);
    }
    driver_exec_finished_cont_ccid(0, size_next, 0);
    assert(ccid_tx[0].w_ptr == frame_len && ccid_tx[0].r_ptr == 0);
    assert(((ccid_header_t *)ccid_tx[0].buffer)->dwLength == size_next);
    mock_available = 2048;
    assert(ccid_tx_pump(0));
    assert(calls == 0 && ccid_tx[0].r_ptr == 0);
    mock_available = 4096;
    assert(ccid_tx_pump(0));
    assert(calls == 1 && wire_len == frame_len);
    assert(accepted_frames[0] == frame_len);
    assert(memcmp(wire, ccid_tx[0].buffer, frame_len) == 0);
    assert(ccid_inflight_length[0] == frame_len);
    for (uint16_t off = 0; off < frame_len; off += 64) {
        uint16_t n = frame_len - off >= 64 ? 64 : (uint16_t)(frame_len - off);
        tud_vendor_tx_cb(0, n);
        if (off + n < frame_len) {
            assert(ccid_inflight_acked[0] == off + n);
            assert(ccid_tx_pump(0)); /* Still waiting for final IN ACK. */
            assert(calls == 1 && ccid_tx[0].w_ptr == frame_len);
        }
    }
    assert(ccid_inflight_acked[0] == frame_len);
    assert(ccid_tx_pump(0)); /* A scheduling tick separates frames. */
    assert(!ccid_tx_pump(0));
    assert(ccid_tx[0].w_ptr == 0 && ccid_tx[0].r_ptr == 0);
    printf("CCID_2105_BYTE_FRAME_64_BYTE_USB_ACKS: PASS\n");
}
static void usb_completion_before_write_return(void) {
    reset_test();
    uint8_t fast_frame[64] = {CCID_DATA_BLOCK_RET};
    assert(ccid_write_fast(0, fast_frame, sizeof(fast_frame)) == sizeof(fast_frame));
    mock_complete_inline = true;
    assert(ccid_tx_pump(0));
    assert(ccid_inflight_length[0] == sizeof(fast_frame));
    assert(ccid_inflight_acked[0] == sizeof(fast_frame));
    assert(ccid_tx_pump(0));
    assert(!ccid_tx_pump(0));
    assert(ccid_fast_length[0] == 0);

    reset_test();
    memset(ccid_tx[0].buffer, 0xAA, 64);
    ccid_tx[0].w_ptr = 64;
    mock_complete_inline = true;
    assert(ccid_tx_pump(0));
    assert(ccid_inflight_length[0] == 64);
    assert(ccid_inflight_acked[0] == 64);
    assert(ccid_tx_pump(0));
    assert(!ccid_tx_pump(0));
    assert(ccid_tx[0].w_ptr == 0);

    reset_test();
    memset(ccid_tx[0].buffer, 0xAB, 20);
    ccid_tx[0].w_ptr = 20;
    mock_accept_limit = 7;
    mock_complete_inline = true;
    assert(ccid_tx_pump(0));
    assert(ccid_inflight_length[0] == 7);
    assert(ccid_inflight_acked[0] == 7);
    assert(ccid_tx_pump(0));
    mock_accept_limit = 4096;
    assert(ccid_tx_pump(0));
    assert(ccid_inflight_length[0] == 13);
    assert(ccid_inflight_acked[0] == 13);
    assert(ccid_tx_pump(0));
    assert(!ccid_tx_pump(0));
    assert(ccid_tx[0].w_ptr == 0);
    printf("CCID_INLINE_USB_ACK_BEFORE_WRITE_RETURN: PASS\n");
}
int main(void) {
    full_frame_backpressure();
    time_extension_before_long_response();
    rsa4096_long_operation_many_time_extensions();
    unexpected_partial_write_no_byte_loss();
    delayed_fast_response_and_get_response_cursor();
    busy_reply_types();
    coalesce_duplicate_time_extension();
    bus_reset_discards_stale_ack_and_data();
    piv_x509_der_tail_never_overwrites_queue_cursors();
    ccid_oversize_and_pending_response_are_bounded();
    ccid_max_frame_with_realistic_usb_ack_chunks();
    usb_completion_before_write_return();
    return 0;
}
"""


def main() -> None:
    source = SOURCE.read_text()
    names = (
        "driver_write_ccid",
        "ccid_write_fast",
        "ccid_busy_response",
        "driver_exec_busy_ccid",
        "driver_exec_busy_status_ccid",
        "driver_exec_timeout_ccid",
        "ccid_write_offset",
        "driver_exec_finished_cont_ccid",
        "driver_exec_finished_fast_ccid",
        "ccid_tx_pump",
        "ccid_sync_bus_reset",
        "ccid_reset_cb",
        "tud_vendor_tx_cb",
    )
    code = HEADER + "\n\n".join(function_body(source, name) for name in names) + TESTS
    with tempfile.TemporaryDirectory(prefix="aromatic-ccid-") as directory:
        source_file = Path(directory) / "test.c"
        binary = Path(directory) / "test"
        source_file.write_text(code)
        subprocess.run(
            ["cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             "-o", str(binary), str(source_file)],
            check=True,
        )
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
