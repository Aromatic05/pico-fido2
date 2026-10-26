#!/usr/bin/env python3
"""Exercise the real HID cross-interface contention gate with source extraction."""
import re
import subprocess
import tempfile
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "pico-keys-sdk/src/usb/hid/hid.c"

def extract_gate(src):
    fn = src.index("int driver_process_usb_packet_hid(uint16_t read)")
    match = re.search(r"if\s*\(!card_is_idle\(\)(?:\s*&&\s*card_command_is_owned_by\(ITF_HID\))?\)\s*\{", src[fn:])
    assert match is not None, "source no longer contains the HID core-ownership gate"
    start = fn + match.start()
    pos = src.index("{", start)
    depth = 0
    for i in range(pos, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    raise AssertionError("HID source gate has unmatched braces")

HEADER = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define ITF_HID_CTAP 0
#define ITF_HID 0
#define TYPE_INIT 0x80
#define CTAPHID_CANCEL 0x91
#define CTAP1_ERR_CHANNEL_BUSY 6
#define FRAME_TYPE(p) ((p)->init.cmd & TYPE_INIT)
typedef struct __attribute__((packed)) {
    uint32_t cid;
    union {
        struct { uint8_t cmd, bcnth, bcntl; uint8_t data[57]; } init;
        struct { uint8_t seq; uint8_t data[59]; } cont;
    };
} CTAPHID_FRAME;
typedef struct {uint8_t buffer[2048]; uint16_t r_ptr, w_ptr;} usb_buffer_t;
static usb_buffer_t hid_rx[1];
static bool fake_card_idle, fake_hid_owns, fake_tx_idle;
static unsigned busy_responses, cancel_calls, response_prepares;
static bool card_is_idle(void) {return fake_card_idle;}
static bool card_command_is_owned_by(int owner) { assert(owner == ITF_HID); return fake_hid_owns; }
static bool hid_tx_idle(void) {return fake_tx_idle;}
static void hid_prepare_response(void) {response_prepares++;}
static int ctap_error_for_cid(uint32_t cid, uint8_t error) {
  assert(cid==0x10203040 && error==CTAP1_ERR_CHANNEL_BUSY);
  busy_responses++;
  return 0;
}
static void button_cancel_request(void) {cancel_calls++;}
static void reset(void) {
  memset(hid_rx,0,sizeof(hid_rx));
  fake_card_idle=true;
  fake_hid_owns=false;
  fake_tx_idle=true;
  busy_responses=cancel_calls=response_prepares=0;
  hid_rx[0].w_ptr=128;
  CTAPHID_FRAME *frame=(CTAPHID_FRAME*)hid_rx[0].buffer;
  frame->cid=0x10203040;
  frame->init.cmd=0x90;
  frame->init.bcnth=0;
  frame->init.bcntl=80;
  frame=(CTAPHID_FRAME*)(hid_rx[0].buffer + 64);
  frame->cid=0x10203040;
  frame->cont.seq=0;
}
static int gate(void) {
  CTAPHID_FRAME *rx_req=(CTAPHID_FRAME *)(hid_rx[ITF_HID_CTAP].buffer+hid_rx[ITF_HID_CTAP].r_ptr);
"""
TESTS = r"""
  return 7; /* Current frame may be assembled by the existing parser. */
}
int main(void) {
  setvbuf(stdout,NULL,_IONBF,0);
  reset();
  fake_card_idle=false; fake_hid_owns=false; /* CCID owns the command core. */
  assert(gate()==7); /* Do not reject the first 64B fragment alone. */
  assert(busy_responses==0 && hid_rx[0].r_ptr==0);
  hid_rx[0].r_ptr=64;
  assert(gate()==7); /* Nor separately reject its continuation. */
  assert(busy_responses==0 && hid_rx[0].r_ptr==64);
  puts("HID_FOREIGN_CCID_FRAGMENTS_ARE_NOT_INDEPENDENT_BUSY: PASS");

  reset();
  fake_card_idle=false; fake_hid_owns=true;
  assert(gate()==0); /* An ongoing HID command must keep its transaction. */
  assert(hid_rx[0].r_ptr==0 && busy_responses==0);
  puts("HID_OWNED_TRANSACTION_REMAINS_UNTOUCHED: PASS");

  reset();
  fake_card_idle=false; fake_hid_owns=true;
  ((CTAPHID_FRAME*)hid_rx[0].buffer)->init.cmd=CTAPHID_CANCEL;
  assert(gate()==1 && cancel_calls==1 && hid_rx[0].r_ptr==64);
  puts("HID_CANCEL_DURING_HID_OWNED_COMMAND: PASS");

  reset();
  assert(gate()==7 && busy_responses==0);
  puts("HID_IDLE_MESSAGE_PASSES_TO_PARSER: PASS");
  return 0;
}
"""
def main():
    gate=extract_gate(SRC.read_text())
    with tempfile.TemporaryDirectory(prefix="ak-hid-foreign-gate-") as tmp:
        source=Path(tmp)/"gate.c"
        binary=Path(tmp)/"gate"
        source.write_text(HEADER+gate+"\n"+TESTS)
        subprocess.run(["cc","-std=c11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-unused-function",
                        "-fsanitize=address,undefined","-fno-omit-frame-pointer",
                        str(source),"-o",str(binary)],check=True)
        subprocess.run([str(binary)],check=True)
if __name__ == "__main__":
    main()
