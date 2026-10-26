#!/usr/bin/env python3
"""Extract the real SDK HID send/complete functions to test early callbacks."""
import re
import subprocess
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT / "pico-keys-sdk/src/usb/hid/hid.c"
def extract(src,name):
    pat=r"(?m)^(?:static\s+)?(?:int|void|bool|uint32_t)\s+"+re.escape(name)+r"\s*\([^;]*?\)\s*\{"
    m=re.search(pat,src,re.S)
    assert m,name
    depth=0
    for j in range(m.end()-1,len(src)):
        if src[j]=="{":depth+=1
        elif src[j]=="}":
            depth-=1
            if depth==0:return src[m.start():j+1]
    raise AssertionError("unbalanced "+name)

HEADER=r"""
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#define HID_TRANSPORT_CAPACITY 2
#define ITF_HID_CTAP 0
#define CTAPHID_KEEPALIVE 0xBB
#define TYPE_INIT 0x80
#define MIN(a,b) ((a)<(b)?(a):(b))
#define DEBUG_PAYLOAD(buf,len) ((void)(buf),(void)(len))
#define FRAME_TYPE(f) ((f)->type & TYPE_INIT)
#define FRAME_SEQ(f) ((f)->cont.seq & 0x7f)
typedef struct __attribute__((packed)) {
  uint32_t cid;
  union {
    uint8_t type;
    struct {uint8_t cmd,bcnth,bcntl;uint8_t data[57];} init;
    struct {uint8_t seq;uint8_t data[59];} cont;
  };
} CTAPHID_FRAME;
typedef struct __attribute__((packed)) {
  uint8_t buffer[2048];
  uint16_t r_ptr,w_ptr;
} usb_buffer_t;
typedef enum {
  WRITE_UNKNOWN=0,WRITE_PENDING,WRITE_FAILED,WRITE_SUCCESS,
} write_status_t;
static usb_buffer_t hid_tx[HID_TRANSPORT_CAPACITY];
static uint16_t send_buffer_size[HID_TRANSPORT_CAPACITY];
static write_status_t last_write_result[HID_TRANSPORT_CAPACITY];
static CTAPHID_FRAME *ctap_resp;
static bool mock_accept=true;
static bool mock_inline=false;
static unsigned submissions;
static bool capture_frames=false;
static unsigned packet_count;
static uint8_t packets[64][64];
void tud_hid_report_complete_cb(uint8_t instance,uint8_t const* report,uint16_t len);
static bool tud_hid_n_report(uint8_t itf,uint8_t id,const uint8_t* data,uint16_t len){
  assert(itf==0 && id==0 && len==64);
  submissions++;
  if (!mock_accept) return false;
  if (capture_frames) {
    assert(packet_count < 64);
    memcpy(packets[packet_count++],data,64);
  }
  if (mock_inline) tud_hid_report_complete_cb(itf,data,len);
  return true;
}
"""
TESTS=r"""
static void reset_case(void){
  memset(hid_tx,0,sizeof(hid_tx));
  memset(send_buffer_size,0,sizeof(send_buffer_size));
  memset(last_write_result,0,sizeof(last_write_result));
  ctap_resp=(CTAPHID_FRAME*)hid_tx[0].buffer;
  ctap_resp->cid=0x01020304;
  ctap_resp->init.cmd=0x90;
  ctap_resp->init.bcntl=1;
  ctap_resp->init.data[0]=0x04;
  send_buffer_size[0]=1;
  hid_tx[0].w_ptr=64;
  submissions=0;
  mock_accept=true;
  mock_inline=false;
  capture_frames=false;
  packet_count=0;
}
static void normal_delayed_completion(void){
  reset_case();
  assert(driver_write_hid(0,hid_tx[0].buffer,64)==64);
  assert(last_write_result[0]==WRITE_PENDING);
  assert(!hid_tx_idle());
  tud_hid_report_complete_cb(0,hid_tx[0].buffer,64);
  assert(last_write_result[0]==WRITE_SUCCESS);
  assert(send_buffer_size[0]==0 && hid_tx_idle());
  printf("HID_DELAYED_USB_COMPLETE: PASS\n");
}
static void rejected_submission_does_not_leave_pending(void){
  reset_case();
  mock_accept=false;
  assert(driver_write_hid(0,hid_tx[0].buffer,64)==0);
  assert(last_write_result[0]==WRITE_FAILED);
  mock_accept=true;
  assert(driver_write_hid(0,hid_tx[0].buffer,64)==64);
  assert(last_write_result[0]==WRITE_PENDING);
  tud_hid_report_complete_cb(0,hid_tx[0].buffer,64);
  assert(hid_tx_idle());
  printf("HID_REJECTED_SUBMIT_CAN_RETRY: PASS\n");
}
static void immediate_completion_before_report_submit_returns(void){
  reset_case();
  mock_inline=true;
  assert(driver_write_hid(0,hid_tx[0].buffer,64)==64);
  assert(last_write_result[0]==WRITE_SUCCESS);
  assert(send_buffer_size[0]==0);
  assert(hid_tx[0].r_ptr==0 && hid_tx[0].w_ptr==0);
  assert(hid_tx_idle());
  printf("HID_INLINE_ACK_BEFORE_REPORT_RETURN: PASS\n");
}
static void real_sdk_multiframe_response(uint16_t payload_len,bool inline_ack){
  reset_case();
  hid_prepare_response();
  capture_frames=true;
  mock_inline=inline_ack;
  uint8_t expected[1500], actual[1500];
  assert(payload_len <= sizeof(expected));
  for (unsigned i=0; i<payload_len; ++i) expected[i]=(uint8_t)(19u+i*173u);
  memset(hid_tx[0].buffer,0,sizeof(hid_tx[0].buffer));
  memcpy(hid_tx[0].buffer+7,expected,payload_len);
  hid_queue_response(0,0x01020304,0x90,payload_len,0);
  unsigned attempts=0;
  while (!hid_tx_idle()) {
    assert(attempts++ < 64);
    assert(last_write_result[0]!=WRITE_PENDING);
    assert(driver_write_hid(0,hid_tx[0].buffer+hid_tx[0].r_ptr,64)==64);
    if (!inline_ack) {
      tud_hid_report_complete_cb(0,packets[packet_count-1],64);
    }
  }
  assert(packet_count>0);
  assert(packets[0][4]==0x90);
  assert(((uint16_t)packets[0][5]<<8|packets[0][6])==payload_len);
  unsigned used=MIN(payload_len,57);
  memcpy(actual,packets[0]+7,used);
  for (unsigned i=1; i<packet_count; ++i) {
    if (packets[i][4]!=i-1) {
      fprintf(stderr,"HID_MULTIFRAME_MISMATCH len=%u inline=%d frame=%u seq=%u expected=%u packets=%u r=%u w=%u remaining=%u\n",
              payload_len,inline_ack,i,packets[i][4],i-1,packet_count,
              hid_tx[0].r_ptr,hid_tx[0].w_ptr,send_buffer_size[0]);
    }
    assert(packets[i][4]==i-1);
    unsigned amount=MIN((unsigned)payload_len-used,59u);
    memcpy(actual+used,packets[i]+5,amount);
    used+=amount;
  }
  assert(used==payload_len);
  assert(memcmp(actual,expected,payload_len)==0);
  printf("HID_ACTUAL_SDK_MULTIFRAME_PAYLOAD_ROUNDTRIP: PASS len=%u inline_ack=%d frames=%u\n",
         payload_len,inline_ack,packet_count);
}
int main(void){
  assert(sizeof(CTAPHID_FRAME)==64);
  normal_delayed_completion();
  rejected_submission_does_not_leave_pending();
  immediate_completion_before_report_submit_returns();
  static const uint16_t lengths[]={57,58,59,116,117,256,320,512,700,1100};
  for(unsigned i=0;i<sizeof(lengths)/sizeof(lengths[0]);++i){
    real_sdk_multiframe_response(lengths[i],false);
    real_sdk_multiframe_response(lengths[i],true);
  }
  return 0;
}
"""
def main():
    src=SOURCE.read_text()
    body="\n\n".join(extract(src,n) for n in ("hid_tx_idle","hid_prepare_response","hid_write_offset","hid_queue_response","tud_hid_report_complete_cb","driver_write_hid"))
    with tempfile.TemporaryDirectory(prefix="aromatic-hid-ack-") as tmp:
        p=Path(tmp)
        (p/"test.c").write_text(HEADER+"\n"+body+"\n"+TESTS)
        subprocess.run(["cc","-std=c11","-O1","-g","-Wall","-Wextra","-Werror",
                        "-fsanitize=address,undefined","-fno-omit-frame-pointer",
                        str(p/"test.c"),"-o",str(p/"test")],check=True)
        subprocess.run([str(p/"test")],check=True)
if __name__=="__main__":
    main()
