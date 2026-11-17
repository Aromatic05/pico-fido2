#include "pico_keys.h"
#undef INITIALIZER
#define INITIALIZER(f) static void __attribute__((unused)) f(void)
#include "../pico-fido/src/fido/oath.c"
#include <assert.h>

struct apdu apdu;
static file_t credential;
static uint8_t record[] = {
    0x71, 4, 'h', 'o', 't', 'p', 0x73, 22, 0x11, 6,
    '1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0',
    0x7A, 8, 0,0,0,0,0,0,0,0, 0x78, 1, 2,
};
static bool timeout;
static unsigned touches;
apdu_session_id_t apdu_current_session(void) { return APDU_SESSION_CCID; }
file_t *search_dynamic_file(uint16_t fid) { return fid == EF_OATH_CRED ? &credential : NULL; }
bool file_has_data(file_t *file) { return file == &credential; }
uint8_t *file_get_data(const file_t *file) { assert(file == &credential); return record; }
uint16_t file_get_size(const file_t *file) { assert(file == &credential); return sizeof(record); }
uint16_t set_res_sw(uint8_t high, uint8_t low) { apdu.rlen = 0; return (high << 8) | low; }
bool wait_button_pressed(void) { touches++; return timeout; }

int main(void) {
    uint8_t response[64];
    uint8_t request[] = {0x71, 4, 'h','o','t','p', 0x75, 4, 0, 0x0B, 0x86, 0x18};
    apdu.data = request;
    apdu.nc = sizeof(request);
    apdu.rdata = response;
    assert(cmd_verify_hotp() == 0x6982);
    assert(touches == 0);
    oath_session()->validated = true;
    timeout = true;
    assert(cmd_verify_hotp() == 0x6985);
    assert(touches == 1);
    timeout = false;
    assert(cmd_verify_hotp() == 0x9000);
    assert(touches == 2);
    assert(get_uint64_t_be(record + 32) == 0);
    puts("H-04 VERIFY_CODE authentication and touch: PASS");
    return 0;
}
