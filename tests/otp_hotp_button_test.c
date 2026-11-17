#define sprintf p1_sprintf
#include "pico_keys.h"
#undef INITIALIZER
#define INITIALIZER(f) static void __attribute__((unused)) f(void)
#include "../pico-fido/src/fido/otp.c"
#undef sprintf
#include <assert.h>
#include <stdarg.h>

static uint8_t record[60];
static file_t slot;
static char output[9];
struct apdu apdu;

int p1_sprintf(char *dest, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int length = vsnprintf(dest, 9, format, args);
    va_end(args);
    memcpy(output, dest, length + 1);
    return length;
}

int scan_all(void) { return PICOKEY_OK; }
bool cap_supported(uint16_t cap) { return cap == CAP_OTP; }
file_t *search_dynamic_file(uint16_t fid) { return fid == EF_OTP_SLOT1 ? &slot : NULL; }
bool file_has_data(file_t *file) { return file == &slot; }
uint8_t *file_get_data(const file_t *file) { return file == &slot ? record : NULL; }
uint16_t file_get_size(const file_t *file) { return file == &slot ? sizeof(record) : 0; }
int file_put_data(file_t *file, const uint8_t *data, uint16_t length) {
    assert(file == &slot && length == sizeof(record));
    memcpy(record, data, length);
    return PICOKEY_OK;
}
void low_flash_available(void) {}
uint16_t set_res_sw(uint8_t high, uint8_t low) { return (high << 8) | low; }
int random_gen(void *arg, unsigned char *dest, size_t length) {
    (void)arg;
    memset(dest, 0, length);
    return 0;
}

int main(void) {
    static uint8_t response[64];
    apdu.rdata = response;
    static const char *six[] = { "504023", "970934", "786250" };
    static const char *eight[] = { "25504023", "23970934", "71786250" };
    for (int digits = 6; digits <= 8; digits += 2) {
        memset(record, 0, sizeof(record));
        otp_config_t *config = (otp_config_t *)record;
        memcpy(config->aes_key, "1234567890123456", 16);
        config->tkt_flags = OATH_HOTP;
        config->cfg_flags = digits == 8 ? OATH_HOTP8 : 0;
        for (int counter = 0; counter < 3; counter++) {
            assert(otp_button_pressed(1) == 0);
            assert(strcmp(output, digits == 6 ? six[counter] : eight[counter]) == 0);
            assert(get_uint64_t_be(record + 52) == (uint64_t)counter + 1);
        }
        config->ext_flags = DORMANT;
        assert(otp_button_pressed(1) == 1);
        assert(get_uint64_t_be(record + 52) == 3);
    }
    puts("R2-05 HOTP button output and counters: PASS");
    return 0;
}
