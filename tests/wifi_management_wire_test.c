#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wifi_management_wire.h"

static void fill(uint8_t out[MAN_CONFIG_LOCK_LEN], uint8_t base) {
    for (size_t i = 0; i < MAN_CONFIG_LOCK_LEN; ++i) {
        out[i] = (uint8_t)(base + i);
    }
}

static void enabled_without_lock(void) {
    uint8_t wire[64] = {0};
    size_t n = fido_wifi_build_enabled_config(wire, sizeof(wire), 0x063B, NULL, false);
    const uint8_t expected[] = {4, TAG_USB_ENABLED, 2, 0x06, 0x3B};
    assert(n == sizeof(expected));
    assert(memcmp(wire, expected, sizeof(expected)) == 0);
}

static void enabled_with_unlock(void) {
    uint8_t unlock[MAN_CONFIG_LOCK_LEN];
    uint8_t wire[64] = {0};
    fill(unlock, 0x10);
    size_t n = fido_wifi_build_enabled_config(wire, sizeof(wire), 0x0203,
                                               unlock, true);
    assert(n == 23);
    assert(wire[0] == 22);
    assert(wire[1] == TAG_USB_ENABLED && wire[2] == 2);
    assert(wire[3] == 0x02 && wire[4] == 0x03);
    assert(wire[5] == TAG_UNLOCK && wire[6] == MAN_CONFIG_LOCK_LEN);
    assert(memcmp(wire + 7, unlock, MAN_CONFIG_LOCK_LEN) == 0);
}

static void set_lock_without_unlock(void) {
    uint8_t next[MAN_CONFIG_LOCK_LEN];
    uint8_t wire[64] = {0};
    fill(next, 0x20);
    size_t n = fido_wifi_build_lock_config(wire, sizeof(wire), NULL, false, next);
    assert(n == 19);
    assert(wire[0] == 18);
    assert(wire[1] == TAG_CONFIG_LOCK && wire[2] == MAN_CONFIG_LOCK_LEN);
    assert(memcmp(wire + 3, next, MAN_CONFIG_LOCK_LEN) == 0);
}

static void change_lock_with_unlock(void) {
    uint8_t old_lock[MAN_CONFIG_LOCK_LEN];
    uint8_t new_lock[MAN_CONFIG_LOCK_LEN];
    uint8_t wire[64] = {0};
    fill(old_lock, 0x30);
    fill(new_lock, 0x50);
    size_t n = fido_wifi_build_lock_config(wire, sizeof(wire), old_lock, true, new_lock);
    assert(n == 37);
    assert(wire[0] == 36);
    assert(wire[1] == TAG_UNLOCK && wire[2] == MAN_CONFIG_LOCK_LEN);
    assert(memcmp(wire + 3, old_lock, MAN_CONFIG_LOCK_LEN) == 0);
    assert(wire[19] == TAG_CONFIG_LOCK && wire[20] == MAN_CONFIG_LOCK_LEN);
    assert(memcmp(wire + 21, new_lock, MAN_CONFIG_LOCK_LEN) == 0);
}

static void clear_lock_is_zero_config_lock(void) {
    uint8_t old_lock[MAN_CONFIG_LOCK_LEN];
    uint8_t zero[MAN_CONFIG_LOCK_LEN] = {0};
    uint8_t wire[64] = {0};
    fill(old_lock, 0x70);
    size_t n = fido_wifi_build_lock_config(wire, sizeof(wire), old_lock, true, zero);
    assert(n == 37);
    assert(wire[19] == TAG_CONFIG_LOCK && wire[20] == MAN_CONFIG_LOCK_LEN);
    assert(memcmp(wire + 21, zero, MAN_CONFIG_LOCK_LEN) == 0);
}

static void bounded_encoding_rejects_short_buffers(void) {
    uint8_t lock[MAN_CONFIG_LOCK_LEN] = {1};
    uint8_t wire[18] = {0};
    assert(fido_wifi_build_lock_config(wire, sizeof(wire), NULL, false, lock) == 0);
    assert(fido_wifi_build_enabled_config(NULL, 0, 1, NULL, false) == 0);
    assert(fido_wifi_build_enabled_config(wire, sizeof(wire), 1, NULL, false) == 5);
}

int main(void) {
    enabled_without_lock();
    enabled_with_unlock();
    set_lock_without_unlock();
    change_lock_with_unlock();
    clear_lock_is_zero_config_lock();
    bounded_encoding_rejects_short_buffers();
    puts("Wi-Fi management wire encoding: PASS");
    return 0;
}
