#ifndef PICO_FIDO2_WIFI_MANAGEMENT_WIRE_H
#define PICO_FIDO2_WIFI_MANAGEMENT_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fido/management.h"

size_t fido_wifi_build_enabled_config(
    uint8_t *out,
    size_t capacity,
    uint16_t enabled,
    const uint8_t unlock[MAN_CONFIG_LOCK_LEN],
    bool unlock_present);

size_t fido_wifi_build_lock_config(
    uint8_t *out,
    size_t capacity,
    const uint8_t unlock[MAN_CONFIG_LOCK_LEN],
    bool unlock_present,
    const uint8_t new_lock[MAN_CONFIG_LOCK_LEN]);

#endif
