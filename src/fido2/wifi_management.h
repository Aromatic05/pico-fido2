#ifndef PICO_FIDO2_WIFI_MANAGEMENT_H
#define PICO_FIDO2_WIFI_MANAGEMENT_H

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "fido/management.h"

typedef struct {
    uint16_t supported;
    uint16_t enabled;
    bool configured;
    bool locked;
} fido_wifi_management_state_t;

esp_err_t fido_wifi_management_init(void);
esp_err_t fido_wifi_management_get_state(fido_wifi_management_state_t *state);
esp_err_t fido_wifi_management_set_enabled(
    uint16_t enabled,
    const uint8_t unlock[MAN_CONFIG_LOCK_LEN],
    bool unlock_present,
    uint16_t *status_word,
    fido_wifi_management_state_t *state);
void fido_wifi_management_task(void);

#endif
