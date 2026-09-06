#ifndef PICO_FIDO2_BLE_FIDO_H
#define PICO_FIDO2_BLE_FIDO_H

#include <stdbool.h>
#include "esp_err.h"

void fido_ble_set_advertising_enabled(bool enabled);
esp_err_t fido_ble_stop_for_commissioning(void);

#endif
