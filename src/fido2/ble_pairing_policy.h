#ifndef PICO_FIDO2_BLE_PAIRING_POLICY_H
#define PICO_FIDO2_BLE_PAIRING_POLICY_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    FIDO_BLE_PAIRING_FAILED = 0,
    FIDO_BLE_PAIRING_ACCEPTED,
    FIDO_BLE_PAIRING_REJECTED,
} fido_ble_pairing_result_t;

typedef struct {
    uint32_t window_started_ms;
    uint32_t window_duration_ms;
    bool window_open;
    bool connection_authorized;
} fido_ble_pairing_policy_t;

void fido_ble_pairing_policy_init(fido_ble_pairing_policy_t *policy,
                                  uint32_t window_duration_ms,
                                  bool grant,
                                  uint32_t now_ms);
bool fido_ble_pairing_window_open(fido_ble_pairing_policy_t *policy,
                                  uint32_t now_ms);
void fido_ble_pairing_on_connect(fido_ble_pairing_policy_t *policy,
                                 bool known_bond);
void fido_ble_pairing_on_disconnect(fido_ble_pairing_policy_t *policy);
bool fido_ble_pairing_access_allowed(const fido_ble_pairing_policy_t *policy);
bool fido_ble_pairing_repeat_allowed(fido_ble_pairing_policy_t *policy,
                                     uint32_t now_ms);
fido_ble_pairing_result_t fido_ble_pairing_complete(
    fido_ble_pairing_policy_t *policy,
    bool success,
    uint32_t now_ms);

#endif
