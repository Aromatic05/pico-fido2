#include "ble_pairing_policy.h"

void fido_ble_pairing_policy_init(fido_ble_pairing_policy_t *policy,
                                  uint32_t window_duration_ms,
                                  bool grant,
                                  uint32_t now_ms) {
    policy->window_started_ms = now_ms;
    policy->window_duration_ms = window_duration_ms;
    policy->window_open = grant;
    policy->connection_authorized = false;
}

bool fido_ble_pairing_window_open(fido_ble_pairing_policy_t *policy,
                                  uint32_t now_ms) {
    if (!policy->window_open) {
        return false;
    }
    if ((uint32_t)(now_ms - policy->window_started_ms) >= policy->window_duration_ms) {
        policy->window_open = false;
        return false;
    }
    return true;
}

void fido_ble_pairing_on_connect(fido_ble_pairing_policy_t *policy,
                                 bool known_bond) {
    policy->connection_authorized = known_bond;
}

void fido_ble_pairing_on_disconnect(fido_ble_pairing_policy_t *policy) {
    policy->connection_authorized = false;
}

bool fido_ble_pairing_access_allowed(const fido_ble_pairing_policy_t *policy) {
    return policy->connection_authorized;
}

bool fido_ble_pairing_repeat_allowed(fido_ble_pairing_policy_t *policy,
                                     uint32_t now_ms) {
    if (!fido_ble_pairing_window_open(policy, now_ms)) {
        return false;
    }
    policy->connection_authorized = false;
    return true;
}

fido_ble_pairing_result_t fido_ble_pairing_complete(
    fido_ble_pairing_policy_t *policy,
    bool success,
    uint32_t now_ms) {
    if (!success) {
        return FIDO_BLE_PAIRING_FAILED;
    }
    if (policy->connection_authorized) {
        return FIDO_BLE_PAIRING_ACCEPTED;
    }
    if (!fido_ble_pairing_window_open(policy, now_ms)) {
        return FIDO_BLE_PAIRING_REJECTED;
    }
    policy->connection_authorized = true;
    policy->window_open = false;
    return FIDO_BLE_PAIRING_ACCEPTED;
}
