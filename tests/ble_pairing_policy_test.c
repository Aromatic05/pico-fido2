#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "ble_pairing_policy.h"

static void fresh_pair_without_grant_is_rejected(void) {
    fido_ble_pairing_policy_t policy;
    fido_ble_pairing_policy_init(&policy, 60000, false, 1000);
    fido_ble_pairing_on_connect(&policy, false);
    assert(!fido_ble_pairing_access_allowed(&policy));
    assert(fido_ble_pairing_complete(&policy, true, 1500) == FIDO_BLE_PAIRING_REJECTED);
    assert(!fido_ble_pairing_access_allowed(&policy));
}

static void grant_allows_exactly_one_fresh_pair(void) {
    fido_ble_pairing_policy_t policy;
    fido_ble_pairing_policy_init(&policy, 60000, true, 1000);
    assert(fido_ble_pairing_window_open(&policy, 1001));
    fido_ble_pairing_on_connect(&policy, false);
    assert(fido_ble_pairing_complete(&policy, true, 2000) == FIDO_BLE_PAIRING_ACCEPTED);
    assert(fido_ble_pairing_access_allowed(&policy));
    assert(!fido_ble_pairing_window_open(&policy, 2001));

    fido_ble_pairing_on_disconnect(&policy);
    fido_ble_pairing_on_connect(&policy, false);
    assert(fido_ble_pairing_complete(&policy, true, 3000) == FIDO_BLE_PAIRING_REJECTED);
}

static void bonded_peer_does_not_need_window(void) {
    fido_ble_pairing_policy_t policy;
    fido_ble_pairing_policy_init(&policy, 60000, false, 5000);
    fido_ble_pairing_on_connect(&policy, true);
    assert(fido_ble_pairing_access_allowed(&policy));
    assert(!fido_ble_pairing_repeat_allowed(&policy, 5100));
    assert(fido_ble_pairing_access_allowed(&policy));
}

static void repeat_pairing_consumes_physical_grant(void) {
    fido_ble_pairing_policy_t policy;
    fido_ble_pairing_policy_init(&policy, 60000, true, 9000);
    fido_ble_pairing_on_connect(&policy, true);
    assert(fido_ble_pairing_repeat_allowed(&policy, 9010));
    assert(!fido_ble_pairing_access_allowed(&policy));
    assert(fido_ble_pairing_complete(&policy, true, 9020) == FIDO_BLE_PAIRING_ACCEPTED);
    assert(fido_ble_pairing_access_allowed(&policy));
    assert(!fido_ble_pairing_window_open(&policy, 9021));
}

static void expired_and_wrapped_windows_are_closed(void) {
    fido_ble_pairing_policy_t policy;
    fido_ble_pairing_policy_init(&policy, 60000, true, 100);
    assert(fido_ble_pairing_window_open(&policy, 60099));
    assert(!fido_ble_pairing_window_open(&policy, 60100));

    fido_ble_pairing_policy_init(&policy, 100, true, UINT32_MAX - 50);
    assert(fido_ble_pairing_window_open(&policy, 20));
    assert(!fido_ble_pairing_window_open(&policy, 49));
}

static void failed_pairing_never_authorizes(void) {
    fido_ble_pairing_policy_t policy;
    fido_ble_pairing_policy_init(&policy, 60000, true, 1000);
    fido_ble_pairing_on_connect(&policy, false);
    assert(fido_ble_pairing_complete(&policy, false, 1100) == FIDO_BLE_PAIRING_FAILED);
    assert(!fido_ble_pairing_access_allowed(&policy));
    assert(fido_ble_pairing_window_open(&policy, 1200));
}

int main(void) {
    fresh_pair_without_grant_is_rejected();
    grant_allows_exactly_one_fresh_pair();
    bonded_peer_does_not_need_window();
    repeat_pairing_consumes_physical_grant();
    expired_and_wrapped_windows_are_closed();
    failed_pairing_never_authorizes();
    puts("BLE pairing policy: PASS");
    return 0;
}
