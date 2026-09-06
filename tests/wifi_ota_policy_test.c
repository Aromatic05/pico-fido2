#include <assert.h>
#include <stdio.h>

#include "wifi_ota_policy.h"

static void valid_equal_epoch(void) {
    assert(fido_ota_policy_check(100, 200, 2, 2, "pico_fido2", "pico_fido2") ==
           FIDO_OTA_POLICY_OK);
}

static void valid_newer_epoch(void) {
    assert(fido_ota_policy_check(200, 200, 2, 3, "pico_fido2", "pico_fido2") ==
           FIDO_OTA_POLICY_OK);
}

static void rejects_bad_sizes(void) {
    assert(fido_ota_policy_check(0, 200, 0, 0, "pico_fido2", "pico_fido2") ==
           FIDO_OTA_POLICY_INVALID_SIZE);
    assert(fido_ota_policy_check(201, 200, 0, 0, "pico_fido2", "pico_fido2") ==
           FIDO_OTA_POLICY_INVALID_SIZE);
}

static void rejects_invalid_epoch(void) {
    assert(fido_ota_policy_check(100, 200, 17, 17, "pico_fido2", "pico_fido2") ==
           FIDO_OTA_POLICY_INVALID_EPOCH);
    assert(fido_ota_policy_check(100, 200, 0, 17, "pico_fido2", "pico_fido2") ==
           FIDO_OTA_POLICY_INVALID_EPOCH);
}

static void rejects_other_project(void) {
    assert(fido_ota_policy_check(100, 200, 1, 1, "pico_fido2", "other") ==
           FIDO_OTA_POLICY_PROJECT_MISMATCH);
    assert(fido_ota_policy_check(100, 200, 1, 1, NULL, "pico_fido2") ==
           FIDO_OTA_POLICY_PROJECT_MISMATCH);
}

static void rejects_downgrade(void) {
    assert(fido_ota_policy_check(100, 200, 3, 2, "pico_fido2", "pico_fido2") ==
           FIDO_OTA_POLICY_DOWNGRADE);
}

int main(void) {
    valid_equal_epoch();
    valid_newer_epoch();
    rejects_bad_sizes();
    rejects_invalid_epoch();
    rejects_other_project();
    rejects_downgrade();
    puts("Wi-Fi OTA policy: PASS");
    return 0;
}
