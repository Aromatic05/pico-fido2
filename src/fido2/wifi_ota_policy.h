#ifndef PICO_FIDO2_WIFI_OTA_POLICY_H
#define PICO_FIDO2_WIFI_OTA_POLICY_H

#include <stddef.h>
#include <stdint.h>

#define FIDO_OTA_MAX_SECURITY_VERSION 16U

typedef enum {
    FIDO_OTA_POLICY_OK = 0,
    FIDO_OTA_POLICY_INVALID_SIZE,
    FIDO_OTA_POLICY_INVALID_EPOCH,
    FIDO_OTA_POLICY_PROJECT_MISMATCH,
    FIDO_OTA_POLICY_DOWNGRADE,
} fido_ota_policy_result_t;

fido_ota_policy_result_t fido_ota_policy_check(
    size_t image_size,
    size_t slot_size,
    uint32_t current_epoch,
    uint32_t candidate_epoch,
    const char *current_project,
    const char *candidate_project);

#endif
