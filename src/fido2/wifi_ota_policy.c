#include "wifi_ota_policy.h"

#include <string.h>

fido_ota_policy_result_t fido_ota_policy_check(
    size_t image_size,
    size_t slot_size,
    uint32_t current_epoch,
    uint32_t candidate_epoch,
    const char *current_project,
    const char *candidate_project) {
    if (image_size == 0 || slot_size == 0 || image_size > slot_size) {
        return FIDO_OTA_POLICY_INVALID_SIZE;
    }
    if (current_epoch > FIDO_OTA_MAX_SECURITY_VERSION ||
        candidate_epoch > FIDO_OTA_MAX_SECURITY_VERSION) {
        return FIDO_OTA_POLICY_INVALID_EPOCH;
    }
    if (current_project == NULL || candidate_project == NULL ||
        current_project[0] == 0 || candidate_project[0] == 0 ||
        strcmp(current_project, candidate_project) != 0) {
        return FIDO_OTA_POLICY_PROJECT_MISMATCH;
    }
    if (candidate_epoch < current_epoch) {
        return FIDO_OTA_POLICY_DOWNGRADE;
    }
    return FIDO_OTA_POLICY_OK;
}
