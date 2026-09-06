#ifndef PICO_FIDO2_WIFI_OTA_H
#define PICO_FIDO2_WIFI_OTA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_app_desc.h"
#include "esp_err.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"

#include "wifi_ota_policy.h"

typedef struct {
    esp_ota_handle_t handle;
    const esp_partition_t *partition;
    size_t expected_size;
    size_t written;
    bool active;
    bool owner_claimed;
} fido_ota_session_t;

typedef struct {
    const esp_partition_t *partition;
    esp_app_desc_t app_desc;
    size_t image_size;
} fido_ota_result_t;

typedef struct {
    bool secure_boot;
    bool flash_encryption;
    bool ready;
    bool confirmation_pending;
    const esp_partition_t *running_partition;
    const esp_partition_t *next_partition;
    uint32_t current_epoch;
} fido_ota_status_t;

esp_err_t fido_ota_get_status(fido_ota_status_t *status);
esp_err_t fido_ota_begin(fido_ota_session_t *session, size_t image_size);
esp_err_t fido_ota_write(fido_ota_session_t *session, const void *data, size_t size);
esp_err_t fido_ota_finish(fido_ota_session_t *session, fido_ota_result_t *result,
                          fido_ota_policy_result_t *policy_result);
void fido_ota_abort(fido_ota_session_t *session);
void fido_ota_boot_confirm_task(void);

#endif
