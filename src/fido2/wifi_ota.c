#include "sdkconfig.h"

#if CONFIG_PICO_FIDO2_AB_OTA

#include "wifi_ota.h"

#include <string.h>

#include "esp_flash_encrypt.h"
#include "esp_log.h"
#include "esp_secure_boot.h"
#include "esp_system.h"
#include "esp_timer.h"

#include "pico_keys.h"
#include "usb.h"

static const char *TAG = "fido_ota";

static void release_owner(fido_ota_session_t *session) {
    if (session->owner_claimed) {
        card_release_maintenance();
        session->owner_claimed = false;
    }
}

esp_err_t fido_ota_get_status(fido_ota_status_t *status) {
    if (status == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(status, 0, sizeof(*status));
    status->secure_boot = esp_secure_boot_enabled();
    status->flash_encryption = esp_flash_encryption_enabled();
    status->running_partition = esp_ota_get_running_partition();
    status->next_partition = esp_ota_get_next_update_partition(NULL);
    const esp_app_desc_t *desc = esp_app_get_description();
    status->current_epoch = desc != NULL ? desc->secure_version : 0;

    if (status->running_partition != NULL) {
        esp_ota_img_states_t state;
        if (esp_ota_get_state_partition(status->running_partition, &state) == ESP_OK) {
            status->confirmation_pending = state == ESP_OTA_IMG_PENDING_VERIFY;
        }
    }

    status->ready = status->secure_boot && status->flash_encryption &&
                    status->running_partition != NULL &&
                    status->next_partition != NULL &&
                    esp_ota_get_app_partition_count() >= 2;
    return ESP_OK;
}

esp_err_t fido_ota_begin(fido_ota_session_t *session, size_t image_size) {
    if (session == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(session, 0, sizeof(*session));

    fido_ota_status_t status;
    esp_err_t err = fido_ota_get_status(&status);
    if (err != ESP_OK || !status.ready || status.confirmation_pending) {
        return ESP_ERR_INVALID_STATE;
    }
    if (image_size == 0 || image_size > status.next_partition->size) {
        return ESP_ERR_INVALID_SIZE;
    }
    if (low_flash_is_pending()) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!card_try_claim_maintenance()) {
        return ESP_ERR_INVALID_STATE;
    }
    session->owner_claimed = true;
    if (low_flash_is_pending()) {
        release_owner(session);
        return ESP_ERR_INVALID_STATE;
    }

    session->partition = status.next_partition;
    session->expected_size = image_size;
    err = esp_ota_begin(session->partition, image_size, &session->handle);
    if (err != ESP_OK) {
        release_owner(session);
        memset(session, 0, sizeof(*session));
        return err;
    }
    session->active = true;
    return ESP_OK;
}

esp_err_t fido_ota_write(fido_ota_session_t *session, const void *data, size_t size) {
    if (session == NULL || !session->active || data == NULL || size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (session->written > session->expected_size ||
        size > session->expected_size - session->written) {
        return ESP_ERR_INVALID_SIZE;
    }
    esp_err_t err = esp_ota_write(session->handle, data, size);
    if (err == ESP_OK) {
        session->written += size;
    }
    return err;
}

void fido_ota_abort(fido_ota_session_t *session) {
    if (session == NULL) {
        return;
    }
    if (session->active) {
        esp_ota_abort(session->handle);
        session->active = false;
    }
    release_owner(session);
}

esp_err_t fido_ota_finish(fido_ota_session_t *session, fido_ota_result_t *result,
                          fido_ota_policy_result_t *policy_result) {
    if (session == NULL || result == NULL || policy_result == NULL || !session->active) {
        return ESP_ERR_INVALID_ARG;
    }
    *policy_result = FIDO_OTA_POLICY_OK;
    if (session->written != session->expected_size) {
        fido_ota_abort(session);
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t err = esp_ota_end(session->handle);
    session->active = false;
    if (err != ESP_OK) {
        release_owner(session);
        return err;
    }

    esp_app_desc_t candidate;
    err = esp_ota_get_partition_description(session->partition, &candidate);
    if (err != ESP_OK) {
        release_owner(session);
        return err;
    }
    const esp_app_desc_t *current = esp_app_get_description();
    if (current == NULL) {
        release_owner(session);
        return ESP_FAIL;
    }

    *policy_result = fido_ota_policy_check(
        session->expected_size,
        session->partition->size,
        current->secure_version,
        candidate.secure_version,
        current->project_name,
        candidate.project_name);
    if (*policy_result != FIDO_OTA_POLICY_OK) {
        release_owner(session);
        return ESP_ERR_INVALID_VERSION;
    }

    err = esp_ota_set_boot_partition(session->partition);
    if (err != ESP_OK) {
        release_owner(session);
        return err;
    }

    result->partition = session->partition;
    result->app_desc = candidate;
    result->image_size = session->expected_size;
    release_owner(session);
    return ESP_OK;
}

void fido_ota_boot_confirm_task(void) {
    static bool checked;
    static bool pending;
    static int64_t pending_since_us;
    if (checked && !pending) {
        return;
    }

    const esp_partition_t *running = esp_ota_get_running_partition();
    if (!checked) {
        checked = true;
        if (running == NULL) {
            return;
        }
        esp_ota_img_states_t state;
        if (esp_ota_get_state_partition(running, &state) != ESP_OK ||
            state != ESP_OTA_IMG_PENDING_VERIFY) {
            return;
        }
        pending = true;
        pending_since_us = esp_timer_get_time();
        ESP_LOGI(TAG, "OTA image pending verification; delaying confirmation for %d seconds",
                 CONFIG_PICO_FIDO2_OTA_CONFIRM_DELAY_SEC);
        return;
    }

    int64_t elapsed_us = esp_timer_get_time() - pending_since_us;
    if (elapsed_us < (int64_t)CONFIG_PICO_FIDO2_OTA_CONFIRM_DELAY_SEC * 1000000LL) {
        return;
    }
    esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to confirm OTA image: %s; rebooting for rollback",
                 esp_err_to_name(err));
        esp_restart();
    }
    pending = false;
    ESP_LOGI(TAG, "OTA image confirmed after service-loop stability window");
}

#endif
