#include "sdkconfig.h"

#if CONFIG_PICO_FIDO2_WIFI_COMMISSIONING

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "mbedtls/platform_util.h"

#include "pico_keys.h"
#include "usb.h"
#include "wifi_management.h"
#include "wifi_management_wire.h"
#if CONFIG_PICO_FIDO2_BLE
#include "ble_fido.h"
#endif

typedef enum {
    WIFI_MANAGEMENT_READ,
    WIFI_MANAGEMENT_SET_ENABLED,
    WIFI_MANAGEMENT_SET_LOCK,
    WIFI_MANAGEMENT_ALLOW_BLE_PAIRING,
    WIFI_MANAGEMENT_RESET_BLE_BONDS,
} wifi_management_operation_t;

typedef struct {
    uint32_t id;
    wifi_management_operation_t operation;
    uint16_t enabled;
    bool unlock_present;
    uint8_t unlock[MAN_CONFIG_LOCK_LEN];
    uint8_t new_lock[MAN_CONFIG_LOCK_LEN];
} wifi_management_request_t;

typedef struct {
    uint32_t id;
    esp_err_t result;
    uint16_t status_word;
    fido_wifi_management_state_t state;
} wifi_management_response_t;

static QueueHandle_t request_queue;
static QueueHandle_t response_queue;
static SemaphoreHandle_t transaction_mutex;
static uint32_t request_id;

static esp_err_t read_state(fido_wifi_management_state_t *state) {
    return man_get_capability_state(
        &state->supported,
        &state->enabled,
        &state->configured,
        &state->locked) == 0 ? ESP_OK : ESP_FAIL;
}

static void clear_request_secrets(wifi_management_request_t *request) {
    mbedtls_platform_zeroize(request->unlock, sizeof(request->unlock));
    mbedtls_platform_zeroize(request->new_lock, sizeof(request->new_lock));
}

static uint16_t write_enabled(const wifi_management_request_t *request) {
    uint8_t wire[64] = {0};
    size_t len = fido_wifi_build_enabled_config(
        wire, sizeof(wire), request->enabled, request->unlock,
        request->unlock_present);
    uint16_t status = len > 0 ? man_write_config(wire, (uint16_t)len) : MAN_SW_WRONG_DATA;
    mbedtls_platform_zeroize(wire, sizeof(wire));
    return status;
}

static uint16_t write_lock(const wifi_management_request_t *request) {
    uint8_t wire[64] = {0};
    size_t len = fido_wifi_build_lock_config(
        wire, sizeof(wire), request->unlock, request->unlock_present,
        request->new_lock);
    uint16_t status = len > 0 ? man_write_config(wire, (uint16_t)len) : MAN_SW_WRONG_DATA;
    mbedtls_platform_zeroize(wire, sizeof(wire));
    return status;
}

static esp_err_t transact(const wifi_management_request_t *request,
                          wifi_management_response_t *response) {
    if (request_queue == NULL || response_queue == NULL || transaction_mutex == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (xSemaphoreTake(transaction_mutex, pdMS_TO_TICKS(5000)) != pdPASS) {
        return ESP_ERR_TIMEOUT;
    }

    esp_err_t result = ESP_ERR_TIMEOUT;
    if (xQueueSend(request_queue, request, pdMS_TO_TICKS(100)) != pdPASS) {
        goto done;
    }

    TickType_t start = xTaskGetTickCount();
    const TickType_t timeout = pdMS_TO_TICKS(5000);
    while (xTaskGetTickCount() - start < timeout) {
        TickType_t elapsed = xTaskGetTickCount() - start;
        TickType_t remaining = timeout - elapsed;
        if (xQueueReceive(response_queue, response, remaining) != pdPASS) {
            break;
        }
        if (response->id == request->id) {
            result = response->result;
            break;
        }
    }

done:
    xSemaphoreGive(transaction_mutex);
    return result;
}

esp_err_t fido_wifi_management_init(void) {
    request_queue = xQueueCreate(1, sizeof(wifi_management_request_t));
    response_queue = xQueueCreate(1, sizeof(wifi_management_response_t));
    transaction_mutex = xSemaphoreCreateMutex();
    return request_queue != NULL && response_queue != NULL && transaction_mutex != NULL
        ? ESP_OK : ESP_ERR_NO_MEM;
}

esp_err_t fido_wifi_management_get_state(fido_wifi_management_state_t *state) {
    if (state == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    wifi_management_request_t request = {
        .id = __atomic_add_fetch(&request_id, 1, __ATOMIC_RELAXED),
        .operation = WIFI_MANAGEMENT_READ,
    };
    wifi_management_response_t response = {0};
    esp_err_t err = transact(&request, &response);
    if (err == ESP_OK) {
        *state = response.state;
    }
    return err;
}

esp_err_t fido_wifi_management_set_enabled(
    uint16_t enabled,
    const uint8_t unlock[MAN_CONFIG_LOCK_LEN],
    bool unlock_present,
    uint16_t *status_word,
    fido_wifi_management_state_t *state) {
    if (status_word == NULL || state == NULL || (unlock_present && unlock == NULL)) {
        return ESP_ERR_INVALID_ARG;
    }
    wifi_management_request_t request = {
        .id = __atomic_add_fetch(&request_id, 1, __ATOMIC_RELAXED),
        .operation = WIFI_MANAGEMENT_SET_ENABLED,
        .enabled = enabled,
        .unlock_present = unlock_present,
    };
    if (unlock_present) {
        memcpy(request.unlock, unlock, MAN_CONFIG_LOCK_LEN);
    }

    wifi_management_response_t response = {0};
    esp_err_t err = transact(&request, &response);
    clear_request_secrets(&request);
    if (err == ESP_OK) {
        *status_word = response.status_word;
        *state = response.state;
    }
    return err;
}

esp_err_t fido_wifi_management_set_lock(
    const uint8_t unlock[MAN_CONFIG_LOCK_LEN],
    bool unlock_present,
    const uint8_t new_lock[MAN_CONFIG_LOCK_LEN],
    uint16_t *status_word,
    fido_wifi_management_state_t *state) {
    if (new_lock == NULL || status_word == NULL || state == NULL ||
        (unlock_present && unlock == NULL)) {
        return ESP_ERR_INVALID_ARG;
    }
    wifi_management_request_t request = {
        .id = __atomic_add_fetch(&request_id, 1, __ATOMIC_RELAXED),
        .operation = WIFI_MANAGEMENT_SET_LOCK,
        .unlock_present = unlock_present,
    };
    if (unlock_present) {
        memcpy(request.unlock, unlock, MAN_CONFIG_LOCK_LEN);
    }
    memcpy(request.new_lock, new_lock, MAN_CONFIG_LOCK_LEN);

    wifi_management_response_t response = {0};
    esp_err_t err = transact(&request, &response);
    clear_request_secrets(&request);
    if (err == ESP_OK) {
        *status_word = response.status_word;
        *state = response.state;
    }
    return err;
}

esp_err_t fido_wifi_management_allow_ble_pairing(void) {
    wifi_management_request_t request = {
        .id = __atomic_add_fetch(&request_id, 1, __ATOMIC_RELAXED),
        .operation = WIFI_MANAGEMENT_ALLOW_BLE_PAIRING,
    };
    wifi_management_response_t response = {0};
    return transact(&request, &response);
}

esp_err_t fido_wifi_management_reset_ble_bonds(void) {
    wifi_management_request_t request = {
        .id = __atomic_add_fetch(&request_id, 1, __ATOMIC_RELAXED),
        .operation = WIFI_MANAGEMENT_RESET_BLE_BONDS,
    };
    wifi_management_response_t response = {0};
    return transact(&request, &response);
}

void fido_wifi_management_task(void) {
    if (request_queue == NULL || response_queue == NULL) {
        return;
    }

    wifi_management_request_t request;
    if (xQueueReceive(request_queue, &request, 0) != pdPASS) {
        return;
    }

    wifi_management_response_t response = {
        .id = request.id,
        .result = ESP_OK,
        .status_word = MAN_SW_OK,
    };

    if (!card_try_claim_maintenance()) {
        response.result = ESP_ERR_INVALID_STATE;
        clear_request_secrets(&request);
        xQueueOverwrite(response_queue, &response);
        return;
    }

    bool config_write = false;
    switch (request.operation) {
        case WIFI_MANAGEMENT_READ:
            break;
        case WIFI_MANAGEMENT_SET_ENABLED:
            response.status_word = write_enabled(&request);
            config_write = true;
            break;
        case WIFI_MANAGEMENT_SET_LOCK:
            response.status_word = write_lock(&request);
            config_write = true;
            break;
        case WIFI_MANAGEMENT_ALLOW_BLE_PAIRING:
#if CONFIG_PICO_FIDO2_BLE
            response.result = fido_ble_schedule_pairing_window();
#else
            response.result = ESP_ERR_NOT_SUPPORTED;
#endif
            break;
        case WIFI_MANAGEMENT_RESET_BLE_BONDS:
#if CONFIG_PICO_FIDO2_BLE
            response.result = fido_ble_schedule_bond_reset();
#else
            response.result = ESP_ERR_NOT_SUPPORTED;
#endif
            break;
        default:
            response.result = ESP_ERR_INVALID_ARG;
            break;
    }

    if (config_write && response.status_word == MAN_SW_OK && low_flash_is_pending()) {
        do_flash();
        if (low_flash_is_pending()) {
            response.result = ESP_FAIL;
        }
    }

    if (response.result == ESP_OK && read_state(&response.state) != ESP_OK) {
        response.result = ESP_FAIL;
    }

    card_release_maintenance();
    clear_request_secrets(&request);
    xQueueOverwrite(response_queue, &response);
}

#endif
