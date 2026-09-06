#include "sdkconfig.h"

#if CONFIG_PICO_FIDO2_WIFI_COMMISSIONING

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include "pico_keys.h"
#include "usb.h"
#include "wifi_management.h"
#if CONFIG_PICO_FIDO2_BLE
#include "ble_fido.h"
#endif

typedef enum {
    WIFI_MANAGEMENT_READ,
    WIFI_MANAGEMENT_WRITE,
    WIFI_MANAGEMENT_ALLOW_BLE_PAIRING,
} wifi_management_operation_t;

typedef struct {
    uint32_t id;
    wifi_management_operation_t operation;
    uint16_t enabled;
    bool unlock_present;
    uint8_t unlock[MAN_CONFIG_LOCK_LEN];
} wifi_management_request_t;

typedef struct {
    uint32_t id;
    esp_err_t result;
    uint16_t status_word;
    fido_wifi_management_state_t state;
} wifi_management_response_t;

static QueueHandle_t request_queue;
static QueueHandle_t response_queue;
static uint32_t request_id;

static esp_err_t read_state(fido_wifi_management_state_t *state) {
    return man_get_capability_state(
        &state->supported,
        &state->enabled,
        &state->configured,
        &state->locked) == 0 ? ESP_OK : ESP_FAIL;
}

static uint16_t write_enabled(const wifi_management_request_t *request) {
    uint8_t wire[1 + 2 + 2 + 2 + MAN_CONFIG_LOCK_LEN];
    uint16_t offset = 1;

    wire[offset++] = TAG_USB_ENABLED;
    wire[offset++] = 2;
    wire[offset++] = (uint8_t)(request->enabled >> 8);
    wire[offset++] = (uint8_t)request->enabled;

    if (request->unlock_present) {
        wire[offset++] = TAG_UNLOCK;
        wire[offset++] = MAN_CONFIG_LOCK_LEN;
        memcpy(wire + offset, request->unlock, MAN_CONFIG_LOCK_LEN);
        offset = (uint16_t)(offset + MAN_CONFIG_LOCK_LEN);
    }

    wire[0] = (uint8_t)(offset - 1);
    return man_write_config(wire, offset);
}

static esp_err_t transact(const wifi_management_request_t *request,
                          wifi_management_response_t *response) {
    if (request_queue == NULL || response_queue == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (xQueueSend(request_queue, request, pdMS_TO_TICKS(100)) != pdPASS) {
        return ESP_ERR_TIMEOUT;
    }

    TickType_t start = xTaskGetTickCount();
    const TickType_t timeout = pdMS_TO_TICKS(5000);
    while (xTaskGetTickCount() - start < timeout) {
        TickType_t elapsed = xTaskGetTickCount() - start;
        TickType_t remaining = timeout - elapsed;
        if (xQueueReceive(response_queue, response, remaining) != pdPASS) {
            return ESP_ERR_TIMEOUT;
        }
        if (response->id == request->id) {
            return response->result;
        }
    }
    return ESP_ERR_TIMEOUT;
}

esp_err_t fido_wifi_management_init(void) {
    request_queue = xQueueCreate(1, sizeof(wifi_management_request_t));
    response_queue = xQueueCreate(1, sizeof(wifi_management_response_t));
    return request_queue != NULL && response_queue != NULL ? ESP_OK : ESP_ERR_NO_MEM;
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
        .operation = WIFI_MANAGEMENT_WRITE,
        .enabled = enabled,
        .unlock_present = unlock_present,
    };
    if (unlock_present) {
        memcpy(request.unlock, unlock, MAN_CONFIG_LOCK_LEN);
    }

    wifi_management_response_t response = {0};
    esp_err_t err = transact(&request, &response);
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
        xQueueOverwrite(response_queue, &response);
        return;
    }

    if (request.operation == WIFI_MANAGEMENT_WRITE) {
        response.status_word = write_enabled(&request);
        if (response.status_word == MAN_SW_OK && low_flash_is_pending()) {
            do_flash();
            if (low_flash_is_pending()) {
                response.result = ESP_FAIL;
            }
        }
    }
    else if (request.operation == WIFI_MANAGEMENT_ALLOW_BLE_PAIRING) {
#if CONFIG_PICO_FIDO2_BLE
        response.result = fido_ble_schedule_pairing_window();
#else
        response.result = ESP_ERR_NOT_SUPPORTED;
#endif
    }

    if (response.result == ESP_OK && read_state(&response.state) != ESP_OK) {
        response.result = ESP_FAIL;
    }

    card_release_maintenance();
    xQueueOverwrite(response_queue, &response);
}

#endif
