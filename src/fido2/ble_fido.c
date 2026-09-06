#include "sdkconfig.h"

#if CONFIG_PICO_FIDO2_BLE

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_att.h"
#include "host/ble_hs.h"
#include "host/ble_hs_mbuf.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "services/dis/ble_svc_dis.h"

#include "apdu.h"
#include "ble_fido_frame.h"
#include "fido/ctap2_cbor.h"
#include "fido/fido.h"
#include "fido/version.h"
#include "hid/ctap_hid.h"
#include "pico_keys.h"
#include "usb.h"

#define FIDO_BLE_CONTROL_POINT_LENGTH 512
#define FIDO_BLE_REVISION_FIDO2       0x20
#define FIDO_BLE_FRAGMENT_TIMEOUT_MS  1500

static const char *TAG = "fido_ble";

static const ble_uuid16_t fido_service_uuid = BLE_UUID16_INIT(0xFFFD);
static const ble_uuid128_t fido_control_point_uuid = BLE_UUID128_INIT(
    0xBB, 0x23, 0xD6, 0x7E, 0xBA, 0xC9, 0x2F, 0xB4,
    0xEE, 0xEC, 0xAA, 0xDE, 0xF1, 0xFF, 0xD0, 0xF1);
static const ble_uuid128_t fido_status_uuid = BLE_UUID128_INIT(
    0xBB, 0x23, 0xD6, 0x7E, 0xBA, 0xC9, 0x2F, 0xB4,
    0xEE, 0xEC, 0xAA, 0xDE, 0xF2, 0xFF, 0xD0, 0xF1);
static const ble_uuid128_t fido_control_point_length_uuid = BLE_UUID128_INIT(
    0xBB, 0x23, 0xD6, 0x7E, 0xBA, 0xC9, 0x2F, 0xB4,
    0xEE, 0xEC, 0xAA, 0xDE, 0xF3, 0xFF, 0xD0, 0xF1);
static const ble_uuid128_t fido_revision_bitfield_uuid = BLE_UUID128_INIT(
    0xBB, 0x23, 0xD6, 0x7E, 0xBA, 0xC9, 0x2F, 0xB4,
    0xEE, 0xEC, 0xAA, 0xDE, 0xF4, 0xFF, 0xD0, 0xF1);

enum fido_ble_attr {
    FIDO_BLE_ATTR_CONTROL_POINT,
    FIDO_BLE_ATTR_STATUS,
    FIDO_BLE_ATTR_CONTROL_POINT_LENGTH,
    FIDO_BLE_ATTR_REVISION_BITFIELD,
};

static uint16_t status_handle;
/* GATT-side state belongs exclusively to the NimBLE host task. */
static uint16_t gatt_connection_handle = BLE_HS_CONN_HANDLE_NONE;
static bool gatt_status_subscribed;
static bool gatt_revision_selected;

/* Core/TX state below belongs exclusively to picokey_extra_transport_task(). */
static uint16_t connection_handle = BLE_HS_CONN_HANDLE_NONE;
static uint8_t own_addr_type;
static bool status_subscribed;
typedef enum {
    FIDO_BLE_CORE_IDLE = 0,
    FIDO_BLE_CORE_RUNNING,
    FIDO_BLE_CORE_ABORTED,
} fido_ble_core_state_t;
static fido_ble_core_state_t core_state = FIDO_BLE_CORE_IDLE;
static uint32_t rx_fragment_time;
static uint8_t ble_itf = ITF_INVALID;
static uint8_t ble_response[USB_BUFFER_SIZE];
static fido_ble_rx_t rx;
static fido_ble_tx_t tx;
static uint8_t tx_payload[FIDO_BLE_MAX_MESSAGE];
static bool tx_active;
static bool tx_waiting;
static SemaphoreHandle_t rx_mutex;

typedef struct {
    uint8_t command;
    uint16_t len;
} fido_ble_request_t;

typedef enum {
    FIDO_BLE_EVENT_CONNECT = 1,
    FIDO_BLE_EVENT_DISCONNECT,
    FIDO_BLE_EVENT_SUBSCRIBE,
    FIDO_BLE_EVENT_NOTIFY_DONE,
    FIDO_BLE_EVENT_CANCEL,
    FIDO_BLE_EVENT_ERROR,
} fido_ble_event_type_t;

typedef struct {
    fido_ble_event_type_t type;
    uint16_t conn_handle;
    int status;
    bool enabled;
    uint8_t error;
} fido_ble_event_t;

static QueueHandle_t request_queue;
static QueueHandle_t event_queue;
static bool event_overflow;
static bool advertising_enabled = true;
static bool ble_stack_running;

extern const uint8_t fido_aid[];
extern void *cbor_thread(void *);
extern bool is_req_button_pending();
void ble_store_config_init(void);

static int fido_ble_gap_event(struct ble_gap_event *event, void *arg);
static void fido_ble_advertise(void);
static void fido_ble_release_request(void);

static void fido_ble_queue_event(fido_ble_event_t event) {
    if (event_queue == NULL || xQueueSend(event_queue, &event, 0) != pdPASS) {
        ESP_LOGE(TAG, "event queue full: %d", event.type);
        __atomic_store_n(&event_overflow, true, __ATOMIC_RELEASE);
        gatt_status_subscribed = false;
        gatt_revision_selected = false;
    }
}

static void fido_ble_recover_event_overflow(void) {
    if (!__atomic_exchange_n(&event_overflow, false, __ATOMIC_ACQ_REL)) {
        return;
    }
    connection_handle = BLE_HS_CONN_HANDLE_NONE;
    status_subscribed = false;
    tx_active = false;
    tx_waiting = false;
    if (core_state == FIDO_BLE_CORE_RUNNING && card_command_is_owned_by(ble_itf)) {
        button_cancel_request();
        core_state = FIDO_BLE_CORE_ABORTED;
    }
    else if (core_state == FIDO_BLE_CORE_IDLE) {
        fido_ble_release_request();
    }
}

static bool fido_ble_request_pending(void) {
    return request_queue != NULL && uxQueueMessagesWaiting(request_queue) != 0;
}

static void fido_ble_release_request(void) {
    if (request_queue == NULL || rx_mutex == NULL) {
        return;
    }
    xSemaphoreTake(rx_mutex, portMAX_DELAY);
    fido_ble_request_t request;
    if (xQueueReceive(request_queue, &request, 0) == pdPASS) {
        fido_ble_rx_reset(&rx);
    }
    xSemaphoreGive(rx_mutex);
}

static size_t fido_ble_notification_capacity(void) {
    uint16_t mtu = ble_att_mtu(connection_handle);
    size_t capacity = mtu > 3 ? mtu - 3 : 20;
    return capacity < FIDO_BLE_CONTROL_POINT_LENGTH ? capacity : FIDO_BLE_CONTROL_POINT_LENGTH;
}

static int fido_ble_tx_pump(void) {
    if (!tx_active || tx_waiting) {
        return 0;
    }
    if (connection_handle == BLE_HS_CONN_HANDLE_NONE || !status_subscribed) {
        tx_active = false;
        return BLE_HS_ENOTCONN;
    }
    if (fido_ble_tx_done(&tx)) {
        tx_active = false;
        return 0;
    }

    uint8_t fragment[FIDO_BLE_CONTROL_POINT_LENGTH];
    size_t fragment_len = fido_ble_tx_next(&tx, fragment, fido_ble_notification_capacity());
    if (fragment_len == 0) {
        tx_active = false;
        return BLE_HS_EINVAL;
    }

    struct os_mbuf *om = ble_hs_mbuf_from_flat(fragment, (uint16_t)fragment_len);
    if (!om) {
        tx_active = false;
        return BLE_HS_ENOMEM;
    }
    int rc = ble_gatts_notify_custom(connection_handle, status_handle, om);
    if (rc != 0) {
        tx_active = false;
        return rc;
    }
    tx_waiting = true;
    return 0;
}

static int fido_ble_notify(uint8_t command, const uint8_t *data, uint16_t len) {
    if (connection_handle == BLE_HS_CONN_HANDLE_NONE || !status_subscribed) {
        return BLE_HS_ENOTCONN;
    }
    if (tx_active || len > sizeof(tx_payload)) {
        return BLE_HS_EBUSY;
    }

    if (len > 0) {
        memcpy(tx_payload, data, len);
    }
    fido_ble_tx_init(&tx, command, tx_payload, len);
    tx_active = true;
    tx_waiting = false;
    return fido_ble_tx_pump();
}

static int fido_ble_error(uint8_t error) {
    return fido_ble_notify(FIDO_BLE_CMD_ERROR, &error, 1);
}

static void fido_ble_dispatch(const fido_ble_request_t *request) {
    uint8_t command = request->command;

    if (command == FIDO_BLE_CMD_CANCEL) {
        if (card_command_is_owned_by(ble_itf)) {
            button_cancel_request();
        }
        fido_ble_release_request();
        return;
    }

    if (command == FIDO_BLE_CMD_PING) {
        if (fido_ble_notify(FIDO_BLE_CMD_PING, rx.data, request->len) != 0) {
            fido_ble_release_request();
        }
        return;
    }

    if (command != FIDO_BLE_CMD_MSG) {
        if (fido_ble_error(FIDO_BLE_ERR_INVALID_CMD) != 0) {
            fido_ble_release_request();
        }
        return;
    }

    if (!card_try_claim(ble_itf)) {
        if (fido_ble_error(FIDO_BLE_ERR_BUSY) != 0) {
            fido_ble_release_request();
        }
        return;
    }

    cbor_process_to(CTAPHID_CBOR, rx.data, request->len, ble_response, FIDO_TRANSPORT_BLE);
    if (!card_start_claimed(ble_itf, cbor_thread)) {
        card_release(ble_itf);
        core_state = FIDO_BLE_CORE_IDLE;
        if (fido_ble_error(FIDO_BLE_ERR_OTHER) != 0) {
            fido_ble_release_request();
        }
        return;
    }
    core_state = FIDO_BLE_CORE_RUNNING;
    usb_send_event(EV_CMD_AVAILABLE);
}

static int fido_ble_control_point_write(struct os_mbuf *om) {
    uint16_t len = OS_MBUF_PKTLEN(om);
    if (len == 0 || len > FIDO_BLE_CONTROL_POINT_LENGTH) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }
    if (!gatt_status_subscribed || gatt_connection_handle == BLE_HS_CONN_HANDLE_NONE) {
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }

    uint8_t fragment[FIDO_BLE_CONTROL_POINT_LENGTH];
    uint16_t flat_len = 0;
    int rc = ble_hs_mbuf_to_flat(om, fragment, sizeof(fragment), &flat_len);
    if (rc != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    if (fido_ble_request_pending()) {
        if (flat_len == 3 && fragment[0] == FIDO_BLE_CMD_CANCEL &&
            fragment[1] == 0 && fragment[2] == 0) {
            fido_ble_queue_event((fido_ble_event_t){ .type = FIDO_BLE_EVENT_CANCEL });
            return 0;
        }
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }

    xSemaphoreTake(rx_mutex, portMAX_DELAY);
    if (fido_ble_request_pending()) {
        xSemaphoreGive(rx_mutex);
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }
    int result = fido_ble_rx_feed(&rx, fragment, flat_len);
    rx_fragment_time = board_millis();
    if (result < 0) {
        uint8_t error = (uint8_t)-result;
        fido_ble_rx_reset(&rx);
        xSemaphoreGive(rx_mutex);
        fido_ble_queue_event((fido_ble_event_t){
            .type = FIDO_BLE_EVENT_ERROR,
            .error = error,
        });
    }
    else if (result == 1) {
        fido_ble_request_t request = {
            .command = rx.command,
            .len = rx.received_len,
        };
        if (xQueueSend(request_queue, &request, 0) != pdPASS) {
            fido_ble_rx_reset(&rx);
            xSemaphoreGive(rx_mutex);
            return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
        }
        xSemaphoreGive(rx_mutex);
    }
    else {
        xSemaphoreGive(rx_mutex);
    }
    return 0;
}

static int fido_ble_access(uint16_t conn_handle, uint16_t attr_handle,
                           struct ble_gatt_access_ctxt *ctxt, void *arg) {
    (void)conn_handle;
    (void)attr_handle;
    enum fido_ble_attr attr = (enum fido_ble_attr)(uintptr_t)arg;

    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR && attr == FIDO_BLE_ATTR_CONTROL_POINT) {
        if (!gatt_revision_selected) {
            return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
        }
        return fido_ble_control_point_write(ctxt->om);
    }

    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR && attr == FIDO_BLE_ATTR_CONTROL_POINT_LENGTH) {
        const uint8_t value[2] = {
            (uint8_t)(FIDO_BLE_CONTROL_POINT_LENGTH >> 8),
            (uint8_t)FIDO_BLE_CONTROL_POINT_LENGTH,
        };
        return os_mbuf_append(ctxt->om, value, sizeof(value)) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    if (attr == FIDO_BLE_ATTR_REVISION_BITFIELD) {
        if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
            const uint8_t value = FIDO_BLE_REVISION_FIDO2;
            return os_mbuf_append(ctxt->om, &value, 1) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
            uint8_t value;
            uint16_t len = 0;
            if (ble_hs_mbuf_to_flat(ctxt->om, &value, 1, &len) != 0 ||
                len != 1 || value != FIDO_BLE_REVISION_FIDO2) {
                return BLE_ATT_ERR_UNLIKELY;
            }
            gatt_revision_selected = true;
            return 0;
        }
    }

    return BLE_ATT_ERR_UNLIKELY;
}

static const struct ble_gatt_svc_def fido_ble_services[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &fido_service_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                .uuid = &fido_control_point_uuid.u,
                .access_cb = fido_ble_access,
                .arg = (void *)(uintptr_t)FIDO_BLE_ATTR_CONTROL_POINT,
                .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC,
            },
            {
                .uuid = &fido_status_uuid.u,
                .access_cb = fido_ble_access,
                .arg = (void *)(uintptr_t)FIDO_BLE_ATTR_STATUS,
                .flags = BLE_GATT_CHR_F_NOTIFY,
                .val_handle = &status_handle,
            },
            {
                .uuid = &fido_control_point_length_uuid.u,
                .access_cb = fido_ble_access,
                .arg = (void *)(uintptr_t)FIDO_BLE_ATTR_CONTROL_POINT_LENGTH,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
            },
            {
                .uuid = &fido_revision_bitfield_uuid.u,
                .access_cb = fido_ble_access,
                .arg = (void *)(uintptr_t)FIDO_BLE_ATTR_REVISION_BITFIELD,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE |
                         BLE_GATT_CHR_F_READ_ENC | BLE_GATT_CHR_F_WRITE_ENC,
            },
            {0},
        },
    },
    {0},
};

static void fido_ble_advertise(void) {
    if (!__atomic_load_n(&advertising_enabled, __ATOMIC_ACQUIRE)) {
        return;
    }
    struct ble_hs_adv_fields fields = {0};
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (uint8_t *)ble_svc_gap_device_name();
    fields.name_len = strlen((const char *)fields.name);
    fields.name_is_complete = 1;
    fields.uuids16 = (ble_uuid16_t *)&fido_service_uuid;
    fields.num_uuids16 = 1;
    fields.uuids16_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "advertisement data: %d", rc);
        return;
    }

    static const uint8_t service_data[] = {0xFD, 0xFF, 0x80};
    struct ble_hs_adv_fields scan_rsp = {0};
    scan_rsp.svc_data_uuid16 = service_data;
    scan_rsp.svc_data_uuid16_len = sizeof(service_data);
    rc = ble_gap_adv_rsp_set_fields(&scan_rsp);
    if (rc != 0) {
        ESP_LOGE(TAG, "scan response data: %d", rc);
        return;
    }

    struct ble_gap_adv_params params = {0};
    params.conn_mode = BLE_GAP_CONN_MODE_UND;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER, &params, fido_ble_gap_event, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "advertisement start: %d", rc);
    }
}

void fido_ble_set_advertising_enabled(bool enabled) {
    __atomic_store_n(&advertising_enabled, enabled, __ATOMIC_RELEASE);
    if (!enabled) {
        int rc = ble_gap_adv_stop();
        if (rc != 0 && rc != BLE_HS_EALREADY) {
            ESP_LOGW(TAG, "advertisement stop: %d", rc);
        }
        return;
    }
    if (gatt_connection_handle == BLE_HS_CONN_HANDLE_NONE) {
        fido_ble_advertise();
    }
}

esp_err_t fido_ble_stop_for_commissioning(void) {
    if (!ble_stack_running) {
        return ESP_OK;
    }
    if (core_state != FIDO_BLE_CORE_IDLE || tx_active ||
        fido_ble_request_pending() || card_command_is_owned_by(ble_itf)) {
        return ESP_ERR_INVALID_STATE;
    }

    fido_ble_set_advertising_enabled(false);
    int rc = nimble_port_stop();
    if (rc != 0) {
        __atomic_store_n(&advertising_enabled, true, __ATOMIC_RELEASE);
        return ESP_FAIL;
    }
    esp_err_t err = nimble_port_deinit();
    if (err != ESP_OK) {
        return err;
    }

    ble_stack_running = false;
    connection_handle = BLE_HS_CONN_HANDLE_NONE;
    status_subscribed = false;
    tx_active = false;
    tx_waiting = false;
    ESP_LOGI(TAG, "BLE host/controller stopped for commissioning; reboot restores BLE");
    return ESP_OK;
}

static int fido_ble_gap_event(struct ble_gap_event *event, void *arg) {
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status != 0) {
            fido_ble_advertise();
            return 0;
        }
        gatt_connection_handle = event->connect.conn_handle;
        gatt_status_subscribed = false;
        gatt_revision_selected = false;
        if (!fido_ble_request_pending()) {
            xSemaphoreTake(rx_mutex, portMAX_DELAY);
            fido_ble_rx_reset(&rx);
            xSemaphoreGive(rx_mutex);
        }
        fido_ble_queue_event((fido_ble_event_t){
            .type = FIDO_BLE_EVENT_CONNECT,
            .conn_handle = event->connect.conn_handle,
        });
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        fido_ble_queue_event((fido_ble_event_t){
            .type = FIDO_BLE_EVENT_DISCONNECT,
            .conn_handle = event->disconnect.conn.conn_handle,
        });
        gatt_connection_handle = BLE_HS_CONN_HANDLE_NONE;
        gatt_status_subscribed = false;
        gatt_revision_selected = false;
        if (!fido_ble_request_pending()) {
            xSemaphoreTake(rx_mutex, portMAX_DELAY);
            fido_ble_rx_reset(&rx);
            xSemaphoreGive(rx_mutex);
        }
        fido_ble_advertise();
        return 0;

    case BLE_GAP_EVENT_SUBSCRIBE:
        if (event->subscribe.attr_handle == status_handle) {
            gatt_status_subscribed = event->subscribe.cur_notify != 0;
            fido_ble_queue_event((fido_ble_event_t){
                .type = FIDO_BLE_EVENT_SUBSCRIBE,
                .conn_handle = event->subscribe.conn_handle,
                .enabled = gatt_status_subscribed,
            });
        }
        return 0;

    case BLE_GAP_EVENT_NOTIFY_TX:
        if (event->notify_tx.attr_handle != status_handle || event->notify_tx.indication) {
            return 0;
        }
        fido_ble_queue_event((fido_ble_event_t){
            .type = FIDO_BLE_EVENT_NOTIFY_DONE,
            .conn_handle = event->notify_tx.conn_handle,
            .status = event->notify_tx.status,
        });
        return 0;

    case BLE_GAP_EVENT_REPEAT_PAIRING: {
        struct ble_gap_conn_desc desc;
        if (ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc) == 0) {
            ble_store_util_delete_peer(&desc.peer_id_addr);
        }
        return BLE_GAP_REPEAT_PAIRING_RETRY;
    }

    default:
        return 0;
    }
}

static void fido_ble_on_reset(int reason) {
    ESP_LOGE(TAG, "host reset: %d", reason);
}

static void fido_ble_on_sync(void) {
    int rc = ble_hs_util_ensure_addr(0);
    assert(rc == 0);
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    assert(rc == 0);
    fido_ble_advertise();
}

static void fido_ble_host_task(void *arg) {
    (void)arg;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static void fido_ble_handle_event(const fido_ble_event_t *event) {
    switch (event->type) {
    case FIDO_BLE_EVENT_CONNECT:
        connection_handle = event->conn_handle;
        status_subscribed = false;
        tx_active = false;
        tx_waiting = false;
        break;

    case FIDO_BLE_EVENT_DISCONNECT:
        if (connection_handle == event->conn_handle) {
            connection_handle = BLE_HS_CONN_HANDLE_NONE;
        }
        status_subscribed = false;
        tx_active = false;
        tx_waiting = false;
        if (core_state == FIDO_BLE_CORE_RUNNING && card_command_is_owned_by(ble_itf)) {
            button_cancel_request();
            core_state = FIDO_BLE_CORE_ABORTED;
        }
        else if (core_state == FIDO_BLE_CORE_IDLE) {
            fido_ble_release_request();
        }
        break;

    case FIDO_BLE_EVENT_SUBSCRIBE:
        if (event->conn_handle != connection_handle) {
            break;
        }
        status_subscribed = event->enabled;
        if (!status_subscribed) {
            tx_active = false;
            tx_waiting = false;
            if (core_state == FIDO_BLE_CORE_RUNNING && card_command_is_owned_by(ble_itf)) {
                button_cancel_request();
                core_state = FIDO_BLE_CORE_ABORTED;
            }
            else if (core_state == FIDO_BLE_CORE_IDLE) {
                fido_ble_release_request();
            }
        }
        break;

    case FIDO_BLE_EVENT_NOTIFY_DONE:
        if (!tx_active || event->conn_handle != connection_handle) {
            break;
        }
        if (event->status != 0 && event->status != BLE_HS_EDONE) {
            ESP_LOGE(TAG, "notification failed: %d", event->status);
            tx_active = false;
            tx_waiting = false;
            if (core_state == FIDO_BLE_CORE_IDLE) {
                fido_ble_release_request();
            }
            break;
        }
        tx_waiting = false;
        if (fido_ble_tx_done(&tx)) {
            tx_active = false;
            if (core_state == FIDO_BLE_CORE_IDLE) {
                fido_ble_release_request();
            }
        }
        break;

    case FIDO_BLE_EVENT_CANCEL:
        if (core_state == FIDO_BLE_CORE_RUNNING && card_command_is_owned_by(ble_itf)) {
            button_cancel_request();
        }
        break;

    case FIDO_BLE_EVENT_ERROR:
        if (!tx_active) {
            fido_ble_error(event->error);
        }
        break;
    }
}

static void fido_ble_process_events(void) {
    fido_ble_event_t event;
    while (xQueueReceive(event_queue, &event, 0) == pdPASS) {
        fido_ble_handle_event(&event);
    }
}

void fido_ble_init(void) {
    ble_itf = card_register_interface(500);
    assert(ble_itf != ITF_INVALID);
    core_state = FIDO_BLE_CORE_IDLE;
    rx_mutex = xSemaphoreCreateMutex();
    request_queue = xQueueCreate(1, sizeof(fido_ble_request_t));
    event_queue = xQueueCreate(16, sizeof(fido_ble_event_t));
    event_overflow = false;
    assert(rx_mutex != NULL && request_queue != NULL && event_queue != NULL);
    gatt_connection_handle = BLE_HS_CONN_HANDLE_NONE;
    gatt_status_subscribed = false;
    gatt_revision_selected = false;
    fido_ble_rx_reset(&rx);

    ESP_ERROR_CHECK(nimble_port_init());

    ble_hs_cfg.reset_cb = fido_ble_on_reset;
    ble_hs_cfg.sync_cb = fido_ble_on_sync;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_NO_INPUT_OUTPUT;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;

    ble_svc_gap_init();
    ble_svc_gatt_init();
    ble_svc_dis_init();
    ESP_ERROR_CHECK(ble_svc_gap_device_name_set("Pico FIDO2"));
    ESP_ERROR_CHECK(ble_svc_gap_device_appearance_set(CONFIG_BT_NIMBLE_SVC_GAP_APPEARANCE));

    static char firmware_revision[16];
    snprintf(firmware_revision, sizeof(firmware_revision), "%u.%u",
             PICO_FIDO_DEVICE_VERSION_MAJOR, PICO_FIDO_DEVICE_VERSION_MINOR);
    ESP_ERROR_CHECK(ble_svc_dis_manufacturer_name_set("Pico FIDO2"));
    ESP_ERROR_CHECK(ble_svc_dis_model_number_set("ESP32-S3"));
    ESP_ERROR_CHECK(ble_svc_dis_firmware_revision_set(firmware_revision));

    assert(ble_gatts_count_cfg(fido_ble_services) == 0);
    assert(ble_gatts_add_svcs(fido_ble_services) == 0);
    ble_store_config_init();
    nimble_port_freertos_init(fido_ble_host_task);
    ble_stack_running = true;
}

void fido_ble_task(void) {
    if (!ble_stack_running) {
        return;
    }
    fido_ble_recover_event_overflow();
    fido_ble_process_events();

    if (!fido_ble_request_pending()) {
        bool expired = false;
        xSemaphoreTake(rx_mutex, portMAX_DELAY);
        if (!fido_ble_request_pending() && rx.active &&
            board_millis() - rx_fragment_time > FIDO_BLE_FRAGMENT_TIMEOUT_MS) {
            fido_ble_rx_reset(&rx);
            expired = true;
        }
        xSemaphoreGive(rx_mutex);
        if (expired && !tx_active) {
            fido_ble_error(FIDO_BLE_ERR_REQ_TIMEOUT);
        }
    }

    if (tx_active && !tx_waiting) {
        if (fido_ble_tx_pump() != 0 && core_state == FIDO_BLE_CORE_IDLE) {
            fido_ble_release_request();
        }
    }

    if (core_state == FIDO_BLE_CORE_IDLE) {
        if (!tx_active && fido_ble_request_pending()) {
            fido_ble_request_t request;
            if (xQueuePeek(request_queue, &request, 0) == pdPASS) {
                fido_ble_dispatch(&request);
            }
        }
        return;
    }
    if (!card_command_is_owned_by(ble_itf)) {
        core_state = FIDO_BLE_CORE_IDLE;
        if (fido_ble_error(FIDO_BLE_ERR_BUSY) != 0) {
            fido_ble_release_request();
        }
        return;
    }

    int status = card_status(ble_itf);
    if (status == PICOKEY_OK) {
        if (core_state == FIDO_BLE_CORE_ABORTED ||
            connection_handle == BLE_HS_CONN_HANDLE_NONE || !status_subscribed) {
            card_release(ble_itf);
            core_state = FIDO_BLE_CORE_IDLE;
            tx_active = false;
            tx_waiting = false;
            fido_ble_release_request();
            return;
        }
        uint16_t response_len = finished_data_size;
        if (!tx_active && fido_ble_notify(FIDO_BLE_CMD_MSG, ble_response, response_len) == 0) {
            card_release(ble_itf);
            core_state = FIDO_BLE_CORE_IDLE;
        }
        else if (!tx_active) {
            card_release(ble_itf);
            core_state = FIDO_BLE_CORE_IDLE;
            fido_ble_release_request();
        }
    }
    else if (status == PICOKEY_ERR_BLOCKED && !tx_active) {
        uint8_t keepalive = is_req_button_pending() ? 0x02 : 0x01;
        fido_ble_notify(FIDO_BLE_CMD_KEEPALIVE, &keepalive, 1);
    }
}

#endif
