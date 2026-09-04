#include "sdkconfig.h"

#if CONFIG_PICO_FIDO2_BLE

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
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
    FIDO_BLE_ATTR_CONTROL_POINT_LENGTH,
    FIDO_BLE_ATTR_REVISION_BITFIELD,
};

static uint16_t status_handle;
static uint16_t connection_handle = BLE_HS_CONN_HANDLE_NONE;
static uint8_t own_addr_type;
static bool status_subscribed;
static bool revision_selected;
static bool processing;
static uint32_t rx_fragment_time;
static uint8_t ble_itf = ITF_INVALID;
static uint8_t ble_response[USB_BUFFER_SIZE];
static fido_ble_rx_t rx;
static fido_ble_tx_t tx;
static uint8_t tx_payload[FIDO_BLE_MAX_MESSAGE];
static bool tx_active;
static bool tx_waiting;

extern const uint8_t fido_aid[];
extern void *cbor_thread(void *);
extern bool cancel_button;
extern bool is_req_button_pending();
void ble_store_config_init(void);

static int fido_ble_gap_event(struct ble_gap_event *event, void *arg);
static void fido_ble_advertise(void);

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

static void fido_ble_error(uint8_t error) {
    fido_ble_notify(FIDO_BLE_CMD_ERROR, &error, 1);
}

static void fido_ble_dispatch(void) {
    uint8_t command = rx.command;

    if (command == FIDO_BLE_CMD_CANCEL) {
        if (card_command_is_owned_by(ble_itf)) {
            cancel_button = true;
        }
        fido_ble_rx_reset(&rx);
        return;
    }

    if (command == FIDO_BLE_CMD_PING) {
        fido_ble_notify(FIDO_BLE_CMD_PING, rx.data, rx.received_len);
        fido_ble_rx_reset(&rx);
        return;
    }

    if (command != FIDO_BLE_CMD_MSG) {
        fido_ble_error(FIDO_BLE_ERR_INVALID_CMD);
        fido_ble_rx_reset(&rx);
        return;
    }

    if (!card_try_claim(ble_itf)) {
        fido_ble_error(FIDO_BLE_ERR_BUSY);
        fido_ble_rx_reset(&rx);
        return;
    }

    select_app(fido_aid + 1, fido_aid[0]);
    cbor_process_to(CTAPHID_CBOR, rx.data, rx.received_len, ble_response);
    card_start_claimed(ble_itf, cbor_thread);
    processing = true;
    fido_ble_rx_reset(&rx);
    usb_send_event(EV_CMD_AVAILABLE);
}

static int fido_ble_control_point_write(struct os_mbuf *om) {
    uint16_t len = OS_MBUF_PKTLEN(om);
    if (len == 0 || len > FIDO_BLE_CONTROL_POINT_LENGTH) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    uint8_t fragment[FIDO_BLE_CONTROL_POINT_LENGTH];
    uint16_t flat_len = 0;
    int rc = ble_hs_mbuf_to_flat(om, fragment, sizeof(fragment), &flat_len);
    if (rc != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    int result = fido_ble_rx_feed(&rx, fragment, flat_len);
    rx_fragment_time = board_millis();
    if (result < 0) {
        fido_ble_error((uint8_t)-result);
        fido_ble_rx_reset(&rx);
    }
    else if (result == 1) {
        fido_ble_dispatch();
    }
    return 0;
}

static int fido_ble_access(uint16_t conn_handle, uint16_t attr_handle,
                           struct ble_gatt_access_ctxt *ctxt, void *arg) {
    (void)conn_handle;
    (void)attr_handle;
    enum fido_ble_attr attr = (enum fido_ble_attr)(uintptr_t)arg;

    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR && attr == FIDO_BLE_ATTR_CONTROL_POINT) {
        if (!revision_selected) {
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
            revision_selected = true;
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

static int fido_ble_gap_event(struct ble_gap_event *event, void *arg) {
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status != 0) {
            fido_ble_advertise();
            return 0;
        }
        connection_handle = event->connect.conn_handle;
        status_subscribed = false;
        revision_selected = false;
        tx_active = false;
        tx_waiting = false;
        fido_ble_rx_reset(&rx);
        ble_gap_security_initiate(connection_handle);
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        if (processing && card_command_is_owned_by(ble_itf)) {
            cancel_button = true;
        }
        connection_handle = BLE_HS_CONN_HANDLE_NONE;
        status_subscribed = false;
        revision_selected = false;
        tx_active = false;
        tx_waiting = false;
        fido_ble_rx_reset(&rx);
        fido_ble_advertise();
        return 0;

    case BLE_GAP_EVENT_SUBSCRIBE:
        if (event->subscribe.attr_handle == status_handle) {
            status_subscribed = event->subscribe.cur_notify != 0;
        }
        return 0;

    case BLE_GAP_EVENT_NOTIFY_TX:
        if (!tx_active || event->notify_tx.conn_handle != connection_handle ||
            event->notify_tx.attr_handle != status_handle || event->notify_tx.indication) {
            return 0;
        }
        if (event->notify_tx.status != 0 && event->notify_tx.status != BLE_HS_EDONE) {
            ESP_LOGE(TAG, "notification failed: %d", event->notify_tx.status);
            tx_active = false;
            tx_waiting = false;
            return 0;
        }
        tx_waiting = false;
        if (fido_ble_tx_done(&tx)) {
            tx_active = false;
        }
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

void fido_ble_init(void) {
    ble_itf = card_register_interface(500);
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
             PICO_FIDO_VERSION_MAJOR, PICO_FIDO_VERSION_MINOR);
    ESP_ERROR_CHECK(ble_svc_dis_manufacturer_name_set("Pico FIDO2"));
    ESP_ERROR_CHECK(ble_svc_dis_model_number_set("ESP32-S3"));
    ESP_ERROR_CHECK(ble_svc_dis_firmware_revision_set(firmware_revision));

    assert(ble_gatts_count_cfg(fido_ble_services) == 0);
    assert(ble_gatts_add_svcs(fido_ble_services) == 0);
    ble_store_config_init();
    nimble_port_freertos_init(fido_ble_host_task);
}

void fido_ble_task(void) {
    if (tx_active && !tx_waiting) {
        fido_ble_tx_pump();
    }

    if (rx.active && board_millis() - rx_fragment_time > FIDO_BLE_FRAGMENT_TIMEOUT_MS) {
        fido_ble_error(FIDO_BLE_ERR_REQ_TIMEOUT);
        fido_ble_rx_reset(&rx);
    }

    if (!processing) {
        return;
    }
    if (!card_command_is_owned_by(ble_itf)) {
        processing = false;
        fido_ble_error(FIDO_BLE_ERR_BUSY);
        return;
    }

    int status = card_status(ble_itf);
    if (status == PICOKEY_OK) {
        uint16_t response_len = finished_data_size;
        if (!tx_active && fido_ble_notify(FIDO_BLE_CMD_MSG, ble_response, response_len) == 0) {
            card_release(ble_itf);
            processing = false;
        }
    }
    else if (status == PICOKEY_ERR_BLOCKED && !tx_active) {
        uint8_t keepalive = is_req_button_pending() ? 0x02 : 0x01;
        fido_ble_notify(FIDO_BLE_CMD_KEEPALIVE, &keepalive, 1);
    }
}

#endif
