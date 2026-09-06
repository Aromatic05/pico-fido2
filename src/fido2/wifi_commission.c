#include "sdkconfig.h"

#if CONFIG_PICO_FIDO2_WIFI_COMMISSIONING

#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#include "fido/version.h"
#include "pico_keys.h"
#if CONFIG_PICO_FIDO2_BLE
#include "ble_fido.h"
#endif

static const char *TAG = "fido_wifi";
static httpd_handle_t http_server;
static char softap_ssid[33];
static bool commissioning_started;
static int (*previous_button_pressed_cb)(uint8_t);

static esp_err_t init_network_stack(void) {
    esp_err_t err = esp_netif_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return err;
    }
    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return err;
    }
    return ESP_OK;
}

static void commissioning_start_failed(const char *step, esp_err_t err) {
    ESP_LOGE(TAG, "%s failed: %s", step, esp_err_to_name(err));
#if CONFIG_PICO_FIDO2_BLE
    fido_ble_set_advertising_enabled(true);
#endif
}

static const char index_html[] =
    "<!doctype html><html><head><meta charset=utf-8>"
    "<meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Pico FIDO2</title>"
    "<style>body{font:16px system-ui;margin:40px;max-width:720px}"
    "pre{background:#111;color:#ddd;padding:16px;border-radius:8px;overflow:auto}"
    "h1{font-size:28px}</style></head><body>"
    "<h1>Pico FIDO2</h1><p>ESP32-S3 commissioning mode</p>"
    "<pre id=s>loading...</pre>"
    "<script>fetch('/api/status').then(r=>r.json()).then(x=>"
    "s.textContent=JSON.stringify(x,null,2)).catch(e=>s.textContent=e)</script>"
    "</body></html>";

static esp_err_t index_get(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_send(req, index_html, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t status_get(httpd_req_t *req) {
    char body[384];
    int len = snprintf(body, sizeof(body),
        "{\"device\":\"Pico FIDO2\",\"platform\":\"ESP32-S3\","
        "\"version\":\"%u.%u\",\"ssid\":\"%s\","
        "\"ble\":%s,\"devKeys\":%s,\"freeHeap\":%u,\"largestInternal\":%u}",
        PICO_FIDO_VERSION_MAJOR, PICO_FIDO_VERSION_MINOR, softap_ssid,
#if CONFIG_PICO_FIDO2_BLE
        "true",
#else
        "false",
#endif
#if CONFIG_PICOKEYS_ESP32_DEV_KEYS
        "true"
#else
        "false"
#endif
        , (unsigned)esp_get_free_heap_size(),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)
    );
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, len);
}

static esp_err_t start_http_server(void) {
    if (http_server != NULL) {
        return ESP_OK;
    }
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.max_open_sockets = 2;
    config.max_uri_handlers = 2;
    config.backlog_conn = 1;
    esp_err_t err = httpd_start(&http_server, &config);
    if (err != ESP_OK) {
        return err;
    }

    const httpd_uri_t root = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = index_get,
    };
    const httpd_uri_t status = {
        .uri = "/api/status",
        .method = HTTP_GET,
        .handler = status_get,
    };
    err = httpd_register_uri_handler(http_server, &root);
    if (err == ESP_OK) {
        err = httpd_register_uri_handler(http_server, &status);
    }
    if (err != ESP_OK) {
        httpd_stop(http_server);
        http_server = NULL;
    }
    return err;
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
    (void)arg;
    (void)event_base;
    if (event_id == WIFI_EVENT_AP_START) {
        ESP_LOGI(TAG, "commissioning AP started: %s", softap_ssid);
    }
    else if (event_id == WIFI_EVENT_AP_STOP) {
        ESP_LOGE(TAG, "commissioning AP stopped unexpectedly");
    }
    else if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *event = event_data;
        ESP_LOGI(TAG, "station " MACSTR " joined", MAC2STR(event->mac));
        esp_err_t err = start_http_server();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "HTTP server start failed: %s", esp_err_to_name(err));
        }
    }
    else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *event = event_data;
        ESP_LOGI(TAG, "station " MACSTR " left", MAC2STR(event->mac));
    }
}

static void fido_wifi_start(void) {
    if (commissioning_started) {
        return;
    }

#if CONFIG_PICO_FIDO2_BLE
    fido_ble_set_advertising_enabled(false);
#endif

    uint8_t mac[6];
    esp_err_t err = esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    if (err != ESP_OK) {
        commissioning_start_failed("SoftAP MAC read", err);
        return;
    }
    snprintf(softap_ssid, sizeof(softap_ssid), "%s-%02X%02X",
             CONFIG_PICO_FIDO2_WIFI_SSID_PREFIX, mac[4], mac[5]);

    err = init_network_stack();
    if (err != ESP_OK) {
        commissioning_start_failed("network stack init", err);
        return;
    }
    if (esp_netif_create_default_wifi_ap() == NULL) {
        commissioning_start_failed("SoftAP netif create", ESP_ERR_NO_MEM);
        return;
    }

    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    err = esp_wifi_init(&init);
    if (err != ESP_OK) {
        commissioning_start_failed("Wi-Fi init", err);
        return;
    }
    err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (err != ESP_OK) {
        commissioning_start_failed("Wi-Fi storage config", err);
        return;
    }
    err = esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL);
    if (err != ESP_OK) {
        commissioning_start_failed("Wi-Fi event handler", err);
        return;
    }

    wifi_config_t config = {0};
    memcpy(config.ap.ssid, softap_ssid, strlen(softap_ssid));
    config.ap.ssid_len = strlen(softap_ssid);
    strlcpy((char *)config.ap.password, CONFIG_PICO_FIDO2_WIFI_PASSWORD,
            sizeof(config.ap.password));
    config.ap.channel = CONFIG_PICO_FIDO2_WIFI_CHANNEL;
    config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    config.ap.max_connection = 2;
    config.ap.pmf_cfg.required = true;

    err = esp_wifi_set_mode(WIFI_MODE_AP);
    if (err == ESP_OK) {
        err = esp_wifi_set_config(WIFI_IF_AP, &config);
    }
    if (err == ESP_OK) {
        err = esp_wifi_start();
    }
    if (err != ESP_OK) {
        commissioning_start_failed("SoftAP start", err);
        return;
    }
    commissioning_started = true;

    ESP_LOGI(TAG, "commissioning AP %s started; HTTP starts after station join", softap_ssid);
}

static int fido_wifi_button_pressed(uint8_t presses) {
    if (presses >= CONFIG_PICO_FIDO2_WIFI_COMMISSION_PRESSES) {
        fido_wifi_start();
        return 0;
    }
    if (previous_button_pressed_cb) {
        return previous_button_pressed_cb(presses);
    }
    return 0;
}

void fido_wifi_init(void) {
    previous_button_pressed_cb = button_pressed_cb;
    button_pressed_cb = fido_wifi_button_pressed;
    ESP_LOGI(TAG, "Wi-Fi off; press BOOT %d times to enter commissioning",
             CONFIG_PICO_FIDO2_WIFI_COMMISSION_PRESSES);
}

void fido_wifi_task(void) {
}

#endif
