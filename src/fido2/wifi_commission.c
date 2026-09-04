#include "sdkconfig.h"

#if CONFIG_PICO_FIDO2_WIFI_COMMISSIONING

#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#include "fido/version.h"

static const char *TAG = "fido_wifi";
static httpd_handle_t http_server;
static char softap_ssid[33];

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
    char body[256];
    int len = snprintf(body, sizeof(body),
        "{\"device\":\"Pico FIDO2\",\"platform\":\"ESP32-S3\","
        "\"version\":\"%u.%u\",\"ssid\":\"%s\","
        "\"ble\":%s,\"devKeys\":%s}",
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
    );
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, len);
}

static void start_http_server(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    ESP_ERROR_CHECK(httpd_start(&http_server, &config));

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
    ESP_ERROR_CHECK(httpd_register_uri_handler(http_server, &root));
    ESP_ERROR_CHECK(httpd_register_uri_handler(http_server, &status));
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
    (void)arg;
    (void)event_base;
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *event = event_data;
        ESP_LOGI(TAG, "station " MACSTR " joined", MAC2STR(event->mac));
    }
    else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *event = event_data;
        ESP_LOGI(TAG, "station " MACSTR " left", MAC2STR(event->mac));
    }
}

void fido_wifi_init(void) {
    uint8_t mac[6];
    ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP));
    snprintf(softap_ssid, sizeof(softap_ssid), "%s-%02X%02X",
             CONFIG_PICO_FIDO2_WIFI_SSID_PREFIX, mac[4], mac[5]);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               wifi_event_handler, NULL));

    wifi_config_t config = {0};
    memcpy(config.ap.ssid, softap_ssid, strlen(softap_ssid));
    config.ap.ssid_len = strlen(softap_ssid);
    strlcpy((char *)config.ap.password, CONFIG_PICO_FIDO2_WIFI_PASSWORD,
            sizeof(config.ap.password));
    config.ap.channel = CONFIG_PICO_FIDO2_WIFI_CHANNEL;
    config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    config.ap.max_connection = 2;
    config.ap.pmf_cfg.required = true;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &config));
    ESP_ERROR_CHECK(esp_wifi_start());
    start_http_server();

    ESP_LOGI(TAG, "commissioning AP %s at http://192.168.4.1", softap_ssid);
}

void fido_wifi_task(void) {
}

#endif
