#include "sdkconfig.h"

#if CONFIG_PICO_FIDO2_WIFI_COMMISSIONING

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/constant_time.h"

#include "fido/management.h"
#include "fido/version.h"
#include "pico_keys.h"
#include "usb.h"
#include "wifi_management.h"
#include "wifi_presence_policy.h"
#if CONFIG_PICO_FIDO2_BLE
#include "ble_fido.h"
#endif

static const char *TAG = "fido_wifi";
static httpd_handle_t http_server;
static char softap_ssid[33];
static char csrf_token[33];
static bool commissioning_started;
static bool restart_requested;
static TickType_t last_activity_tick;
static int (*previous_button_pressed_cb)(uint8_t);
static fido_wifi_presence_policy_t presence_policy;
static portMUX_TYPE presence_mux = portMUX_INITIALIZER_UNLOCKED;

static void touch_activity(void) {
    __atomic_store_n(&last_activity_tick, xTaskGetTickCount(), __ATOMIC_RELEASE);
}

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
}

static esp_err_t json_response(httpd_req_t *req, const char *status, const char *body) {
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t management_transport_error(httpd_req_t *req, esp_err_t err) {
    if (err == ESP_ERR_INVALID_STATE) {
        return json_response(req, "409 Conflict", "{\"error\":\"device busy\"}");
    }
    if (err == ESP_ERR_TIMEOUT) {
        return json_response(req, "503 Service Unavailable", "{\"error\":\"management timeout\"}");
    }
    return json_response(req, "500 Internal Server Error", "{\"error\":\"management failure\"}");
}

static bool csrf_valid(httpd_req_t *req) {
    char header[sizeof(csrf_token)];
    if (httpd_req_get_hdr_value_str(req, "X-Pico-CSRF", header, sizeof(header)) != ESP_OK) {
        return false;
    }
    return strlen(header) == sizeof(csrf_token) - 1 &&
           mbedtls_ct_memcmp(header, csrf_token, sizeof(csrf_token) - 1) == 0;
}

static void grant_physical_presence(void) {
    portENTER_CRITICAL(&presence_mux);
    fido_wifi_presence_grant(&presence_policy, board_millis());
    portEXIT_CRITICAL(&presence_mux);
}

static bool consume_physical_presence(void) {
    portENTER_CRITICAL(&presence_mux);
    bool granted = fido_wifi_presence_consume(&presence_policy, board_millis());
    portEXIT_CRITICAL(&presence_mux);
    return granted;
}

static const char index_html[] =
    "<!doctype html><html><head><meta charset=utf-8>"
    "<meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Pico FIDO2 Maintenance</title>"
    "<style>body{font:15px system-ui;margin:32px auto;max-width:760px;padding:0 18px;color:#ddd;background:#111}"
    "h1{font-size:26px}h2{font-size:18px;margin-top:28px}.card{background:#1c1c1c;border:1px solid #333;border-radius:10px;padding:16px;margin:12px 0}"
    "label{display:block;padding:6px 0}button,input{font:inherit;background:#282828;color:#eee;border:1px solid #555;border-radius:6px;padding:8px 10px}"
    "button{cursor:pointer;margin-right:8px}.muted{color:#999}.bad{color:#ff8b8b}.ok{color:#8bd49c}code{font-family:ui-monospace,monospace}</style></head><body>"
    "<h1>Pico FIDO2 Maintenance</h1><p class=muted>Physical commissioning mode. Persistent or trust-changing actions require one BOOT press immediately before the action.</p>"
    "<div class=card><h2>Device</h2><pre id=status>loading...</pre></div>"
    "<div class=card><h2>USB applications</h2><div id=apps></div>"
    "<div id=unlockRow style='display:none'><label>Configuration lock code (32 hex)<br><input id=unlock maxlength=32 autocomplete=off></label></div>"
    "<p id=msg class=muted></p><button onclick=save()>Save configuration</button><button onclick=pairBle()>Allow BLE pairing</button><button onclick=reboot()>Restart device</button></div>"
    "<script>const caps=[['OTP',1],['U2F',2],['OpenPGP',8],['PIV',16],['OATH',32],['FIDO2',512],['Management',1024]];let cfg;const st=document.getElementById('status'),appBox=document.getElementById('apps'),lockRow=document.getElementById('unlockRow'),unlockInput=document.getElementById('unlock'),msgBox=document.getElementById('msg');"
    "async function load(){const [s,c]=await Promise.all([fetch('/api/status').then(r=>r.json()),fetch('/api/config').then(r=>r.json())]);cfg=c;"
    "st.textContent=JSON.stringify(s,null,2);appBox.innerHTML='';for(const [n,b] of caps){const l=document.createElement('label');const x=document.createElement('input');x.type='checkbox';x.dataset.bit=b;x.checked=!!(c.enabled&b);x.disabled=!(c.supported&b);l.append(x,' '+n);appBox.append(l)}"
    "lockRow.style.display=c.locked?'block':'none';msgBox.textContent=c.locked?'Configuration is locked; the existing 16-byte lock code is required to save.':'Configuration is unlocked.'}"
    "async function save(){let enabled=0;for(const x of appBox.querySelectorAll('input'))if(x.checked)enabled|=+x.dataset.bit;if(!(enabled&(1|2|512|1024))){msgBox.className='bad';msgBox.textContent='Keep at least one management-capable USB transport enabled.';return}"
    "const p=new URLSearchParams({enabled:String(enabled)});if(cfg.locked)p.set('unlock',unlockInput.value.trim());const r=await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Pico-CSRF':cfg.csrf},body:p});const j=await r.json();"
    "if(!r.ok){msgBox.className='bad';msgBox.textContent=j.error||'Save failed';return}msgBox.className='ok';msgBox.textContent='Saved to flash. Restart to apply USB interface changes.';await load()}"
    "async function pairBle(){const r=await fetch('/api/ble/pairing',{method:'POST',headers:{'X-Pico-CSRF':cfg.csrf}});const j=await r.json();msgBox.className=r.ok?'ok':'bad';msgBox.textContent=r.ok?'BLE pairing authorized for the next window; restarting.':(j.error||'Pairing authorization failed.')}"
    "async function reboot(){const r=await fetch('/api/reboot',{method:'POST',headers:{'X-Pico-CSRF':cfg.csrf}});msgBox.className=r.ok?'ok':'bad';msgBox.textContent=r.ok?'Restart requested.':'Restart request failed.'}load().catch(e=>{msgBox.className='bad';msgBox.textContent=e})</script>"
    "</body></html>";

static esp_err_t index_get(httpd_req_t *req) {
    touch_activity();
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, index_html, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t status_get(httpd_req_t *req) {
    touch_activity();
    char body[448];
    int len = snprintf(body, sizeof(body),
        "{\"device\":\"Pico FIDO2\",\"platform\":\"ESP32-S3\","
        "\"version\":\"%u.%u\",\"ssid\":\"%s\","
        "\"ble\":%s,\"devKeys\":%s,\"idleTimeoutSec\":%u,"
        "\"freeHeap\":%u,\"largestInternal\":%u}",
        PICO_FIDO_VERSION_MAJOR, PICO_FIDO_VERSION_MINOR, softap_ssid,
#if CONFIG_PICO_FIDO2_BLE
        fido_ble_is_running() ? "true" : "false",
#else
        "false",
#endif
#if CONFIG_PICOKEYS_ESP32_DEV_KEYS
        "true",
#else
        "false",
#endif
        (unsigned)CONFIG_PICO_FIDO2_WIFI_IDLE_TIMEOUT_SEC,
        (unsigned)esp_get_free_heap_size(),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, body, len);
}

static esp_err_t config_get(httpd_req_t *req) {
    touch_activity();
    fido_wifi_management_state_t state;
    esp_err_t err = fido_wifi_management_get_state(&state);
    if (err != ESP_OK) {
        return management_transport_error(req, err);
    }

    char body[240];
    snprintf(body, sizeof(body),
             "{\"supported\":%u,\"enabled\":%u,\"configured\":%s,\"locked\":%s,\"restartRequired\":true,\"csrf\":\"%s\"}",
             state.supported, state.enabled,
             state.configured ? "true" : "false",
             state.locked ? "true" : "false", csrf_token);
    return json_response(req, "200 OK", body);
}

static esp_err_t read_form_body(httpd_req_t *req, char *body, size_t body_size) {
    if (req->content_len <= 0 || (size_t)req->content_len >= body_size) {
        return ESP_ERR_INVALID_SIZE;
    }
    size_t received = 0;
    while (received < (size_t)req->content_len) {
        int n = httpd_req_recv(req, body + received, req->content_len - received);
        if (n <= 0) {
            return ESP_FAIL;
        }
        received += (size_t)n;
    }
    body[received] = 0;
    return ESP_OK;
}

static bool parse_enabled(const char *body, uint16_t *enabled) {
    char value[16];
    if (httpd_query_key_value(body, "enabled", value, sizeof(value)) != ESP_OK) {
        return false;
    }
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 0);
    if (end == value || *end != 0 || parsed > UINT16_MAX) {
        return false;
    }
    *enabled = (uint16_t)parsed;
    return true;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_unlock(const char *body, uint8_t unlock[MAN_CONFIG_LOCK_LEN],
                         bool *present) {
    char value[MAN_CONFIG_LOCK_LEN * 2 + 1];
    if (httpd_query_key_value(body, "unlock", value, sizeof(value)) != ESP_OK) {
        *present = false;
        return true;
    }
    if (strlen(value) != MAN_CONFIG_LOCK_LEN * 2) {
        return false;
    }
    for (size_t i = 0; i < MAN_CONFIG_LOCK_LEN; ++i) {
        int high = hex_nibble(value[i * 2]);
        int low = hex_nibble(value[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        unlock[i] = (uint8_t)((high << 4) | low);
    }
    *present = true;
    return true;
}

static esp_err_t config_post(httpd_req_t *req) {
    touch_activity();
    if (!csrf_valid(req)) {
        return json_response(req, "403 Forbidden", "{\"error\":\"invalid session token\"}");
    }
    char body[128];
    if (read_form_body(req, body, sizeof(body)) != ESP_OK) {
        return json_response(req, "400 Bad Request", "{\"error\":\"invalid request body\"}");
    }

    uint16_t enabled = 0;
    uint8_t unlock[MAN_CONFIG_LOCK_LEN] = {0};
    bool unlock_present = false;
    if (!parse_enabled(body, &enabled) || !parse_unlock(body, unlock, &unlock_present)) {
        return json_response(req, "400 Bad Request", "{\"error\":\"invalid configuration\"}");
    }
    if (!consume_physical_presence()) {
        return json_response(req, "428 Precondition Required",
                             "{\"error\":\"press BOOT once, then retry within the physical confirmation window\"}");
    }

    uint16_t status_word = 0;
    fido_wifi_management_state_t state;
    esp_err_t err = fido_wifi_management_set_enabled(
        enabled, unlock, unlock_present, &status_word, &state);
    if (err != ESP_OK) {
        return management_transport_error(req, err);
    }
    if (status_word == MAN_SW_SECURITY_STATUS_NOT_SATISFIED) {
        return json_response(req, "403 Forbidden", "{\"error\":\"configuration lock rejected\"}");
    }
    if (status_word != MAN_SW_OK) {
        return json_response(req, "400 Bad Request", "{\"error\":\"configuration rejected\"}");
    }

    char response[160];
    snprintf(response, sizeof(response),
             "{\"ok\":true,\"enabled\":%u,\"locked\":%s,\"restartRequired\":true}",
             state.enabled, state.locked ? "true" : "false");
    return json_response(req, "200 OK", response);
}

static esp_err_t reboot_post(httpd_req_t *req) {
    touch_activity();
    if (!csrf_valid(req)) {
        return json_response(req, "403 Forbidden", "{\"error\":\"invalid session token\"}");
    }
    esp_err_t err = json_response(req, "202 Accepted", "{\"ok\":true}");
    if (err == ESP_OK) {
        __atomic_store_n(&restart_requested, true, __ATOMIC_RELEASE);
    }
    return err;
}

static esp_err_t ble_pairing_post(httpd_req_t *req) {
    touch_activity();
    if (!csrf_valid(req)) {
        return json_response(req, "403 Forbidden", "{\"error\":\"invalid session token\"}");
    }
    if (!consume_physical_presence()) {
        return json_response(req, "428 Precondition Required",
                             "{\"error\":\"press BOOT once, then retry within the physical confirmation window\"}");
    }
    esp_err_t err = fido_wifi_management_allow_ble_pairing();
    if (err != ESP_OK) {
        return management_transport_error(req, err);
    }
    char response[64];
    snprintf(response, sizeof(response),
             "{\"ok\":true,\"pairingWindowSec\":%u}",
             (unsigned)CONFIG_PICO_FIDO2_BLE_PAIRING_WINDOW_SEC);
    err = json_response(req, "202 Accepted", response);
    if (err == ESP_OK) {
        __atomic_store_n(&restart_requested, true, __ATOMIC_RELEASE);
    }
    return err;
}

static esp_err_t start_http_server(void) {
    if (http_server != NULL) {
        return ESP_OK;
    }
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.max_open_sockets = 2;
    config.max_uri_handlers = 6;
    config.backlog_conn = 1;
    esp_err_t err = httpd_start(&http_server, &config);
    if (err != ESP_OK) {
        return err;
    }

    const httpd_uri_t handlers[] = {
        {.uri = "/", .method = HTTP_GET, .handler = index_get},
        {.uri = "/api/status", .method = HTTP_GET, .handler = status_get},
        {.uri = "/api/config", .method = HTTP_GET, .handler = config_get},
        {.uri = "/api/config", .method = HTTP_POST, .handler = config_post},
        {.uri = "/api/ble/pairing", .method = HTTP_POST, .handler = ble_pairing_post},
        {.uri = "/api/reboot", .method = HTTP_POST, .handler = reboot_post},
    };
    for (size_t i = 0; i < sizeof(handlers) / sizeof(handlers[0]); ++i) {
        err = httpd_register_uri_handler(http_server, &handlers[i]);
        if (err != ESP_OK) {
            httpd_stop(http_server);
            http_server = NULL;
            return err;
        }
    }
    return ESP_OK;
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
        touch_activity();
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

    uint8_t mac[6];
    esp_err_t err = esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    if (err != ESP_OK) {
        commissioning_start_failed("SoftAP MAC read", err);
        return;
    }
    snprintf(softap_ssid, sizeof(softap_ssid), "%s-%02X%02X",
             CONFIG_PICO_FIDO2_WIFI_SSID_PREFIX, mac[4], mac[5]);

    uint8_t csrf_random[16];
    esp_fill_random(csrf_random, sizeof(csrf_random));
    for (size_t i = 0; i < sizeof(csrf_random); ++i) {
        snprintf(csrf_token + i * 2, 3, "%02x", csrf_random[i]);
    }

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
    config.ap.max_connection = 1;
    config.ap.pmf_cfg.required = true;

    err = esp_wifi_set_mode(WIFI_MODE_AP);
    if (err == ESP_OK) {
        err = esp_wifi_set_config(WIFI_IF_AP, &config);
    }
#if CONFIG_PICO_FIDO2_BLE
    if (err == ESP_OK) {
        err = fido_ble_stop_for_commissioning();
        if (err != ESP_OK) {
            commissioning_start_failed("BLE commissioning transition", err);
            return;
        }
    }
#endif
    if (err == ESP_OK) {
        err = esp_wifi_start();
    }
    if (err != ESP_OK) {
        commissioning_start_failed("SoftAP start", err);
        return;
    }
    commissioning_started = true;
    touch_activity();

    ESP_LOGI(TAG, "commissioning AP %s started; HTTP starts after station join", softap_ssid);
}

static int fido_wifi_button_pressed(uint8_t presses) {
    if (commissioning_started) {
        if (presses == 1) {
            grant_physical_presence();
            touch_activity();
            ESP_LOGI(TAG, "physical confirmation granted for %d seconds",
                     CONFIG_PICO_FIDO2_WIFI_PRESENCE_WINDOW_SEC);
        }
        else {
            ESP_LOGI(TAG, "ignoring %u BOOT presses while maintenance mode is active",
                     (unsigned)presses);
        }
        return 0;
    }
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
    ESP_ERROR_CHECK(fido_wifi_management_init());
    fido_wifi_presence_init(
        &presence_policy,
        CONFIG_PICO_FIDO2_WIFI_PRESENCE_WINDOW_SEC * 1000U);
    previous_button_pressed_cb = button_pressed_cb;
    button_pressed_cb = fido_wifi_button_pressed;
    ESP_LOGI(TAG, "Wi-Fi off; press BOOT %d times to enter commissioning",
             CONFIG_PICO_FIDO2_WIFI_COMMISSION_PRESSES);
}

void fido_wifi_task(void) {
    fido_wifi_management_task();
    if (!commissioning_started) {
        return;
    }

    TickType_t now = xTaskGetTickCount();
    TickType_t last = __atomic_load_n(&last_activity_tick, __ATOMIC_ACQUIRE);
    bool idle_expired = now - last >= pdMS_TO_TICKS(CONFIG_PICO_FIDO2_WIFI_IDLE_TIMEOUT_SEC * 1000U);
    bool restart = __atomic_load_n(&restart_requested, __ATOMIC_ACQUIRE);
    if (!idle_expired && !restart) {
        return;
    }
    if (!card_try_claim_maintenance()) {
        return;
    }
    if (low_flash_is_pending()) {
        do_flash();
    }
    bool durable = !low_flash_is_pending();
    card_release_maintenance();
    if (!durable) {
        return;
    }

    ESP_LOGI(TAG, "%s; rebooting to normal USB/BLE mode",
             restart ? "maintenance restart requested" : "maintenance idle timeout");
    esp_restart();
}

#endif
