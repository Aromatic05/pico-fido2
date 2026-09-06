#include "sdkconfig.h"

#if CONFIG_PICO_FIDO2_WIFI_COMMISSIONING

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_app_desc.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_flash_encrypt.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_pm.h"
#include "esp_random.h"
#include "esp_secure_boot.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"

#include "fido/management.h"
#include "fido/version.h"
#include "pico_keys.h"
#include "usb.h"
#include "wifi_captive_dns.h"
#include "wifi_management.h"
#include "wifi_presence_policy.h"
#if CONFIG_PICO_FIDO2_AB_OTA
#include "wifi_ota.h"
#endif
#if CONFIG_PICO_FIDO2_BLE
#include "ble_fido.h"
#endif

static const char *TAG = "fido_wifi";
static httpd_handle_t http_server;
static esp_netif_t *softap_netif;
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
    bool valid = strlen(header) == sizeof(csrf_token) - 1 &&
                 mbedtls_ct_memcmp(header, csrf_token, sizeof(csrf_token) - 1) == 0;
    mbedtls_platform_zeroize(header, sizeof(header));
    return valid;
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
    "<div class=card><h2>USB applications</h2><div id=apps></div><button onclick=save()>Save configuration</button></div>"
    "<div class=card><h2>Configuration lock</h2><p id=lockState class=muted></p>"
    "<div id=unlockRow style='display:none'><label>Current lock code (32 hex)<br><input id=unlock maxlength=32 autocomplete=off></label></div>"
    "<label>New lock code (32 hex)<br><input id=newLock maxlength=32 autocomplete=off></label>"
    "<label>Confirm new lock code<br><input id=confirmLock maxlength=32 autocomplete=off></label>"
    "<button onclick=changeLock(false)>Set/change lock</button><button id=clearLockButton onclick=changeLock(true)>Clear lock</button></div>"
    "<div class=card id=otaCard style='display:none'><h2>Firmware update</h2><p class=muted>Signed A/B update. Choose the signed plaintext application .bin, then press BOOT once and install within the physical confirmation window.</p>"
    "<input id=firmware type=file accept='.bin,application/octet-stream'><button id=updateButton onclick=installUpdate()>Install signed update</button><p id=otaState class=muted></p></div>"
    "<div class=card><h2>Maintenance actions</h2><button onclick=pairBle()>Allow BLE pairing</button><button onclick=resetBle()>Reset BLE bonds + pair</button><button onclick=reboot()>Restart device</button><p id=msg class=muted></p></div>"
    "<script>const caps=[['OTP',1],['U2F',2],['OpenPGP',8],['PIV',16],['OATH',32],['HSM Auth',256],['FIDO2',512],['Management',1024]];let cfg;const st=document.getElementById('status'),appBox=document.getElementById('apps'),lockRow=document.getElementById('unlockRow'),unlockInput=document.getElementById('unlock'),newLockInput=document.getElementById('newLock'),confirmLockInput=document.getElementById('confirmLock'),lockState=document.getElementById('lockState'),clearLockButton=document.getElementById('clearLockButton'),msgBox=document.getElementById('msg'),otaCard=document.getElementById('otaCard'),firmwareInput=document.getElementById('firmware'),updateButton=document.getElementById('updateButton'),otaState=document.getElementById('otaState');"
    "async function load(){const [s,c]=await Promise.all([fetch('/api/status').then(r=>r.json()),fetch('/api/config').then(r=>r.json())]);cfg=c;"
    "st.textContent=JSON.stringify(s,null,2);appBox.innerHTML='';for(const [n,b] of caps){const l=document.createElement('label');const x=document.createElement('input');x.type='checkbox';x.dataset.bit=b;x.checked=!!(c.enabled&b);x.disabled=!(c.supported&b);l.append(x,' '+n);appBox.append(l)}"
    "lockRow.style.display=c.locked?'block':'none';clearLockButton.style.display=c.locked?'inline-block':'none';lockState.textContent=c.locked?'Locked. Current lock code is required for USB changes, lock changes, or clearing.':'Unlocked. Set a 16-byte lock code to protect management changes.';const o=s.ota||{};otaCard.style.display=o.enabled?'block':'none';if(o.enabled)otaState.textContent=o.ready?`Running ${o.runningPartition}; next update slot ${o.nextPartition}; epoch ${o.securityVersion}.`:(o.confirmationPending?'New image is still in rollback verification window.':'OTA requires active Secure Boot + Flash Encryption and two OTA slots.')}"
    "async function save(){let enabled=0;for(const x of appBox.querySelectorAll('input'))if(x.checked)enabled|=+x.dataset.bit;if(!(enabled&(1|2|512|1024))){msgBox.className='bad';msgBox.textContent='Keep at least one management-capable USB transport enabled.';return}"
    "const p=new URLSearchParams({enabled:String(enabled)});if(cfg.locked)p.set('unlock',unlockInput.value.trim());const r=await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Pico-CSRF':cfg.csrf},body:p});const j=await r.json();"
    "if(!r.ok){msgBox.className='bad';msgBox.textContent=j.error||'Save failed';return}unlockInput.value='';await load();msgBox.className='ok';msgBox.textContent='Saved to flash. Restart to apply USB interface changes.'}"
    "async function changeLock(clear){const p=new URLSearchParams();if(cfg.locked)p.set('unlock',unlockInput.value.trim());if(clear){p.set('clear','1')}else{const n=newLockInput.value.trim(),c=confirmLockInput.value.trim();if(!/^[0-9a-fA-F]{32}$/.test(n)||/^0+$/.test(n)){msgBox.className='bad';msgBox.textContent='New lock must be 32 non-zero hexadecimal characters.';return}if(n.toLowerCase()!==c.toLowerCase()){msgBox.className='bad';msgBox.textContent='New lock confirmation does not match.';return}p.set('new',n)}const r=await fetch('/api/config/lock',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Pico-CSRF':cfg.csrf},body:p});const j=await r.json();if(!r.ok){msgBox.className='bad';msgBox.textContent=j.error||'Lock update failed';return}unlockInput.value='';newLockInput.value='';confirmLockInput.value='';await load();msgBox.className='ok';msgBox.textContent=clear?'Configuration lock cleared.':'Configuration lock saved.'}"
    "async function pairBle(){const r=await fetch('/api/ble/pairing',{method:'POST',headers:{'X-Pico-CSRF':cfg.csrf}});const j=await r.json();msgBox.className=r.ok?'ok':'bad';msgBox.textContent=r.ok?'BLE pairing authorized for the next window; restarting.':(j.error||'Pairing authorization failed.')}"
    "async function resetBle(){if(!confirm('Revoke every persisted BLE bond? Existing paired phones/computers will lose trust. One new pairing window will open after restart.'))return;const r=await fetch('/api/ble/bonds/reset',{method:'POST',headers:{'X-Pico-CSRF':cfg.csrf}});const j=await r.json();msgBox.className=r.ok?'ok':'bad';msgBox.textContent=r.ok?'BLE bond reset scheduled; restarting into one fresh-pairing window.':(j.error||'BLE bond reset failed.')}"
    "async function installUpdate(){const f=firmwareInput.files[0];if(!f){msgBox.className='bad';msgBox.textContent='Choose a signed application .bin first.';return}if(!confirm(`Install ${f.name} (${f.size} bytes) into the inactive slot?`))return;updateButton.disabled=true;msgBox.className='muted';msgBox.textContent='Uploading and verifying signed firmware...';try{const r=await fetch('/api/update',{method:'POST',headers:{'Content-Type':'application/octet-stream','X-Pico-CSRF':cfg.csrf},body:f});const j=await r.json();if(!r.ok){msgBox.className='bad';msgBox.textContent=j.error||'Update rejected';updateButton.disabled=false;return}msgBox.className='ok';msgBox.textContent=`Verified ${j.version}, epoch ${j.securityVersion}, in ${j.partition}; restarting.`}catch(e){msgBox.className='bad';msgBox.textContent=String(e);updateButton.disabled=false}}"
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
    const esp_app_desc_t *app_desc = esp_app_get_description();
    const esp_partition_t *running_partition = esp_ota_get_running_partition();
    uint8_t image_sha[32] = {0};
    bool image_sha_ok = running_partition != NULL &&
                        esp_partition_get_sha256(running_partition, image_sha) == ESP_OK;
    char image_sha_hex[65] = {0};
    char image_sha_json[67] = "null";
    char elf_sha_hex[65] = {0};
    for (size_t i = 0; i < 32; ++i) {
        snprintf(elf_sha_hex + i * 2, 3, "%02x", app_desc->app_elf_sha256[i]);
        if (image_sha_ok) {
            snprintf(image_sha_hex + i * 2, 3, "%02x", image_sha[i]);
        }
    }
    if (image_sha_ok) {
        snprintf(image_sha_json, sizeof(image_sha_json), "\"%s\"", image_sha_hex);
    }

    esp_pm_config_t pm = {
        .max_freq_mhz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
        .min_freq_mhz = 80,
        .light_sleep_enable = false,
    };
    bool pm_readback = esp_pm_get_configuration(&pm) == ESP_OK;
    unsigned secure_version = esp_efuse_read_secure_version();
    bool secure_boot = esp_secure_boot_enabled();
    bool flash_encryption = esp_flash_encryption_enabled();
    bool rom_download = !esp_efuse_read_field_bit(ESP_EFUSE_DIS_DOWNLOAD_MODE);
    bool usb_download = !esp_efuse_read_field_bit(
        ESP_EFUSE_DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE);

    char ota_json[320];
#if CONFIG_PICO_FIDO2_AB_OTA
    fido_ota_status_t ota_status;
    if (fido_ota_get_status(&ota_status) == ESP_OK) {
        snprintf(ota_json, sizeof(ota_json),
                 "{\"enabled\":true,\"ready\":%s,\"softwareRollback\":true,"
                 "\"confirmationPending\":%s,\"runningPartition\":\"%s\","
                 "\"nextPartition\":\"%s\",\"slotSize\":%u,\"securityVersion\":%u}",
                 ota_status.ready ? "true" : "false",
                 ota_status.confirmation_pending ? "true" : "false",
                 ota_status.running_partition != NULL ? ota_status.running_partition->label : "",
                 ota_status.next_partition != NULL ? ota_status.next_partition->label : "",
                 ota_status.next_partition != NULL ? (unsigned)ota_status.next_partition->size : 0U,
                 (unsigned)ota_status.current_epoch);
    }
    else {
        snprintf(ota_json, sizeof(ota_json),
                 "{\"enabled\":true,\"ready\":false,\"softwareRollback\":true}");
    }
#else
    snprintf(ota_json, sizeof(ota_json), "{\"enabled\":false}");
#endif

    char body[1536];
    int len = snprintf(body, sizeof(body),
        "{\"device\":\"Pico FIDO2\",\"platform\":\"ESP32-S3\","
        "\"version\":\"%u.%u\",\"ssid\":\"%s\","
        "\"ble\":%s,\"devKeys\":%s,\"idleTimeoutSec\":%u,"
        "\"freeHeap\":%u,\"largestInternal\":%u,"
        "\"firmware\":{\"project\":\"%.*s\",\"projectVersion\":\"%.*s\","
        "\"securityVersion\":%u,\"appElfSha256\":\"%s\","
        "\"imageSha256\":%s},"
        "\"security\":{\"secureBoot\":%s,\"flashEncryption\":%s,"
        "\"secureVersion\":%u,\"romDownload\":%s,"
        "\"usbSerialJtagDownload\":%s},"
        "\"power\":{\"pmReadback\":%s,\"minCpuMHz\":%d,"
        "\"maxCpuMHz\":%d,\"lightSleep\":%s},\"ota\":%s}",
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
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
        (int)sizeof(app_desc->project_name), app_desc->project_name,
        (int)sizeof(app_desc->version), app_desc->version,
        (unsigned)app_desc->secure_version,
        elf_sha_hex,
        image_sha_json,
        secure_boot ? "true" : "false",
        flash_encryption ? "true" : "false",
        secure_version,
        rom_download ? "true" : "false",
        usb_download ? "true" : "false",
        pm_readback ? "true" : "false",
        pm.min_freq_mhz,
        pm.max_freq_mhz,
        pm.light_sleep_enable ? "true" : "false",
        ota_json);
    if (len < 0 || (size_t)len >= sizeof(body)) {
        return json_response(req, "500 Internal Server Error",
                             "{\"error\":\"status encoding overflow\"}");
    }
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

static bool parse_lock_parameter(const char *body, const char *key,
                                 uint8_t lock[MAN_CONFIG_LOCK_LEN], bool *present) {
    char value[MAN_CONFIG_LOCK_LEN * 2 + 1];
    if (httpd_query_key_value(body, key, value, sizeof(value)) != ESP_OK) {
        *present = false;
        return true;
    }
    if (strlen(value) != MAN_CONFIG_LOCK_LEN * 2) {
        mbedtls_platform_zeroize(value, sizeof(value));
        return false;
    }
    for (size_t i = 0; i < MAN_CONFIG_LOCK_LEN; ++i) {
        int high = hex_nibble(value[i * 2]);
        int low = hex_nibble(value[i * 2 + 1]);
        if (high < 0 || low < 0) {
            mbedtls_platform_zeroize(value, sizeof(value));
            return false;
        }
        lock[i] = (uint8_t)((high << 4) | low);
    }
    mbedtls_platform_zeroize(value, sizeof(value));
    *present = true;
    return true;
}

static bool lock_all_zero(const uint8_t lock[MAN_CONFIG_LOCK_LEN]) {
    uint8_t combined = 0;
    for (size_t i = 0; i < MAN_CONFIG_LOCK_LEN; ++i) {
        combined |= lock[i];
    }
    return combined == 0;
}

static esp_err_t config_post(httpd_req_t *req) {
    touch_activity();
    if (!csrf_valid(req)) {
        return json_response(req, "403 Forbidden", "{\"error\":\"invalid session token\"}");
    }
    char body[128];
    if (read_form_body(req, body, sizeof(body)) != ESP_OK) {
        mbedtls_platform_zeroize(body, sizeof(body));
        return json_response(req, "400 Bad Request", "{\"error\":\"invalid request body\"}");
    }

    uint16_t enabled = 0;
    uint8_t unlock[MAN_CONFIG_LOCK_LEN] = {0};
    bool unlock_present = false;
    if (!parse_enabled(body, &enabled) ||
        !parse_lock_parameter(body, "unlock", unlock, &unlock_present)) {
        mbedtls_platform_zeroize(body, sizeof(body));
        mbedtls_platform_zeroize(unlock, sizeof(unlock));
        return json_response(req, "400 Bad Request", "{\"error\":\"invalid configuration\"}");
    }
    mbedtls_platform_zeroize(body, sizeof(body));
    if (!consume_physical_presence()) {
        mbedtls_platform_zeroize(unlock, sizeof(unlock));
        return json_response(req, "428 Precondition Required",
                             "{\"error\":\"press BOOT once, then retry within the physical confirmation window\"}");
    }

    uint16_t status_word = 0;
    fido_wifi_management_state_t state;
    esp_err_t err = fido_wifi_management_set_enabled(
        enabled, unlock, unlock_present, &status_word, &state);
    mbedtls_platform_zeroize(unlock, sizeof(unlock));
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

static esp_err_t config_lock_post(httpd_req_t *req) {
    touch_activity();
    if (!csrf_valid(req)) {
        return json_response(req, "403 Forbidden", "{\"error\":\"invalid session token\"}");
    }

    char body[192];
    if (read_form_body(req, body, sizeof(body)) != ESP_OK) {
        mbedtls_platform_zeroize(body, sizeof(body));
        return json_response(req, "400 Bad Request", "{\"error\":\"invalid request body\"}");
    }

    uint8_t unlock[MAN_CONFIG_LOCK_LEN] = {0};
    uint8_t new_lock[MAN_CONFIG_LOCK_LEN] = {0};
    bool unlock_present = false;
    bool new_lock_present = false;
    char clear_value[4] = {0};
    bool clear = httpd_query_key_value(body, "clear", clear_value,
                                       sizeof(clear_value)) == ESP_OK &&
                 strcmp(clear_value, "1") == 0;
    bool parsed = parse_lock_parameter(body, "unlock", unlock, &unlock_present) &&
                  parse_lock_parameter(body, "new", new_lock, &new_lock_present);
    mbedtls_platform_zeroize(body, sizeof(body));
    if (!parsed || clear == new_lock_present ||
        (new_lock_present && lock_all_zero(new_lock))) {
        mbedtls_platform_zeroize(unlock, sizeof(unlock));
        mbedtls_platform_zeroize(new_lock, sizeof(new_lock));
        return json_response(req, "400 Bad Request", "{\"error\":\"invalid lock update\"}");
    }
    if (!consume_physical_presence()) {
        mbedtls_platform_zeroize(unlock, sizeof(unlock));
        mbedtls_platform_zeroize(new_lock, sizeof(new_lock));
        return json_response(req, "428 Precondition Required",
                             "{\"error\":\"press BOOT once, then retry within the physical confirmation window\"}");
    }

    uint16_t status_word = 0;
    fido_wifi_management_state_t state;
    esp_err_t err = fido_wifi_management_set_lock(
        unlock, unlock_present, new_lock, &status_word, &state);
    mbedtls_platform_zeroize(unlock, sizeof(unlock));
    mbedtls_platform_zeroize(new_lock, sizeof(new_lock));
    if (err != ESP_OK) {
        return management_transport_error(req, err);
    }
    if (status_word == MAN_SW_SECURITY_STATUS_NOT_SATISFIED) {
        return json_response(req, "403 Forbidden", "{\"error\":\"configuration lock rejected\"}");
    }
    if (status_word != MAN_SW_OK) {
        return json_response(req, "400 Bad Request", "{\"error\":\"lock update rejected\"}");
    }

    return json_response(req, "200 OK",
                         state.locked ? "{\"ok\":true,\"locked\":true}" :
                                        "{\"ok\":true,\"locked\":false}");
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

static esp_err_t ble_bond_reset_post(httpd_req_t *req) {
    touch_activity();
    if (!csrf_valid(req)) {
        return json_response(req, "403 Forbidden", "{\"error\":\"invalid session token\"}");
    }
    if (!consume_physical_presence()) {
        return json_response(req, "428 Precondition Required",
                             "{\"error\":\"press BOOT once, then retry within the physical confirmation window\"}");
    }
    esp_err_t err = fido_wifi_management_reset_ble_bonds();
    if (err != ESP_OK) {
        return management_transport_error(req, err);
    }
    char response[80];
    snprintf(response, sizeof(response),
             "{\"ok\":true,\"pairingWindowSec\":%u,\"resetBonds\":true}",
             (unsigned)CONFIG_PICO_FIDO2_BLE_PAIRING_WINDOW_SEC);
    err = json_response(req, "202 Accepted", response);
    if (err == ESP_OK) {
        __atomic_store_n(&restart_requested, true, __ATOMIC_RELEASE);
    }
    return err;
}

#if CONFIG_PICO_FIDO2_AB_OTA
static esp_err_t ota_error_response(httpd_req_t *req, esp_err_t err,
                                    fido_ota_policy_result_t policy) {
    if (policy == FIDO_OTA_POLICY_DOWNGRADE) {
        return json_response(req, "409 Conflict",
                             "{\"error\":\"signed firmware epoch is older than the running image\"}");
    }
    if (policy == FIDO_OTA_POLICY_PROJECT_MISMATCH) {
        return json_response(req, "400 Bad Request",
                             "{\"error\":\"signed firmware is for a different project\"}");
    }
    if (policy == FIDO_OTA_POLICY_INVALID_EPOCH) {
        return json_response(req, "400 Bad Request",
                             "{\"error\":\"signed firmware epoch is outside the supported range\"}");
    }
    if (policy == FIDO_OTA_POLICY_INVALID_SIZE || err == ESP_ERR_INVALID_SIZE) {
        return json_response(req, "413 Payload Too Large",
                             "{\"error\":\"firmware image does not fit the inactive slot\"}");
    }
    if (err == ESP_ERR_OTA_VALIDATE_FAILED) {
        return json_response(req, "400 Bad Request",
                             "{\"error\":\"firmware image or Secure Boot signature validation failed\"}");
    }
    if (err == ESP_ERR_INVALID_STATE || err == ESP_ERR_OTA_ROLLBACK_INVALID_STATE ||
        err == ESP_ERR_OTA_PARTITION_CONFLICT) {
        return json_response(req, "409 Conflict",
                             "{\"error\":\"A/B update is not ready or the device is busy\"}");
    }
    return json_response(req, "500 Internal Server Error",
                         "{\"error\":\"firmware update failed\"}");
}

static esp_err_t update_post(httpd_req_t *req) {
    touch_activity();
    if (!csrf_valid(req)) {
        return json_response(req, "403 Forbidden", "{\"error\":\"invalid session token\"}");
    }
    if (req->content_len <= 0) {
        return json_response(req, "400 Bad Request", "{\"error\":\"empty firmware image\"}");
    }
    if (!consume_physical_presence()) {
        return json_response(req, "428 Precondition Required",
                             "{\"error\":\"choose the update, press BOOT once, then retry within the physical confirmation window\"}");
    }

    uint8_t *chunk = malloc(2048);
    if (chunk == NULL) {
        return json_response(req, "503 Service Unavailable",
                             "{\"error\":\"insufficient memory for update buffer\"}");
    }

    fido_ota_session_t session;
    fido_ota_policy_result_t policy = FIDO_OTA_POLICY_OK;
    esp_err_t err = fido_ota_begin(&session, (size_t)req->content_len);
    if (err != ESP_OK) {
        free(chunk);
        return ota_error_response(req, err, policy);
    }

    size_t remaining = (size_t)req->content_len;
    while (remaining > 0) {
        size_t wanted = remaining < 2048 ? remaining : 2048;
        int received = httpd_req_recv(req, (char *)chunk, wanted);
        if (received <= 0) {
            fido_ota_abort(&session);
            free(chunk);
            return json_response(req, "408 Request Timeout",
                                 "{\"error\":\"firmware upload was interrupted\"}");
        }
        err = fido_ota_write(&session, chunk, (size_t)received);
        if (err != ESP_OK) {
            fido_ota_abort(&session);
            free(chunk);
            return ota_error_response(req, err, policy);
        }
        remaining -= (size_t)received;
        touch_activity();
    }
    free(chunk);

    fido_ota_result_t result;
    err = fido_ota_finish(&session, &result, &policy);
    if (err != ESP_OK) {
        return ota_error_response(req, err, policy);
    }

    char response[192];
    int len = snprintf(response, sizeof(response),
                       "{\"ok\":true,\"partition\":\"%s\",\"version\":\"%.31s\","
                       "\"securityVersion\":%u,\"bytes\":%u}",
                       result.partition->label, result.app_desc.version,
                       (unsigned)result.app_desc.secure_version,
                       (unsigned)result.image_size);
    if (len < 0 || (size_t)len >= sizeof(response)) {
        __atomic_store_n(&restart_requested, true, __ATOMIC_RELEASE);
        return json_response(req, "500 Internal Server Error",
                             "{\"error\":\"update installed but response encoding failed; device will restart\"}");
    }
    esp_err_t response_err = json_response(req, "202 Accepted", response);
    __atomic_store_n(&restart_requested, true, __ATOMIC_RELEASE);
    return response_err;
}
#endif

static esp_err_t start_http_server(void) {
    if (http_server != NULL) {
        return ESP_OK;
    }
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.max_open_sockets = 2;
    config.max_uri_handlers = 10;
    config.backlog_conn = 1;
    config.uri_match_fn = httpd_uri_match_wildcard;
    esp_err_t err = httpd_start(&http_server, &config);
    if (err != ESP_OK) {
        return err;
    }

    const httpd_uri_t handlers[] = {
        {.uri = "/", .method = HTTP_GET, .handler = index_get},
        {.uri = "/api/status", .method = HTTP_GET, .handler = status_get},
        {.uri = "/api/config", .method = HTTP_GET, .handler = config_get},
        {.uri = "/api/config", .method = HTTP_POST, .handler = config_post},
        {.uri = "/api/config/lock", .method = HTTP_POST, .handler = config_lock_post},
        {.uri = "/api/ble/pairing", .method = HTTP_POST, .handler = ble_pairing_post},
        {.uri = "/api/ble/bonds/reset", .method = HTTP_POST, .handler = ble_bond_reset_post},
        {.uri = "/api/reboot", .method = HTTP_POST, .handler = reboot_post},
#if CONFIG_PICO_FIDO2_AB_OTA
        {.uri = "/api/update", .method = HTTP_POST, .handler = update_post},
#endif
        {.uri = "/*", .method = HTTP_GET, .handler = index_get},
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
        fido_wifi_captive_dns_close();
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
    softap_netif = esp_netif_create_default_wifi_ap();
    if (softap_netif == NULL) {
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

    esp_netif_ip_info_t ip_info;
    err = esp_netif_get_ip_info(softap_netif, &ip_info);
    if (err == ESP_OK) {
        const uint8_t captive_ip[4] = {
            esp_ip4_addr1(&ip_info.ip),
            esp_ip4_addr2(&ip_info.ip),
            esp_ip4_addr3(&ip_info.ip),
            esp_ip4_addr4(&ip_info.ip),
        };
        esp_err_t dns_err = fido_wifi_captive_dns_open(captive_ip);
        if (dns_err != ESP_OK) {
            ESP_LOGW(TAG, "captive DNS unavailable: %s", esp_err_to_name(dns_err));
        }
    }
    else {
        ESP_LOGW(TAG, "SoftAP IP readback failed: %s", esp_err_to_name(err));
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

    fido_wifi_captive_dns_poll();

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
    fido_wifi_captive_dns_close();
    esp_restart();
}

#endif
