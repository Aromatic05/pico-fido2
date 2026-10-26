#include "sdkconfig.h"

#if CONFIG_PICO_FIDO2_BLE || CONFIG_PICO_FIDO2_WIFI_COMMISSIONING

#include "esp_err.h"
#include "nvs_flash.h"

void fido_ble_init(void);
void fido_ble_task(void);
void fido_wifi_init(void);
void fido_wifi_task(void);

static void transport_nvs_init(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
}

void picokey_extra_transport_init(void) {
    transport_nvs_init();
#if CONFIG_PICO_FIDO2_BLE
    fido_ble_init();
#endif
#if CONFIG_PICO_FIDO2_WIFI_COMMISSIONING
    fido_wifi_init();
#endif
}

void picokey_extra_transport_task(void) {
#if CONFIG_PICO_FIDO2_BLE
    fido_ble_task();
#endif
#if CONFIG_PICO_FIDO2_WIFI_COMMISSIONING
    fido_wifi_task();
#endif
}

#endif
