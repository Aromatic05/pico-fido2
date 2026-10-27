#include "sdkconfig.h"

#if CONFIG_PICO_FIDO2_BLE || CONFIG_PICO_FIDO2_WIFI_COMMISSIONING || CONFIG_PICO_FIDO2_AB_OTA || CONFIG_PICO_FIDO2_QEMU_RESET_SELFTEST

#include "esp_err.h"
#include "nvs_flash.h"
#include "phy.h"
#if CONFIG_PICO_FIDO2_BLE
#include "esp_log.h"
#include "pico_keys.h"
#include "usb.h"
#include "fido/fido.h"
#endif

void fido_ble_init(void);
void fido_ble_task(void);
void fido_wifi_init(void);
void fido_wifi_task(void);
#if CONFIG_PICO_FIDO2_AB_OTA
#include "wifi_ota.h"
#endif
#if CONFIG_PICO_FIDO2_QEMU_RESET_SELFTEST
void fido_reset_qemu_selftest_task(void);
#endif
#if CONFIG_PICO_FIDO2_QEMU_OTA_STATE_SELFTEST
void fido_ota_state_qemu_selftest_task(void);
#endif

static void transport_nvs_init(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
}

#if CONFIG_PICO_FIDO2_BLE
/* USB HID CTAPHID_INIT is not a prerequisite for BLE FIDO. Initialize FIDO
 * once from core0 before servicing BLE requests, under the shared card claim.
 * A concurrent USB INIT may have already performed the same initialization. */
static bool ble_fido_bootstrap_attempted;
static bool ble_fido_bootstrap_failed;
static uint32_t ble_fido_bootstrap_last_ms;

static void ble_fido_bootstrap(void) {
    if (ble_fido_bootstrap_attempted) {
        return;
    }
    if (fido_is_ready()) {
        ble_fido_bootstrap_attempted = true;
        return;
    }
    /* Flash/NVS can temporarily fail at boot. Keep retry possible, with a
     * bounded rate rather than turning a transient error into permanent 0x21. */
    if (ble_fido_bootstrap_failed &&
        (uint32_t)(board_millis() - ble_fido_bootstrap_last_ms) < 1000U) {
        return;
    }
    if (!card_try_claim_maintenance()) {
        return; /* A USB command owns the device: retry on the next tick. */
    }
    ble_fido_bootstrap_last_ms = board_millis();
    int ret = init_fido();
    card_release_maintenance();
    if (ret == PICOKEY_OK) {
        ble_fido_bootstrap_attempted = true;
        ble_fido_bootstrap_failed = false;
    } else {
        ble_fido_bootstrap_failed = true;
        ESP_LOGE("fido_ble", "cold-start FIDO initialization failed: %d", ret);
    }
}
#endif

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
#if CONFIG_PICO_FIDO2_QEMU_RESET_SELFTEST
    fido_reset_qemu_selftest_task();
#endif
#if CONFIG_PICO_FIDO2_QEMU_OTA_STATE_SELFTEST
    fido_ota_state_qemu_selftest_task();
#endif
#if CONFIG_PICO_FIDO2_BLE
    ble_fido_bootstrap();
    fido_ble_task();
#endif
#if CONFIG_PICO_FIDO2_WIFI_COMMISSIONING
    fido_wifi_task();
#endif
#if CONFIG_PICO_FIDO2_AB_OTA
    fido_ota_boot_confirm_task();
#endif
}

#endif
