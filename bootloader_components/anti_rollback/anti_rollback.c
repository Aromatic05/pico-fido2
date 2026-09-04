#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bootloader_utility.h"
#include "esp_app_desc.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_log.h"

#define PICO_FIDO2_SECURE_VERSION_BITS 16

static const char *TAG = "pico_rollback";

// ESP-IDF 5.5 bootloader_support private API. The implementation is already
// linked by the stock bootloader; declaring the narrow read primitive here
// avoids importing the private SPI flash header dependency graph.
esp_err_t bootloader_flash_read(size_t src, void *dest, size_t size, bool allow_decrypt);

__attribute__((noreturn))
void __real_bootloader_utility_load_boot_image(const bootloader_state_t *bs, int start_index);

static uint32_t pico_fido2_read_security_floor(void)
{
    uint32_t raw = 0;
    size_t field_size = esp_efuse_get_field_size(ESP_EFUSE_SECURE_VERSION);
    if (field_size < PICO_FIDO2_SECURE_VERSION_BITS) {
        ESP_LOGE(TAG, "SECURE_VERSION field is only %u bits", (unsigned)field_size);
        bootloader_reset();
    }
    if (esp_efuse_read_field_blob(ESP_EFUSE_SECURE_VERSION, &raw,
                                  PICO_FIDO2_SECURE_VERSION_BITS) != ESP_OK) {
        ESP_LOGE(TAG, "failed to read SECURE_VERSION eFuse");
        bootloader_reset();
    }
    return (uint32_t)__builtin_popcount(raw & 0xFFFFu);
}

static void pico_fido2_check_single_slot_version(const bootloader_state_t *bs, int start_index)
{
    if (start_index != FACTORY_INDEX || bs->factory.offset == 0 ||
        bs->app_count != 0 || bs->test.offset != 0) {
        ESP_LOGE(TAG, "single-slot anti-rollback requires factory-only partition layout");
        bootloader_reset();
    }

    const uint32_t app_desc_offset = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t);
    esp_app_desc_t app_desc = {0};
    if (bootloader_flash_read(bs->factory.offset + app_desc_offset, &app_desc,
                              sizeof(app_desc), true) != ESP_OK) {
        ESP_LOGE(TAG, "failed to read factory application descriptor");
        bootloader_reset();
    }
    if (app_desc.magic_word != ESP_APP_DESC_MAGIC_WORD) {
        ESP_LOGE(TAG, "factory application descriptor is invalid");
        bootloader_reset();
    }
    if (app_desc.secure_version > PICO_FIDO2_SECURE_VERSION_BITS) {
        ESP_LOGE(TAG, "factory application security version is out of range");
        bootloader_reset();
    }

    uint32_t floor = pico_fido2_read_security_floor();
    ESP_LOGI(TAG, "security floor=%" PRIu32 ", image=%" PRIu32,
             floor, app_desc.secure_version);
    if (app_desc.secure_version < floor) {
        ESP_LOGE(TAG, "rejecting rolled-back factory image");
        bootloader_reset();
    }
}

__attribute__((noreturn))
void __wrap_bootloader_utility_load_boot_image(const bootloader_state_t *bs, int start_index)
{
#if CONFIG_PICO_FIDO2_SINGLE_SLOT_ANTI_ROLLBACK
    pico_fido2_check_single_slot_version(bs, start_index);
#endif
    __real_bootloader_utility_load_boot_image(bs, start_index);
}
