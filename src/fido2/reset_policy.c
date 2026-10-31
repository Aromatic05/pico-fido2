#include "openpgp/openpgp.h"

#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#if CONFIG_PICO_FIDO2_BLE
#include "ble_fido.h"
#endif
#endif

extern int openpgp_unload(void);
extern int piv_unload(void);

/* The combined product owns PIV factory identity outside FIDO's namespace.
 * Capture slot F9 before a global dynamic-store reset, while also dropping
 * any authenticated OpenPGP/PIV RAM sessions. */
int picokey_prepare_device_reset(void) {
    openpgp_reset_all_sessions();
    piv_reset_all_sessions();
    file_clear_all_authenticated_sessions();
    int r = piv_prepare_device_reset();
    if (r != PICOKEY_OK) {
        return r;
    }
#if defined(ESP_PLATFORM) && CONFIG_PICO_FIDO2_BLE
    if (fido_ble_factory_reset() != ESP_OK) {
        piv_cancel_device_reset();
        return PICOKEY_EXEC_ERROR;
    }
#endif
    return PICOKEY_OK;
}

int picokey_finish_device_reset(void) {
    return piv_restore_device_reset();
}
