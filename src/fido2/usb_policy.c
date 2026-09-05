#include "fido/management.h"
#include "fido/management_usb.h"
#include "usb.h"

uint8_t picokey_usb_interface_policy(uint8_t configured) {
    uint16_t enabled = 0;
    bool management_configured = false;
    if (man_get_usb_config(&enabled, &management_configured) != 0 ||
        !management_configured) {
        return configured;
    }
    return man_usb_interfaces_for_caps(enabled);
}
