#include "fido/management.h"
#include "fido/management_usb.h"
#include "fido/version.h"
#include "usb.h"

uint8_t picokey_usb_interface_policy(uint8_t configured) {
    uint16_t enabled = 0;
    bool management_configured = false;
    if (man_get_usb_config(&enabled, &management_configured) != 0 ||
        !management_configured) {
        return configured & ~PHY_USB_ITF_WCID;
    }
    return man_usb_interfaces_for_caps(enabled) & ~PHY_USB_ITF_WCID;
}

void picokey_usb_identity_policy(uint8_t enabled_usb_itf, uint16_t *vid, uint16_t *pid) {
    uint16_t yubikey_interfaces = 0;

    if (enabled_usb_itf & PHY_USB_ITF_KB) {
        yubikey_interfaces |= 0x01;
    }
    if (enabled_usb_itf & PHY_USB_ITF_HID) {
        yubikey_interfaces |= 0x02;
    }
    if (enabled_usb_itf & PHY_USB_ITF_CCID) {
        yubikey_interfaces |= 0x04;
    }

    *vid = 0x1050;
    *pid = 0x0400 | yubikey_interfaces;
}

uint16_t picokey_usb_device_version_policy(uint16_t configured) {
    (void)configured;
    return (uint16_t)((PICO_FIDO_DEVICE_VERSION_MAJOR << 8) |
                      (PICO_FIDO_DEVICE_VERSION_MINOR << 4));
}
