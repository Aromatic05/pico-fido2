#ifndef PICO_FIDO2_WIFI_CAPTIVE_DNS_H
#define PICO_FIDO2_WIFI_CAPTIVE_DNS_H

#include <stddef.h>
#include <stdint.h>

size_t fido_wifi_dns_build_response(
    const uint8_t *request,
    size_t request_len,
    const uint8_t ipv4[4],
    uint8_t *response,
    size_t response_capacity);

#ifdef ESP_PLATFORM
#include "esp_err.h"
esp_err_t fido_wifi_captive_dns_open(const uint8_t ipv4[4]);
void fido_wifi_captive_dns_poll(void);
void fido_wifi_captive_dns_close(void);
#endif

#endif
