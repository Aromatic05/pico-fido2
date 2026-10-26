#ifndef PICO_FIDO2_WIFI_PRESENCE_POLICY_H
#define PICO_FIDO2_WIFI_PRESENCE_POLICY_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t granted_at_ms;
    uint32_t duration_ms;
    bool available;
} fido_wifi_presence_policy_t;

void fido_wifi_presence_init(fido_wifi_presence_policy_t *policy,
                             uint32_t duration_ms);
void fido_wifi_presence_grant(fido_wifi_presence_policy_t *policy,
                              uint32_t now_ms);
bool fido_wifi_presence_is_available(fido_wifi_presence_policy_t *policy,
                                     uint32_t now_ms);
bool fido_wifi_presence_consume(fido_wifi_presence_policy_t *policy,
                                uint32_t now_ms);

#endif
