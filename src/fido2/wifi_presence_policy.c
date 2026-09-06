#include "wifi_presence_policy.h"

void fido_wifi_presence_init(fido_wifi_presence_policy_t *policy,
                             uint32_t duration_ms) {
    policy->granted_at_ms = 0;
    policy->duration_ms = duration_ms;
    policy->available = false;
}

void fido_wifi_presence_grant(fido_wifi_presence_policy_t *policy,
                              uint32_t now_ms) {
    policy->granted_at_ms = now_ms;
    policy->available = true;
}

bool fido_wifi_presence_is_available(fido_wifi_presence_policy_t *policy,
                                     uint32_t now_ms) {
    if (!policy->available) {
        return false;
    }
    if ((uint32_t)(now_ms - policy->granted_at_ms) >= policy->duration_ms) {
        policy->available = false;
        return false;
    }
    return true;
}

bool fido_wifi_presence_consume(fido_wifi_presence_policy_t *policy,
                                uint32_t now_ms) {
    if (!fido_wifi_presence_is_available(policy, now_ms)) {
        return false;
    }
    policy->available = false;
    return true;
}
