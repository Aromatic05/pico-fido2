#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "wifi_presence_policy.h"

static void absent_presence_rejects(void) {
    fido_wifi_presence_policy_t policy;
    fido_wifi_presence_init(&policy, 15000);
    assert(!fido_wifi_presence_is_available(&policy, 100));
    assert(!fido_wifi_presence_consume(&policy, 100));
}

static void grant_is_one_shot(void) {
    fido_wifi_presence_policy_t policy;
    fido_wifi_presence_init(&policy, 15000);
    fido_wifi_presence_grant(&policy, 1000);
    assert(fido_wifi_presence_is_available(&policy, 1001));
    assert(fido_wifi_presence_consume(&policy, 2000));
    assert(!fido_wifi_presence_is_available(&policy, 2001));
    assert(!fido_wifi_presence_consume(&policy, 2001));
}

static void grant_expires_at_boundary(void) {
    fido_wifi_presence_policy_t policy;
    fido_wifi_presence_init(&policy, 15000);
    fido_wifi_presence_grant(&policy, 1000);
    assert(fido_wifi_presence_is_available(&policy, 15999));
    assert(!fido_wifi_presence_is_available(&policy, 16000));
    assert(!fido_wifi_presence_consume(&policy, 16000));
}

static void regrant_restarts_window(void) {
    fido_wifi_presence_policy_t policy;
    fido_wifi_presence_init(&policy, 100);
    fido_wifi_presence_grant(&policy, 1000);
    fido_wifi_presence_grant(&policy, 1050);
    assert(fido_wifi_presence_is_available(&policy, 1149));
    assert(!fido_wifi_presence_is_available(&policy, 1150));
}

static void wraparound_is_elapsed_time_safe(void) {
    fido_wifi_presence_policy_t policy;
    fido_wifi_presence_init(&policy, 100);
    fido_wifi_presence_grant(&policy, UINT32_MAX - 50);
    assert(fido_wifi_presence_is_available(&policy, 20));
    assert(!fido_wifi_presence_is_available(&policy, 49));
}

int main(void) {
    absent_presence_rejects();
    grant_is_one_shot();
    grant_expires_at_boundary();
    regrant_restarts_window();
    wraparound_is_elapsed_time_safe();
    puts("Wi-Fi physical presence policy: PASS");
    return 0;
}
