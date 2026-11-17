#include "../pico-fido/src/fido/cbor_client_pin.c"
#include <assert.h>

pinUvAuthToken_t paut;
uint32_t user_present_time_limit;
static uint32_t now;

int gettimeofday(struct timeval *restrict value, void *restrict zone) {
    (void)zone;
    value->tv_sec = now / 1000;
    value->tv_usec = (now % 1000) * 1000;
    return 0;
}

int main(void) {
    now = 0;
    beginUsingPinUvAuthToken(true);
    paut.permissions = CTAP_PERMISSION_CM;
    now = 29999;
    pinUvAuthTokenUsageTimerObserver();
    assert(paut.in_use && paut.permissions == CTAP_PERMISSION_CM);
    now = 30000;
    pinUvAuthTokenUsageTimerObserver();
    assert(!paut.in_use && paut.permissions == 0);

    now = 1000;
    beginUsingPinUvAuthToken(false);
    paut.permissions = CTAP_PERMISSION_CM;
    now += max_usage_time_period;
    initial_usage_time_limit = now;
    pinUvAuthTokenUsageTimerObserver();
    assert(!paut.in_use && paut.permissions == 0);

    now = UINT32_MAX - 1000;
    beginUsingPinUvAuthToken(false);
    paut.permissions = CTAP_PERMISSION_CM;
    now += 29999;
    pinUvAuthTokenUsageTimerObserver();
    assert(paut.in_use);
    now++;
    pinUvAuthTokenUsageTimerObserver();
    assert(!paut.in_use && paut.permissions == 0);
    puts("R3-04 token initial/max expiry and clock wrap: PASS");
    return 0;
}
