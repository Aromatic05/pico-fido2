#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wifi_captive_dns.h"

static size_t make_query(uint8_t *out, size_t capacity, uint16_t type) {
    static const uint8_t name[] = {
        7, 'e','x','a','m','p','l','e',
        3, 'c','o','m',
        0,
    };
    size_t required = 12 + sizeof(name) + 4;
    assert(capacity >= required);
    memset(out, 0, required);
    out[0] = 0x12; out[1] = 0x34;
    out[2] = 0x01; out[3] = 0x00;
    out[4] = 0x00; out[5] = 0x01;
    memcpy(out + 12, name, sizeof(name));
    size_t p = 12 + sizeof(name);
    out[p] = (uint8_t)(type >> 8); out[p + 1] = (uint8_t)type;
    out[p + 2] = 0x00; out[p + 3] = 0x01;
    return required;
}

static void a_query_redirects_to_softap(void) {
    uint8_t request[128], response[160];
    const uint8_t ip[4] = {192, 168, 4, 1};
    size_t request_len = make_query(request, sizeof(request), 1);
    size_t n = fido_wifi_dns_build_response(
        request, request_len, ip, response, sizeof(response));
    assert(n == request_len + 16);
    assert(response[0] == 0x12 && response[1] == 0x34);
    assert(response[2] == 0x85 && response[3] == 0x00);
    assert(response[4] == 0x00 && response[5] == 0x01);
    assert(response[6] == 0x00 && response[7] == 0x01);
    assert(response[request_len] == 0xc0 && response[request_len + 1] == 0x0c);
    assert(response[request_len + 2] == 0x00 && response[request_len + 3] == 0x01);
    assert(memcmp(response + n - 4, ip, 4) == 0);
}

static void any_query_gets_a_answer(void) {
    uint8_t request[128], response[160];
    const uint8_t ip[4] = {10, 0, 0, 1};
    size_t request_len = make_query(request, sizeof(request), 255);
    size_t n = fido_wifi_dns_build_response(
        request, request_len, ip, response, sizeof(response));
    assert(n == request_len + 16);
    assert(response[6] == 0x00 && response[7] == 0x01);
    assert(memcmp(response + n - 4, ip, 4) == 0);
}

static void aaaa_query_is_noerror_without_fake_aaaa(void) {
    uint8_t request[128], response[160];
    const uint8_t ip[4] = {192, 168, 4, 1};
    size_t request_len = make_query(request, sizeof(request), 28);
    size_t n = fido_wifi_dns_build_response(
        request, request_len, ip, response, sizeof(response));
    assert(n == request_len);
    assert(response[6] == 0x00 && response[7] == 0x00);
    assert(response[2] == 0x85 && response[3] == 0x00);
}

static void malformed_queries_are_rejected(void) {
    uint8_t request[128], response[160];
    const uint8_t ip[4] = {192, 168, 4, 1};
    size_t n = make_query(request, sizeof(request), 1);
    assert(fido_wifi_dns_build_response(request, 11, ip, response, sizeof(response)) == 0);
    request[2] |= 0x80;
    assert(fido_wifi_dns_build_response(request, n, ip, response, sizeof(response)) == 0);
    request[2] &= (uint8_t)~0x80;
    request[4] = 0; request[5] = 2;
    assert(fido_wifi_dns_build_response(request, n, ip, response, sizeof(response)) == 0);
    request[4] = 0; request[5] = 1;
    request[12] = 0xc0;
    assert(fido_wifi_dns_build_response(request, n, ip, response, sizeof(response)) == 0);
}

static void short_response_buffer_is_rejected(void) {
    uint8_t request[128], response[32];
    const uint8_t ip[4] = {192, 168, 4, 1};
    size_t n = make_query(request, sizeof(request), 1);
    assert(fido_wifi_dns_build_response(request, n, ip, response, sizeof(response)) == 0);
}

int main(void) {
    a_query_redirects_to_softap();
    any_query_gets_a_answer();
    aaaa_query_is_noerror_without_fake_aaaa();
    malformed_queries_are_rejected();
    short_response_buffer_is_rejected();
    puts("Wi-Fi captive DNS framing: PASS");
    return 0;
}
