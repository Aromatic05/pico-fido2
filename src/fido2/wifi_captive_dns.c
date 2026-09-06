#include "wifi_captive_dns.h"

#include <stdbool.h>
#include <string.h>

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void write_be16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void write_be32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static size_t question_end(const uint8_t *request, size_t request_len) {
    size_t pos = 12;
    while (pos < request_len) {
        uint8_t label_len = request[pos++];
        if (label_len == 0) {
            return pos + 4 <= request_len ? pos + 4 : 0;
        }
        if ((label_len & 0xc0) != 0 || label_len > 63 ||
            pos > request_len || request_len - pos < label_len) {
            return 0;
        }
        pos += label_len;
    }
    return 0;
}

size_t fido_wifi_dns_build_response(
    const uint8_t *request,
    size_t request_len,
    const uint8_t ipv4[4],
    uint8_t *response,
    size_t response_capacity) {
    if (request == NULL || ipv4 == NULL || response == NULL || request_len < 12 ||
        response_capacity < 12) {
        return 0;
    }

    uint16_t flags = read_be16(request + 2);
    uint16_t qdcount = read_be16(request + 4);
    if ((flags & 0x8000U) != 0 || (flags & 0x7800U) != 0 || qdcount != 1) {
        return 0;
    }

    size_t qend = question_end(request, request_len);
    if (qend == 0) {
        return 0;
    }
    uint16_t qtype = read_be16(request + qend - 4);
    uint16_t qclass = read_be16(request + qend - 2);
    bool answer_a = qclass == 1 && (qtype == 1 || qtype == 255);
    size_t answer_len = answer_a ? 16 : 0;
    size_t required = qend + answer_len;
    if (required > response_capacity) {
        return 0;
    }

    memcpy(response, request, qend);
    uint16_t response_flags = 0x8400U | (flags & 0x0100U);
    write_be16(response + 2, response_flags);
    write_be16(response + 4, 1);
    write_be16(response + 6, answer_a ? 1 : 0);
    write_be16(response + 8, 0);
    write_be16(response + 10, 0);

    if (!answer_a) {
        return qend;
    }

    uint8_t *answer = response + qend;
    answer[0] = 0xc0;
    answer[1] = 0x0c;
    write_be16(answer + 2, 1);
    write_be16(answer + 4, 1);
    write_be32(answer + 6, 30);
    write_be16(answer + 10, 4);
    memcpy(answer + 12, ipv4, 4);
    return required;
}

#ifdef ESP_PLATFORM

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "esp_log.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

#define DNS_PORT 53
#define DNS_PACKET_MAX 512
#define DNS_POLL_BUDGET 4

static const char *TAG = "fido_dns";
static int dns_socket = -1;
static uint8_t dns_ipv4[4];

esp_err_t fido_wifi_captive_dns_open(const uint8_t ipv4[4]) {
    if (ipv4 == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (dns_socket >= 0) {
        memcpy(dns_ipv4, ipv4, sizeof(dns_ipv4));
        return ESP_OK;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return ESP_FAIL;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return ESP_FAIL;
    }

    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        close(fd);
        return ESP_FAIL;
    }

    memcpy(dns_ipv4, ipv4, sizeof(dns_ipv4));
    dns_socket = fd;
    ESP_LOGI(TAG, "captive DNS listening on UDP/%d", DNS_PORT);
    return ESP_OK;
}

void fido_wifi_captive_dns_poll(void) {
    if (dns_socket < 0) {
        return;
    }
    for (int i = 0; i < DNS_POLL_BUDGET; ++i) {
        uint8_t request[DNS_PACKET_MAX];
        uint8_t response[DNS_PACKET_MAX + 16];
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        ssize_t received = recvfrom(dns_socket, request, sizeof(request), 0,
                                    (struct sockaddr *)&peer, &peer_len);
        if (received < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ESP_LOGW(TAG, "DNS recv failed: errno=%d", errno);
            }
            return;
        }

        size_t response_len = fido_wifi_dns_build_response(
            request, (size_t)received, dns_ipv4, response, sizeof(response));
        if (response_len == 0) {
            continue;
        }
        ssize_t sent = sendto(dns_socket, response, response_len, 0,
                              (struct sockaddr *)&peer, peer_len);
        if (sent < 0) {
            ESP_LOGW(TAG, "DNS send failed: errno=%d", errno);
        }
    }
}

void fido_wifi_captive_dns_close(void) {
    if (dns_socket >= 0) {
        close(dns_socket);
        dns_socket = -1;
    }
}

#endif
