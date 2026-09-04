#include "ble_fido_frame.h"

#include <string.h>

void fido_ble_rx_reset(fido_ble_rx_t *rx) {
    memset(rx, 0, sizeof(*rx));
}

int fido_ble_rx_feed(fido_ble_rx_t *rx, const uint8_t *fragment, size_t fragment_len) {
    if (fragment_len == 0) {
        return -FIDO_BLE_ERR_INVALID_LEN;
    }

    if (fragment[0] & 0x80) {
        if (rx->active) {
            return -FIDO_BLE_ERR_BUSY;
        }
        if (fragment_len < 3) {
            return -FIDO_BLE_ERR_INVALID_LEN;
        }
        uint16_t expected = ((uint16_t)fragment[1] << 8) | fragment[2];
        size_t payload_len = fragment_len - 3;
        if (expected > FIDO_BLE_MAX_MESSAGE || payload_len > expected) {
            return -FIDO_BLE_ERR_INVALID_LEN;
        }
        rx->command = fragment[0];
        rx->next_sequence = 0;
        rx->expected_len = expected;
        rx->received_len = (uint16_t)payload_len;
        rx->active = payload_len < expected;
        if (payload_len) {
            memcpy(rx->data, fragment + 3, payload_len);
        }
        return rx->active ? 0 : 1;
    }

    if (!rx->active || fragment[0] != rx->next_sequence) {
        return -FIDO_BLE_ERR_INVALID_SEQ;
    }

    size_t payload_len = fragment_len - 1;
    size_t remaining = rx->expected_len - rx->received_len;
    if (payload_len > remaining) {
        fido_ble_rx_reset(rx);
        return -FIDO_BLE_ERR_INVALID_LEN;
    }
    if (payload_len) {
        memcpy(rx->data + rx->received_len, fragment + 1, payload_len);
    }
    rx->received_len += (uint16_t)payload_len;
    rx->next_sequence = (uint8_t)((rx->next_sequence + 1) & 0x7f);
    if (rx->received_len == rx->expected_len) {
        rx->active = false;
        return 1;
    }
    return 0;
}

void fido_ble_tx_init(fido_ble_tx_t *tx, uint8_t command, const uint8_t *data, uint16_t len) {
    tx->command = command;
    tx->next_sequence = 0;
    tx->total_len = len;
    tx->offset = 0;
    tx->started = false;
    tx->data = data;
}

size_t fido_ble_tx_next(fido_ble_tx_t *tx, uint8_t *fragment, size_t fragment_capacity) {
    if (fido_ble_tx_done(tx) || fragment_capacity < 3) {
        return 0;
    }

    size_t header_len;
    if (!tx->started) {
        fragment[0] = tx->command;
        fragment[1] = (uint8_t)(tx->total_len >> 8);
        fragment[2] = (uint8_t)tx->total_len;
        header_len = 3;
        tx->started = true;
    }
    else {
        fragment[0] = tx->next_sequence;
        tx->next_sequence = (uint8_t)((tx->next_sequence + 1) & 0x7f);
        header_len = 1;
    }

    size_t remaining = tx->total_len - tx->offset;
    size_t payload_capacity = fragment_capacity - header_len;
    size_t payload_len = remaining < payload_capacity ? remaining : payload_capacity;
    if (payload_len) {
        memcpy(fragment + header_len, tx->data + tx->offset, payload_len);
    }
    tx->offset += (uint16_t)payload_len;
    return header_len + payload_len;
}

bool fido_ble_tx_done(const fido_ble_tx_t *tx) {
    return tx->started && tx->offset >= tx->total_len;
}
