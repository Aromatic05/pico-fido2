#ifndef PICO_FIDO_BLE_FRAME_H
#define PICO_FIDO_BLE_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FIDO_BLE_CMD_PING       0x81
#define FIDO_BLE_CMD_KEEPALIVE  0x82
#define FIDO_BLE_CMD_MSG        0x83
#define FIDO_BLE_CMD_CANCEL     0xBE
#define FIDO_BLE_CMD_ERROR      0xBF

#define FIDO_BLE_ERR_INVALID_CMD 0x01
#define FIDO_BLE_ERR_INVALID_PAR 0x02
#define FIDO_BLE_ERR_INVALID_LEN 0x03
#define FIDO_BLE_ERR_INVALID_SEQ 0x04
#define FIDO_BLE_ERR_REQ_TIMEOUT 0x05
#define FIDO_BLE_ERR_BUSY        0x06
#define FIDO_BLE_ERR_OTHER       0x7F

#define FIDO_BLE_MAX_MESSAGE 7609

typedef struct {
    uint8_t command;
    uint8_t next_sequence;
    uint16_t expected_len;
    uint16_t received_len;
    bool active;
    uint8_t data[FIDO_BLE_MAX_MESSAGE];
} fido_ble_rx_t;

typedef struct {
    uint8_t command;
    uint8_t next_sequence;
    uint16_t total_len;
    uint16_t offset;
    bool started;
    const uint8_t *data;
} fido_ble_tx_t;

void fido_ble_rx_reset(fido_ble_rx_t *rx);
void fido_ble_rx_release(fido_ble_rx_t *rx);
int fido_ble_rx_feed(fido_ble_rx_t *rx, const uint8_t *fragment, size_t fragment_len);

void fido_ble_tx_init(fido_ble_tx_t *tx, uint8_t command, const uint8_t *data, uint16_t len);
size_t fido_ble_tx_next(fido_ble_tx_t *tx, uint8_t *fragment, size_t fragment_capacity);
bool fido_ble_tx_done(const fido_ble_tx_t *tx);

#endif
