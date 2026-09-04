#include "ble_fido_frame.h"

#include <assert.h>
#include <string.h>

static void test_single_fragment(void) {
    fido_ble_rx_t rx;
    fido_ble_rx_reset(&rx);
    const uint8_t frame[] = {FIDO_BLE_CMD_MSG, 0, 3, 1, 2, 3};
    assert(fido_ble_rx_feed(&rx, frame, sizeof(frame)) == 1);
    assert(rx.command == FIDO_BLE_CMD_MSG);
    assert(rx.received_len == 3);
    assert(memcmp(rx.data, frame + 3, 3) == 0);
}

static void test_fragmented_message(void) {
    fido_ble_rx_t rx;
    fido_ble_rx_reset(&rx);
    const uint8_t first[] = {FIDO_BLE_CMD_MSG, 0, 6, 1, 2};
    const uint8_t cont0[] = {0, 3, 4};
    const uint8_t cont1[] = {1, 5, 6};
    assert(fido_ble_rx_feed(&rx, first, sizeof(first)) == 0);
    assert(fido_ble_rx_feed(&rx, cont0, sizeof(cont0)) == 0);
    assert(fido_ble_rx_feed(&rx, cont1, sizeof(cont1)) == 1);
    const uint8_t expected[] = {1, 2, 3, 4, 5, 6};
    assert(memcmp(rx.data, expected, sizeof(expected)) == 0);
}


static void test_collision_busy(void) {
    fido_ble_rx_t rx;
    fido_ble_rx_reset(&rx);
    const uint8_t first[] = {FIDO_BLE_CMD_MSG, 0, 4, 1};
    const uint8_t collision[] = {FIDO_BLE_CMD_PING, 0, 1, 9};
    assert(fido_ble_rx_feed(&rx, first, sizeof(first)) == 0);
    assert(fido_ble_rx_feed(&rx, collision, sizeof(collision)) == -FIDO_BLE_ERR_BUSY);
    assert(rx.active);
    assert(rx.command == FIDO_BLE_CMD_MSG);
}

static void test_invalid_sequence(void) {
    fido_ble_rx_t rx;
    fido_ble_rx_reset(&rx);
    const uint8_t first[] = {FIDO_BLE_CMD_MSG, 0, 4, 1};
    const uint8_t bad[] = {1, 2, 3, 4};
    assert(fido_ble_rx_feed(&rx, first, sizeof(first)) == 0);
    assert(fido_ble_rx_feed(&rx, bad, sizeof(bad)) == -FIDO_BLE_ERR_INVALID_SEQ);
}

static void test_invalid_length(void) {
    fido_ble_rx_t rx;
    fido_ble_rx_reset(&rx);
    const uint8_t frame[] = {FIDO_BLE_CMD_MSG, 0, 1, 1, 2};
    assert(fido_ble_rx_feed(&rx, frame, sizeof(frame)) == -FIDO_BLE_ERR_INVALID_LEN);
}


static void test_zero_length_tx(void) {
    fido_ble_tx_t tx;
    fido_ble_tx_init(&tx, FIDO_BLE_CMD_PING, NULL, 0);
    uint8_t fragment[20];
    assert(fido_ble_tx_next(&tx, fragment, sizeof(fragment)) == 3);
    assert(fragment[0] == FIDO_BLE_CMD_PING);
    assert(fragment[1] == 0 && fragment[2] == 0);
    assert(fido_ble_tx_done(&tx));
}

static void test_tx_round_trip(void) {
    uint8_t data[257];
    for (size_t i = 0; i < sizeof(data); ++i) data[i] = (uint8_t)i;

    fido_ble_tx_t tx;
    fido_ble_tx_init(&tx, FIDO_BLE_CMD_MSG, data, sizeof(data));
    fido_ble_rx_t rx;
    fido_ble_rx_reset(&rx);
    uint8_t fragment[23];
    int result = 0;
    while (!fido_ble_tx_done(&tx)) {
        size_t len = fido_ble_tx_next(&tx, fragment, sizeof(fragment));
        assert(len > 0);
        result = fido_ble_rx_feed(&rx, fragment, len);
        assert(result >= 0);
    }
    assert(result == 1);
    assert(rx.received_len == sizeof(data));
    assert(memcmp(rx.data, data, sizeof(data)) == 0);
}

int main(void) {
    test_single_fragment();
    test_fragmented_message();
    test_collision_busy();
    test_invalid_sequence();
    test_invalid_length();
    test_zero_length_tx();
    test_tx_round_trip();
    return 0;
}
