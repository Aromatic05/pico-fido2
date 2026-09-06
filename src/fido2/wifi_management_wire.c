#include "wifi_management_wire.h"

#include <string.h>

static bool append_tlv(uint8_t *out, size_t capacity, size_t *offset,
                       uint8_t tag, const uint8_t *data, size_t len) {
    if (len > UINT8_MAX || *offset > capacity || capacity - *offset < 2 + len) {
        return false;
    }
    out[(*offset)++] = tag;
    out[(*offset)++] = (uint8_t)len;
    if (len > 0) {
        memcpy(out + *offset, data, len);
        *offset += len;
    }
    return true;
}

static size_t finish(uint8_t *out, size_t offset) {
    if (offset < 1 || offset - 1 > UINT8_MAX) {
        return 0;
    }
    out[0] = (uint8_t)(offset - 1);
    return offset;
}

size_t fido_wifi_build_enabled_config(
    uint8_t *out,
    size_t capacity,
    uint16_t enabled,
    const uint8_t unlock[MAN_CONFIG_LOCK_LEN],
    bool unlock_present) {
    if (out == NULL || capacity < 1 || (unlock_present && unlock == NULL)) {
        return 0;
    }
    size_t offset = 1;
    const uint8_t enabled_bytes[2] = {
        (uint8_t)(enabled >> 8),
        (uint8_t)enabled,
    };
    if (!append_tlv(out, capacity, &offset, TAG_USB_ENABLED,
                    enabled_bytes, sizeof(enabled_bytes))) {
        return 0;
    }
    if (unlock_present &&
        !append_tlv(out, capacity, &offset, TAG_UNLOCK,
                    unlock, MAN_CONFIG_LOCK_LEN)) {
        return 0;
    }
    return finish(out, offset);
}

size_t fido_wifi_build_lock_config(
    uint8_t *out,
    size_t capacity,
    const uint8_t unlock[MAN_CONFIG_LOCK_LEN],
    bool unlock_present,
    const uint8_t new_lock[MAN_CONFIG_LOCK_LEN]) {
    if (out == NULL || new_lock == NULL || capacity < 1 ||
        (unlock_present && unlock == NULL)) {
        return 0;
    }
    size_t offset = 1;
    if (unlock_present &&
        !append_tlv(out, capacity, &offset, TAG_UNLOCK,
                    unlock, MAN_CONFIG_LOCK_LEN)) {
        return 0;
    }
    if (!append_tlv(out, capacity, &offset, TAG_CONFIG_LOCK,
                    new_lock, MAN_CONFIG_LOCK_LEN)) {
        return 0;
    }
    return finish(out, offset);
}
