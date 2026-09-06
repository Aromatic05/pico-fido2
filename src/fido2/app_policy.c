#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fido/management.h"

static bool aid_equal(const uint8_t *aid, size_t aid_len,
                      const uint8_t *expected, size_t expected_len) {
    return aid_len == expected_len && memcmp(aid, expected, expected_len) == 0;
}

bool picokey_app_policy(const uint8_t *aid, size_t aid_len) {
    static const uint8_t otp[] = {0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01};
    static const uint8_t u2f[] = {0xA0, 0x00, 0x00, 0x05, 0x27, 0x10, 0x02};
    static const uint8_t fido[] = {0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01};
    static const uint8_t fido_backup[] = {0xB0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01};
    static const uint8_t oath[] = {0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01};
    static const uint8_t hsmauth[] = {0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01};
    static const uint8_t management[] = {0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17};
    static const uint8_t openpgp[] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
    static const uint8_t piv[] = {0xA0, 0x00, 0x00, 0x03, 0x08};
    static const uint8_t piv_yubico[] = {0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01};

    if (aid_equal(aid, aid_len, otp, sizeof(otp))) {
        return cap_supported(CAP_OTP);
    }
    if (aid_equal(aid, aid_len, u2f, sizeof(u2f))) {
        return cap_supported(CAP_U2F);
    }
    if (aid_equal(aid, aid_len, fido, sizeof(fido)) ||
        aid_equal(aid, aid_len, fido_backup, sizeof(fido_backup))) {
        return cap_supported(CAP_FIDO2);
    }
    if (aid_equal(aid, aid_len, oath, sizeof(oath))) {
        return cap_supported(CAP_OATH);
    }
    if (aid_equal(aid, aid_len, hsmauth, sizeof(hsmauth))) {
        return cap_supported(CAP_HSMAUTH);
    }
    if (aid_equal(aid, aid_len, management, sizeof(management))) {
        return cap_supported(CAP_MANAGEMENT);
    }
    if (aid_equal(aid, aid_len, openpgp, sizeof(openpgp))) {
        return cap_supported(CAP_OPENPGP);
    }
    if (aid_equal(aid, aid_len, piv, sizeof(piv)) ||
        aid_equal(aid, aid_len, piv_yubico, sizeof(piv_yubico))) {
        return cap_supported(CAP_PIV);
    }
    return true;
}
