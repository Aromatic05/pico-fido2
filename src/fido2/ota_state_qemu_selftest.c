#include "sdkconfig.h"

#if CONFIG_PICO_FIDO2_QEMU_OTA_STATE_SELFTEST

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

#include "pico_keys.h"
#include "usb/usb.h"
#include "fido/credential.h"
#include "fido/ctap2_cbor.h"
#include "fido/fido.h"
#include "fido/files.h"

static const char rp_id_text[] = "ota-state.invalid";
static const uint8_t user_id_bytes[] = "ota-state-user-id";
static const char user_name_text[] = "ota-state-user";
static const char user_display_text[] = "OTA State User";

static void fail(const char *reason) {
    printf("OTA_STATE_QEMU_FAIL:%s\n", reason);
    fflush(stdout);
    abort();
}

static void require(bool condition, const char *reason) {
    if (!condition) {
        fail(reason);
    }
}

static file_t *find_credential_record(const uint8_t rp_hash[32]) {
    file_t *found = NULL;
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; ++i) {
        file_t *ef = search_dynamic_file((uint16_t)(EF_CRED + i));
        if (!file_has_data(ef) || file_get_size(ef) < 32) {
            continue;
        }
        if (memcmp(file_get_data(ef), rp_hash, 32) == 0) {
            require(found == NULL, "multiple resident credentials for probe RP");
            found = ef;
        }
    }
    return found;
}

static file_t *find_rp_record(const uint8_t rp_hash[32]) {
    file_t *found = NULL;
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; ++i) {
        file_t *ef = search_dynamic_file((uint16_t)(EF_RP + i));
        if (!file_has_data(ef) || file_get_size(ef) < 33) {
            continue;
        }
        if (memcmp(file_get_data(ef) + 1, rp_hash, 32) == 0) {
            require(found == NULL, "multiple RP records for probe RP");
            found = ef;
        }
    }
    return found;
}

static void validate_credential(file_t *cred_file, const uint8_t rp_hash[32]) {
    require(cred_file != NULL, "resident credential missing");
    Credential cred = {0};
    int ret = credential_load_resident(cred_file, rp_hash, &cred);
    require(ret == 0, "resident credential cannot be parsed");
    require(cred.userId.present, "resident credential user id missing");
    require(cred.userId.len == sizeof(user_id_bytes) - 1,
            "resident credential user id length changed");
    require(memcmp(cred.userId.data, user_id_bytes, sizeof(user_id_bytes) - 1) == 0,
            "resident credential user id changed");
    require(cred.rpId.present, "resident credential RP id missing");
    require(cred.rpId.len == sizeof(rp_id_text) - 1,
            "resident credential RP id length changed");
    require(memcmp(cred.rpId.data, rp_id_text, sizeof(rp_id_text) - 1) == 0,
            "resident credential RP id changed");
    credential_free(&cred);
}

static void seed_credential(const uint8_t rp_hash[32]) {
    CborCharString rp_id = {
        .data = (char *)rp_id_text,
        .len = sizeof(rp_id_text) - 1,
        .present = true,
        .nofree = true,
    };
    CborByteString user_id = {
        .data = (uint8_t *)user_id_bytes,
        .len = sizeof(user_id_bytes) - 1,
        .present = true,
        .nofree = true,
    };
    CborCharString user_name = {
        .data = (char *)user_name_text,
        .len = sizeof(user_name_text) - 1,
        .present = true,
        .nofree = true,
    };
    CborCharString display_name = {
        .data = (char *)user_display_text,
        .len = sizeof(user_display_text) - 1,
        .present = true,
        .nofree = true,
    };
    CredOptions opts = {
        .rk = ptrue,
        .present = true,
    };
    CredExtensions extensions = {0};
    uint8_t cred_id[MAX_CRED_ID_LENGTH] = {0};
    uint16_t cred_id_len = 0;

    int ret = credential_create(&rp_id, &user_id, &user_name, &display_name,
                                &opts, &extensions, false,
                                FIDO2_ALG_ES256, FIDO2_CURVE_P256,
                                cred_id, &cred_id_len);
    require(ret == 0 && cred_id_len > 0, "resident credential creation failed");
    ret = credential_store(cred_id, cred_id_len, rp_hash);
    mbedtls_platform_zeroize(cred_id, sizeof(cred_id));
    require(ret == 0, "resident credential store failed");

    low_flash_available();
    do_flash();
    scan_flash();
}

static void print_record_hash(const char *label, file_t *ef) {
    require(file_has_data(ef), "record hash requested for empty file");
    uint8_t digest[32];
    uint16_t len = file_get_size(ef);
    require(mbedtls_sha256(file_get_data(ef), len, digest, 0) == 0,
            "record sha256 failed");
    printf("OTA_STATE_%s:FID=%04x:LEN=%u:SHA256=", label, ef->fid, len);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    mbedtls_platform_zeroize(digest, sizeof(digest));
}

static void print_root_hash(void) {
    file_t *root = search_by_fid(EF_KEY_DEV, NULL, SPECIFY_EF);
    file_t *root_enc = search_by_fid(EF_KEY_DEV_ENC, NULL, SPECIFY_EF);
    if (file_has_data(root_enc)) {
        print_record_hash("ROOT", root_enc);
        return;
    }
    require(file_has_data(root), "FIDO root missing");
    print_record_hash("ROOT", root);
}

static void print_state_hash(file_t *cred_file, file_t *rp_file) {
    uint8_t digest[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    require(mbedtls_sha256_starts(&ctx, 0) == 0, "sha256 init failed");

    uint16_t fid = cred_file->fid;
    uint16_t len = file_get_size(cred_file);
    require(mbedtls_sha256_update(&ctx, (const uint8_t *)&fid, sizeof(fid)) == 0,
            "sha256 credential fid failed");
    require(mbedtls_sha256_update(&ctx, (const uint8_t *)&len, sizeof(len)) == 0,
            "sha256 credential length failed");
    require(mbedtls_sha256_update(&ctx, file_get_data(cred_file), len) == 0,
            "sha256 credential data failed");

    fid = rp_file->fid;
    len = file_get_size(rp_file);
    require(mbedtls_sha256_update(&ctx, (const uint8_t *)&fid, sizeof(fid)) == 0,
            "sha256 RP fid failed");
    require(mbedtls_sha256_update(&ctx, (const uint8_t *)&len, sizeof(len)) == 0,
            "sha256 RP length failed");
    require(mbedtls_sha256_update(&ctx, file_get_data(rp_file), len) == 0,
            "sha256 RP data failed");
    require(mbedtls_sha256_finish(&ctx, digest) == 0, "sha256 finish failed");
    mbedtls_sha256_free(&ctx);

    printf("OTA_STATE_CREDENTIAL_SHA256:");
    for (size_t i = 0; i < sizeof(digest); ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    fflush(stdout);
    mbedtls_platform_zeroize(digest, sizeof(digest));
}

void fido_ota_state_qemu_selftest_task(void) {
    static bool done;
    if (done) {
        return;
    }
    done = true;

    /* QEMU skips the normal USB task, so explicitly enable the same
     * low-flash commit path used by hardware before creating durable state.
     * The reset QEMU self-test has the same bootstrap requirement. */
    card_init_core1();
    require(card_try_claim_maintenance(), "cannot claim card for OTA state probe");
    require(init_fido() == PICOKEY_OK, "FIDO init failed for OTA state probe");

    uint8_t rp_hash[32];
    require(mbedtls_sha256((const uint8_t *)rp_id_text, sizeof(rp_id_text) - 1,
                           rp_hash, 0) == 0,
            "RP hash failed");

    file_t *cred_file = find_credential_record(rp_hash);
    bool created = cred_file == NULL;
    if (cred_file == NULL) {
        seed_credential(rp_hash);
        cred_file = find_credential_record(rp_hash);
    }
    require(credential_count_resident_for_rp(rp_hash) == 1,
            "resident credential count changed");
    file_t *rp_file = find_rp_record(rp_hash);
    require(rp_file != NULL, "resident RP index missing");
    validate_credential(cred_file, rp_hash);
    printf("OTA_STATE_CREDENTIAL_MODE:%s\n", created ? "created" : "existing");
    print_record_hash("CRED", cred_file);
    print_record_hash("RP", rp_file);
    print_root_hash();
    print_state_hash(cred_file, rp_file);

    mbedtls_platform_zeroize(rp_hash, sizeof(rp_hash));
    card_release_maintenance();
}

#endif
