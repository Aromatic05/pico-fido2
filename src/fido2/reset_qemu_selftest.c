#include "sdkconfig.h"

#if CONFIG_PICO_FIDO2_QEMU_RESET_SELFTEST

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pico_keys.h"
#include "usb/usb.h"
#include "fido/fido.h"
#include "fido/files.h"
#include "fido/ctap.h"
#undef _FILES_H_
#include "openpgp/files.h"
#include "openpgp/openpgp.h"

#define HSMAUTH_CONFIG_FID 0xBC00

static const uint8_t marker_openpgp[] = "qemu-openpgp";
static const uint8_t marker_piv[] = "qemu-piv";
static const uint8_t marker_oath[] = "qemu-oath";
static const uint8_t marker_otp[] = "qemu-otp";
static const uint8_t marker_hsm[] = "qemu-hsm";
static const uint8_t marker_management[] = "qemu-management";
static const uint8_t marker_fido_pin[] = "qemu-fido-pin";
static const uint8_t marker_fido_credential[] = "qemu-resident-credential";
static const uint8_t marker_fido_rp[] = "qemu-resident-rp";
static const uint8_t marker_piv_attestation_meta[] = {0x11, 0x22, 0x33};

static uint8_t expected_piv_attestation_key[PICO_KEYS_FLASH_SECTOR_SIZE];
static uint8_t expected_piv_attestation_cert[PICO_KEYS_FLASH_SECTOR_SIZE];
static uint16_t expected_piv_attestation_key_len;
static uint16_t expected_piv_attestation_cert_len;

static void fail(const char *reason) {
    printf("RESET_ISOLATION_QEMU_FAIL: %s\n", reason);
    abort();
}

static void require(bool condition, const char *reason) {
    if (!condition) {
        fail(reason);
    }
}

static void claim_phase(void) {
    for (unsigned i = 0; i < 1000; ++i) {
        if (card_try_claim_maintenance()) {
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    fail("could not claim card ownership");
}

static void release_and_commit(void) {
    low_flash_available();
    do_flash();
    card_release_maintenance();
}

static void committed_rescan(void) {
    claim_phase();
    scan_flash();
}

static file_t *static_file(uint16_t fid) {
    return search_by_fid(fid, NULL, SPECIFY_EF);
}

static void put_static(uint16_t fid, const uint8_t *data, size_t len) {
    file_t *ef = static_file(fid);
    require(ef != NULL, "missing static file");
    require(file_put_data(ef, data, (uint16_t)len) == PICOKEY_OK, "static write failed");
    low_flash_available();
}

static void put_dynamic(uint16_t fid, const uint8_t *data, size_t len) {
    file_t *ef = search_dynamic_file(fid);
    if (ef == NULL) {
        ef = file_new(fid);
    }
    require(ef != NULL, "dynamic file allocation failed");
    require(file_put_data(ef, data, (uint16_t)len) == PICOKEY_OK, "dynamic write failed");
    low_flash_available();
}

static bool static_equals(uint16_t fid, const uint8_t *data, size_t len) {
    file_t *ef = static_file(fid);
    return file_has_data(ef) && file_get_size(ef) == len &&
           memcmp(file_get_data(ef), data, len) == 0;
}

static bool dynamic_equals(uint16_t fid, const uint8_t *data, size_t len) {
    file_t *ef = search_dynamic_file(fid);
    return file_has_data(ef) && file_get_size(ef) == len &&
           memcmp(file_get_data(ef), data, len) == 0;
}

static bool static_empty(uint16_t fid) {
    return !file_has_data(static_file(fid));
}

static bool dynamic_empty(uint16_t fid) {
    return !file_has_data(search_dynamic_file(fid));
}

static size_t capture_fido_root(uint8_t out[64]) {
    file_t *ef = static_file(EF_KEY_DEV);
    require(file_has_data(ef), "FIDO root missing");
    size_t len = file_get_size(ef);
    require(len > 0 && len <= 64, "unexpected FIDO root length");
    memcpy(out, file_get_data(ef), len);
    return len;
}

static bool root_equals(const uint8_t *expected, size_t expected_len) {
    file_t *ef = static_file(EF_KEY_DEV);
    return file_has_data(ef) && file_get_size(ef) == expected_len &&
           memcmp(file_get_data(ef), expected, expected_len) == 0;
}

static bool all_zero(const uint8_t *data, size_t len) {
    uint8_t value = 0;
    for (size_t i = 0; i < len; ++i) {
        value |= data[i];
    }
    return value == 0;
}

static void seed_sibling_markers(void) {
    put_static(EF_CH_NAME, marker_openpgp, sizeof(marker_openpgp));
    put_static(EF_PIV_CHUID, marker_piv, sizeof(marker_piv));
    require(meta_add(EF_PIV_KEY_ATTESTATION, marker_piv_attestation_meta,
                     sizeof(marker_piv_attestation_meta)) == PICOKEY_OK,
            "PIV F9 metadata marker write failed");
    put_dynamic(EF_OATH_CODE, marker_oath, sizeof(marker_oath));
    put_dynamic(EF_OTP_SLOT4, marker_otp, sizeof(marker_otp));
    put_dynamic(HSMAUTH_CONFIG_FID, marker_hsm, sizeof(marker_hsm));
    put_dynamic(EF_DEV_CONF, marker_management, sizeof(marker_management));
}

static void require_sibling_markers(void) {
    require(static_equals(EF_CH_NAME, marker_openpgp, sizeof(marker_openpgp)), "OpenPGP marker lost");
    require(static_equals(EF_PIV_CHUID, marker_piv, sizeof(marker_piv)), "PIV marker lost");
    require(dynamic_equals(EF_OATH_CODE, marker_oath, sizeof(marker_oath)), "OATH marker lost");
    require(dynamic_equals(EF_OTP_SLOT4, marker_otp, sizeof(marker_otp)), "OTP marker lost");
    require(dynamic_equals(HSMAUTH_CONFIG_FID, marker_hsm, sizeof(marker_hsm)), "HSM Auth marker lost");
    require(dynamic_equals(EF_DEV_CONF, marker_management, sizeof(marker_management)), "management marker lost");
}

static void seed_fido_persistent_markers(void) {
    put_static(EF_PIN, marker_fido_pin, sizeof(marker_fido_pin));
    put_dynamic(EF_CRED, marker_fido_credential, sizeof(marker_fido_credential));
    put_dynamic(EF_RP, marker_fido_rp, sizeof(marker_fido_rp));
}

static void require_fido_persistent_markers(void) {
    require(static_equals(EF_PIN, marker_fido_pin, sizeof(marker_fido_pin)),
            "foreign applet reset erased FIDO PIN record");
    require(dynamic_equals(EF_CRED, marker_fido_credential, sizeof(marker_fido_credential)),
            "foreign applet reset erased FIDO resident credential record");
    require(dynamic_equals(EF_RP, marker_fido_rp, sizeof(marker_fido_rp)),
            "foreign applet reset erased FIDO resident RP index");
}

static void capture_piv_attestation(void) {
    file_t *key = static_file(EF_PIV_KEY_ATTESTATION);
    file_t *cert = static_file(EF_PIV_ATTESTATION);
    require(file_has_data(key), "PIV F9 attestation key was not initialized");
    require(file_has_data(cert), "PIV F9 attestation certificate was not initialized");
    expected_piv_attestation_key_len = file_get_size(key);
    expected_piv_attestation_cert_len = file_get_size(cert);
    require(expected_piv_attestation_key_len > 0 &&
            expected_piv_attestation_key_len <= sizeof(expected_piv_attestation_key),
            "unexpected PIV F9 attestation key length");
    require(expected_piv_attestation_cert_len > 0 &&
            expected_piv_attestation_cert_len <= sizeof(expected_piv_attestation_cert),
            "unexpected PIV F9 attestation certificate length");
    memcpy(expected_piv_attestation_key, file_get_data(key),
           expected_piv_attestation_key_len);
    memcpy(expected_piv_attestation_cert, file_get_data(cert),
           expected_piv_attestation_cert_len);
}

static void require_piv_attestation_preserved(void) {
    require(static_equals(EF_PIV_KEY_ATTESTATION, expected_piv_attestation_key,
                          expected_piv_attestation_key_len),
            "PIV F9 attestation key changed");
    require(static_equals(EF_PIV_ATTESTATION, expected_piv_attestation_cert,
                          expected_piv_attestation_cert_len),
            "PIV F9 attestation certificate changed");
    uint8_t *meta = NULL;
    uint16_t meta_len = meta_find(EF_PIV_KEY_ATTESTATION, &meta);
    require(meta_len == sizeof(marker_piv_attestation_meta) &&
            memcmp(meta, marker_piv_attestation_meta, meta_len) == 0,
            "PIV F9 attestation metadata changed");

    mbedtls_ecdsa_context attestation;
    mbedtls_ecdsa_init(&attestation);
    require(load_private_key_ecdsa(&attestation,
                                   static_file(EF_PIV_KEY_ATTESTATION),
                                   false) == PICOKEY_OK,
            "PIV F9 attestation private key became unusable");
    mbedtls_ecdsa_free(&attestation);
}

static void poison_fido_transient_state(void) {
    memset(session_pin, 0xA5, sizeof(session_pin));
    memset(keydev_dec, 0x5A, sizeof(keydev_dec));
    has_keydev_dec = true;
    paut.in_use = true;
    paut.permissions = 0xFF;
    paut.user_present = true;
    paut.user_verified = true;
    paut.has_rp_id = true;
    memset(paut.rp_id_hash, 0x33, sizeof(paut.rp_id_hash));
    ppaut.permissions = 0xFF;

    memset(&mse, 0x5C, sizeof(mse));
    mse.init = true;

    /* offset=0, set=1 byte, total length=17. Missing pinUvAuth is
     * intentionally rejected after the transaction counters are initialized. */
    static const uint8_t partial_large_blob[] = {
        0xA3, 0x02, 0x41, 0xAA, 0x03, 0x00, 0x04, 0x11,
    };
    extern int cbor_large_blobs(const uint8_t *data, size_t len);
    (void)cbor_large_blobs(partial_large_blob, sizeof(partial_large_blob));
    require(large_blob_write_in_progress(), "could not poison large-blob transaction state");
}

static void require_fido_transient_cleared(void) {
    require(!has_keydev_dec, "decrypted FIDO root cache survived reset");
    require(all_zero(session_pin, sizeof(session_pin)), "FIDO PIN session key survived reset");
    require(!paut.in_use && paut.permissions == 0 && !paut.user_present && !paut.user_verified && !paut.has_rp_id,
            "pinUvAuthToken state survived reset");
    require(ppaut.permissions == 0, "persistent pinUvAuthToken permissions survived reset");
    require(!large_blob_write_in_progress(), "large-blob transaction survived reset");
    require(all_zero((const uint8_t *)&mse, sizeof(mse)), "vendor MSE session survived reset");
}

static void verify_legacy_default_rc_migration(void) {
    static const uint8_t legacy_rc[] = {
        '1', '2', '3', '4', '5', '6', '7', '8'
    };
    uint8_t legacy_hash[33];
    legacy_hash[0] = sizeof(legacy_rc);
    double_hash_pin(legacy_rc, sizeof(legacy_rc), legacy_hash + 1);
    put_static(EF_RC, legacy_hash, sizeof(legacy_hash));

    file_t *status = static_file(EF_PW_PRIV);
    require(file_has_data(status) && file_get_size(status) >= 7,
            "PW status missing before legacy RC migration");
    uint8_t status_copy[16];
    uint16_t status_len = file_get_size(status);
    require(status_len <= sizeof(status_copy), "unexpected PW status length");
    memcpy(status_copy, file_get_data(status), status_len);
    status_copy[5] = 3;
    put_static(EF_PW_PRIV, status_copy, status_len);

    file_t *dek_ef = static_file(EF_DEK);
    require(file_has_data(dek_ef) && file_get_size(dek_ef) >= IV_SIZE + 96,
            "DEK missing before legacy RC migration");
    uint16_t dek_len = file_get_size(dek_ef);
    uint8_t dek_before[IV_SIZE + 4 * 32];
    require(dek_len <= sizeof(dek_before), "unexpected DEK length");
    memcpy(dek_before, file_get_data(dek_ef), dek_len);

    release_and_commit();
    committed_rescan();
    scan_files_openpgp();
    release_and_commit();
    committed_rescan();

    require(static_empty(EF_RC), "legacy public Reset Code survived migration");
    status = static_file(EF_PW_PRIV);
    require(file_has_data(status) && file_get_size(status) >= 7 &&
            file_get_data(status)[5] == 0,
            "legacy Reset Code retry counter survived migration");
    dek_ef = static_file(EF_DEK);
    require(file_has_data(dek_ef) && file_get_size(dek_ef) == dek_len,
            "legacy RC migration changed DEK record shape");
    const uint8_t *dek_after = file_get_data(dek_ef);
    require(memcmp(dek_after, dek_before, IV_SIZE + 32) == 0,
            "legacy RC migration changed PW1 DEK wrapper");
    require(memcmp(dek_after + IV_SIZE + 32,
                   dek_before + IV_SIZE + 32, 32) != 0,
            "legacy RC migration did not invalidate RC DEK wrapper");
    require(memcmp(dek_after + IV_SIZE + 64,
                   dek_before + IV_SIZE + 64, dek_len - (IV_SIZE + 64)) == 0,
            "legacy RC migration changed PW3/PIV DEK wrappers");
    mbedtls_platform_zeroize(legacy_hash, sizeof(legacy_hash));
    mbedtls_platform_zeroize(status_copy, sizeof(status_copy));
    mbedtls_platform_zeroize(dek_before, sizeof(dek_before));
}

void fido_reset_qemu_selftest(void) {
    printf("RESET_ISOLATION_QEMU_BEGIN\n");

    claim_phase();
    init_openpgp();
    init_piv();
    init_fido();
    printf("RESET_ISOLATION_QEMU_PHASE: init-complete\n");

    printf("RESET_ISOLATION_QEMU_PHASE: legacy-rc-migration-begin\n");
    uint8_t root_before_rc_migration[64];
    size_t root_before_rc_migration_len = capture_fido_root(root_before_rc_migration);
    verify_legacy_default_rc_migration();
    require(root_equals(root_before_rc_migration, root_before_rc_migration_len),
            "legacy RC migration changed FIDO root");
    printf("RESET_ISOLATION_QEMU_PHASE: legacy-rc-migration-verified\n");

    uint8_t root_initial[64];
    size_t root_initial_len = capture_fido_root(root_initial);
    seed_sibling_markers();
    capture_piv_attestation();
    put_static(EF_PIN, marker_fido_pin, sizeof(marker_fido_pin));
    poison_fido_transient_state();

    printf("RESET_ISOLATION_QEMU_PHASE: fido-reset-begin\n");
    require(reset_fido_application() == PICOKEY_OK, "FIDO reset failed");
    printf("RESET_ISOLATION_QEMU_PHASE: fido-reset-memory-done\n");
    release_and_commit();
    printf("RESET_ISOLATION_QEMU_PHASE: fido-reset-commit-done\n");
    committed_rescan();
    require_fido_transient_cleared();
    require(static_empty(EF_PIN), "FIDO PIN record survived authenticatorReset");
    require(!root_equals(root_initial, root_initial_len), "FIDO root did not rotate");
    require_sibling_markers();
    require_piv_attestation_preserved();
    printf("RESET_ISOLATION_QEMU_PHASE: fido-reset-verified\n");

    /* Persistent storage sentinels supplement the FIDO root invariant: a
     * foreign applet reset must preserve PIN, credential and RP records.
     * These markers are not valid CTAP2 credentials; the protocol lifecycle
     * is covered independently by the native host test. */
    seed_fido_persistent_markers();
    release_and_commit();
    committed_rescan();
    require_fido_persistent_markers();
    printf("RESET_ISOLATION_QEMU_PHASE: fido-pin-resident-seeded\n");

    uint8_t root_after_fido[64];
    size_t root_after_fido_len = capture_fido_root(root_after_fido);

    printf("RESET_ISOLATION_QEMU_PHASE: openpgp-reset-begin\n");
    require(reset_openpgp_storage() == PICOKEY_OK, "OpenPGP reset failed");
    printf("RESET_ISOLATION_QEMU_PHASE: openpgp-reset-storage-done\n");
    init_openpgp();
    printf("RESET_ISOLATION_QEMU_PHASE: openpgp-reset-init-done\n");
    release_and_commit();
    printf("RESET_ISOLATION_QEMU_PHASE: openpgp-reset-commit-done\n");
    committed_rescan();
    require(static_empty(EF_CH_NAME), "OpenPGP marker survived OpenPGP reset");
    require(root_equals(root_after_fido, root_after_fido_len), "OpenPGP reset rotated FIDO root");
    require_fido_persistent_markers();
    require(static_equals(EF_PIV_CHUID, marker_piv, sizeof(marker_piv)), "OpenPGP reset changed PIV state");
    require(dynamic_equals(EF_OATH_CODE, marker_oath, sizeof(marker_oath)), "OpenPGP reset changed OATH state");
    require(dynamic_equals(EF_OTP_SLOT4, marker_otp, sizeof(marker_otp)), "OpenPGP reset changed OTP state");
    require(dynamic_equals(HSMAUTH_CONFIG_FID, marker_hsm, sizeof(marker_hsm)), "OpenPGP reset changed HSM Auth state");
    require(dynamic_equals(EF_DEV_CONF, marker_management, sizeof(marker_management)), "OpenPGP reset changed management state");
    require_piv_attestation_preserved();
    printf("RESET_ISOLATION_QEMU_PHASE: openpgp-reset-verified\n");

    put_static(EF_CH_NAME, marker_openpgp, sizeof(marker_openpgp));
    printf("RESET_ISOLATION_QEMU_PHASE: piv-reset-begin\n");
    require(reset_piv_storage() == PICOKEY_OK, "PIV reset failed");
    printf("RESET_ISOLATION_QEMU_PHASE: piv-reset-storage-done\n");
    init_piv();
    printf("RESET_ISOLATION_QEMU_PHASE: piv-reset-init-done\n");
    release_and_commit();
    printf("RESET_ISOLATION_QEMU_PHASE: piv-reset-commit-done\n");
    committed_rescan();
    require(static_empty(EF_PIV_CHUID), "PIV marker survived PIV reset");
    require(root_equals(root_after_fido, root_after_fido_len), "PIV reset rotated FIDO root");
    require_fido_persistent_markers();
    require(static_equals(EF_CH_NAME, marker_openpgp, sizeof(marker_openpgp)), "PIV reset changed OpenPGP state");
    require(dynamic_equals(EF_OATH_CODE, marker_oath, sizeof(marker_oath)), "PIV reset changed OATH state");
    require(dynamic_equals(EF_OTP_SLOT4, marker_otp, sizeof(marker_otp)), "PIV reset changed OTP state");
    require(dynamic_equals(HSMAUTH_CONFIG_FID, marker_hsm, sizeof(marker_hsm)), "PIV reset changed HSM Auth state");
    require(dynamic_equals(EF_DEV_CONF, marker_management, sizeof(marker_management)), "PIV reset changed management state");
    require_piv_attestation_preserved();
    printf("RESET_ISOLATION_QEMU_PHASE: piv-reset-verified\n");

    put_static(EF_PIV_CHUID, marker_piv, sizeof(marker_piv));
    put_static(EF_PIN, marker_fido_pin, sizeof(marker_fido_pin));
    poison_fido_transient_state();
    uint8_t root_before_device_reset[64];
    size_t root_before_device_reset_len = capture_fido_root(root_before_device_reset);

    printf("RESET_ISOLATION_QEMU_PHASE: device-reset-begin\n");
    require(reset_device_storage() == PICOKEY_OK, "management full-device reset failed");
    printf("RESET_ISOLATION_QEMU_PHASE: device-reset-memory-done\n");
    release_and_commit();
    printf("RESET_ISOLATION_QEMU_PHASE: device-reset-commit-done\n");
    committed_rescan();
    require_fido_transient_cleared();
    require(!root_equals(root_before_device_reset, root_before_device_reset_len), "device reset did not rotate FIDO root");
    require(static_empty(EF_PIN), "device reset preserved FIDO PIN");
    require(dynamic_empty(EF_CRED), "device reset preserved FIDO resident credential");
    require(dynamic_empty(EF_RP), "device reset preserved FIDO resident RP index");
    require(static_empty(EF_CH_NAME), "device reset preserved OpenPGP data");
    require(static_empty(EF_PIV_CHUID), "device reset preserved PIV data");
    require(dynamic_empty(EF_OATH_CODE), "device reset preserved OATH data");
    require(dynamic_empty(EF_OTP_SLOT4), "device reset preserved OTP data");
    require(dynamic_empty(HSMAUTH_CONFIG_FID), "device reset preserved HSM Auth data");
    require(dynamic_empty(EF_DEV_CONF), "device reset preserved management config");
    require_piv_attestation_preserved();
    printf("RESET_ISOLATION_QEMU_PHASE: device-reset-verified\n");

    card_release_maintenance();
    printf("RESET_ISOLATION_QEMU_PASS\n");
}

void fido_reset_qemu_selftest_task(void) {
    static bool ran = false;
    if (ran) {
        return;
    }
    ran = true;
    /* Run on the normal core0 service task. random_gen() services its own
     * refill path on core0, which avoids depending on a second QEMU CPU task
     * merely to feed the RNG ring buffer. */
    card_init_core1();
    fido_reset_qemu_selftest();
}

#endif
