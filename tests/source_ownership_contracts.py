#!/usr/bin/env python3
"""Static source contracts connecting the ownership model to product C code."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT / "pico-keys-sdk" / "src"
HID = SDK / "usb" / "hid" / "hid.c"
CCID = SDK / "usb" / "ccid" / "ccid.c"
USB = SDK / "usb" / "usb.c"
USB_H = SDK / "usb" / "usb.h"
MAIN = SDK / "main.c"
APDU = SDK / "apdu.c"
HWRNG = SDK / "rng" / "hwrng.c"
EMULATION = SDK / "usb" / "emulation" / "emulation.c"
LED = SDK / "led" / "led.c"
BLE = ROOT / "src" / "fido2" / "ble_fido.c"
WIFI_COMMISSION = ROOT / "src" / "fido2" / "wifi_commission.c"
WIFI_MANAGEMENT = ROOT / "src" / "fido2" / "wifi_management.c"
WIFI_OTA = ROOT / "src" / "fido2" / "wifi_ota.c"
WIFI_OTA_POLICY = ROOT / "src" / "fido2" / "wifi_ota_policy.c"
WIFI_DEFAULTS = ROOT / "sdkconfig.wifi.defaults"
WIRELESS_LAYOUT_DEFAULTS = ROOT / "sdkconfig.wireless-layout.defaults"
SECURE_OTA_DEFAULTS = ROOT / "sdkconfig.secure-ota.defaults"
SECURITY_PREPROVISIONED_DEFAULTS = ROOT / "sdkconfig.security-preprovisioned.defaults"
DEVELOPMENT_MAINTENANCE_DEFAULTS = ROOT / "sdkconfig.development-maintenance.defaults"
TRANSPORT_KCONFIG = ROOT / "src" / "fido2" / "Kconfig"
FIDO2_CMAKE = ROOT / "src" / "fido2" / "CMakeLists.txt"
ESP32_TRANSPORTS = ROOT / "src" / "fido2" / "esp32_transports.c"
SECURE_OTA_PARTITIONS = ROOT / "pico-keys-sdk" / "config" / "esp32" / "partitions-secure-ota.csv"
BLE_DEFAULTS = ROOT / "sdkconfig.ble.defaults"
SECURITY_BUNDLE = ROOT / "tools" / "build_esp32s3_security_bundle.sh"
UPDATE_BUNDLE = ROOT / "tools" / "build_esp32s3_update_bundle.sh"
OTP = ROOT / "pico-fido" / "src" / "fido" / "otp.c"
CBOR_CONFIG = ROOT / "pico-fido" / "src" / "fido" / "cbor_config.c"
CREDENTIAL = ROOT / "pico-fido" / "src" / "fido" / "credential.c"
GET_ASSERTION = ROOT / "pico-fido" / "src" / "fido" / "cbor_get_assertion.c"
MAKE_CREDENTIAL = ROOT / "pico-fido" / "src" / "fido" / "cbor_make_credential.c"
CTAP_H = ROOT / "pico-fido" / "src" / "fido" / "ctap.h"
AUTHENTICATE = ROOT / "pico-fido" / "src" / "fido" / "cmd_authenticate.c"
PIV = ROOT / "pico-openpgp" / "src" / "openpgp" / "piv.c"
CMAKE = ROOT / "CMakeLists.txt"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", source, re.S)
    if not match:
        raise AssertionError(f"function not found: {name}")
    start = match.end()
    depth = 1
    pos = start
    while pos < len(source) and depth:
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
        pos += 1
    if depth:
        raise AssertionError(f"unterminated function: {name}")
    return source[start : pos - 1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def before(body: str, first: str, second: str, message: str) -> None:
    a = body.find(first)
    b = body.find(second)
    require(a >= 0, f"missing source marker: {first}")
    require(b >= 0, f"missing source marker: {second}")
    require(a < b, message)


def verify_product_sdk_binding() -> None:
    source = text(CMAKE)
    require("pico-keys-sdk/src" in source, "product ESP32 build no longer binds root pico-keys-sdk")
    require(
        "include(pico-keys-sdk/pico_keys_sdk_import.cmake)" in source,
        "product host build no longer imports root pico-keys-sdk",
    )
    require(
        "pico-fido/pico-keys-sdk" not in source and "pico-openpgp/pico-keys-sdk" not in source,
        "product build must not silently bind a nested SDK copy",
    )


def verify_arbiter() -> None:
    source = text(USB)
    main_source = text(MAIN)
    header = text(USB_H)
    start = function_body(source, "card_start_claimed")
    exit_claimed = function_body(source, "card_exit_claimed")
    try_claim = function_body(source, "card_try_claim")
    release = function_body(source, "card_release")
    status = function_body(source, "card_status")
    core0 = function_body(main_source, "core0_loop")
    require(
        "card_command_is_owned_by(itf)" in start,
        "card_start_claimed must verify the caller owns the card command",
    )
    require("return false" in start, "card_start_claimed must reject non-owner callers")
    require(
        "card_command_is_owned_by(itf)" in exit_claimed and "return false" in exit_claimed,
        "card_exit_claimed must reject non-owner callers",
    )
    require("static bool card_start(" in source, "raw worker start must remain private to the arbiter")
    require("static void card_exit_unchecked(" in source, "raw worker exit must remain private to the arbiter")
    require("extern bool card_start(" not in header, "raw worker start must not be exported")
    require("extern void card_exit(" not in header, "raw worker exit must not be exported")
    require("mutex_enter_blocking(&card_state_mutex)" in try_claim and
            "mutex_exit(&card_state_mutex)" in try_claim,
            "product command claim must serialize cross-task owner changes")
    require("mutex_enter_blocking(&card_state_mutex)" in release and
            "mutex_exit(&card_state_mutex)" in release,
            "product command release must serialize cross-task owner changes")
    require("card_try_claim_maintenance()" in core0,
            "flash/cache maintenance must participate in the global command arbiter")
    before(core0, "low_flash_is_pending()", "card_try_claim_maintenance()",
           "idle maintenance must only contend for the owner when flash work is pending")
    before(core0, "card_try_claim_maintenance()", "do_flash()",
           "main loop must claim maintenance ownership before flash cache reuse")
    before(core0, "do_flash()", "card_release_maintenance()",
           "main loop must retain maintenance ownership until flash work completes")
    finished = status[status.find("m == EV_EXEC_FINISHED") :]
    require(finished, "card_status must handle worker completion")
    before(finished, "low_flash_is_pending()", "do_flash()",
           "worker completion must detect pending flash before owner-local flush")
    before(finished, "do_flash()", "queue_try_add(&card_to_usb_q, &m)",
           "worker completion must try owner-local flush before requeueing completion")
    before(finished, "do_flash()", "return PICOKEY_OK",
           "worker completion must finish pending flash before reporting response ready")


def verify_button_signals() -> None:
    source = text(MAIN)
    wait = function_body(source, "wait_button")
    core0 = function_body(source, "core0_loop")
    wifi = function_body(text(WIFI_COMMISSION), "fido_wifi_button_pressed")
    otp = function_body(text(OTP), "otp_button_pressed")
    require("__atomic_store_n(&cancel_button" in source, "cancel request must use atomic stores")
    require("__atomic_load_n(&cancel_button" in source, "cancel request must use atomic loads")
    require("__atomic_store_n(&req_button_pending" in source, "button-pending state must use atomic stores")
    require("__atomic_load_n(&req_button_pending" in source, "button-pending state must use atomic loads")
    require("execute_tasks()" not in wait, "worker-side button wait must not recursively run transport tasks")
    require("#define BUTTON_DEBOUNCE_MS 40U" in source,
            "BOOT multi-press must retain an explicit stable-state debounce interval")
    require("raw_button_state != button_raw_state" in core0 and
            "now - button_raw_changed_time >= BUTTON_DEBOUNCE_MS" in core0,
            "BOOT multi-press must accept GPIO transitions only after stable debounce")
    require("now - button_pressed_time >= BUTTON_MULTI_PRESS_WINDOW_MS" in core0,
            "BOOT multi-press completion must use wrap-safe elapsed-time arithmetic")
    require("button_press = 1" in core0,
            "a release after the sequence window must start a new sequence")
    require("button_press < UINT8_MAX" in core0,
            "BOOT multi-press count must saturate instead of wrapping")
    require("presses >= CONFIG_PICO_FIDO2_WIFI_COMMISSION_PRESSES" in wifi,
            "commissioning must accept threshold-or-more presses so bounce cannot bypass it")
    require("previous_button_pressed_cb(presses)" in wifi,
            "sub-threshold BOOT sequences must remain routable to OTP outside maintenance mode")
    before(wifi, "if (commissioning_started)",
           "if (presses >= CONFIG_PICO_FIDO2_WIFI_COMMISSION_PRESSES)",
           "maintenance-mode BOOT routing must take precedence over commissioning entry/OTP routing")
    require("grant_physical_presence" not in wifi,
            "maintenance-mode BOOT handling must not create a second authorization layer")
    before(otp, "slot == 0 || slot > (EF_OTP_SLOT4 - EF_OTP_SLOT1 + 1)",
           "uint16_t slot_ef = EF_OTP_SLOT1 + slot - 1",
           "OTP button callback must reject out-of-range slots before deriving a file id")


def verify_hwrng_state() -> None:
    source = text(HWRNG)
    task = function_body(source, "hwrng_task")
    get = function_body(source, "hwrng_get")
    flush = function_body(source, "hwrng_flush")
    wait_full = function_body(source, "hwrng_wait_full")
    require("static mutex_t hwrng_mutex" in source, "HWRNG shared state must have one ownership mutex")
    for label, body in (("task", task), ("get", get), ("flush", flush), ("wait_full", wait_full)):
        require("mutex_enter_blocking(&hwrng_mutex)" in body, f"HWRNG {label} must acquire the shared-state mutex")
        require("mutex_exit(&hwrng_mutex)" in body, f"HWRNG {label} must release the shared-state mutex")


def verify_wifi_commissioning() -> None:
    source = text(WIFI_COMMISSION)
    ble = text(BLE)
    defaults = text(WIFI_DEFAULTS)
    wireless_layout = text(WIRELESS_LAYOUT_DEFAULTS)
    security_bundle = text(SECURITY_BUNDLE)
    update_bundle = text(UPDATE_BUNDLE)
    start = function_body(source, "fido_wifi_start")
    event = function_body(source, "wifi_event_handler")
    ble_stop = function_body(ble, "fido_ble_stop_for_commissioning")
    config_post = function_body(source, "config_post")
    lock_post = function_body(source, "config_lock_post")
    pairing_post = function_body(source, "ble_pairing_post")
    bond_reset_post = function_body(source, "ble_bond_reset_post")
    reboot_post = function_body(source, "reboot_post")
    status_get = function_body(source, "status_get")
    init = function_body(source, "fido_wifi_init")
    task = function_body(source, "fido_wifi_task")
    dev_start = function_body(source, "picokey_vendor_maintenance_start")
    button = function_body(source, "fido_wifi_button_pressed")
    request_session = function_body(source, "request_session_valid")
    development_defaults = text(DEVELOPMENT_MAINTENANCE_DEFAULTS)
    transport_kconfig = text(TRANSPORT_KCONFIG)

    require("fido_ble_stop_for_commissioning()" in start,
            "Wi-Fi commissioning must fully stop BLE before enabling SoftAP")
    require("nimble_port_stop()" in ble_stop and "nimble_port_deinit()" in ble_stop,
            "commissioning must stop both the NimBLE host and Bluetooth controller")
    before(start, "esp_wifi_set_config(WIFI_IF_AP", "fido_ble_stop_for_commissioning()",
           "Wi-Fi configuration preflight must complete before the modal BLE shutdown")
    before(start, "fido_ble_stop_for_commissioning()", "esp_wifi_start()",
           "Bluetooth must be fully stopped before the SoftAP starts")
    require("start_http_server()" not in start,
            "SoftAP startup must not allocate the HTTP server before a station connects")
    require("WIFI_EVENT_AP_STACONNECTED" in event and "start_http_server()" in event,
            "HTTP server startup must be deferred until a station actually joins the SoftAP")
    require("ESP_ERROR_CHECK(esp_wifi_start())" not in start,
            "optional Wi-Fi startup must not abort the YubiKey core on a recoverable Wi-Fi failure")
    require("ESP_ERROR_CHECK" not in start and
            "ESP_ERROR_CHECK" not in function_body(source, "init_network_stack"),
            "optional Wi-Fi commissioning setup must not abort the YubiKey core")
    require("__atomic_load_n(&advertising_enabled" in ble and
            "ble_gap_adv_stop()" in function_body(ble, "fido_ble_set_advertising_enabled"),
            "BLE advertising pause must be an explicit transport state, not a one-shot side effect")
    require("if (!fido_ble_is_running())" in function_body(ble, "fido_ble_task"),
            "BLE transport task must remain quiescent after commissioning deinitializes NimBLE")
    require("fido_ble_is_running() ? \"true\" : \"false\"" in status_get,
            "commissioning status must report the runtime BLE state rather than compile-time capability")
    require('\\"bleSupported\\"' in status_get and
            "#if CONFIG_PICO_FIDO2_BLE\nstatic esp_err_t ble_pairing_post" in source,
            "Wi-Fi-only builds must report BLE capability explicitly and compile BLE maintenance handlers only when BLE exists")
    require("#if CONFIG_PICO_FIDO2_BLE\n        {.uri = \"/api/ble/pairing\"" in source,
            "Wi-Fi-only builds must not register BLE maintenance routes")
    require("esp_secure_boot_enabled()" in status_get and
            "esp_flash_encryption_enabled()" in status_get and
            "esp_efuse_read_secure_version()" in status_get,
            "maintenance status must use public ESP-IDF read-only security-state APIs")
    require("ESP_EFUSE_DIS_DOWNLOAD_MODE" in status_get and
            "ESP_EFUSE_DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE" in status_get,
            "maintenance status must expose both retained ROM recovery paths")
    require("esp_pm_get_configuration(&pm)" in status_get and
            '\\"minCpuMHz\\"' in status_get and '\\"maxCpuMHz\\"' in status_get and
            '\\"lightSleep\\"' in status_get,
            "maintenance status must expose configured DFS/light-sleep bounds")
    require("esp_app_get_description()" in status_get and
            "esp_ota_get_running_partition()" in status_get and
            "esp_partition_get_sha256" in status_get,
            "maintenance status must derive firmware provenance from public ESP-IDF app/partition APIs")
    require('\\"projectVersion\\"' in status_get and
            '\\"securityVersion\\"' in status_get and
            '\\"appElfSha256\\"' in status_get and
            '\\"imageSha256\\"' in status_get,
            "maintenance status must expose project/version and unambiguous firmware digest fields")
    require('char image_sha_json[67] = "null"' in status_get,
            "running image SHA failure must be represented as null rather than a fabricated digest")
    for secret_marker in ("BLOCK_KEY", "KEY_PURPOSE", "flash_encryption_key", "mkek", "device_key"):
        require(secret_marker not in status_get,
                f"maintenance status must not expose provisioning/key material: {secret_marker}")
    for label, body in (("config", config_post), ("lock", lock_post),
                        ("pairing", pairing_post), ("bond reset", bond_reset_post),
                        ("reboot", reboot_post)):
        require("consume_physical_presence" not in body,
                f"{label} must not add a second physical authorization inside maintenance")
        require("request_session_valid(req)" in body,
                f"{label} must use the common maintenance-session request policy")
    require("CONFIG_PICO_FIDO2_DEVELOPMENT_MAINTENANCE_OPEN" in request_session and
            "return true" in request_session and "csrf_valid(req)" in request_session,
            "development must bypass portal session authorization while production retains CSRF integrity")
    require("CONFIG_PICO_FIDO2_DEVELOPMENT_MAINTENANCE_OPEN=y" in development_defaults,
            "the dedicated development maintenance defaults must enable open maintenance mode")
    require("default n" in transport_kconfig and
            "config PICO_FIDO2_DEVELOPMENT_MAINTENANCE_OPEN" in transport_kconfig,
            "open maintenance must remain an explicit opt-in profile, not the production default")
    require("CONFIG_PICO_FIDO2_DEVELOPMENT_MAINTENANCE_OPEN" in dev_start and
            "development_maintenance_requested" in dev_start and
            "__atomic_store_n" in dev_start,
            "development mode must expose a software maintenance request without authorization")
    require("__atomic_exchange_n(&development_maintenance_requested" in task and
            "fido_wifi_start()" in task,
            "core0 must consume the development USB request and enter maintenance")
    require("fido_wifi_start()" not in init,
            "development mode must keep normal USB/BLE running until maintenance is requested")
    require("presses >= CONFIG_PICO_FIDO2_WIFI_COMMISSION_PRESSES" in button,
            "production mode must retain the physical multi-press maintenance entry")
    require("WIFI_AUTH_OPEN" in start and "WIFI_AUTH_WPA2_PSK" in start,
            "development and production SoftAP authentication modes must remain explicitly separated")
    require("mbedtls_platform_zeroize(new_lock" in lock_post,
            "configuration-lock replacement material must still be zeroized after use")

    management = text(WIFI_MANAGEMENT)
    transact = function_body(management, "transact")
    management_init = function_body(management, "fido_wifi_management_init")
    management_task = function_body(management, "fido_wifi_management_task")
    write_enabled = function_body(management, "write_enabled")
    write_lock = function_body(management, "write_lock")
    require("xSemaphoreCreateMutex()" in management_init,
            "Wi-Fi management must serialize HTTP request/response transactions")
    require("xSemaphoreTake(transaction_mutex" in transact and
            "xSemaphoreGive(transaction_mutex)" in transact,
            "Wi-Fi management transaction mutex must cover queue send/response receive")
    require("WIFI_MANAGEMENT_SET_LOCK" in management_task and
            "write_lock(&request)" in management_task,
            "configuration-lock writes must execute through the core0 management task")
    require("man_write_config_maintenance" in write_enabled and
            "man_write_config_maintenance" in write_lock,
            "maintenance portal writes must bypass the USB management lock after maintenance entry")
    before(management_task, "card_try_claim_maintenance()", "write_lock(&request)",
           "configuration-lock writes must claim the global maintenance owner first")
    before(management_task, "write_lock(&request)", "do_flash()",
           "configuration-lock writes must use the durable core0 flash barrier")
    require("WIFI_MANAGEMENT_RESET_BLE_BONDS" in management_task and
            "fido_ble_schedule_bond_reset()" in management_task,
            "BLE bond reset must be scheduled through the core0 management task")
    before(management_task, "card_try_claim_maintenance()", "fido_ble_schedule_bond_reset()",
           "BLE bond reset scheduling must claim the global maintenance owner first")
    for assignment in (
        "CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM=6",
        "CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM=12",
        "CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM=12",
    ):
        require(assignment in defaults,
                f"commissioning Wi-Fi defaults must retain bounded memory profile: {assignment}")
    require("PARTITION_TABLE" not in defaults,
            "Wi-Fi feature defaults must not own a flash partition layout")
    require('partitions.wireless.csv' in wireless_layout,
            "reversible wireless layout must select partitions.wireless.csv")
    for label, builder in (("initial secure", security_bundle), ("secure update", update_bundle)):
        require("sdkconfig.ble.defaults" in builder and "sdkconfig.wifi.defaults" in builder,
                f"{label} build must preserve BLE and Wi-Fi feature profiles")
        require("sdkconfig.security-preprovisioned.defaults" in builder,
                f"{label} build must retain the secure hardware profile")


def verify_ab_ota() -> None:
    portal = text(WIFI_COMMISSION)
    ota = text(WIFI_OTA)
    policy = text(WIFI_OTA_POLICY)
    defaults = text(SECURE_OTA_DEFAULTS)
    security_defaults = text(SECURITY_PREPROVISIONED_DEFAULTS)
    partitions = text(SECURE_OTA_PARTITIONS)
    transport_kconfig = text(TRANSPORT_KCONFIG)
    fido2_cmake = text(FIDO2_CMAKE)
    esp32_transports = text(ESP32_TRANSPORTS)
    update_post = function_body(portal, "update_post")
    begin = function_body(ota, "fido_ota_begin")
    finish = function_body(ota, "fido_ota_finish")
    confirm = function_body(ota, "fido_ota_boot_confirm_task")

    for line in (
        "otadata,  data, ota,     0x18000,  0x2000,    encrypted",
        "ota_0,    app,  ota_0,   0x20000,  0x170000",
        "ota_1,    app,  ota_1,   0x190000, 0x170000",
        "part0,    0x40, 0x1,     0x300000, 1M,        encrypted",
    ):
        require(line in partitions, f"secure A/B layout must retain exact partition contract: {line}")
    require("factory," not in partitions,
            "secure A/B layout must not contain a factory app partition")
    require("CONFIG_PICO_FIDO2_AB_OTA=y" in defaults and
            "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y" in defaults,
            "secure A/B profile must enable product OTA and ESP-IDF software rollback")
    require("# CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK is not set" in defaults,
            "secure A/B profile must not enable irreversible eFuse anti-rollback")
    ab_kconfig = transport_kconfig[
        transport_kconfig.index("config PICO_FIDO2_AB_OTA"):
        transport_kconfig.index("config PICO_FIDO2_OTA_CONFIRM_DELAY_SEC")
    ]
    require("depends on PICO_FIDO2_WIFI_COMMISSIONING" not in ab_kconfig,
            "A/B rollback/confirmation lifecycle must not depend on the Wi-Fi upload transport")
    require("CONFIG_PICO_FIDO2_AB_OTA" in fido2_cmake and
            "${CMAKE_CURRENT_LIST_DIR}/esp32_transports.c" in fido2_cmake,
            "A/B-only builds must retain the shared service-loop wrapper")
    require("CONFIG_PICO_FIDO2_AB_OTA" in esp32_transports and
            "fido_ota_boot_confirm_task()" in esp32_transports,
            "A/B-only builds must run boot confirmation without BLE or Wi-Fi")
    require("nvs_keys" not in partitions and
            "# CONFIG_NVS_ENCRYPTION is not set" in security_defaults,
            "recovery-first secure profile must keep NVS Encryption off until an nvs_keys partition exists")

    require("request_session_valid(req)" in update_post and
            "consume_physical_presence" not in update_post,
            "firmware upload must use the active maintenance session without a second BOOT confirmation")
    require("httpd_req_recv" in update_post and "fido_ota_write(&session" in update_post,
            "firmware upload must stream into the bounded OTA writer instead of buffering the image")

    require("esp_secure_boot_enabled()" in function_body(ota, "fido_ota_get_status") and
            "esp_flash_encryption_enabled()" in function_body(ota, "fido_ota_get_status"),
            "A/B updates must fail closed unless Secure Boot and Flash Encryption are active")
    before(begin, "card_try_claim_maintenance()", "esp_ota_begin(session->partition",
           "OTA writes must own the global card maintenance lease before erasing an inactive slot")
    require("esp_ota_abort(session->handle)" in function_body(ota, "fido_ota_abort"),
            "interrupted OTA sessions must explicitly abort the IDF update handle")
    before(finish, "esp_ota_end(session->handle)", "fido_ota_policy_check(",
           "Secure Boot image verification must complete before product downgrade policy")
    before(finish, "fido_ota_policy_check(", "esp_ota_set_boot_partition(session->partition)",
           "wrong-project or older signed images must be rejected before changing the boot slot")
    require("candidate_epoch < current_epoch" in policy,
            "software downgrade policy must reject a candidate signed epoch older than the running image")
    require("esp_ota_mark_app_valid_cancel_rollback()" in confirm and
            "CONFIG_PICO_FIDO2_OTA_CONFIRM_DELAY_SEC" in confirm,
            "a new OTA image must remain rollback-eligible until the service-loop stability delay expires")


def verify_emulator_arbiter() -> None:
    source = text(EMULATION)
    read = function_body(source, "emul_read")
    task = function_body(source, "emul_ccid_task")
    require("process_apdu()" not in read,
            "host emulator CCID receive path must not synchronously bypass the product arbiter")
    require("memcpy(emul_ccid_request, emul_rx, len)" in read,
            "host emulator must snapshot CCID request bytes before deferred execution")
    for reset in ("apdu_reset_warm_session(APDU_SESSION_CCID)", "apdu_reset_session(APDU_SESSION_CCID)"):
        reset_pos = read.index(reset)
        claim_pos = read.rfind("card_try_claim(ITF_CCID)", 0, reset_pos)
        release_pos = read.find("card_release(ITF_CCID)", reset_pos)
        require(claim_pos >= 0,
                "host emulator session reset must claim global APDU/application state")
        require(release_pos >= 0,
                "host emulator session reset must release global APDU/application state")
    before(task, "card_try_claim(ITF_CCID)", "apdu_process(APDU_SESSION_CCID",
           "host emulator CCID must claim the same global owner before APDU execution")
    before(task, "card_try_claim(ITF_CCID)", "card_start_claimed(ITF_CCID, apdu_thread)",
           "host emulator CCID worker start must remain owner-checked")
    require("uint16_t ret = finished_data_size" in task,
            "host emulator async completion must use the worker-produced response length")
    require("apdu_next()" not in task,
            "host emulator must not advance an async APDU response a second time")
    require("card_release(ITF_CCID)" in task,
            "host emulator CCID must release the shared owner after response completion")


def verify_runtime_ui_state() -> None:
    led_source = text(LED)
    config_source = text(CBOR_CONFIG)
    set_mode = function_body(led_source, "led_set_mode")
    get_mode = function_body(led_source, "led_get_mode")
    blink = function_body(led_source, "led_blinking_task")
    require("__atomic_store_n(&led_mode" in set_mode,
            "LED mode is written by workers and must use an atomic store")
    require("__atomic_load_n(&led_mode" in get_mode,
            "LED mode is read by the main task and must use an atomic load")
    require("uint32_t mode = led_get_mode()" in blink,
            "LED task must snapshot LED mode once per tick")
    require(re.search(r"\bled_mode\b", blink) is None,
            "LED task must not bypass the atomic led_get_mode snapshot")
    require("__atomic_load_n(&phy_data.opts" in blink,
            "runtime PHY options read by LED task must be atomic")
    require("__atomic_store_n(&phy_data.opts" in config_source,
            "runtime vendor PHY option updates must use an atomic store")


def verify_hid_adapter() -> None:
    source = text(HID)
    init = function_body(source, "driver_init_hid")
    callback = function_body(source, "tud_hid_set_report_cb")
    parser = function_body(source, "driver_process_usb_packet_hid")
    task = function_body(source, "hid_task")
    keepalive = function_body(source, "send_keepalive")
    queue_response = function_body(source, "hid_queue_response")
    async_finish = function_body(source, "driver_exec_finished_hid")
    finish = function_body(source, "driver_exec_finished_cont_hid")

    for forbidden in (
        "ctap_req = (CTAPHID_FRAME *) (hid_rx",
        "apdu.header =",
        "apdu.rdata =",
        "memset(ctap_resp",
        "hid_tx[ITF_HID_CTAP].w_ptr =",
    ):
        require(forbidden not in init, f"HID init mutates shared/response state before claim: {forbidden}")

    require(
        "driver_process_usb_packet_hid" not in callback,
        "TinyUSB RX callback must only enqueue data; it must not enter core parsing directly",
    )
    require(
        "sizeof(hid_rx[itf].buffer)" in callback,
        "HID RX enqueue must bounds-check the ring storage",
    )

    require(
        "card_command_is_owned_by(ITF_HID)" in parser,
        "HID parser must refuse ordinary input while its worker owns the command",
    )
    require("memcpy(&ctap_req_snapshot, rx_req, sizeof(ctap_req_snapshot))" in parser,
            "HID must snapshot each report before releasing reusable RX ring storage")
    before(parser,
           "if (!card_is_idle())",
           "memcpy(&ctap_req_snapshot, rx_req, sizeof(ctap_req_snapshot))",
           "HID must arbitrate an existing owner before overwriting the worker-visible request snapshot")
    require("ctap_error_for_cid(rx_req->cid, CTAP1_ERR_CHANNEL_BUSY)" in parser,
            "HID foreign-owner BUSY response must use the incoming RX CID without borrowing worker snapshot state")
    snapshot_pos = parser.index("memcpy(&ctap_req_snapshot, rx_req, sizeof(ctap_req_snapshot))")
    owner_guard_pos = parser.index("if (!card_is_idle())")
    busy_prefix = parser[owner_guard_pos:snapshot_pos]
    require("ctap_req_snapshot" not in busy_prefix,
            "HID BUSY/CANCEL handling must not overwrite or borrow the active worker snapshot")
    normal_release_pos = parser.find("hid_rx[ITF_HID_CTAP].r_ptr += 64", snapshot_pos)
    require(normal_release_pos > snapshot_pos,
            "HID normal path must snapshot the report before releasing reusable RX ring storage")
    require("ctap_req = &ctap_req_snapshot" in parser,
            "HID parser must read the stable report snapshot, not the RX ring")
    before(parser, "if (!card_is_idle())", "hid_prepare_response()",
           "HID must arbitrate foreign owners before mutating response/transaction state")
    require("static void hid_abort_transaction(void)" in source,
            "HID must have one explicit transaction-abort boundary")
    init_block = parser[parser.find("ctap_req->init.cmd == CTAPHID_INIT") :
                        parser.find("ctap_req->init.cmd == CTAPHID_WINK")]
    before(init_block, "card_try_claim(ITF_HID)", "card_exit_claimed(ITF_HID)",
           "CTAPHID_INIT may replace a parked worker only after acquiring the HID owner")
    before(parser, "if (!card_is_idle())", "card_exit_claimed(ITF_HID)",
           "worker exit must be unreachable while a command/completion still owns the core")
    busy_claims = re.findall(
        r"if \(!card_try_claim\(ITF_HID\)\) \{\s*hid_abort_transaction\(\);\s*return ctap_error\(CTAP1_ERR_CHANNEL_BUSY\);\s*\}",
        parser,
        re.S,
    )
    require(len(busy_claims) == 3,
            "every completed HID request that loses owner arbitration must abort stale transaction state")
    require("hid_tx_idle()" in parser, "HID parser must not reuse response storage while TX is active")
    require("hid_prepare_response()" in parser, "HID response storage must be prepared only at safe parse time")

    require(
        re.search(r"apdu_process\([^;]*msg_packet\.data\s*,\s*msg_packet\.len\s*\)", parser) is not None,
        "HID APDU worker request must use stable msg_packet storage",
    )
    require(
        re.search(r"cbor_process\([^;]*msg_packet\.data\s*,\s*msg_packet\.len\s*\)", parser) is not None,
        "HID CBOR worker request must use stable msg_packet storage",
    )
    require(
        "apdu_process(APDU_SESSION_HID, ITF_HID_CTAP, ctap_req->init.data" not in parser,
        "HID APDU worker must not borrow reusable RX report storage",
    )
    require(
        "cbor_process(last_cmd, ctap_req->init.data" not in parser,
        "HID CBOR worker must not borrow reusable RX report storage",
    )

    before(
        parser,
        "card_try_claim(ITF_HID)",
        "apdu.rdata = ctap_resp->init.data",
        "HID APDU response context must be bound only after claim",
    )
    require("active_cid = last_req.cid" in parser, "HID must snapshot CID for async response")
    require("active_cmd = last_cmd" in parser, "HID must snapshot command for async response")
    require("active_cid" in keepalive and "ctap_req->cid" not in keepalive, "HID keepalive must use snapshotted CID")
    require("ctap_resp->cid = cid" in queue_response and "ctap_resp->init.cmd = cmd" in queue_response,
            "HID response primitive must take header ownership explicitly")
    require("hid_queue_response(ITF_HID_CTAP, active_cid, active_cmd" in async_finish,
            "HID async completion must use the worker response snapshot")
    require("hid_queue_response(itf, active_cid, active_cmd" in finish,
            "HID APDU continuation must use the worker response snapshot")
    require("offset -= 7" not in finish,
            "HID continuation offset must not use the legacy underflow-prone header magic")

    ping_begin = parser.index("else if ((last_cmd == CTAPHID_PING || last_cmd == CTAPHID_SYNC)")
    ping_end = parser.index("else if (ctap_req->init.cmd == CTAPHID_LOCK)", ping_begin)
    ping = parser[ping_begin:ping_end]
    require("hid_queue_response(ITF_HID_CTAP, last_req.cid, last_cmd" in ping,
            "HID synchronous PING/SYNC response must use the current transaction snapshot")
    require("active_cid" not in ping and "active_cmd" not in ping,
            "HID synchronous response must not borrow a stale async worker header")

    before(
        task,
        "card_status(ITF_HID)",
        "driver_process_usb_packet_hid(64)",
        "HID task must collect worker completion before consuming another RX report",
    )
    require(
        "hid_tx_idle()" in task,
        "HID task must wait for transport-owned TX to drain before reusing response storage",
    )


def verify_ccid_adapter() -> None:
    source = text(CCID)
    init = function_body(source, "driver_init_ccid")
    rx_callback = function_body(source, "tud_vendor_rx_cb")
    fast_write = function_body(source, "ccid_write_fast")
    parser = function_body(source, "driver_process_usb_packet_ccid")
    task = function_body(source, "ccid_task")
    timeout = function_body(source, "driver_exec_timeout_ccid")
    finish = function_body(source, "driver_exec_finished_cont_ccid")
    fast_finish = function_body(source, "driver_exec_finished_fast_ccid")

    require(
        "ccid_response[itf] =" not in init,
        "CCID init must not bind mutable response storage before command claim",
    )
    require(
        "sizeof(ccid_rx[itf].buffer) - ccid_rx[itf].w_ptr" in rx_callback,
        "CCID RX callback must cap reads to remaining ring capacity",
    )
    require(
        "driver_process_usb_packet_ccid" not in rx_callback,
        "CCID TinyUSB RX callback must only enqueue bytes; parsing belongs to the main transport task",
    )
    require(
        "driver_process_usb_packet_ccid" in task,
        "CCID main task must be the only runtime consumer of the RX ring",
    )
    before(task,
           "card_command_is_owned_by(sc_itf_to_usb_itf(itf))",
           "driver_process_usb_packet_ccid",
           "CCID must not parse a second request while its worker still owns the active request snapshot")
    owner_guard = task[task.find("card_command_is_owned_by(sc_itf_to_usb_itf(itf))") :
                       task.find("driver_process_usb_packet_ccid")]
    require("continue" in owner_guard,
            "CCID owner guard must stop parsing until the active worker releases request ownership")
    require(
        "driver_write_ccid" not in fast_write,
        "CCID fast scratch packets must not advance the normal TX ring",
    )
    require(
        "ccid_tx[itf].r_ptr" not in fast_write and "ccid_tx[itf].w_ptr" not in fast_write,
        "CCID fast writer must not mutate normal TX ring cursors",
    )

    xfr = parser[parser.find("CCID_XFR_BLOCK") :]
    before(
        xfr,
        "card_try_claim(usb_itf)",
        "ccid_response[itf] =",
        "CCID XFR response storage must be bound only after claim",
    )
    before(
        xfr,
        "card_try_claim(usb_itf)",
        "apdu.rdata =",
        "CCID XFR APDU response pointer must be bound only after claim",
    )
    require("memcpy(ccid_request[itf].buffer, ccid_header[itf], frame_len)" in parser,
            "CCID must snapshot the complete message before releasing RX ring storage")
    release_pos = parser.find("ccid_rx[itf].r_ptr += frame_len")
    require(release_pos >= 0, "CCID parser must explicitly release snapshotted RX storage")
    complete_tail = parser[release_pos:]
    require("ccid_header[itf]" not in complete_tail,
            "CCID parser must not read mutable RX header after releasing ring storage")
    require(
        "ccid_active_seq[itf] = request->bSeq" in xfr,
        "CCID must snapshot bSeq from the stable request copy while it owns the command",
    )
    require(
        "ccid_response[itf]->bSeq = ccid_active_seq[itf]" in xfr,
        "CCID response must bind the snapshotted bSeq",
    )
    require(
        re.search(r"apdu_process\([^;]*&request->apdu\s*,\s*apdu_len\s*\)", xfr) is not None,
        "CCID worker must not borrow the reusable RX ring",
    )
    require(
        "ccid_header[itf]->bSeq" not in finish,
        "CCID async completion must not read the current mutable RX header",
    )
    require("ccid_active_seq[itf]" in finish, "CCID final response must use snapshotted sequence")
    require("ccid_header[itf]->bSeq" not in timeout and "ccid_active_seq[itf]" in timeout,
            "CCID TIMEEXT must use the active command sequence")
    require("ccid_header[itf]->bSeq" not in fast_finish and "ccid_active_seq[itf]" in fast_finish,
            "CCID synchronous continuation must use the active command sequence")

    power_on = parser[parser.find("CCID_POWER_ON") : parser.find("CCID_POWER_OFF")]
    power_off = parser[parser.find("CCID_POWER_OFF") : parser.find("CCID_SET_PARAMS")]
    for label, block in (("POWER_ON", power_on), ("POWER_OFF", power_off)):
        before(
            block,
            "card_try_claim(usb_itf)",
            "apdu_reset_session",
            f"CCID {label} must claim global APDU/application state before session reset",
        )
        require("card_release(usb_itf)" in block, f"CCID {label} must release its claim")


def verify_apdu_sessions() -> None:
    source = text(APDU)
    session_struct = source[source.find("typedef struct apdu_session_state") : source.find("} apdu_session_state_t;")]
    require("response_buf[" in session_struct, "GET RESPONSE cache must be session-owned storage")
    require("uint8_t *response_data" not in session_struct, "GET RESPONSE cache must not borrow transport TX pointers")
    require("uint8_t *response_next" not in session_struct, "GET RESPONSE cursor must be an offset, not a transport pointer")
    require("response_offset" in session_struct, "GET RESPONSE must use session-relative offsets")


def verify_ble_adapter() -> None:
    source = text(BLE)
    dispatch = function_body(source, "fido_ble_dispatch")
    write = function_body(source, "fido_ble_control_point_write")
    gap = function_body(source, "fido_ble_gap_event")
    release = function_body(source, "fido_ble_release_request")
    reducer = function_body(source, "fido_ble_handle_event")
    task = function_body(source, "fido_ble_task")
    queue_event = function_body(source, "fido_ble_queue_event")
    overflow = function_body(source, "fido_ble_recover_event_overflow")

    require("FIDO_BLE_CORE_IDLE" in source and "FIDO_BLE_CORE_RUNNING" in source and "FIDO_BLE_CORE_ABORTED" in source,
            "BLE core lifecycle must use an explicit enum state")
    require(re.search(r"\bprocessing\b", source) is None, "BLE must not regress to an independent processing boolean")
    require(re.search(r"\bprocessing_aborted\b", source) is None, "BLE must not regress to an independent aborted boolean")
    require("__atomic_store_n(&event_overflow" in queue_event,
            "BLE event queue overflow must become a sticky fail-closed fault, not a dropped event")
    require("__atomic_exchange_n(&event_overflow" in overflow,
            "BLE core task must consume the sticky event-overflow fault")
    require("FIDO_BLE_CORE_ABORTED" in overflow and "button_cancel_request()" in overflow,
            "BLE event overflow during execution must abort the owned command")
    require("fido_ble_release_request()" in overflow,
            "BLE event overflow while idle must release any retained RX ownership token")
    before(task, "fido_ble_recover_event_overflow()", "fido_ble_process_events()",
           "BLE must fail closed on queue overflow before consuming later events")

    before(dispatch, "card_try_claim(ble_itf)", "cbor_process_to", "BLE must claim shared CBOR context before binding it")
    require("xQueueCreate(1, sizeof(fido_ble_request_t))" in source,
            "BLE request queue must remain capacity one so its entry is the RX ownership token")
    require("xQueuePeek(request_queue" in task,
            "BLE main task must peek, not consume, the request while worker/TX still owns RX data")
    require("xQueueReceive(request_queue" in release and "fido_ble_rx_reset(&rx)" in release,
            "BLE request release must atomically consume the ownership token and clear RX")
    require("rx_mutex" in release, "BLE RX ownership-token release must synchronize with the GATT task")
    require("fido_ble_request_pending()" in write,
            "BLE GATT writer must reject reuse while a request ownership token exists")
    for forbidden in ("core_state", "card_try_claim", "card_start_claimed", "card_status", "card_release", "tx_active", "tx_waiting"):
        require(forbidden not in write, f"BLE GATT write callback must not enter main/core state: {forbidden}")
        require(forbidden not in gap, f"BLE GAP callback must only publish events, not mutate main/core state: {forbidden}")
    require("fido_ble_queue_event" in gap, "BLE GAP callback must publish lifecycle events to the main reducer")
    require("FIDO_BLE_EVENT_CANCEL" in write, "BLE cancel must be serialized through the event queue")
    require("core_state = FIDO_BLE_CORE_RUNNING" in dispatch,
            "BLE main-thread dispatch must own the RUNNING transition")
    running_tail = dispatch[dispatch.find("core_state = FIDO_BLE_CORE_RUNNING") :]
    require("fido_ble_release_request" not in running_tail,
            "BLE worker-owned RX token must not be released at dispatch time")
    require("FIDO_BLE_CORE_ABORTED" in reducer and "button_cancel_request" in reducer,
            "BLE reducer must serialize disconnect/unsubscribe cancellation")
    require("FIDO_BLE_CORE_ABORTED" in task, "BLE task must explicitly complete aborted workers")
    notify_pos = task.find("fido_ble_notify(FIDO_BLE_CMD_MSG")
    require(notify_pos >= 0, "BLE normal completion must queue the response into private TX storage")
    release_after_notify = task.find("card_release(ble_itf)", notify_pos)
    require(
        release_after_notify > notify_pos,
        "BLE normal completion must copy response into transport-owned TX payload before release",
    )


def verify_ble_pairing_security() -> None:
    source = text(BLE)
    gap = function_body(source, "fido_ble_gap_event")
    access = function_body(source, "fido_ble_access")
    init = function_body(source, "fido_ble_init")
    schedule_actions = function_body(source, "fido_ble_schedule_actions")
    schedule = function_body(source, "fido_ble_schedule_pairing_window")
    schedule_reset = function_body(source, "fido_ble_schedule_bond_reset")
    clear_bonds = function_body(source, "fido_ble_clear_all_bonds")
    wifi_management = text(WIFI_MANAGEMENT)
    wifi_task = function_body(wifi_management, "fido_wifi_management_task")
    wifi_allow = function_body(wifi_management, "fido_wifi_management_allow_ble_pairing")
    wifi_reset = function_body(wifi_management, "fido_wifi_management_reset_ble_bonds")
    defaults = text(BLE_DEFAULTS)

    require("CONFIG_BT_NIMBLE_NVS_PERSIST=y" in defaults,
            "BLE security must persist bond records across reboot")
    require("fido_ble_pairing_access_allowed(&pairing_policy)" in access,
            "FIDO GATT access must fail closed until the connection is pairing-authorized")
    require("BLE_ATT_ERR_INSUFFICIENT_AUTHOR" in access,
            "unauthorized BLE FIDO access must return an explicit ATT authorization failure")
    require("fido_ble_peer_is_bonded" in gap and
            "#if CONFIG_PICO_FIDO2_DEVELOPMENT_MAINTENANCE_OPEN" in gap and
            "known_bond = true" in gap,
            "production BLE reconnect must use bonds while development can bypass the pairing grant")
    require("#if !CONFIG_PICO_FIDO2_DEVELOPMENT_MAINTENANCE_OPEN" in gap and
            "fido_ble_pairing_repeat_allowed" in gap,
            "repeat-pairing grant enforcement must remain active outside the development profile")
    require("BLE_GAP_EVENT_PARING_COMPLETE" in gap and
            "BLE_GAP_EVENT_ENC_CHANGE" in gap,
            "fresh-pair rejection must track NimBLE pairing completion through post-persist encryption change")
    pairing_pos = gap.find("case BLE_GAP_EVENT_PARING_COMPLETE")
    enc_pos = gap.find("case BLE_GAP_EVENT_ENC_CHANGE")
    delete_pos = gap.find("ble_store_util_delete_peer", pairing_pos)
    require(pairing_pos >= 0 and enc_pos > pairing_pos and delete_pos > enc_pos,
            "unauthorized bond deletion must occur after NimBLE persistence, not in pairing-complete callback")
    require("ble_gap_terminate" in gap[enc_pos:],
            "an unauthorized fresh bond must be disconnected after its persisted record is removed")
    before(init, "ble_store_config_init()", "FIDO_BLE_BOND_RESET_NVS_KEY",
           "persistent bonds must be restored before a scheduled reset is consumed")
    before(init, "FIDO_BLE_BOND_RESET_NVS_KEY", "fido_ble_clear_all_bonds()",
           "the reset flag must be consumed before deleting persisted bonds")
    before(init, "fido_ble_clear_all_bonds()", "FIDO_BLE_PAIRING_NVS_KEY",
           "old bonds must be revoked before the fresh-pairing grant is consumed")
    before(init, "FIDO_BLE_PAIRING_NVS_KEY", "nimble_port_freertos_init",
           "the one-time pairing grant must be consumed before BLE begins accepting connections")
    require("ble_store_util_bonded_peers" in clear_bonds and
            "ble_store_util_delete_peer" in clear_bonds,
            "bond reset must enumerate the persistent bond store and delete each peer")
    require("if (!reset_ok)" in init and "pairing_grant = false" in init,
            "an incomplete bond reset must fail closed and suppress fresh pairing")
    require("nvs_set_u8" in schedule_actions and "nvs_commit" in schedule_actions,
            "maintenance BLE actions must be durable before reboot")
    require("fido_ble_schedule_actions(true, false)" in schedule,
            "normal pairing grant must schedule pairing without bond reset")
    require("fido_ble_schedule_actions(true, true)" in schedule_reset,
            "bond reset must atomically schedule both revocation and one fresh-pairing window")
    require("WIFI_MANAGEMENT_ALLOW_BLE_PAIRING" in wifi_allow,
            "the HTTP pairing action must enter the serialized core0 management queue")
    require("WIFI_MANAGEMENT_RESET_BLE_BONDS" in wifi_reset,
            "the HTTP bond reset action must enter the serialized core0 management queue")
    before(wifi_task, "card_try_claim_maintenance()", "fido_ble_schedule_pairing_window()",
           "pairing-grant persistence must execute under the global maintenance owner")


def verify_otp_hid_adapter() -> None:
    source = text(OTP)
    set_report = function_body(source, "otp_hid_set_report_cb")
    get_report = function_body(source, "otp_hid_get_report_cb")

    before(
        set_report,
        "card_try_claim(ITF_KEYBOARD)",
        "apdu.header = hdr",
        "OTP HID command path must claim shared APDU state before binding request context",
    )
    before(
        set_report,
        "card_try_claim(ITF_KEYBOARD)",
        "otp_process_apdu()",
        "OTP HID command path must claim before synchronous APDU execution",
    )
    require("struct apdu saved_apdu = apdu" in set_report, "OTP HID command must preserve prior APDU context")
    require("apdu = saved_apdu" in set_report, "OTP HID command must restore APDU context before release")
    before(
        set_report,
        "apdu = saved_apdu",
        "card_release(ITF_KEYBOARD)",
        "OTP HID command must restore APDU context before releasing owner",
    )

    before(
        get_report,
        "card_try_claim(ITF_KEYBOARD)",
        "res_APDU = buffer",
        "OTP HID status path must claim shared APDU state before binding response context",
    )
    require("struct apdu saved_apdu = apdu" in get_report, "OTP HID status must preserve prior APDU context")
    require("apdu = saved_apdu" in get_report, "OTP HID status must restore APDU context")
    before(
        get_report,
        "apdu = saved_apdu",
        "card_release(ITF_KEYBOARD)",
        "OTP HID status must restore APDU context before releasing owner",
    )


def verify_piv_slot_storage() -> None:
    source = text(PIV)
    x509_create = function_body(source, "x509_create_cert")
    get_metadata = function_body(source, "cmd_get_metadata")
    authenticate = function_body(source, "cmd_authenticate")
    keygen = function_body(source, "cmd_asym_keygen")
    move_key = function_body(source, "cmd_move_key")
    import_key = function_body(source, "cmd_import_asym")

    require(
        source.count("key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref") == 1,
        "PIV logical slot 0x93 mapping must exist only inside piv_key_storage_fid",
    )
    require("piv_key_storage_fid" in get_metadata,
            "PIV GET_METADATA must resolve the logical slot through storage mapping")
    require("key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK" in get_metadata and
            "? key_ref" in get_metadata,
            "PIV PIN/PUK GET_METADATA must preserve their full 16-bit file identifiers")
    require("while (serial_offset + 1 < sizeof(serial) && serial[serial_offset] == 0)" in x509_create,
            "PIV X.509 serials must strip random leading zero octets before DER INTEGER encoding")
    require("serial[serial_offset] = 1" in x509_create,
            "PIV X.509 serial generation must turn the all-zero value into a positive non-zero INTEGER")
    require("serial + serial_offset" in x509_create and
            "sizeof(serial) - serial_offset" in x509_create,
            "PIV X.509 serial writer must receive the canonicalized serial span")
    require(authenticate.count("piv_key_storage_fid(key_ref)") >= 3,
            "PIV authenticate/ECDH paths must resolve private-key storage through one mapping")
    require("piv_key_storage_fid(key_ref)" in keygen,
            "PIV generated keys must use the logical-to-physical storage mapping")
    require("piv_key_storage_fid(from_ref)" in move_key and
            "piv_key_storage_fid(to_ref)" in move_key,
            "PIV move/delete-key must map both source and destination logical slots")
    require("piv_key_storage_fid(key_ref)" in import_key,
            "PIV imported keys must use the logical-to-physical storage mapping")


def verify_credential_ownership() -> None:
    credential = text(CREDENTIAL)
    assertion = text(GET_ASSERTION)
    make_credential = text(MAKE_CREDENTIAL)
    move = function_body(credential, "credential_move")
    get_assertion = function_body(assertion, "cbor_get_assertion")
    make = function_body(make_credential, "cbor_make_credential")

    before(move, "credential_free(dst)", "*dst = *src",
           "Credential move must release any previous destination ownership before transfer")
    before(move, "*dst = *src", "memset(src, 0, sizeof(*src))",
           "Credential move must clear the source immediately after transferring owned pointers")
    require("creds[numberOfCredentials++] = creds[i]" not in get_assertion,
            "GetAssertion compaction must not shallow-copy owned Credential values")
    require("credsx[i] = creds[i]" not in get_assertion,
            "GetNextAssertion transfer must not duplicate Credential ownership")
    require(get_assertion.count("credential_move(&creds[numberOfCredentials], &creds[i])") == 2,
            "both GetAssertion compaction branches must use explicit Credential move semantics")
    require("credential_move(&credsx[i], &creds[i])" in get_assertion,
            "GetNextAssertion retained credentials must receive ownership through credential_move")

    for label, body in (("GetAssertion", get_assertion), ("MakeCredential", make)):
        cleanup = body.find("err:")
        require(cleanup >= 0, f"{label} must have one common cleanup boundary")
        for ret in re.finditer(r"\breturn\b", body):
            require(ret.start() > cleanup,
                    f"{label} static request-owned storage must not bypass cleanup with an early return")

    require("static PublicKeyCredentialDescriptor allowList" in get_assertion and
            "static Credential creds" in get_assertion,
            "GetAssertion large request-owned arrays must stay outside the worker task stack")
    require("memset(allowList, 0, sizeof(allowList))" in get_assertion and
            "memset(creds, 0, sizeof(creds))" in get_assertion,
            "GetAssertion static owned arrays must be cleared at request boundaries")
    require("static uint8_t aut_data[CTAP_MAX_CBOR_PAYLOAD]" in make and
            "static uint8_t cred_id[MAX_CRED_ID_LENGTH]" in make and
            "static uint8_t cbor_buf[1024]" in make,
            "MakeCredential large request scratch must stay outside the worker task stack")
    require(make.count("mbedtls_platform_zeroize(aut_data, sizeof(aut_data))") >= 2 and
            make.count("mbedtls_platform_zeroize(cred_id, sizeof(cred_id))") >= 2 and
            make.count("mbedtls_platform_zeroize(cbor_buf, sizeof(cbor_buf))") >= 2,
            "MakeCredential static scratch must be zeroized on both entry and cleanup")


def verify_allocation_boundaries() -> None:
    cmake = text(CMAKE)
    usb = text(USB)
    hid = text(HID)
    ccid = text(CCID)
    ble = text(BLE)
    credential = text(CREDENTIAL)

    require("set(DEBUG_APDU 1)" not in cmake,
            "product builds must not enable protocol payload dumps by default")

    for label, source in (("USB core", usb), ("HID", hid), ("CCID", ccid), ("BLE", ble)):
        require(re.search(r"\b(?:malloc|calloc|realloc)\s*\(", source) is None,
                f"{label} runtime transport state must use deterministic static storage, not heap allocation")

    require("CARD_INTERFACE_CAPACITY = 8" in text(USB_H),
            "logical transport registration must have an explicit fixed capacity")
    require("HID_TRANSPORT_CAPACITY = 2" in text(USB_H),
            "HID transport storage capacity must be explicit")
    require("CCID_TRANSPORT_CAPACITY = 2" in text(USB_H),
            "CCID transport storage capacity must be explicit")
    require("if (ITF_TOTAL >= CARD_INTERFACE_CAPACITY)" in function_body(usb, "card_register_interface"),
            "extra transport registration must reject capacity exhaustion")
    require("assert(ble_itf != ITF_INVALID)" in function_body(ble, "fido_ble_init"),
            "BLE initialization must treat interface registration failure as a hard invariant")

    fido_dir = ROOT / "pico-fido" / "src" / "fido"
    allocations: list[tuple[Path, str]] = []
    for path in sorted(fido_dir.glob("*.c")):
        for match in re.finditer(r"\b(?:malloc|calloc|realloc)\s*\([^;]*", text(path)):
            allocations.append((path, match.group(0)))
    require(len(allocations) == 1,
            f"common FIDO protocol code must have exactly one explicit owned allocation, found {allocations}")
    allocation_path, allocation = allocations[0]
    require(allocation_path == CREDENTIAL and "calloc(1, cred_id_len)" in allocation,
            "the only common FIDO heap allocation must be Credential.id owned storage")

    load = function_body(credential, "credential_load")
    before(load, "cred->id.data = (uint8_t *) calloc(1, cred_id_len)",
           "if (cred->id.data == NULL && cred_id_len != 0)",
           "Credential.id allocation must be checked before copying into owned storage")
    before(load, "if (cred->id.data == NULL && cred_id_len != 0)",
           "memcpy(cred->id.data, cred_id, cred_id_len)",
           "Credential.id must never be dereferenced before allocation success")


def verify_protocol_buffer_bounds() -> None:
    assertion = text(GET_ASSERTION)
    ctap_h = text(CTAP_H)
    authenticate = function_body(text(AUTHENTICATE), "cmd_authenticate")

    require("uint8_t datax[CTAP_MAX_CBOR_PAYLOAD]" in assertion,
            "GetNextAssertion must retain the complete negotiated CTAP CBOR payload, not MAX_MSG_SIZE")
    require("#define CTAP_MAX_KH_SIZE         255" in ctap_h,
            "U2F key-handle storage must match the one-byte wire length range")
    require("uint8_t tmp_kh[CTAP_MAX_KH_SIZE]" in authenticate,
            "U2F in-place credential verification must use a full wire-capacity scratch copy")
    require("apdu.nc != CTAP_CHAL_SIZE + CTAP_APPID_SIZE + 1 + req->keyHandleLen" in authenticate,
            "U2F Authenticate must require the actual APDU payload to exactly match keyHandleLen")


def main() -> None:
    checks = (
        ("product SDK binding", verify_product_sdk_binding),
        ("global arbiter", verify_arbiter),
        ("button signals", verify_button_signals),
        ("HWRNG state", verify_hwrng_state),
        ("Wi-Fi commissioning", verify_wifi_commissioning),
        ("A/B OTA", verify_ab_ota),
        ("emulator arbiter", verify_emulator_arbiter),
        ("runtime UI state", verify_runtime_ui_state),
        ("HID ownership", verify_hid_adapter),
        ("CCID ownership", verify_ccid_adapter),
        ("APDU session storage", verify_apdu_sessions),
        ("BLE ownership", verify_ble_adapter),
        ("BLE pairing security", verify_ble_pairing_security),
        ("OTP HID ownership", verify_otp_hid_adapter),
        ("PIV slot storage", verify_piv_slot_storage),
        ("Credential ownership", verify_credential_ownership),
        ("allocation boundaries", verify_allocation_boundaries),
        ("protocol buffer bounds", verify_protocol_buffer_bounds),
    )
    for label, check in checks:
        check()
        print(f"{label}: PASS")


if __name__ == "__main__":
    main()
