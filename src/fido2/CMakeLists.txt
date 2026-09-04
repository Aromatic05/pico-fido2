list(APPEND SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/usb_policy.c
    ${CMAKE_CURRENT_LIST_DIR}/app_policy.c
)

idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS . ../../pico-keys-sdk/src ../../pico-keys-sdk/src/fs ../../pico-keys-sdk/src/rng ../../pico-keys-sdk/src/usb  ../../pico-keys-sdk/tinycbor/src ../../pico-fido/src ../../pico-openpgp/src
    REQUIRES esp_tinyusb mbedtls efuse
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
