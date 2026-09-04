if(CONFIG_PICO_FIDO2_BLE)
    list(APPEND SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/ble_fido.c
        ${CMAKE_CURRENT_LIST_DIR}/ble_fido_frame.c
    )
endif()

# ESP-IDF resolves component dependencies before project Kconfig values are
# available, so optional transport dependencies cannot be conditional here.
idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS . ../../pico-keys-sdk/src ../../pico-keys-sdk/src/fs ../../pico-keys-sdk/src/rng ../../pico-keys-sdk/src/usb  ../../pico-keys-sdk/tinycbor/src ../../pico-fido/src ../../pico-openpgp/src
    REQUIRES esp_tinyusb mbedtls efuse bt nvs_flash
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
