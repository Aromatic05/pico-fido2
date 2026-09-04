if(CONFIG_PICO_FIDO2_SINGLE_SLOT_ANTI_ROLLBACK)
    idf_component_register(
        SRCS "anti_rollback.c"
        INCLUDE_DIRS
            "$ENV{IDF_PATH}/components/bootloader_support/include"
            "$ENV{IDF_PATH}/components/bootloader_support/private_include"
            "$ENV{IDF_PATH}/components/esp_app_format/include"
            "$ENV{IDF_PATH}/components/efuse/include"
            "$ENV{IDF_PATH}/components/efuse/esp32s3/include"
        WHOLE_ARCHIVE
    )
    target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=bootloader_utility_load_boot_image")
else()
    idf_component_register()
endif()
