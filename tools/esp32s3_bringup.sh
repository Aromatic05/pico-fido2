#!/usr/bin/env bash
set -euo pipefail

mode="${1:-build}"
port="${2:-}"
build_dir="${BUILD_DIR:-build-bringup-wireless}"
sdkconfig="${SDKCONFIG:-sdkconfig.bringup-wireless}"
defaults='sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.ble.defaults;sdkconfig.wifi.defaults'

case "$mode" in
    build|flash) ;;
    *) echo "usage: $0 [build|flash [PORT]]" >&2; exit 2 ;;
esac

if ! command -v idf.py >/dev/null 2>&1; then
    echo "idf.py not found; activate ESP-IDF 5.5 first" >&2
    exit 2
fi

SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" set-target esp32s3

require_config() {
    local pattern="$1"
    local description="$2"
    if ! grep -qx "$pattern" "$sdkconfig"; then
        echo "unsafe bring-up config: expected $description" >&2
        exit 3
    fi
}

reject_config() {
    local pattern="$1"
    local description="$2"
    if grep -qx "$pattern" "$sdkconfig"; then
        echo "unsafe bring-up config: $description is enabled" >&2
        exit 3
    fi
}

require_config 'CONFIG_PICOKEYS_ESP32_DEV_KEYS=y' 'development root keys'
require_config 'CONFIG_PICO_FIDO2_BLE=y' 'FIDO BLE transport'
require_config 'CONFIG_PICO_FIDO2_WIFI_COMMISSIONING=y' 'Wi-Fi commissioning'
require_config 'CONFIG_APP_REPRODUCIBLE_BUILD=y' 'reproducible application build'
require_config 'CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM=6' 'bounded Wi-Fi static RX buffers'
require_config 'CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM=12' 'bounded Wi-Fi dynamic RX buffers'
require_config 'CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM=12' 'bounded Wi-Fi dynamic TX buffers'
require_config 'CONFIG_PM_ENABLE=y' 'runtime power management'
require_config 'CONFIG_BT_CTRL_MODEM_SLEEP=y' 'Bluetooth modem sleep'
require_config 'CONFIG_BT_CTRL_DFT_TX_POWER_LEVEL_N0=y' '0 dBm Bluetooth transmit power'
require_config 'CONFIG_PICO_FIDO2_WIFI_IDLE_TIMEOUT_SEC=300' 'bounded Wi-Fi maintenance timeout'
reject_config 'CONFIG_FREERTOS_USE_TICKLESS_IDLE=y' 'automatic light sleep'
reject_config 'CONFIG_SECURE_BOOT=y' 'Secure Boot'
reject_config 'CONFIG_SECURE_FLASH_ENC_ENABLED=y' 'Flash Encryption'

SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" build

(
    cd "$build_dir"
    python -m esptool --chip esp32s3 merge_bin -o pico_fido2_bringup.bin @flash_args
    sha256sum pico_fido2_bringup.bin pico_fido2.bin
)

if [[ "$mode" == flash ]]; then
    if [[ -z "$port" ]]; then
        echo "flash mode requires a serial port, for example /dev/ttyACM0" >&2
        exit 2
    fi
    SDKCONFIG_DEFAULTS="$defaults" idf.py -B "$build_dir" -DSDKCONFIG="$sdkconfig" -p "$port" flash
fi
