#!/usr/bin/env bash

prepare_maintenance_profile_defaults() {
    local profile="$1"
    local out_dir="$2"
    case "$profile" in
        development)
            printf '%s\n' 'sdkconfig.development-maintenance.defaults'
            ;;
        production)
            local defaults="$out_dir/.production-maintenance.defaults"
            umask 077
            {
                printf '# CONFIG_PICO_FIDO2_DEVELOPMENT_MAINTENANCE_OPEN is not set\n'
                printf '# CONFIG_PICO_FIDO2_DEVELOPMENT_INSECURE_OTA is not set\n'
                # Select the Kconfig destination, not the derived ENABLE
                # symbol. Never expose authenticator RAM through UART.
                printf '# CONFIG_ESP_COREDUMP_ENABLE_TO_UART is not set\n'
                printf 'CONFIG_ESP_COREDUMP_ENABLE_TO_NONE=y\n'
                printf 'CONFIG_PICO_FIDO2_WIFI_SSID_PREFIX="Aromatic-Key"\n'
                printf 'CONFIG_PICO_FIDO2_WIFI_PASSWORD="Aromatic-Key"\n'
                printf 'CONFIG_PICO_FIDO2_WIFI_IDLE_TIMEOUT_SEC=600\n'
            } >"$defaults"
            printf '%s\n' "$defaults"
            ;;
        *)
            echo "unknown maintenance profile: $profile" >&2
            return 1
            ;;
    esac
}

assert_maintenance_profile() {
    local sdkconfig="$1"
    local profile="$2"
    case "$profile" in
        development)
            grep -qx 'CONFIG_PICO_FIDO2_DEVELOPMENT_MAINTENANCE_OPEN=y' "$sdkconfig" || return 1
            grep -qx 'CONFIG_PICO_FIDO2_DEVELOPMENT_INSECURE_OTA=y' "$sdkconfig" || return 1
            ;;
        production)
            grep -qx '# CONFIG_PICO_FIDO2_DEVELOPMENT_MAINTENANCE_OPEN is not set' "$sdkconfig" || return 1
            # Kconfig omits this symbol entirely when its development-mode
            # dependency is disabled, rather than writing an explicit '#'.
            if grep -qx 'CONFIG_PICO_FIDO2_DEVELOPMENT_INSECURE_OTA=y' "$sdkconfig"; then
                return 1
            fi
            grep -qx 'CONFIG_ESP_COREDUMP_ENABLE_TO_NONE=y' "$sdkconfig" || return 1
            grep -qx '# CONFIG_ESP_COREDUMP_ENABLE_TO_UART is not set' "$sdkconfig" || return 1
            grep -Fqx 'CONFIG_PICO_FIDO2_WIFI_SSID_PREFIX="Aromatic-Key"' "$sdkconfig" || return 1
            grep -Fqx 'CONFIG_PICO_FIDO2_WIFI_PASSWORD="Aromatic-Key"' "$sdkconfig" || return 1
            grep -qx 'CONFIG_PICO_FIDO2_WIFI_IDLE_TIMEOUT_SEC=600' "$sdkconfig" || return 1
            ;;
        *)
            return 1
            ;;
    esac
}
