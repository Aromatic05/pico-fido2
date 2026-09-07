#!/usr/bin/env bash

prepare_maintenance_profile_defaults() {
    local profile="$1"
    local out_dir="$2"
    case "$profile" in
        development)
            printf '%s\n' 'sdkconfig.development-maintenance.defaults'
            ;;
        production)
            local password_file="${PICO_FIDO2_WIFI_PASSWORD_FILE:-}"
            [[ -n "$password_file" && -f "$password_file" ]] || {
                echo 'production maintenance requires PICO_FIDO2_WIFI_PASSWORD_FILE' >&2
                return 1
            }
            local password
            password="$(tr -d '\r\n' <"$password_file")"
            (( ${#password} >= 8 && ${#password} <= 63 )) || {
                echo 'production Wi-Fi password must be 8..63 characters' >&2
                return 1
            }
            [[ "$password" =~ ^[A-Za-z0-9._+-]+$ ]] || {
                echo 'production Wi-Fi password must use portable [A-Za-z0-9._+-] characters' >&2
                return 1
            }
            local defaults="$out_dir/.production-maintenance.defaults"
            umask 077
            {
                printf '# CONFIG_PICO_FIDO2_DEVELOPMENT_MAINTENANCE_OPEN is not set\n'
                printf '# CONFIG_PICO_FIDO2_DEVELOPMENT_INSECURE_OTA is not set\n'
                printf 'CONFIG_PICO_FIDO2_WIFI_PASSWORD="%s"\n' "$password"
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
            grep -qx 'CONFIG_PICO_FIDO2_DEVELOPMENT_MAINTENANCE_OPEN=y' "$sdkconfig"
            grep -qx 'CONFIG_PICO_FIDO2_DEVELOPMENT_INSECURE_OTA=y' "$sdkconfig"
            ;;
        production)
            grep -qx '# CONFIG_PICO_FIDO2_DEVELOPMENT_MAINTENANCE_OPEN is not set' "$sdkconfig"
            grep -qx '# CONFIG_PICO_FIDO2_DEVELOPMENT_INSECURE_OTA is not set' "$sdkconfig"
            grep -qx 'CONFIG_PICO_FIDO2_WIFI_IDLE_TIMEOUT_SEC=600' "$sdkconfig"
            ;;
        *)
            return 1
            ;;
    esac
}
