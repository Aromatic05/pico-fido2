# Pico FIDO2

This project transforms your Raspberry RP235x or ESP32 microcontroller into an integrated FIDO Passkey **and** OpenPGP smartcard, functioning like a standard USB Passkey for authentication and as a smartcard for cryptographic operations.

This is a fork of the last community edition version of the pico-fido2 firmware, from December 9th 2025, that was available on https://github.com/polhenarejos/pico-fido2 before that repository was deleted and replaced by something else.

---

## Supported platforms

| | RP2040 | RP2350 | ESP32-S2 | ESP32-S3 |
|---|---|---|---|---|
| CPU | 2x Cortex-M0+ | 2x Cortex-M33 | 1x Xtensa | 2x Xtensa |
| Core pinning | Yes  | Yes | No  | Yes |
| RTOS | No (Pico SDK) | No (Pico SDK) | FreeRTOS | FreeRTOS |
| MCU ID | `0` | `1` | `2` | `2` |

### Security

Currently most secure features are supported and implemented only for RP2350.

| | RP2350 | RP2040 | ESP32-S2 | ESP32-S3 |
|---|---|---|---|---|
| Secure Boot | Full (boot key hash, CRIT1 flags, debug disable, glitch detector) | No HW support | No (`// TODO`) | Yes (ESP-IDF Secure Boot v2 / RSA-3072, host-provisioned) |
| Secure Lock | Yes (key invalidation, page locking) | No | No | No |
| MKEK in OTP/eFuse | Yes (OTP rows with ECC, chaff, page locking) | No (plaintext flash) | Yes (eFuse `BLK_KEY3`, write-locked) | Yes (eFuse `BLK_KEY3`, write-locked) |
| Device key in OTP/eFuse | Yes (OTP + chaff + migration) | No | Yes (eFuse `BLK_KEY4`) | Yes (eFuse `BLK_KEY4`) |
| `cmd_secure` APDU | Available | Not available | Not available | Not available |
| Firmware signing | Yes (`pico_sign_binary`) | No | No | Yes (ESP-IDF Secure Boot v2) |
| Rollback protection | Yes | No | No | Yes (single-slot, host-managed `SECURE_VERSION` floor) |
| HW crypto | SHA-256	| No | SHA-256 + AES-GCM + ECDSA/ECDH | SHA-256 + AES-GCM + ECDSA/ECDH |

## Features

Pico FIDO2 includes the following features:

### FIDO2 / U2F / WebAuthn

- CTAP 2.1 / CTAP 1
- WebAuthn
- U2F
- HMAC-Secret extension
- CredProtect extension
- User presence enforcement through physical button
- User verification with PIN
- Discoverable credentials (resident keys)
- Credential management
- ECDSA and EDDSA authentication
- Support for SECP256R1, SECP384R1, SECP521R1, SECP256K1 and Ed25519 curves
- App registration and login
- Device selection
- Support for vendor configuration
- Backup with 24 words
- Secure lock to protect the device from flash dumps
- Permissions support (MC, GA, CM, ACFG, LBW)
- Authenticator configuration
- minPinLength extension
- Self attestation
- Enterprise attestation
- credBlobs extension
- largeBlobKey extension
- Large blobs support (2048 bytes max)
- OATH (based on YKOATH protocol specification)
- TOTP / HOTP
- YubiHSM Auth compatible AES-128/SCP03 and P-256/SCP11 credentials over CCID
- Yubikey One Time Password
- Challenge-response generation
- Emulated keyboard interface
- Button press generates an OTP that is directly typed
- Yubico YKMAN compatible
- Nitrokey nitropy and nitroapp compatible
- Secure Boot on RP2350 and ESP32-S3; Secure Lock on RP2350
- One Time Programming to store the master key that encrypts all resident keys and seeds.
- Rescue interface to allow recovery of the device if it becomes unresponsive or undetectable.
- LED customization with Pico Commissioner.

### OpenPGP Smartcard

- OpenPGP card specification v3.4
- 3 key slots (Signature, Encryption, Authentication)
- RSA (2048, 3072, 4096), Ed25519, Curve25519, ECDSA (NIST P-256, P-384, P-521)
- Key generation on device
- Key import/export
- PIN and Admin PIN protection
- Reset and Unblock functions
- Works with GnuPG, SSH, S/MIME, and compatible tools
- CCID over USB
- Compatible with major OS (Linux, Windows, macOS)
- Touch button for user presence confirmation (optional)
- Open source

---

## Security Considerations

Microcontrollers RP2350 and ESP32-S3 are designed to support secure environments when Secure Boot is enabled, and optionally, Secure Lock. These features allow a master key encryption key (MKEK) to be stored in a one-time programmable (OTP) memory region, which is inaccessible from outside secure code. This master key is then used to encrypt all private and secret keys on the device, protecting sensitive data from potential flash memory dumps.

**However**, the RP2040 microcontroller lacks this level of security hardware, meaning that it cannot provide the same protection. Data stored on its flash memory, including private or master keys, can be easily accessed or dumped, as encryption of the master key itself is not feasible. Consequently, if an RP2040 device is stolen, any stored private or secret keys may be exposed.

---

## Build for Raspberry Pico

Before building, ensure you have installed the toolchain for the Pico and that the Pico SDK is properly located on your drive.

```
git clone https://github.com/youruser/pico-fido2
git submodule update --init --recursive
cd pico-fido2
mkdir build
cd build
PICO_SDK_PATH=/path/to/pico-sdk cmake .. -DPICO_BOARD=board_type -DUSB_VID=0x1D50 -DUSB_PID=0x619B
make
```

Note that `PICO_BOARD`, `USB_VID` and `USB_PID` are optional. If not provided, `pico` board and VID/PID `1D50:619B` will be used.

Additionally, you can pass the `VIDPID=value` parameter to build the firmware with a known VID/PID. The supported values are:

- `NitroHSM`
- `NitroFIDO2`
- `NitroStart`
- `NitroPro`
- `Nitro3`
- `Yubikey5`
- `YubikeyNeo`
- `YubiHSM`
- `Gnuk`
- `GnuPG`

You can use whatever VID/PID for your own personal use. **But remember that you are not authorized to distribute the binary with a VID/PID that you do not own.**
The VID/PID `1D50:619B` is provided to the project by [OpenMoko](https://wiki.openmoko.org/wiki/USB_Product_IDs). It can only be used for builds distributed under a free and open source license.

After running `make`, the binary file `pico_fido2.uf2` will be generated. To load this onto your Pico board:

1. Put the Pico board into loading mode by holding the `BOOTSEL` button while plugging it in.
2. Copy the `pico_fido2.uf2` file to the new USB mass storage device that appears.
3. Once the file is copied, the Pico mass storage device will automatically disconnect, and the Pico board will reset with the new firmware.
4. A blinking LED will indicate that the device is ready to work.

To configure your device you can use the [picoforge desktop application ](https://github.com/librekeys/picoforge).

## Build for ESP32

Replace
- `ESP_PRODUCT` with your SoC's name: e.g. `esp32s2` or `esp32s3`
- `ESP_NAME` with it's full name: `ESP32-S2` or `ESP32-S3`

Install ESP-IDF and toolchain

```bash
git clone --recursive https://github.com/espressif/esp-idf.git -b v5.5 --depth=1
cd esp-idf
./install.sh ESP_PRODUCT
. ./export.sh
cd ..
```

Then, you can build with:
```bash
idf.py set-target ESP_PRODUCT
idf.py all
cd build
esptool.py --chip ESP_NAME merge_bin -o pico_fido_esp32.bin @flash_args
```

### ESP32-S3 reversible bring-up

Before provisioning eFuse key blocks, the ESP32-S3 can be built with development-only root keys so USB, FIDO, OpenPGP, Wi-Fi, and Bluetooth work can be tested without consuming KEY3/KEY4:

```bash
rm -rf build-bringup sdkconfig.bringup
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.bringup.defaults" idf.py -B build-bringup -DSDKCONFIG=sdkconfig.bringup set-target esp32s3
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.bringup.defaults" idf.py -B build-bringup -DSDKCONFIG=sdkconfig.bringup build
```

This profile is intentionally insecure and is only for bring-up. It does not write Pico FIDO2 root keys to eFuse.

### ESP32-S3 FIDO over BLE bring-up

The BLE profile exposes the standard FIDO GATT service through ESP-NimBLE while reusing the same CTAP2 core as USB HID:

```bash
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.ble.defaults" idf.py -B build-ble -DSDKCONFIG=sdkconfig.ble set-target esp32s3
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.ble.defaults" idf.py -B build-ble -DSDKCONFIG=sdkconfig.ble build
```

BLE bonds are persisted in NimBLE's NVS store. Existing bonded peers may reconnect normally, but fresh or repeat pairing is fail-closed unless a one-time pairing grant has been created from the physically entered Wi-Fi maintenance portal. That grant is consumed on the next normal boot, opens a 60-second window, and authorizes exactly one new bond. The maintenance portal can also schedule a full BLE bond reset plus one fresh-pairing window: after reboot, the restored persistent store is enumerated and each old peer is durably deleted before new pairing is allowed. If any deletion fails, the fresh-pairing window is suppressed. This revokes BLE trust records only; it does not delete FIDO/WebAuthn credentials.

### ESP32-S3 Wi-Fi commissioning bring-up

The Wi-Fi profile keeps the radio off during normal boot. Press the BOOT button five times after startup to enter commissioning mode; outside maintenance mode this preserves the existing one-through-four press OTP slot behavior. Commissioning stops BLE, starts a WPA2 SoftAP named `PicoFIDO2-XXXX`, and exposes the maintenance page at `http://192.168.4.1`. The default development password is `pico-fido2`.

The portal reports runtime device state, reads the existing YubiKey management capability mask, can enable/disable OTP/U2F/FIDO2/OATH/PIV/OpenPGP/HSM Auth/management USB applications through the same `man_write_config()` path used by USB management, can set/change/clear the same 16-byte configuration lock used by stock YubiKey management, can authorize the next BLE fresh-pairing window, and can revoke all persisted BLE bonds before opening one replacement pairing window. `/api/status` also exposes read-only security and power diagnostics through public ESP-IDF APIs: Secure Boot state, Flash Encryption state, decoded `SECURE_VERSION`, ROM/USB Serial-JTAG recovery availability, and the configured PM minimum/maximum CPU frequencies plus light-sleep state. Firmware provenance is reported separately as the ESP-IDF project name/version, application `secure_version`, app-descriptor ELF SHA-256, and the running app partition's ESP-IDF image SHA-256. These digest fields are intentionally named differently from the update bundle's whole-file plaintext/ciphertext SHA-256 values. If the running-image digest cannot be obtained, `imageSha256` is `null` rather than a fabricated value. No eFuse key block, key purpose, MKEK, device key, or Flash Encryption key material is exposed. Lock material is never returned by the status API and temporary HTTP/queue copies are explicitly zeroized. Successful configuration writes are flushed to flash on core0 under the global maintenance owner before HTTP reports success. The portal does not modify FIDO, HSM Auth, OpenPGP, or PIV credential/key material, firmware, or eFuses.

Maintenance is deliberately short-lived and physically gated: only one Wi-Fi station is accepted, the session reboots after five minutes of inactivity, and each commissioning session has a new 128-bit CSRF token. Persistent configuration changes and BLE trust changes additionally require one BOOT press immediately before the HTTP action; that confirmation is valid for 15 seconds and is consumed by exactly one mutation. While maintenance mode is active, this one-press confirmation is intercepted by the portal and is not routed to OTP. A plain maintenance reboot does not require or consume the mutation confirmation.

Wi-Fi only:

```bash
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.wifi.defaults;sdkconfig.wireless-layout.defaults" idf.py -B build-wifi -DSDKCONFIG=sdkconfig.wifi set-target esp32s3
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.wifi.defaults;sdkconfig.wireless-layout.defaults" idf.py -B build-wifi -DSDKCONFIG=sdkconfig.wifi build
```

BLE and Wi-Fi together:

```bash
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.ble.defaults;sdkconfig.wifi.defaults;sdkconfig.wireless-layout.defaults" idf.py -B build-wireless -DSDKCONFIG=sdkconfig.wireless set-target esp32s3
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.ble.defaults;sdkconfig.wifi.defaults;sdkconfig.wireless-layout.defaults" idf.py -B build-wireless -DSDKCONFIG=sdkconfig.wireless build
```

For the reversible hardware bring-up image, use the guarded helper after activating ESP-IDF 5.5:

```bash
./tools/esp32s3_bringup.sh build
# Later, with a board connected:
./tools/esp32s3_bringup.sh flash /dev/ttyACM0
```

The helper refuses to flash unless development root keys are enabled and both Secure Boot and Flash Encryption are disabled.

Wireless builds use a 1920 KiB application partition while keeping the PicoKeys data partition fixed at `0x200000`. SoftAP configuration is kept in RAM; management changes use the existing PicoKeys durable configuration store. Wi-Fi and BLE remain modal on ESP32-S3: entering maintenance fully stops NimBLE before the SoftAP starts, and reboot returns to normal USB/BLE mode.

### ESP32-S3 QEMU platform test

The QEMU profile runs the ESP32-S3 boot/storage/eFuse platform path while replacing peripherals that Espressif QEMU does not emulate (USB and NeoPixel) with no-op platform behavior. It uses DIO/40 MHz flash settings only for QEMU and starts from a blank virtual eFuse image:

```bash
. "$IDF_PATH/export.sh"
./tools/test_esp32s3_qemu.sh
```

The test requires the Espressif QEMU fork with the `esp32s3` machine, verifies that `app_main()` starts and returns without a reset loop, and asserts that reversible bring-up leaves the blank virtual eFuse unchanged.

### ESP32-S3 security QEMU test

The security-only QEMU profile builds a signed Secure Boot v2 image, moves the partition table to `0x10000` to make room for the signed bootloader, and marks PicoKeys `part0` as encrypted. It then validates the first-boot Secure Boot/Flash Encryption transition entirely in a virtual ESP32-S3:

```bash
. "$IDF_PATH/export.sh"
./tools/test_esp32s3_security_qemu.sh
```

The gate verifies RSA-PSS signatures for the bootloader and application, rejects a deliberately tampered signed application, observes virtual KEY0/KEY1 provisioning, confirms `SECURE_BOOT_EN` and Flash Encryption activation, and verifies that the encrypted `part0` is no longer plaintext erased flash. The profile is QEMU-only and must not be flashed to hardware. Espressif currently documents ESP32-S3 QEMU Secure Boot as unsupported, so post-reset ROM Secure Boot verification is deliberately not a pass condition.

### ESP32-S3 single-slot anti-rollback test

ESP-IDF's stock anti-rollback policy requires OTA slots and disallows a factory partition. Pico FIDO2 keeps its single `factory` application and instead uses a small bootloader wrapper that compares the application's `esp_app_desc.secure_version` with the ESP32-S3 16-bit `SECURE_VERSION` eFuse floor. The firmware never advances that floor automatically; host provisioning owns irreversible revocation.

```bash
. "$IDF_PATH/export.sh"
./tools/test_esp32s3_anti_rollback_qemu.sh
```

The QEMU gate sets a disposable virtual floor of `2` and requires `v1` to be rejected while `v2` and `v3` boot. Each run also verifies that the virtual eFuse backing file is unchanged. Normal firmware updates therefore do not consume eFuse bits; advance the floor only when an older signed firmware must be permanently revoked. Hardware anti-rollback builds require Secure Boot.

The floor is advanced by the host provisioning tool, not by normal firmware. Without `--apply`, the command is dry-run/read-only. For example, to plan floor `2 -> 3`, inspect a connected device, and then explicitly apply the change:

```bash
./tools/esp32s3_provision.py security-version --current 2 --target 3
./tools/esp32s3_provision.py security-version --port /dev/ttyACM0 --target 3
./tools/esp32s3_provision.py security-version --port /dev/ttyACM0 --target 3 --expect-current 2 --expect-mac 12:34:56:78:9a:bc --apply
```

`SECURE_VERSION` is a unary bit field: floor `3` is raw `0x0007`, not integer value `3`. The tool validates this canonical form, refuses a lower target, and prints the factory MAC during device dry-run. A real apply requires both `--expect-current` and `--expect-mac`. The complete apply path is tested with `espefuse --virt` and does not require hardware:

```bash
. "$IDF_PATH/export.sh"
./tools/test_esp32s3_security_floor.sh
```

The eventual hardware provisioning layout is deterministic and generated off-device:

```text
KEY0 = SECURE_BOOT_DIGEST0
KEY1 = XTS_AES_128_KEY
KEY2 = FREE
KEY3 = USER / PicoKeys MKEK
KEY4 = USER / PicoKeys secp256k1 device key
KEY5 = FREE
```

`tools/esp32s3_provision.py` keeps key provisioning host-only. It can show the plan or generate host-only RSA-3072, XTS-AES-128, MKEK, and secp256k1 material plus an integrity manifest; the separate `security-version --apply` path can only advance the `SECURE_VERSION` floor:

```bash
./tools/esp32s3_provision.py plan
./tools/esp32s3_provision.py generate --output-dir build-provisioning
./tools/esp32s3_provision.py verify build-provisioning/manifest.json
```

The exact KEY0/KEY1/KEY3/KEY4 burn sequence can be rehearsed against an `espefuse --virt` backing file without exposing any physical-device key-write path. Initialize the virtual file with the existing read-only preflight, inspect the pending plan, then explicitly apply it:

```bash
./tools/esp32s3_provision.py preflight --virt-file build-provisioning/efuse-virtual.bin
./tools/esp32s3_provision.py provision-virtual \
    --virt-file build-provisioning/efuse-virtual.bin \
    --manifest build-provisioning/manifest.json
./tools/esp32s3_provision.py provision-virtual \
    --virt-file build-provisioning/efuse-virtual.bin \
    --manifest build-provisioning/manifest.json \
    --apply
./tools/esp32s3_provision.py verify-device \
    --virt-file build-provisioning/efuse-virtual.bin \
    --manifest build-provisioning/manifest.json
```

`provision-virtual` has no `--port` argument. It is dry-run by default, is idempotent once all four blocks match, and can resume only while every previously written block is still independently verifiable. In particular, if KEY1 has already become read-protected while any other required block is incomplete, the tool refuses to continue because the Flash Encryption key can no longer be compared with the manifest. Initial provisioning also refuses any nonzero `SECURE_VERSION`.

The virtual failure-state gate covers full provisioning, idempotency, safe readable-key partial recovery, unreadable KEY1 partial refusal, wrong readable key material, nonzero `SECURE_VERSION`, and the absence of any hardware port option:

```bash
. "$IDF_PATH/export.sh"
./tools/test_esp32s3_virtual_provisioning.sh
```

Before any hardware key provisioning, run the read-only blank-device preflight and bind the inspection to the exact factory MAC. It requires Secure Boot and Flash Encryption to still be disabled, `SECURE_VERSION=0`, both ROM recovery paths to remain available, and KEY0/KEY1/KEY3/KEY4 to still be empty/readable/writeable with blank purposes:

```bash
./tools/esp32s3_provision.py preflight \
    --port /dev/ttyACM0 \
    --expect-mac 12:34:56:78:9a:bc
```

After KEY0/KEY1/KEY3/KEY4 have eventually been provisioned, but **before** enabling Flash Encryption or Secure Boot, the separate read-only verification checks the key purposes, key-block write protection, KEY1 read protection, and exact readable KEY0/KEY3/KEY4 material against the host manifest:

```bash
./tools/esp32s3_provision.py verify-device \
    --port /dev/ttyACM0 \
    --expect-mac 12:34:56:78:9a:bc \
    --manifest build-provisioning/manifest.json
```

`preflight`, `verify-device`, and `verify-secure` are all read-only and have no apply/write option. `provision-virtual --apply` writes only the specified virtual backing file; the tool still does **not** provide a real-device KEY0/KEY1/KEY3/KEY4 provisioning command. Initial provisioning requires `SECURE_VERSION=0`; anti-rollback advancement is a later, independent operation and is not part of this flow.

After the encrypted image has been programmed and the development Flash Encryption state plus Secure Boot have both been enabled, use the final read-only verifier before treating the device as a secured candidate:

```bash
./tools/esp32s3_provision.py verify-secure \
    --port /dev/ttyACM0 \
    --expect-mac 12:34:56:78:9a:bc \
    --manifest build-provisioning/manifest.json
```

`verify-secure` intentionally accepts only the current reversible experiment policy: Secure Boot enabled, `SPI_BOOT_CRYPT_CNT=0b001`, `SECURE_VERSION=0`, ROM and USB Serial/JTAG recovery still enabled, and KEY0/KEY1/KEY3/KEY4 purposes/protection/readable material matching the provisioning manifest. It has no apply/write option. A more hardened production eFuse state is a separate policy and is not silently treated as equivalent to this bring-up state.

For experiments the plan uses `SPI_BOOT_CRYPT_CNT=0b001` and leaves JTAG/ROM download available. Production hardening is intentionally a separate irreversible step.

The pre-provisioned firmware contract is fail-closed: with `CONFIG_PICOKEYS_ESP32_REQUIRE_PROVISIONED_KEYS=y`, blank or incorrectly purposed KEY3/KEY4 cause startup to return `PICOKEY_ERR_PROVISIONING_REQUIRED` without changing eFuses. The QEMU gate verifies blank/fail-closed, virtual provisioning, and provisioned/read-only startup states:

```bash
. "$IDF_PATH/export.sh"
./tools/test_esp32s3_preprovisioned_qemu.sh
```

A fully host-prepared 4 MiB security image can then be built without any connected device:

```bash
. "$IDF_PATH/export.sh"
./tools/esp32s3_provision.py generate --output-dir build-provisioning
./tools/build_esp32s3_security_bundle.sh build-provisioning build-security-bundle 0
./tools/verify_esp32s3_security_bundle.py build-security-bundle build-provisioning
```

The hardware security profile reuses the same BLE, Wi-Fi commissioning, and low-power defaults as the reversible wireless image while retaining the secure partition-table offset. Its factory application partition spans `0x20000..0x200000` (1920 KiB), so enabling Secure Boot/Flash Encryption does not require dropping the wireless transports or maintenance portal. The bundle builder signs the bootloader/application with RSA-3072 Secure Boot v2, requires pre-provisioned KEY3/KEY4, sets Flash Encryption to `REQUIRE_ALREADY_ENABLED`, XTS-encrypts the bootloader, partition table, application and initially erased `part0`, and decrypts every region again for byte-for-byte verification. The standalone verifier independently checks bundle/provisioning manifest hashes, decrypts all regions, verifies plaintext hashes, verifies the bootloader/application RSA-PSS signatures, and checks that initial `part0` decrypts to erased flash. Neither tool contains a device flash or eFuse write action.

The intended first hardware boot order is therefore: verify the untouched board baseline with `preflight`, provision KEY0/KEY1/KEY3/KEY4, verify those key blocks with `verify-device`, program the already encrypted bundle, set development Flash Encryption state (`SPI_BOOT_CRYPT_CNT=0b001`), enable Secure Boot last, and then confirm the final eFuse/key state with `verify-secure`. The firmware is not expected to create any root key during that boot, and `SECURE_VERSION` remains zero throughout initial provisioning.

After the device is provisioned, firmware updates do not consume any additional eFuse key slot or `SECURE_VERSION` bit. Keep the same Secure Boot signing key and per-device Flash Encryption key, choose an application security epoch, build a signed application, and pre-encrypt it for the fixed factory-app offset (`0x20000`):

```bash
. "$IDF_PATH/export.sh"
./tools/build_esp32s3_update_bundle.sh build-provisioning build-update-bundle 7.4.1 3
./tools/verify_esp32s3_update_bundle.py build-update-bundle build-provisioning --security-floor 2
./tools/esp32s3_update.py verify build-update-bundle build-provisioning --security-floor 2
./tools/test_esp32s3_update_bundle.sh build-provisioning
./tools/test_esp32s3_rom_update_qemu.sh
```

The update bundle binds its manifest `security_version` to the encrypted application's `esp_app_desc.secure_version`; the verifier can reject a bundle below a supplied device floor before flashing. It contains an app-only ciphertext image and must be written as raw ciphertext at `0x20000`; do **not** pass esptool's `--encrypt` flag to an already pre-encrypted update. It requires no eFuse changes: KEY0 continues to anchor the RSA-3072 Secure Boot signing key digest and KEY1 continues to hold the same per-device XTS-AES-128 key.

`esp32s3_update.py` is the guarded host-side write path. Put the device in ROM download mode first, inspect without writing, then copy the reported MAC and ciphertext hash into the explicit apply command:

```bash
./tools/esp32s3_update.py inspect build-update-bundle build-provisioning --port /dev/ttyACM0
./tools/esp32s3_update.py apply build-update-bundle build-provisioning \
    --port /dev/ttyACM0 \
    --expect-mac 12:34:56:78:9a:bc \
    --expect-update-sha256 <ciphertext-sha256>
```

The updater fails closed unless Secure Boot and Flash Encryption are already enabled, ROM/USB download remains available, KEY0 is `SECURE_BOOT_DIGEST0`, the readable KEY0 digest matches the bundle trust anchor, and the current encrypted application can be read from flash and decrypted with the candidate provisioning KEY1 into a valid `pico_fido2` image. That last check binds a per-device XTS key even when several devices share the same Secure Boot signing key. `apply` repeats all checks immediately before writing, writes only raw ciphertext at `0x20000` with no esptool `--encrypt` flag, leaves the device in ROM mode, then re-reads the eFuse state and the encrypted app prefix to prove that eFuses did not change and the new app decrypts to the expected version/security version.

This is a **single-slot ROM recovery update**, not an A/B OTA or live hot-patch mechanism. A power loss while the app region is being erased/written can leave the application unbootable and require another ROM update; the retained ROM download path is the recovery mechanism. Normal app updates do not advance `SECURE_VERSION` and never write anti-rollback eFuses. Local updates remain possible while ROM download and, on boards using it, `DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE` remain enabled. The ESP32-S3 USB Serial/JTAG controller is distinct from the USB-OTG ROM stack that Secure Boot/Flash Encryption disables. The QEMU ROM-update gates verify that the eFuse image remains byte-for-byte unchanged and that non-application flash regions are untouched.

### Native host emulation

The native emulator can run FIDO2 and OpenPGP protocol smoke tests without an ESP32-S3 or any eFuse writes:

```bash
cmake -S . -B build-host -DENABLE_EMULATION=1
cmake --build build-host -j
./tests/host_protocol_smoke.py build-host/pico_fido2
```

The smoke test drives the emulator through both transport paths and deliberately interleaves them: CCID PIV selection must survive HID `INIT`, CTAP2 `authenticatorGetInfo`, and U2F `MSG`, while an OpenPGP `GET RESPONSE` continuation must survive interleaved HID CTAP2 and OATH traffic. This guards the per-transport APDU application/chaining/continuation session state without requiring physical hardware. The same smoke gate also configures an OATH access code and proves that CCID and HID keep independent validation/challenge state while global access-code changes invalidate stale sessions on every transport.

YubiHSM Auth compatibility is driven through stock `yubikit` against the same native emulator:

```bash
python tests/host_hsmauth.py build-host/pico_fido2
```

The gate covers AES-128/SCP03 and P-256/SCP11 credentials, management and credential retry counters, public-key retrieval, challenge/session-key calculation, receipt verification, and immediate power-loss durability. The asymmetric path independently simulates the YubiHSM side's static and ephemeral ECDH operations and verifies the returned S-ENC/S-MAC/S-RMAC keys against the X9.63-SHA256 derivation instead of accepting a self-derived result.

Mutating commands also have a hard power-loss durability gate. It waits only for the protocol success response, immediately sends `SIGKILL`, and then restarts against the same `memory.flash`:

```bash
# The upstream FIDO test environment uses python-fido2.
python tests/host_powercycle_durability.py build-host/pico_fido2 --iterations 5
```

The gate covers raw CCID/OATH access-code writes and HID/FIDO Client PIN writes. A successful command response must therefore imply that queued flash writes are already durable.

The complete upstream FIDO/U2F/OATH pytest suite can be run in an isolated container against the native emulator:

```bash
./tools/test_fido_host_container.sh
```

This gate builds a Release emulator, provides virtual HID and PC/SC transports, and runs the full upstream protocol suite without accessing physical hardware.

OpenPGP has a full native-emulator pytest gate over virtual PC/SC as well:

```bash
./tools/test_openpgp_host_container.sh
```

It runs the upstream OpenPGP card suite, including KDF, PIN/admin flows, key generation/import, signing/decryption, attributes, counters, and reset behavior.

PIV compatibility can be exercised against the same native emulator through a containerized vsmartcard/PCSC environment and Yubico's `yubico-piv-tool` 2.5.1 tests:

```bash
./tools/test_piv_host_container.sh
```

The gate runs 96 key-generation/deletion cases, 96 certificate/signature cases, 96 attestation cases, and the libykpiv hardware API suite. The only accepted libykpiv mismatch is the expected device-model check for the virtual `Virtual PCD` reader. No physical smart-card device is accessed.

YubiKey management compatibility is tested separately against `ykman` 5.9.2:

```bash
./tools/test_ykman_management_container.sh
```

The management gate verifies device/application discovery, partial configuration merge semantics, power-cycle persistence, configuration-lock redaction and enforcement, correct/wrong lock handling, lock clearing, USB application updates that carry the management reboot TLV, and a management-over-CCID-only (`0x400`) power-cycle/restore cycle. Together with the FIDO and OTP gates below, every surviving management transport is proven able to recover the full USB capability set. The test uses only the native emulator and virtual PC/SC reader.

Management over FIDO HID is covered separately using yubikit's YubiKey vendor commands (`0x42` READ_CONFIG and `0x43` WRITE_CONFIG):

```bash
./tools/test_ykman_fido_management_container.sh
```

This gate verifies FIDO-side read/write configuration, power-cycle persistence, Yubico's hidden `0x400` management-over-CCID capability, FIDO-only mode with CCID removed, and restoring CCID through the surviving FIDO management transport. It also verifies that disabling FIDO2 while retaining U2F blocks standard CTAP2 commands without killing the physical FIDO HID management path, allowing FIDO2 to be restored through the same interface. USB interface selection remains backward-compatible with legacy `phy` configuration until `USB_ENABLED` has been explicitly written through the management application.

YubiKey OTP HID management uses yubikit 5.9.2's native 8-byte feature-report protocol and is tested independently:

```bash
./tools/test_ykman_otp_management_container.sh
```

The OTP gate exercises `READ_CONFIG`/`WRITE_CONFIG`, switches to a true OTP-only USB configuration, immediately power-cycles after successful programming-sequence responses, restores all USB capabilities through OTP management, and also verifies HMAC-SHA1 slot configuration/calculation and slot deletion across hard power cycles. Because OTP itself now provides a management transport, OTP-only mode no longer needs to be rejected to prevent configuration lockout. No physical device is accessed.

Application disable semantics are also exercised at the APDU selection boundary:

```bash
./tools/test_ykman_app_disable_container.sh
```

The gate disables OTP, U2F, FIDO2, OATH, PIV, OpenPGP, and HSM Auth one at a time through `ykman`, power-cycles the emulator, verifies that each disabled application AID is no longer selectable, then re-enables it and confirms selection is restored. PIV is checked through both its standard AID and Yubico's longer alternate AID; the SDK resolves overlapping application names by the longest registered AID before applying the centralized application policy, so a disabled longer PIV AID cannot fall back to the shorter OTP AID. The same policy is checked before every USB APDU dispatch, so already selected PIV, OpenPGP, OATH, and HSM Auth sessions are revoked immediately when management disables the application; revocation also discards any partial chained APDU from the old app. The hidden `0x400` management-over-CCID capability is enforced independently from the other CCID applications. `USB_ENABLED` remains transport-scoped: disabling USB FIDO2 does not disable the independent BLE FIDO transport.

The binary file `pico_fido_esp32.bin` will be generated. To load this onto your board:

1. Put the board into loading mode by holding the `BOOT` button while plugging it in.
2. For Windows users, install drivers with [this guide](https://github.com/espressif/esp-win-usb-drivers#documentation)
3. Go to https://espressif.github.io/esptool-js/
4. Click on Connect and choose the board
5. Choose the `pico_fido_esp32.bin` file
6. Set Flash Address=0x0000
7. Click Program
8. Press RST/Reset button on the board. A blinking LED will indicate that the device is ready to work.

To configure your device you can use the [picoforge desktop application ](https://github.com/librekeys/picoforge).


## Drivers

Pico FIDO2 uses the `HID` driver for FIDO and `CCID` for OpenPGP, both present in all major operating systems. It should be detected by all OS and browser/applications just like normal USB FIDO keys and smartcards.

## License

This project is released under the GNU Affero General Public License v3 (AGPLv3).
A copy of the AGPLv3 license is available in the `LICENSE` file.

## Credits
This project uses libraries and portion of code from other projects that are detailed in the `LICENSE` file.
