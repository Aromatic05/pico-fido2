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

The bring-up BLE profile keeps pairing mode continuously available so radio, bonding, framing, and CTAP interoperability can be tested without provisioning eFuse keys. A production build must gate pairing mode behind deliberate user presence.

### ESP32-S3 Wi-Fi commissioning bring-up

The Wi-Fi profile keeps the radio off during normal boot. Press the BOOT button five times after startup to enter commissioning mode; this preserves the existing one-through-four press OTP slot behavior. Commissioning starts a WPA2 SoftAP named `PicoFIDO2-XXXX` and a read-only page at `http://192.168.4.1`. The default development password is `pico-fido2`. The page currently exposes only device/build status; it does not modify credentials, OpenPGP data, firmware, or eFuses.

Wi-Fi only:

```bash
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.wifi.defaults" idf.py -B build-wifi -DSDKCONFIG=sdkconfig.wifi set-target esp32s3
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.wifi.defaults" idf.py -B build-wifi -DSDKCONFIG=sdkconfig.wifi build
```

BLE and Wi-Fi together:

```bash
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.ble.defaults;sdkconfig.wifi.defaults" idf.py -B build-wireless -DSDKCONFIG=sdkconfig.wireless set-target esp32s3
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.bringup.defaults;sdkconfig.ble.defaults;sdkconfig.wifi.defaults" idf.py -B build-wireless -DSDKCONFIG=sdkconfig.wireless build
```

For the reversible hardware bring-up image, use the guarded helper after activating ESP-IDF 5.5:

```bash
./tools/esp32s3_bringup.sh build
# Later, with a board connected:
./tools/esp32s3_bringup.sh flash /dev/ttyACM0
```

The helper refuses to flash unless development root keys are enabled and both Secure Boot and Flash Encryption are disabled.

Wireless builds use a 1920 KiB application partition while keeping the PicoKeys data partition fixed at `0x200000`. Wi-Fi configuration is kept in RAM for this bring-up mode. Production firmware should only enable commissioning after deliberate physical user presence.

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

The bundle builder signs the bootloader/application with RSA-3072 Secure Boot v2, requires pre-provisioned KEY3/KEY4, sets Flash Encryption to `REQUIRE_ALREADY_ENABLED`, XTS-encrypts the bootloader, partition table, application and initially erased `part0`, and decrypts every region again for byte-for-byte verification. The standalone verifier independently checks bundle/provisioning manifest hashes, decrypts all regions, verifies plaintext hashes, verifies the bootloader/application RSA-PSS signatures, and checks that initial `part0` decrypts to erased flash. Neither tool contains a device flash or eFuse write action.

The intended first hardware boot order is therefore: verify the untouched board baseline, provision KEY0/KEY1/KEY3/KEY4, program the already encrypted bundle, set development Flash Encryption state (`SPI_BOOT_CRYPT_CNT=0b001`), and enable Secure Boot last. The firmware is not expected to create any root key during that boot.

After the device is provisioned, firmware updates do not consume any additional eFuse key slot or `SECURE_VERSION` bit. Keep the same Secure Boot signing key and per-device Flash Encryption key, choose an application security epoch, build a signed application, and pre-encrypt it for the fixed factory-app offset (`0x20000`):

```bash
. "$IDF_PATH/export.sh"
./tools/build_esp32s3_update_bundle.sh build-provisioning build-update-bundle 7.4.1 3
./tools/verify_esp32s3_update_bundle.py build-update-bundle build-provisioning --security-floor 2
./tools/test_esp32s3_update_bundle.sh build-provisioning
./tools/test_esp32s3_rom_update_qemu.sh
```

The update bundle binds its manifest `security_version` to the encrypted application's `esp_app_desc.secure_version`; the verifier can reject a bundle below a supplied device floor before flashing. It contains an app-only ciphertext image and must be written as raw ciphertext at `0x20000`; do **not** pass esptool's `--encrypt` flag to an already pre-encrypted update. It requires no eFuse changes: KEY0 continues to anchor the RSA-3072 Secure Boot signing key digest and KEY1 continues to hold the same XTS-AES-128 key. Local updates remain possible while ROM download and, on boards using it, `DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE` remain enabled. The ESP32-S3 USB Serial/JTAG controller is distinct from the USB-OTG ROM stack that Secure Boot/Flash Encryption disables. The QEMU ROM-update gate additionally performs an encrypted app write after Secure Boot and Flash Encryption have been enabled, verifies that the eFuse image is byte-for-byte unchanged, and asserts that the bootloader, partition-table region, and `part0` credential-storage region are untouched.

### Native host emulation

The native emulator can run FIDO2 and OpenPGP protocol smoke tests without an ESP32-S3 or any eFuse writes:

```bash
cmake -S . -B build-host -DENABLE_EMULATION=1
cmake --build build-host -j
./tests/host_protocol_smoke.py build-host/pico_fido2
```

The smoke test drives the emulator through both transport paths: CTAPHID `INIT` plus CTAP2 `authenticatorGetInfo` over the HID TCP transport, and OpenPGP `SELECT` plus `GET DATA 006E` over the raw APDU TCP transport.

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

The management gate verifies device/application discovery, partial configuration merge semantics, power-cycle persistence, configuration-lock redaction and enforcement, correct/wrong lock handling, lock clearing, and USB application updates that carry the management reboot TLV. The test uses only the native emulator and virtual PC/SC reader.

Management over FIDO HID is covered separately using yubikit's YubiKey vendor commands (`0x42` READ_CONFIG and `0x43` WRITE_CONFIG):

```bash
./tools/test_ykman_fido_management_container.sh
```

This gate verifies FIDO-side read/write configuration, power-cycle persistence, Yubico's hidden `0x400` management-over-CCID capability, FIDO-only mode with CCID removed, and restoring CCID through the surviving FIDO management transport. USB interface selection remains backward-compatible with legacy `phy` configuration until `USB_ENABLED` has been explicitly written through the management application.

YubiKey OTP HID management uses yubikit 5.9.2's native 8-byte feature-report protocol and is tested independently:

```bash
./tools/test_ykman_otp_management_container.sh
```

The OTP gate exercises `READ_CONFIG`/`WRITE_CONFIG`, switches to a true OTP-only USB configuration, immediately power-cycles after successful programming-sequence responses, restores all USB capabilities through OTP management, and also verifies HMAC-SHA1 slot configuration/calculation and slot deletion across hard power cycles. Because OTP itself now provides a management transport, OTP-only mode no longer needs to be rejected to prevent configuration lockout. No physical device is accessed.

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
