#!/usr/bin/env bash
set -euo pipefail

runtime="${CONTAINER_RUNTIME:-podman}"
base_image="${PIV_TEST_IMAGE:-localhost/pico-fido2-piv-test:jammy}"
image="${YKMAN_TEST_IMAGE:-localhost/pico-fido2-ykman-test:5.9.2}"

fail() {
    echo "ykman-management: $*" >&2
    exit 1
}

command -v "$runtime" >/dev/null || fail "$runtime not found"
[[ -f pico-openpgp/tests/docker/jammy/Dockerfile ]] || fail 'run from pico-fido2 repository root'

if ! "$runtime" image exists "$base_image" >/dev/null 2>&1; then
    "$runtime" build -f pico-openpgp/tests/docker/jammy/Dockerfile \
        -t "$base_image" pico-openpgp
fi

if ! "$runtime" image exists "$image" >/dev/null 2>&1; then
    printf 'FROM %s\nRUN pip3 install --no-cache-dir yubikey-manager==5.9.2\n' "$base_image" \
        | "$runtime" build -t "$image" -f - .
fi

"$runtime" run --rm -i --network none -v "$PWD:/src:ro" "$image" bash -s <<'INNER'
set -euo pipefail
mkdir -p /work
cmake -S /src -B /work/build -DENABLE_EMULATION=1 -DCMAKE_BUILD_TYPE=Release >/work/cmake.log
cmake --build /work/build -j"$(nproc)" >/work/build.log
mkdir -p /work/run
rm -f /work/run/memory.flash

emu_pid=""
/usr/sbin/pcscd --foreground >/work/pcscd.log 2>&1 &
pcsc_pid=$!
cleanup() {
    [[ -z "$emu_pid" ]] || kill "$emu_pid" 2>/dev/null || true
    kill "$pcsc_pid" 2>/dev/null || true
}
trap cleanup EXIT
sleep 1

start_emulator() {
    cd /work/run
    /work/build/pico_fido2 >emulator.log 2>&1 &
    emu_pid=$!
    cd /work
    sleep 1
    kill -0 "$emu_pid" 2>/dev/null || { cat /work/run/emulator.log >&2; return 1; }
}

stop_emulator() {
    [[ -z "$emu_pid" ]] || kill "$emu_pid" 2>/dev/null || true
    [[ -z "$emu_pid" ]] || wait "$emu_pid" 2>/dev/null || true
    emu_pid=""
    sleep 1
}

reader='Virtual PCD 00 00'
lock=00112233445566778899aabbccddeeff
wrong=ffeeddccbbaa99887766554433221100

start_emulator
ykman -r "$reader" info >/work/info-initial.txt
grep -q '^Device type: YubiKey 5A$' /work/info-initial.txt
for app in 'Yubico OTP' 'FIDO U2F' 'FIDO2' 'OATH' 'PIV' 'OpenPGP'; do
    grep -Eq "^${app}[[:space:]]+Enabled$" /work/info-initial.txt || fail="missing $app"
    [[ -z "${fail:-}" ]] || { echo "$fail" >&2; exit 1; }
done
printf 'ykman info/applications: PASS\n'

ykman -r "$reader" config usb --disable OATH --force >/work/disable-oath.txt
ykman -r "$reader" config usb --list >/work/list-oath-disabled.txt
! grep -qx OATH /work/list-oath-disabled.txt
stop_emulator
start_emulator
ykman -r "$reader" config usb --list >/work/list-oath-cycle.txt
! grep -qx OATH /work/list-oath-cycle.txt
ykman -r "$reader" config usb --enable OATH --force >/dev/null
printf 'partial config merge/power-cycle: PASS\n'

ykman -r "$reader" config set-lock-code --new-lock-code "$lock" --force >/dev/null
stop_emulator
start_emulator
ykman -r "$reader" --log-level traffic --log-file /work/locked-traffic.log info >/work/info-locked.txt
grep -q 'protected by a lock code' /work/info-locked.txt
compact=$(tr -d ' :\r\n' </work/locked-traffic.log | tr 'A-F' 'a-f')
[[ "$compact" != *"$lock"* ]] || { echo 'lock secret leaked through READ_CONFIG traffic' >&2; exit 1; }
python3 - <<'PYDEVICE'
from ykman.pcsc import list_devices
from yubikit.core import TRANSPORT
from yubikit.core.smartcard import ApduError, SmartCardConnection
from yubikit.management import CAPABILITY, DeviceConfig, ManagementSession

devices = list_devices('Virtual PCD 00 00')
assert len(devices) == 1, devices
with devices[0].open_connection(SmartCardConnection) as conn:
    session = ManagementSession(conn)
    raw = session.backend.read_config()
    lock = bytes.fromhex('00112233445566778899aabbccddeeff')
    assert lock not in raw
    assert b'\x0a\x01\x01' in raw
    config = DeviceConfig(
        enabled_capabilities={
            TRANSPORT.USB: CAPABILITY.OTP | CAPABILITY.U2F | CAPABILITY.FIDO2
            | CAPABILITY.OATH | CAPABILITY.PIV
        }
    )
    try:
        session.write_device_config(config)
    except ApduError:
        pass
    else:
        raise AssertionError('locked WRITE_CONFIG without unlock was accepted')
print('device-side lock enforcement: PASS')
PYDEVICE
printf 'lock indicator/redaction/power-cycle: PASS\n'

set +e
ykman -r "$reader" config usb --disable OPENPGP --force >/work/no-lock.txt 2>&1
no_lock_rc=$?
ykman -r "$reader" config usb --enable OPENPGP --lock-code "$wrong" --force >/work/wrong-lock.txt 2>&1
wrong_lock_rc=$?
set -e
[[ "$no_lock_rc" -ne 0 ]]
[[ "$wrong_lock_rc" -ne 0 ]]
grep -q 'supply the --lock-code option' /work/no-lock.txt
grep -q 'Failed to configure USB applications' /work/wrong-lock.txt

ykman -r "$reader" config usb --disable OPENPGP --lock-code "$lock" --force >/dev/null
! ykman -r "$reader" config usb --list | grep -qx OpenPGP
ykman -r "$reader" config usb --enable OPENPGP --lock-code "$lock" --force >/dev/null
ykman -r "$reader" config set-lock-code --lock-code "$lock" --clear --force >/dev/null
ykman -r "$reader" info >/work/info-unlocked.txt
! grep -q 'protected by a lock code' /work/info-unlocked.txt
printf 'lock enforcement/change/clear: PASS\n'

python3 - <<'PYCCIDONLY'
from ykman.pcsc import list_devices
from yubikit.core import TRANSPORT
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import CAPABILITY, DeviceConfig, ManagementSession

devices = list_devices('Virtual PCD 00 00')
assert len(devices) == 1, devices
with devices[0].open_connection(SmartCardConnection) as conn:
    session = ManagementSession(conn)
    supported = session.read_device_info().supported_capabilities[TRANSPORT.USB]
    session.write_device_config(DeviceConfig({TRANSPORT.USB: CAPABILITY(0x400)}))
    assert session.read_device_info().config.enabled_capabilities[TRANSPORT.USB] == CAPABILITY(0x400)
print('management-over-CCID only configuration: PASS')
PYCCIDONLY
stop_emulator
start_emulator
python3 - <<'PYCCIDRESTORE'
from ykman.pcsc import list_devices
from yubikit.core import TRANSPORT
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import CAPABILITY, DeviceConfig, ManagementSession

devices = list_devices('Virtual PCD 00 00')
assert len(devices) == 1, devices
with devices[0].open_connection(SmartCardConnection) as conn:
    session = ManagementSession(conn)
    info = session.read_device_info()
    assert info.config.enabled_capabilities[TRANSPORT.USB] == CAPABILITY(0x400)
    supported = info.supported_capabilities[TRANSPORT.USB]
    session.write_device_config(DeviceConfig({TRANSPORT.USB: supported}))
    assert session.read_device_info().config.enabled_capabilities[TRANSPORT.USB] == supported
print('management-over-CCID only power-cycle/restore: PASS')
PYCCIDRESTORE
stop_emulator
start_emulator

ykman -r "$reader" config usb --disable OTP --force >/work/disable-otp.txt
grep -q 'YubiKey will reboot' /work/disable-otp.txt
stop_emulator
start_emulator
ykman -r "$reader" config usb --list >/work/list-otp-cycle.txt
! grep -qx 'Yubico OTP' /work/list-otp-cycle.txt
printf 'reboot-tag update/power-cycle: PASS\n'

kill -0 "$emu_pid" 2>/dev/null || { cat /work/run/emulator.log >&2; exit 1; }
printf 'ykman 5.9.2 management compatibility: PASS\n'
printf 'No physical device was accessed.\n'
INNER
