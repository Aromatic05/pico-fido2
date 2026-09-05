#!/usr/bin/env bash
set -euo pipefail

runtime="${CONTAINER_RUNTIME:-podman}"
image="${YKMAN_TEST_IMAGE:-localhost/pico-fido2-ykman-test:5.9.2}"

fail() {
    echo "ykman-fido-management: $*" >&2
    exit 1
}

command -v "$runtime" >/dev/null || fail "$runtime not found"
"$runtime" image exists "$image" >/dev/null 2>&1 || fail "missing test image: $image"

"$runtime" run --rm -i --network none -v "$PWD:/src:ro" "$image" bash -s <<'INNER'
set -euo pipefail
mkdir -p /work
cmake -S /src -B /work/build -DENABLE_EMULATION=1 -DCMAKE_BUILD_TYPE=Release >/work/cmake.log
cmake --build /work/build -j"$(nproc)" >/work/build.log

# Reuse the project's HID TCP backend inside the installed python-fido2 package,
# preserving the same CtapDevice type imported by yubikit.
hid_dir=$(python3 - <<'PY'
import pathlib
import fido2.hid
print(pathlib.Path(fido2.hid.__file__).parent)
PY
)
cp /src/pico-fido/tests/docker/fido2/__init__.py "$hid_dir/__init__.py"
cp /src/pico-fido/tests/docker/fido2/emulation.py "$hid_dir/emulation.py"

mkdir -p /work/run
cd /work/run
rm -f memory.flash emulator.log pcscd.log
/usr/sbin/pcscd --foreground >pcscd.log 2>&1 &
pcsc_pid=$!
emu_pid=""
cleanup() {
    [[ -z "$emu_pid" ]] || kill "$emu_pid" 2>/dev/null || true
    kill "$pcsc_pid" 2>/dev/null || true
}
trap cleanup EXIT
sleep 1

start_emulator() {
    /work/build/pico_fido2 >emulator.log 2>&1 &
    emu_pid=$!
    sleep 1
    kill -0 "$emu_pid" 2>/dev/null || { cat emulator.log >&2; return 1; }
}

stop_emulator() {
    [[ -z "$emu_pid" ]] || kill "$emu_pid" 2>/dev/null || true
    [[ -z "$emu_pid" ]] || wait "$emu_pid" 2>/dev/null || true
    emu_pid=""
    sleep 1
}

start_emulator
python3 - <<'PY'
from fido2.hid import CtapHidDevice
from yubikit.core import TRANSPORT
from yubikit.management import CAPABILITY, DeviceConfig, ManagementSession

CCID_APPS = CAPABILITY.OATH | CAPABILITY.PIV | CAPABILITY.OPENPGP

def open_session():
    dev = next(CtapHidDevice.list_devices(), None)
    assert dev is not None, "FIDO HID emulator not found"
    return dev, ManagementSession(dev)

dev, session = open_session()
info = session.read_device_info()
enabled = info.config.enabled_capabilities[TRANSPORT.USB]
assert enabled & CCID_APPS == CCID_APPS
assert enabled & 0x400
print("FIDO READ_CONFIG: PASS")

without_ccid_apps = enabled & ~int(CCID_APPS)
session.write_device_config(DeviceConfig({TRANSPORT.USB: without_ccid_apps}))
info = session.read_device_info()
assert info.config.enabled_capabilities[TRANSPORT.USB] == without_ccid_apps
print("FIDO WRITE_CONFIG: PASS")
dev.close()
PY

stop_emulator
start_emulator
python3 - <<'PY'
from fido2.hid import CtapHidDevice
from yubikit.core import TRANSPORT
from yubikit.management import (
    CAPABILITY,
    DeviceConfig,
    ManagementSession,
    Mode,
    USB_INTERFACE,
)

CCID_APPS = CAPABILITY.OATH | CAPABILITY.PIV | CAPABILITY.OPENPGP
dev = next(CtapHidDevice.list_devices())
session = ManagementSession(dev)
info = session.read_device_info()
enabled = info.config.enabled_capabilities[TRANSPORT.USB]
assert enabled & CCID_APPS == 0
assert enabled & (CAPABILITY.U2F | CAPABILITY.FIDO2)
assert enabled & 0x400

supported = info.supported_capabilities[TRANSPORT.USB]
assert supported & 0x400
session.write_device_config(DeviceConfig({TRANSPORT.USB: supported}))
assert session.read_device_info().config.enabled_capabilities[TRANSPORT.USB] == supported
session.set_mode(Mode(USB_INTERFACE.OTP | USB_INTERFACE.FIDO))
mode_enabled = session.read_device_info().config.enabled_capabilities[TRANSPORT.USB]
assert mode_enabled == (CAPABILITY.OTP | CAPABILITY.U2F | CAPABILITY.FIDO2)
try:
    session.write_device_config(DeviceConfig({TRANSPORT.USB: CAPABILITY.OTP}))
except Exception:
    pass
else:
    raise AssertionError("OTP-only configuration must be rejected to preserve a management transport")
print("FIDO management power-cycle/re-enable/mode-write: PASS")
dev.close()
PY

stop_emulator
start_emulator
python3 - <<'PY'
from fido2.hid import CtapHidDevice
from yubikit.core import TRANSPORT
from yubikit.management import CAPABILITY, ManagementSession, Mode, USB_INTERFACE

dev = next(CtapHidDevice.list_devices())
session = ManagementSession(dev)
info = session.read_device_info()
enabled = info.config.enabled_capabilities[TRANSPORT.USB]
assert enabled == (CAPABILITY.OTP | CAPABILITY.U2F | CAPABILITY.FIDO2)
assert not (enabled & 0x400)
assert not (enabled & (CAPABILITY.OATH | CAPABILITY.PIV | CAPABILITY.OPENPGP))

session.set_mode(Mode(USB_INTERFACE.OTP | USB_INTERFACE.FIDO | USB_INTERFACE.CCID))
restored = session.read_device_info().config.enabled_capabilities[TRANSPORT.USB]
assert restored == info.supported_capabilities[TRANSPORT.USB]
print("FIDO-only mode survives power-cycle and restores CCID: PASS")
dev.close()
PY

printf 'ykman 5.9.2 FIDO management transport: PASS\n'
printf 'No physical device was accessed.\n'
INNER
