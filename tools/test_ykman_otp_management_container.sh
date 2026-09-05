#!/usr/bin/env bash
set -euo pipefail

runtime="${CONTAINER_RUNTIME:-podman}"
base_image="${PIV_TEST_IMAGE:-localhost/pico-fido2-piv-test:jammy}"
image="${YKMAN_TEST_IMAGE:-localhost/pico-fido2-ykman-test:5.9.2}"

fail() {
    echo "ykman-otp-management: $*" >&2
    exit 1
}

command -v "$runtime" >/dev/null || fail "$runtime not found"
[[ -f pico-openpgp/tests/docker/jammy/Dockerfile ]] || fail 'run from pico-fido2 repository root'

if ! "$runtime" image exists "$base_image" >/dev/null 2>&1; then
    "$runtime" build -f pico-openpgp/tests/docker/jammy/Dockerfile -t "$base_image" pico-openpgp
fi
if ! "$runtime" image exists "$image" >/dev/null 2>&1; then
    printf 'FROM %s\nRUN pip3 install --no-cache-dir yubikey-manager==5.9.2\n' "$base_image" \
        | "$runtime" build -t "$image" -f - .
fi

"$runtime" run --rm -i --network none -v "$PWD:/src:ro" "$image" bash -s <<'INNER'
set -euo pipefail
mkdir -p /work/build /work/run
cmake -S /src -B /work/build -DENABLE_EMULATION=1 -DCMAKE_BUILD_TYPE=Release >/work/cmake.log
cmake --build /work/build -j"$(nproc)" >/work/build.log
rm -f /work/run/memory.flash

cat >/work/otp_socket.py <<'PY'
import socket
from yubikit.core.otp import OtpConnection

class SocketOtpConnection(OtpConnection):
    """Yubikit OTP feature reports over Pico FIDO2's host-emulation socket."""
    def __init__(self, host="127.0.0.1", port=35962):
        self.sock = socket.create_connection((host, port), timeout=5)

    def close(self):
        self.sock.close()

    def _write(self, payload: bytes):
        self.sock.sendall(len(payload).to_bytes(2, "big") + payload)

    def _read_exact(self, size: int) -> bytes:
        out = bytearray()
        while len(out) < size:
            chunk = self.sock.recv(size - len(out))
            if not chunk:
                raise OSError("emulator closed OTP HID socket")
            out.extend(chunk)
        return bytes(out)

    def send(self, data: bytes) -> None:
        if len(data) != 8:
            raise ValueError(f"OTP feature report must be 8 bytes, got {len(data)}")
        self._write(data)

    def receive(self) -> bytes:
        # 0x05 is a host-emulation-only GET_REPORT request.
        self._write(b"\x05")
        size = int.from_bytes(self._read_exact(2), "big")
        report = self._read_exact(size)
        if len(report) != 8:
            raise ValueError(f"OTP feature report must be 8 bytes, got {len(report)}")
        return report
PY
export PYTHONPATH=/work

/usr/sbin/pcscd --foreground >/work/pcscd.log 2>&1 &
pcsc_pid=$!
emu_pid=""
cleanup() {
    [[ -z "$emu_pid" ]] || kill -9 "$emu_pid" 2>/dev/null || true
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

kill_emulator_now() {
    [[ -z "$emu_pid" ]] || kill -9 "$emu_pid" 2>/dev/null || true
    [[ -z "$emu_pid" ]] || wait "$emu_pid" 2>/dev/null || true
    emu_pid=""
}

run_management_action() {
    python3 - "$1" <<'PY'
import sys
from otp_socket import SocketOtpConnection
from yubikit.core import TRANSPORT
from yubikit.management import CAPABILITY, DeviceConfig, ManagementSession

def state(session):
    info = session.read_device_info()
    return (
        int(info.config.enabled_capabilities[TRANSPORT.USB]),
        int(info.supported_capabilities[TRANSPORT.USB]),
    )

action = sys.argv[1]
with SocketOtpConnection() as conn:
    session = ManagementSession(conn)
    enabled, supported = state(session)
    print(f"{action}: enabled={enabled:#06x} supported={supported:#06x} version={session.version}")
    assert session.version[0] >= 5
    assert supported & int(CAPABILITY.OTP)

    if action == "set-otp-only":
        session.write_device_config(DeviceConfig({TRANSPORT.USB: CAPABILITY.OTP}))
        assert state(session)[0] == int(CAPABILITY.OTP)
        print("OTP WRITE_CONFIG to OTP-only: PASS")
    elif action == "verify-otp-only":
        assert enabled == int(CAPABILITY.OTP)
        print("OTP-only power-cycle persistence: PASS")
    elif action == "restore-all":
        session.write_device_config(DeviceConfig({TRANSPORT.USB: supported}))
        enabled2, supported2 = state(session)
        assert enabled2 == supported2
        print("OTP management restores all USB capabilities: PASS")
    elif action == "verify-restored":
        assert enabled == supported
        assert enabled & int(CAPABILITY.FIDO2)
        assert enabled & int(CAPABILITY.PIV)
        print("OTP restore power-cycle persistence: PASS")
    else:
        raise AssertionError(action)
PY
}

start_emulator
run_management_action set-otp-only
# A successful programming-sequence response must already be durable.
kill_emulator_now
start_emulator
run_management_action verify-otp-only
run_management_action restore-all
kill_emulator_now
start_emulator
run_management_action verify-restored

python3 - <<'PY'
import hashlib, hmac
from otp_socket import SocketOtpConnection
from yubikit.yubiotp import HmacSha1SlotConfiguration, SLOT, YubiOtpSession
key=b'0123456789ABCDEFGHIJ'
challenge=b'otp-management-durability'
with SocketOtpConnection() as conn:
    session=YubiOtpSession(conn)
    assert not session.get_config_state().is_configured(SLOT.ONE)
    session.put_configuration(SLOT.ONE, HmacSha1SlotConfiguration(key))
    assert session.get_config_state().is_configured(SLOT.ONE)
    assert session.calculate_hmac_sha1(SLOT.ONE, challenge) == hmac.new(key, challenge, hashlib.sha1).digest()
print('YubiOTP HMAC-SHA1 slot configure/calculate: PASS')
PY
kill_emulator_now
start_emulator
python3 - <<'PY'
import hashlib, hmac
from otp_socket import SocketOtpConnection
from yubikit.yubiotp import SLOT, YubiOtpSession
key=b'0123456789ABCDEFGHIJ'
challenge=b'otp-management-durability'
with SocketOtpConnection() as conn:
    session=YubiOtpSession(conn)
    assert session.get_config_state().is_configured(SLOT.ONE)
    assert session.calculate_hmac_sha1(SLOT.ONE, challenge) == hmac.new(key, challenge, hashlib.sha1).digest()
    session.delete_slot(SLOT.ONE)
print('YubiOTP slot power-cycle persistence/delete: PASS')
PY
kill_emulator_now
start_emulator
python3 - <<'PY'
from otp_socket import SocketOtpConnection
from yubikit.yubiotp import SLOT, YubiOtpSession
with SocketOtpConnection() as conn:
    assert not YubiOtpSession(conn).get_config_state().is_configured(SLOT.ONE)
print('YubiOTP slot delete power-cycle persistence: PASS')
PY

# YubiKey 3/4 legacy mode frames still use SLOT_DEVICE_CONFIG (0x11).
python3 - <<'PY'
import struct
from otp_socket import SocketOtpConnection
from yubikit.core import TRANSPORT
from yubikit.management import CAPABILITY, ManagementSession, Mode, USB_INTERFACE
with SocketOtpConnection() as conn:
    session = ManagementSession(conn)
    mode = Mode(USB_INTERFACE.OTP | USB_INTERFACE.FIDO)
    session.backend.set_mode(struct.pack('<BBH', mode.code, 9, 0))
    info = session.read_device_info()
    enabled = int(info.config.enabled_capabilities[TRANSPORT.USB])
    expected = int(CAPABILITY.OTP | CAPABILITY.U2F | CAPABILITY.FIDO2)
    assert enabled == expected
    assert info.config.challenge_response_timeout == 9
print('legacy 0x11 OTP+FIDO mode: PASS')
PY
kill_emulator_now
start_emulator
python3 - <<'PY'
import struct
from otp_socket import SocketOtpConnection
from yubikit.core import TRANSPORT
from yubikit.management import CAPABILITY, DEVICE_FLAG, ManagementSession, Mode, USB_INTERFACE
with SocketOtpConnection() as conn:
    session = ManagementSession(conn)
    info = session.read_device_info()
    enabled = int(info.config.enabled_capabilities[TRANSPORT.USB])
    expected = int(CAPABILITY.OTP | CAPABILITY.U2F | CAPABILITY.FIDO2)
    assert enabled == expected
    assert info.config.challenge_response_timeout == 9
    print('legacy 0x11 OTP+FIDO power-cycle persistence: PASS')

    mode = Mode(USB_INTERFACE.CCID)
    code = mode.code | int(DEVICE_FLAG.EJECT)
    session.backend.set_mode(struct.pack('<BBH', code, 0, 42))
print('legacy 0x11 CCID-only write: PASS')
PY
kill_emulator_now
start_emulator
python3 - <<'PY'
from ykman.pcsc import list_devices
from yubikit.core import TRANSPORT
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import CAPABILITY, DEVICE_FLAG, DeviceConfig, ManagementSession

devices = list_devices('Virtual PCD 00 00')
assert len(devices) == 1, devices
with devices[0].open_connection(SmartCardConnection) as conn:
    session = ManagementSession(conn)
    info = session.read_device_info()
    enabled = int(info.config.enabled_capabilities[TRANSPORT.USB])
    supported = int(info.supported_capabilities[TRANSPORT.USB])
    ccid_mask = int(CAPABILITY.OATH | CAPABILITY.PIV | CAPABILITY.OPENPGP | CAPABILITY.HSMAUTH) | 0x400
    assert enabled == (supported & ccid_mask)
    assert info.config.auto_eject_timeout == 42
    assert int(info.config.device_flags) & int(DEVICE_FLAG.EJECT)
    print('legacy 0x11 CCID-only power-cycle via CCID: PASS')

    session.write_device_config(DeviceConfig({TRANSPORT.USB: CAPABILITY(supported)}))
    restored = session.read_device_info()
    assert int(restored.config.enabled_capabilities[TRANSPORT.USB]) == supported
print('CCID management restores legacy mode: PASS')
PY
kill_emulator_now
start_emulator
python3 - <<'PY'
from otp_socket import SocketOtpConnection
from yubikit.core import TRANSPORT
from yubikit.management import ManagementSession
with SocketOtpConnection() as conn:
    session = ManagementSession(conn)
    info = session.read_device_info()
    enabled = int(info.config.enabled_capabilities[TRANSPORT.USB])
    supported = int(info.supported_capabilities[TRANSPORT.USB])
    assert enabled == supported
print('legacy restore power-cycle visible over OTP: PASS')
PY

printf 'ykman 5.9.2 OTP management transport: PASS\n'
printf 'No physical device was accessed.\n'
INNER
