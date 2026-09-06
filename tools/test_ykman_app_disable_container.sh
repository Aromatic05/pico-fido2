#!/usr/bin/env bash
set -euo pipefail
runtime="${CONTAINER_RUNTIME:-podman}"
base_image="${PIV_TEST_IMAGE:-localhost/pico-fido2-piv-test:jammy}"
image="${YKMAN_TEST_IMAGE:-localhost/pico-fido2-ykman-test:5.9.2}"

if ! "$runtime" image exists "$base_image" >/dev/null 2>&1; then
    "$runtime" build -f pico-openpgp/tests/docker/jammy/Dockerfile -t "$base_image" pico-openpgp
fi
if ! "$runtime" image exists "$image" >/dev/null 2>&1; then
    printf 'FROM %s\nRUN pip3 install --no-cache-dir yubikey-manager==5.9.2\n' "$base_image" | "$runtime" build -t "$image" -f - .
fi

"$runtime" run --rm -i --network none -v "$PWD:/src:ro" "$image" bash -s <<'INNER'
set -euo pipefail
mkdir -p /work/build /work/run
cmake -S /src -B /work/build -DENABLE_EMULATION=1 -DCMAKE_BUILD_TYPE=Release >/work/cmake.log
cmake --build /work/build -j"$(nproc)" >/work/build.log
rm -f /work/run/memory.flash
/usr/sbin/pcscd --foreground >/work/pcscd.log 2>&1 &
pcsc_pid=$!
emu_pid=""
trap '[[ -z "$emu_pid" ]] || kill "$emu_pid" 2>/dev/null || true; kill "$pcsc_pid" 2>/dev/null || true' EXIT
sleep 1
start_emulator() {
  cd /work/run
  /work/build/pico_fido2 >emulator.log 2>&1 & emu_pid=$!
  cd /work
  sleep 1
  kill -0 "$emu_pid" 2>/dev/null || { cat /work/run/emulator.log >&2; exit 1; }
}
stop_emulator() {
  [[ -z "$emu_pid" ]] || kill "$emu_pid" 2>/dev/null || true
  [[ -z "$emu_pid" ]] || wait "$emu_pid" 2>/dev/null || true
  emu_pid=""
  sleep 1
}
assert_select() {
  local aid=$1 expected=$2 label=$3
  python3 - "$aid" "$expected" "$label" <<'PY'
import sys
from smartcard.System import readers
aid=bytes.fromhex(sys.argv[1]); expected=sys.argv[2]; label=sys.argv[3]
r=[x for x in readers() if 'Virtual PCD 00 00' in str(x)][0]
c=r.createConnection(); c.connect()
_, sw1, sw2=c.transmit([0x00,0xA4,0x04,0x00,len(aid),*aid])
sw=(sw1<<8)|sw2
selected = sw == 0x9000 or sw1 == 0x61
if expected == 'enabled':
    assert selected, f'{label} SELECT expected success, got {sw:04x}'
else:
    assert not selected, f'{label} SELECT remained enabled ({sw:04x})'
print(f'{label} SELECT {expected}: PASS ({sw:04x})')
PY
}
reader='Virtual PCD 00 00'
start_emulator
assert_select A0000005272001 enabled OTP-AID
assert_select A000000308 enabled PIV
assert_select A000000527200101 enabled PIV-Yubico-AID
assert_select D27600012401 enabled OpenPGP
assert_select A0000005272101 enabled OATH
assert_select A000000527210701 enabled HSM-Auth

python3 - <<'PYLIVE'
import socket
from smartcard.System import readers
from yubikit.core import TRANSPORT
from yubikit.core.otp import OtpConnection
from yubikit.management import CAPABILITY, DeviceConfig, ManagementSession

class SocketOtpConnection(OtpConnection):
    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", 35962), timeout=5)
    def close(self): self.sock.close()
    def _write(self, payload): self.sock.sendall(len(payload).to_bytes(2, 'big') + payload)
    def _read_exact(self, n):
        out=b''
        while len(out)<n:
            chunk=self.sock.recv(n-len(out))
            if not chunk: raise OSError('OTP socket closed')
            out += chunk
        return out
    def send(self, data):
        assert len(data) == 8
        self._write(data)
    def receive(self):
        self._write(b'\x05')
        n=int.from_bytes(self._read_exact(2),'big')
        report=self._read_exact(n)
        assert len(report)==8
        return report

reader=[r for r in readers() if 'Virtual PCD 00 00' in str(r)][0]
ccid=reader.createConnection(); ccid.connect()
_, sw1, sw2=ccid.transmit([0x00,0xA4,0x04,0x00,5,0xA0,0x00,0x00,0x03,0x08])
assert sw1 == 0x61 or (sw1,sw2)==(0x90,0x00)
_, sw1, sw2=ccid.transmit([0x00,0xFD,0x00,0x00])
assert (sw1,sw2)==(0x90,0x00), f'PIV VERSION before disable: {sw1:02x}{sw2:02x}'
with SocketOtpConnection() as otp:
    mgmt=ManagementSession(otp)
    info=mgmt.read_device_info()
    supported=info.supported_capabilities[TRANSPORT.USB]
    enabled=info.config.enabled_capabilities[TRANSPORT.USB]
    mgmt.write_device_config(DeviceConfig({TRANSPORT.USB: enabled & ~CAPABILITY.PIV}))
_, sw1, sw2=ccid.transmit([0x00,0xFD,0x00,0x00])
assert (sw1,sw2)!=(0x90,0x00), f'live PIV session survived disable: {sw1:02x}{sw2:02x}'
with SocketOtpConnection() as otp:
    mgmt=ManagementSession(otp)
    mgmt.write_device_config(DeviceConfig({TRANSPORT.USB: supported}))
print(f'live PIV session revoked without reboot: PASS ({sw1:02x}{sw2:02x})')

# Revocation must also discard any partial chained APDU from the old app.
_, sw1, sw2=ccid.transmit([0x00,0xA4,0x04,0x00,5,0xA0,0x00,0x00,0x03,0x08])
assert sw1 == 0x61 or (sw1,sw2)==(0x90,0x00)
_, sw1, sw2=ccid.transmit([0x10,0xDB,0x3F,0xFF,3,0x01,0x02,0x03])
assert (sw1,sw2)==(0x90,0x00), f'PIV chained prefix: {sw1:02x}{sw2:02x}'
with SocketOtpConnection() as otp:
    mgmt=ManagementSession(otp)
    info=mgmt.read_device_info()
    enabled=info.config.enabled_capabilities[TRANSPORT.USB]
    mgmt.write_device_config(DeviceConfig({TRANSPORT.USB: enabled & ~CAPABILITY.PIV}))
_, sw1, sw2=ccid.transmit([0x00,0xFD,0x00,0x00])
assert (sw1,sw2)!=(0x90,0x00)
with SocketOtpConnection() as otp:
    mgmt=ManagementSession(otp)
    mgmt.write_device_config(DeviceConfig({TRANSPORT.USB: supported}))
_, sw1, sw2=ccid.transmit([0x00,0xA4,0x04,0x00,5,0xA0,0x00,0x00,0x03,0x08])
assert sw1 == 0x61 or (sw1,sw2)==(0x90,0x00), f'PIV SELECT after chained revoke: {sw1:02x}{sw2:02x}'
print('live revoke clears APDU chaining state: PASS')

openpgp_aid=bytes.fromhex('D27600012401')
_, sw1, sw2=ccid.transmit([0x00,0xA4,0x04,0x00,len(openpgp_aid),*openpgp_aid])
assert (sw1,sw2)==(0x90,0x00), f'OpenPGP SELECT: {sw1:02x}{sw2:02x}'
def get_openpgp_data():
    data, s1, s2=ccid.transmit([0x00,0xCA,0x00,0x6E,0xFE])
    while s1 == 0x61:
        data2, s1, s2=ccid.transmit([0x00,0xC0,0x00,0x00,s2])
        data += data2
    return data, s1, s2
_, sw1, sw2=get_openpgp_data()
assert (sw1,sw2)==(0x90,0x00), f'OpenPGP GET DATA before disable: {sw1:02x}{sw2:02x}'
with SocketOtpConnection() as otp:
    mgmt=ManagementSession(otp)
    info=mgmt.read_device_info()
    enabled=info.config.enabled_capabilities[TRANSPORT.USB]
    mgmt.write_device_config(DeviceConfig({TRANSPORT.USB: enabled & ~CAPABILITY.OPENPGP}))
_, sw1, sw2=ccid.transmit([0x00,0xCA,0x00,0x6E,0xFE])
assert (sw1,sw2)!=(0x90,0x00) and sw1 != 0x61, f'live OpenPGP session survived disable: {sw1:02x}{sw2:02x}'
with SocketOtpConnection() as otp:
    mgmt=ManagementSession(otp)
    mgmt.write_device_config(DeviceConfig({TRANSPORT.USB: supported}))
print(f'live OpenPGP session revoked without reboot: PASS ({sw1:02x}{sw2:02x})')

oath_aid=bytes.fromhex('A0000005272101')
_, sw1, sw2=ccid.transmit([0x00,0xA4,0x04,0x00,len(oath_aid),*oath_aid])
assert (sw1,sw2)==(0x90,0x00), f'OATH SELECT: {sw1:02x}{sw2:02x}'
_, sw1, sw2=ccid.transmit([0x00,0xA1,0x00,0x00])
assert (sw1,sw2)==(0x90,0x00), f'OATH LIST before disable: {sw1:02x}{sw2:02x}'
with SocketOtpConnection() as otp:
    mgmt=ManagementSession(otp)
    info=mgmt.read_device_info()
    enabled=info.config.enabled_capabilities[TRANSPORT.USB]
    mgmt.write_device_config(DeviceConfig({TRANSPORT.USB: enabled & ~CAPABILITY.OATH}))
_, sw1, sw2=ccid.transmit([0x00,0xA1,0x00,0x00])
assert (sw1,sw2)!=(0x90,0x00), f'live OATH session survived disable: {sw1:02x}{sw2:02x}'
with SocketOtpConnection() as otp:
    mgmt=ManagementSession(otp)
    mgmt.write_device_config(DeviceConfig({TRANSPORT.USB: supported}))
print(f'live OATH session revoked without reboot: PASS ({sw1:02x}{sw2:02x})')

hsmauth_aid=bytes.fromhex('A000000527210701')
_, sw1, sw2=ccid.transmit([0x00,0xA4,0x04,0x00,len(hsmauth_aid),*hsmauth_aid])
assert (sw1,sw2)==(0x90,0x00), f'HSM Auth SELECT: {sw1:02x}{sw2:02x}'
_, sw1, sw2=ccid.transmit([0x00,0x09,0x00,0x00])
assert (sw1,sw2)==(0x90,0x00), f'HSM Auth GET_MGMT_RETRIES before disable: {sw1:02x}{sw2:02x}'
with SocketOtpConnection() as otp:
    mgmt=ManagementSession(otp)
    info=mgmt.read_device_info()
    enabled=info.config.enabled_capabilities[TRANSPORT.USB]
    mgmt.write_device_config(DeviceConfig({TRANSPORT.USB: enabled & ~CAPABILITY.HSMAUTH}))
_, sw1, sw2=ccid.transmit([0x00,0x09,0x00,0x00])
assert (sw1,sw2)!=(0x90,0x00), f'live HSM Auth session survived disable: {sw1:02x}{sw2:02x}'
with SocketOtpConnection() as otp:
    mgmt=ManagementSession(otp)
    mgmt.write_device_config(DeviceConfig({TRANSPORT.USB: supported}))
print(f'live HSM Auth session revoked without reboot: PASS ({sw1:02x}{sw2:02x})')

management_aid=bytes.fromhex('A000000527471117')
with SocketOtpConnection() as otp:
    mgmt=ManagementSession(otp)
    info=mgmt.read_device_info()
    enabled=info.config.enabled_capabilities[TRANSPORT.USB]
    mgmt.write_device_config(DeviceConfig({TRANSPORT.USB: enabled & ~0x400}))
_, sw1, sw2=ccid.transmit([0x00,0xA4,0x04,0x00,len(management_aid),*management_aid])
assert (sw1,sw2)!=(0x90,0x00) and sw1 != 0x61, f'management AID survived 0x400 disable: {sw1:02x}{sw2:02x}'
_, sw1, sw2=ccid.transmit([0x00,0xA4,0x04,0x00,5,0xA0,0x00,0x00,0x03,0x08])
assert sw1 == 0x61 or (sw1,sw2)==(0x90,0x00), f'PIV vanished with management bit: {sw1:02x}{sw2:02x}'
with SocketOtpConnection() as otp:
    mgmt=ManagementSession(otp)
    mgmt.write_device_config(DeviceConfig({TRANSPORT.USB: supported}))
print(f'management-over-CCID bit enforcement: PASS ({sw1:02x}{sw2:02x})')
PYLIVE

for app in PIV OPENPGP OATH HSMAUTH OTP U2F FIDO2; do
  case "$app" in
    PIV) aid=A000000308; label=PIV ;;
    OPENPGP) aid=D27600012401; label=OpenPGP ;;
    OATH) aid=A0000005272101; label=OATH ;;
    HSMAUTH) aid=A000000527210701; label=HSM-Auth ;;
    OTP) aid=A0000005272001; label=OTP ;;
    U2F) aid=A0000005271002; label=U2F ;;
    FIDO2) aid=A0000006472F0001; label=FIDO2 ;;
  esac
  ykman -r "$reader" config usb --disable "$app" --force >/dev/null
  stop_emulator; start_emulator
  assert_select "$aid" disabled "$label"
  if [[ "$app" == PIV ]]; then
    assert_select A000000527200101 disabled PIV-Yubico-AID
    assert_select A0000005272001 enabled OTP-AID
  fi
  ykman -r "$reader" config usb --enable "$app" --force >/dev/null
  stop_emulator; start_emulator
  assert_select "$aid" enabled "$label"
  if [[ "$app" == PIV ]]; then
    assert_select A000000527200101 enabled PIV-Yubico-AID
  fi
done
printf 'ykman application disable enforcement: PASS\n'
printf 'No physical device was accessed.\n'
INNER
