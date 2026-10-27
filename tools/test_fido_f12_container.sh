#!/usr/bin/env bash
set -euo pipefail
image="localhost/pico-fido2-ykman-test:5.9.2"
F12_SCOPE="${F12_SCOPE:-all}"
podman image exists "$image"
podman run --rm -i --network none -v "$PWD:/src:ro" -e F12_SCOPE "$image" bash -s <<'INNER'
set -euo pipefail
mkdir -p /work/build /work/run
cmake -S /src -B /work/build -DENABLE_EMULATION=1 -DCMAKE_BUILD_TYPE=Release >/work/cmake.log
cmake --build /work/build -j"$(nproc)" >/work/build.log
hid_dir=$(python3 - <<'PY'
from pathlib import Path
import fido2.hid
print(Path(fido2.hid.__file__).parent)
PY
)
cp /src/pico-fido/tests/docker/fido2/__init__.py "$hid_dir/__init__.py"
cp /src/pico-fido/tests/docker/fido2/emulation.py "$hid_dir/emulation.py"
/usr/sbin/pcscd --foreground >/work/pcscd.log 2>&1 &
pcsc_pid=$!
sleep 1
cd /work/run
emu_pid=""
cleanup(){
    if [ -n "$emu_pid" ]; then kill "$emu_pid" 2>/dev/null || true; wait "$emu_pid" 2>/dev/null || true; fi
    kill "$pcsc_pid" 2>/dev/null || true
}
trap cleanup EXIT
phase(){
    local name="$1"
    /work/build/pico_fido2 >emulator.log 2>&1 &
    emu_pid=$!
    sleep 1
    kill -0 "$emu_pid" || { cat emulator.log; exit 1; }
    echo "VIRTUAL_F12_PHASE=$name"
    timeout 190s python3 -u /src/tests/host_fido_f12.py "$name"
    kill "$emu_pid" 2>/dev/null || true
    wait "$emu_pid" 2>/dev/null || true
    emu_pid=""
    sleep 1
}
if [ "$F12_SCOPE" = "probe" ]; then
  rm -f memory.flash
  phase pin-make
fi
if [ "$F12_SCOPE" != "pin" ] && [ "$F12_SCOPE" != "probe" ]; then
  rm -f memory.flash
  phase fill
  phase check-full
fi
if [ "$F12_SCOPE" != "capacity" ] && [ "$F12_SCOPE" != "probe" ]; then
  rm -f memory.flash
  phase pin-softlock
  phase pin-unlock
  rm -f memory.flash
  phase pin-hardlock1
  phase pin-hardlock2
  phase pin-hardlock3
  phase pin-reset
fi
case "$F12_SCOPE" in
  capacity) echo "F12_256_RESIDENT_FULL_CAPACITY_REAL_SOURCE_EMULATION: PASS" ;;
  pin) echo "F12_PIN_LOCKOUT_AND_RECOVERY_REAL_SOURCE_EMULATION: PASS" ;;
  probe) echo "F12_FRESH_CARD_PIN_AUTHENTICATED_REGISTER_REAL_SOURCE_EMULATION: PASS" ;;
  all) echo "F12_256_CAPACITY_AND_PIN_LIFECYCLE_REAL_SOURCE_EMULATION: PASS" ;;
  *) echo "F12 invalid test scope: $F12_SCOPE" >&2; exit 2 ;;
esac
echo "No physical USB device was accessed."
INNER
