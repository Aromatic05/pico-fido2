#!/usr/bin/env python3
"""CTAPHID_INIT uses fresh channel IDs for broadcast and preserves known CID on sync."""
import re
import subprocess
import tempfile
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'pico-keys-sdk/src/usb/hid/hid.c'


def function_body(source: str, name: str) -> str:
    match = re.search(r'(?m)^static uint32_t\s+' + re.escape(name) + r'\s*\([^)]*\)\s*\{', source)
    assert match is not None, f'missing real SDK HID {name} implementation'
    depth = 0
    for i in range(match.end() - 1, len(source)):
        if source[i] == '{':
            depth += 1
        elif source[i] == '}':
            depth -= 1
            if depth == 0:
                return source[match.start(): i + 1]
    raise AssertionError('unbalanced function braces')


def main() -> None:
    src = SOURCE.read_text()
    allocator = function_body(src, 'hid_init_response_cid')
    parser = src[src.index('int driver_process_usb_packet_hid(uint16_t read) {'):]
    assert re.search(r'resp->cid\s*=\s*hid_init_response_cid\(ctap_req->cid\);', parser), (
        'HID must use assigned channel ID for its actual CTAPHID_INIT response'
    )
    with tempfile.TemporaryDirectory(prefix='ak-hid-init-channel-') as tmp:
        p = Path(tmp)
        (p / 'check.c').write_text('''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#define CID_BROADCAST UINT32_C(0xFFFFFFFF)
''' + allocator + '''
int main(void) {
    uint32_t previous=0;
    for (int i=0;i<512;i++) {
        uint32_t cid=hid_init_response_cid(CID_BROADCAST);
        assert(cid!=0 && cid!=CID_BROADCAST && cid!=previous);
        assert(hid_init_response_cid(cid)==cid);
        previous=cid;
    }
    assert(hid_init_response_cid(UINT32_C(0x12345678))==UINT32_C(0x12345678));
    puts("HID_BROADCAST_INIT_512_FRESH_CHANNELS: PASS");
    puts("HID_NON_BROADCAST_INIT_PRESERVES_CHANNEL: PASS");
    return 0;
}
''')
        binary = p / 'check'
        subprocess.run(['cc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        str(p / 'check.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
