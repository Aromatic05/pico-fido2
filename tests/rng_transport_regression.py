#!/usr/bin/env python3
"""Exercise the real SDK random.c with deterministic hardware RNG stubs.

Both ESP_PLATFORM and non-ESP byte-consumption paths are built. This is a
functional memory/API test, not an entropy or physical hardware certification.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RNG = ROOT / "pico-keys-sdk/src/rng"

TEST = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "random.h"

static uint32_t *ring;
static uint8_t word_count;
static uint32_t next_word = 0x12345678;
/* The test source has a long cycle: a 0..255 byte counter incorrectly
 * repeats after a 1024-byte request and would generate a false failure. */
static uint32_t next_esp_state = 0xA71C35E9U;
static unsigned direct_calls;

void hwrng_init(uint32_t *buf, uint8_t len) {
    ring=buf; word_count=len;
}
uint32_t hwrng_get(void) {
    return next_word++;
}
void hwrng_flush(void) {
    (void)0;
}
void hwrng_wait_full(void) {
    assert(ring!=NULL && word_count==8);
    for (unsigned i=0;i<word_count;i++) {
        ring[i] = next_word++;
    }
}
void esp_fill_random(void *buffer, size_t size) {
    uint8_t *bytes=buffer;
    direct_calls++;
    for (size_t i=0;i<size;i++) {
        next_esp_state ^= next_esp_state << 13;
        next_esp_state ^= next_esp_state >> 17;
        next_esp_state ^= next_esp_state << 5;
        bytes[i] = (uint8_t)(next_esp_state >> 16);
    }
}

int main(void) {
    random_init();
    uint8_t a[16], b[16], idx=3;
    assert(random_gen(NULL,a,16)==0);
    assert(random_gen(NULL,b,16)==0);
    assert(memcmp(a,b,16)!=0);
    assert(random_gen(&idx,a,16)==0);
    assert(random_gen(NULL,NULL,1)!=0);
    assert(random_gen(NULL,NULL,0)==0);
    assert(random_bytes_get(1025)==NULL);
    const uint8_t *p=random_bytes_get(1024);
    assert(p!=NULL);
    uint8_t copy[1024];memcpy(copy,p,sizeof(copy));
    random_bytes_free(p);
    for (size_t i=0;i<1024;i++) assert(p[i]==0);
    p=random_bytes_get(17);
    assert(p!=NULL && memcmp(p,copy,17)!=0);
    /* Partial last blocks must not read/write beyond the requested length.
     * ASan/UBSan validates the path at the same time. */
    assert(random_bytes_get(1)!=NULL);
    assert(random_bytes_get(33)!=NULL);
    assert(random_bytes_get(1023)!=NULL);
#if defined(ESP_PLATFORM)
    assert(direct_calls>=7);
    printf("ESP_RANDOM_HARDWARE_DIRECT_AND_NO_REUSE: PASS\n");
#else
    assert(direct_calls==0);
    printf("HOST_HWRNG_CONSUMES_UNIQUE_WORDS: PASS\n");
#endif
    printf("RNG_BOUNDARY_0_1_17_33_1023_1024_1025_AND_ZEROIZE: PASS\n");
    return 0;
}
"""


def run(platform: str) -> None:
    with tempfile.TemporaryDirectory(prefix="aromatic-rng-") as directory:
        temp = Path(directory)
        (temp / "esp_random.h").write_text(
            "#include <stddef.h>\nvoid esp_fill_random(void *buffer, size_t len);\n"
        )
        source = temp / "test.c"
        source.write_text(TEST)
        binary = temp / "test"
        command = [
            "cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            "-I", str(temp), "-I", str(RNG),
            *([] if platform == "host" else ["-DESP_PLATFORM"]),
            str(RNG / "random.c"), str(source), "-o", str(binary),
        ]
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    for target in ("host", "esp"):
        run(target)
