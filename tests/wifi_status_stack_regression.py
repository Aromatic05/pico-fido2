#!/usr/bin/env python3
"""Verify the actual ESP32-S3 HTTP status handler leaves room on the task stack.

Run after idf.py build, using the compiled wifi_commission.c.obj, not source
estimates.  This catches accidental return of the multi-KiB status response
buffer to the 8-KiB HTTP task stack.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/fido2/wifi_commission.c"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--object", type=Path, required=True,
                        help="ESP-IDF wifi_commission.c.obj produced by the firmware build")
    args = parser.parse_args()

    source = SOURCE.read_text()
    assert "config.stack_size = 8192;" in source, "HTTP task stack changed; review budget"
    assert "heap_caps_malloc(STATUS_JSON_CAPACITY" in source
    assert "if (body == NULL)" in source, "OOM must return a response"
    status = source.split("static esp_err_t status_get(", 1)[1].split(
        "static esp_err_t config_get(", 1
    )[0]
    assert status.count("free(body);") == 2, "error and normal return must release JSON"
    assert "char body[3072]" not in status

    objdump = (shutil.which("xtensa-esp-elf-objdump")
               or shutil.which("xtensa-esp32s3-elf-objdump"))
    if not objdump:
        raise SystemExit("ESP-IDF Xtensa objdump not in PATH; activate export.sh")
    assembly = subprocess.run(
        [objdump, "-d", str(args.object)],
        check=True, capture_output=True, text=True
    ).stdout
    match = re.search(
        r"(?m)^([0-9a-f]+) <status_get>:\s*\n"
        r"\s*[0-9a-f]+:\s+[0-9a-f]+\s+entry\s+a1,\s*0x([0-9a-f]+)",
        assembly,
    )
    assert match is not None, "compiled status_get stack entry not found"
    frame_bytes = int(match.group(2), 16)
    print("STATUS_GET_COMPILED_FRAME_BYTES", frame_bytes)
    print("HTTP_TASK_STACK_BYTES", 8192)
    assert frame_bytes <= 4096, "status_get alone uses over half the HTTP task stack"
    print("STATUS_GET_STACK_HEADROOM_AND_HEAP_LIFETIME: PASS")


if __name__ == "__main__":
    main()
