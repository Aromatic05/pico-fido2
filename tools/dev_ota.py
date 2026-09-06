#!/usr/bin/env python3
"""Install one signed A/B application through development maintenance Wi-Fi.

This tool never changes the host Wi-Fi configuration. It opens maintenance over
USB, waits for the maintenance portal to become reachable, uploads the signed
application, and leaves the device to reboot into the A/B trial slot.
"""

from __future__ import annotations

import argparse
import http.client
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from dev_open_maintenance import request_maintenance

DEFAULT_PORTAL = "http://192.168.4.1"


def wait_for_portal(base_url: str, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    status_url = base_url.rstrip("/") + "/api/status"
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(status_url, timeout=1.0) as response:
                if response.status != 200:
                    raise RuntimeError(f"maintenance status returned HTTP {response.status}")
                return json.loads(response.read())
        except (OSError, RuntimeError, json.JSONDecodeError, urllib.error.URLError) as exc:
            last_error = exc
            time.sleep(0.5)
    raise SystemExit(
        "maintenance portal did not become reachable; connect the host to the "
        f"PicoFIDO2-* development SoftAP and retry ({last_error})"
    )


def upload_firmware(base_url: str, firmware: Path) -> dict:
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise SystemExit("development OTA URL must be an http:// URL")
    path = (parsed.path.rstrip("/") if parsed.path else "") + "/api/update"
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=10)
    size = firmware.stat().st_size
    if size <= 0:
        raise SystemExit("firmware image is empty")

    connection.putrequest("POST", path)
    connection.putheader("Content-Type", "application/octet-stream")
    connection.putheader("Content-Length", str(size))
    connection.endheaders()
    with firmware.open("rb") as source:
        while chunk := source.read(16 * 1024):
            connection.send(chunk)

    response = connection.getresponse()
    body = response.read()
    connection.close()
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"OTA returned HTTP {response.status} with non-JSON body: {body[:200]!r}"
        ) from exc
    if response.status != 202 or payload.get("ok") is not True:
        raise SystemExit(f"OTA rejected: HTTP {response.status}: {payload}")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware", type=Path, help="Secure Boot signed plaintext A/B application")
    parser.add_argument("--serial", help="select one 1050:0407 development device by USB serial")
    parser.add_argument("--portal", default=DEFAULT_PORTAL, help="maintenance portal base URL")
    parser.add_argument("--wait", type=float, default=60.0, help="seconds to wait for the portal")
    args = parser.parse_args()

    if not args.firmware.is_file():
        raise SystemExit(f"firmware image not found: {args.firmware}")

    serial = request_maintenance(args.serial)
    identity = f" serial={serial}" if serial else ""
    print(f"maintenance requested over USB{identity}")
    print("waiting for maintenance portal; this tool will not change host Wi-Fi state")
    status = wait_for_portal(args.portal, args.wait)
    ota = status.get("ota") or {}
    if not ota.get("enabled"):
        raise SystemExit("connected firmware does not expose A/B OTA")
    if not ota.get("ready"):
        raise SystemExit(f"A/B OTA is not ready: {ota}")

    result = upload_firmware(args.portal, args.firmware)
    print(
        "OTA accepted: "
        f"partition={result.get('partition')} version={result.get('version')} "
        f"securityVersion={result.get('securityVersion')} bytes={result.get('bytes')}"
    )
    print("device restart requested; the new slot must survive its PENDING_VERIFY window")


if __name__ == "__main__":
    main()
