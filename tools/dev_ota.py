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
DEFAULT_UPLOAD_TIMEOUT = 120.0


def get_portal_config(base_url: str, timeout: float = 2.0) -> dict:
    config_url = base_url.rstrip("/") + "/api/config"
    try:
        with urllib.request.urlopen(config_url, timeout=timeout) as response:
            if response.status != 200:
                raise RuntimeError(f"maintenance config returned HTTP {response.status}")
            return json.loads(response.read())
    except (OSError, RuntimeError, json.JSONDecodeError, urllib.error.URLError) as exc:
        raise SystemExit(f"failed to read maintenance config: {exc}") from exc


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


def wait_for_config_only(base_url: str, timeout: float) -> dict:
    """Wait for the small CSRF/config endpoint, never probing /api/status.

    Used only for recovering a development board whose old HIL status page
    exhausts its HTTPD stack. The device-side fido_ota_begin() independently
    enforces signed A/B readiness, rollback state and inactive-slot capacity.
    """
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            config = get_portal_config(base_url, timeout=1.0)
            csrf = config.get("csrf")
            version = config.get("projectVersion")
            if not isinstance(csrf, str) or len(csrf) != 32:
                raise RuntimeError("maintenance config has no valid CSRF token")
            if not isinstance(version, str) or not version:
                raise RuntimeError("maintenance config has no firmware version")
            return config
        except (SystemExit, RuntimeError) as exc:
            last_error = exc
            time.sleep(0.5)
    raise SystemExit(f"maintenance config unavailable: {last_error}")


def upload_firmware(
    base_url: str,
    firmware: Path,
    timeout: float = DEFAULT_UPLOAD_TIMEOUT,
    config: dict | None = None,
    body_start_delay: float = 0.0,
    upload_chunk_size: int = 16 * 1024,
    upload_chunk_interval: float = 0.0,
) -> dict:
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise SystemExit("development OTA URL must be an http:// URL")
    path = (parsed.path.rstrip("/") if parsed.path else "") + "/api/update"
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=timeout)
    size = firmware.stat().st_size
    if size <= 0:
        raise SystemExit("firmware image is empty")

    connection.putrequest("POST", path)
    connection.putheader("Content-Type", "application/octet-stream")
    connection.putheader("Content-Length", str(size))
    if config is None:
        config = get_portal_config(base_url)
    csrf = config.get("csrf")
    if not isinstance(csrf, str) or len(csrf) != 32:
        raise SystemExit("maintenance config did not provide a valid CSRF token")
    connection.putheader("X-Pico-CSRF", csrf)
    connection.endheaders()
    # On low-memory ESP32-S3 profiles, TCP receive buffers may consume the
    # largest free internal heap block before the OTA handler allocates its
    # fixed 16 KiB buffer. Let the handler allocate before sending the body.
    if body_start_delay:
        time.sleep(body_start_delay)
    with firmware.open("rb") as source:
        while chunk := source.read(upload_chunk_size):
            connection.send(chunk)
            if upload_chunk_interval:
                time.sleep(upload_chunk_interval)

    response = connection.getresponse()
    if response.status == 202:
        payload = {
            "ok": True,
            "partition": response.getheader("X-Pico-Partition"),
            "version": response.getheader("X-Pico-Version"),
            "securityVersion": response.getheader("X-Pico-Security-Version"),
            "bytes": response.getheader("X-Pico-Image-Bytes"),
        }
        response.read()
        connection.close()
        return payload

    body = response.read()
    connection.close()
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"OTA returned HTTP {response.status} with non-JSON body: {body[:200]!r}"
        ) from exc
    if payload.get("ok") is not True:
        raise SystemExit(f"OTA rejected: HTTP {response.status}: {payload}")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware", type=Path, help="Secure Boot signed plaintext A/B application")
    parser.add_argument("--serial", help="select one 1050:0407 development device by USB serial")
    parser.add_argument("--portal", default=DEFAULT_PORTAL, help="maintenance portal base URL")
    parser.add_argument("--wait", type=float, default=60.0, help="seconds to wait for the portal")
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="do not request maintenance over USB; use an already-open physical maintenance session",
    )
    parser.add_argument(
        "--skip-status",
        action="store_true",
        help="recovery only: probe /api/config, not the older HIL /api/status endpoint; "
             "server still checks A/B readiness, Secure Boot signature and image policy",
    )
    parser.add_argument(
        "--expect-current-version",
        help="refuse update unless the lightweight /api/config reports this exact "
             "currently running firmware version",
    )
    parser.add_argument(
        "--upload-timeout",
        type=float,
        default=DEFAULT_UPLOAD_TIMEOUT,
        help="seconds to wait for the OTA upload/verification response",
    )
    parser.add_argument("--body-start-delay", type=float, default=0.0,
                        help="seconds to wait after HTTP headers before streaming firmware")
    parser.add_argument("--upload-chunk-size", type=int, default=16 * 1024,
                        help="bytes to stream per TCP write (default: 16384)")
    parser.add_argument("--upload-chunk-interval", type=float, default=0.0,
                        help="optional pacing interval in seconds after each write")
    args = parser.parse_args()
    if args.body_start_delay < 0 or args.upload_chunk_interval < 0 or args.upload_chunk_size <= 0:
        parser.error("upload pacing intervals must be nonnegative and chunk size positive")

    if not args.firmware.is_file():
        raise SystemExit(f"firmware image not found: {args.firmware}")

    if not args.no_open:
        serial = request_maintenance(args.serial)
        identity = f" serial={serial}" if serial else ""
        print(f"maintenance requested over USB{identity}")
    else:
        print("using an already-open maintenance session")
    print("waiting for maintenance portal; this tool will not change host Wi-Fi state")
    if args.skip_status:
        print("recovering via lightweight /api/config only; device OTA policy "
              "will reject unavailable or unverified A/B updates")
        config = wait_for_config_only(args.portal, args.wait)
    else:
        status = wait_for_portal(args.portal, args.wait)
        ota = status.get("ota") or {}
        if not ota.get("enabled"):
            raise SystemExit("connected firmware does not expose A/B OTA")
        if not ota.get("ready") or ota.get("confirmationPending"):
            raise SystemExit(f"A/B OTA is not ready: {ota}")
        config = get_portal_config(args.portal)
    if args.expect_current_version is not None:
        if config.get("projectVersion") != args.expect_current_version:
            raise SystemExit(
                "maintenance firmware version mismatch: expected "
                f"{args.expect_current_version!r}, "
                f"observed {config.get('projectVersion')!r}"
            )
    result = upload_firmware(
        args.portal, args.firmware, args.upload_timeout, config,
        body_start_delay=args.body_start_delay,
        upload_chunk_size=args.upload_chunk_size,
        upload_chunk_interval=args.upload_chunk_interval,
    )
    print(
        "OTA accepted: "
        f"partition={result.get('partition')} version={result.get('version')} "
        f"securityVersion={result.get('securityVersion')} bytes={result.get('bytes')}"
    )
    print("device restart requested; the new slot must survive its PENDING_VERIFY window")


if __name__ == "__main__":
    main()
