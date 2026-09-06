#!/usr/bin/env python3
"""Host-only tests for the development maintenance and OTA clients."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import dev_open_maintenance
from dev_ota import upload_firmware, wait_for_portal
from fido2 import cbor


class FakeDescriptor:
    serial_number = "test-serial"


class FakeDevice:
    descriptor = FakeDescriptor()

    def __init__(self) -> None:
        self.closed = False

    def call(self, command: int, payload: bytes) -> bytes:
        assert command == dev_open_maintenance.CTAPHID_VENDOR_CBOR
        assert payload[0] == dev_open_maintenance.VENDOR_MAINTENANCE
        assert cbor.decode(payload[1:]) == {1: dev_open_maintenance.SUBCOMMAND_OPEN}
        return b"\x00" + cbor.encode({1: True})

    def close(self) -> None:
        self.closed = True


def test_usb_request() -> None:
    fake = FakeDevice()
    original = dev_open_maintenance.select_device
    dev_open_maintenance.select_device = lambda serial: fake
    try:
        serial = dev_open_maintenance.request_maintenance("test-serial")
    finally:
        dev_open_maintenance.select_device = original
    assert serial == "test-serial"
    assert fake.closed


class Handler(BaseHTTPRequestHandler):
    received = b""

    def log_message(self, *_args) -> None:
        pass

    def do_GET(self) -> None:
        assert self.path == "/api/status"
        body = json.dumps({"ota": {"enabled": True, "ready": True}}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        assert self.path == "/api/update"
        Handler.received = self.rfile.read(int(self.headers["Content-Length"]))
        body = json.dumps(
            {
                "ok": True,
                "partition": "ota_1",
                "version": "test",
                "securityVersion": 0,
                "bytes": len(Handler.received),
            }
        ).encode()
        self.send_response(202)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_http_client() -> None:
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "app.bin"
            image.write_bytes(b"firmware-test" * 1000)
            assert wait_for_portal(base, 2)["ota"]["ready"] is True
            result = upload_firmware(base, image)
            assert result["ok"] is True
            assert Handler.received == image.read_bytes()
    finally:
        server.shutdown()
        thread.join()


def main() -> None:
    test_usb_request()
    test_http_client()
    print("development maintenance USB + OTA client: PASS")


if __name__ == "__main__":
    main()
