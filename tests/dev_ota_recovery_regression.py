#!/usr/bin/env python3
"""Check A/B OTA recovery when an old HIL /api/status handler is unusable.

All HTTP runs on localhost against this process's ephemeral test server.
No device discovery, Wi-Fi configuration, flash access or real firmware.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import dev_ota  # noqa: E402

VERSION = "aromatic-key-test-recovery"
CSRF = "0123456789abcdef0123456789abcdef"


class Handler(BaseHTTPRequestHandler):
    status_reads = 0
    config_reads = 0
    uploads = 0
    payload = b""

    def log_message(self, fmt: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        if self.path == "/api/status":
            type(self).status_reads += 1
            self.send_error(503, "old status endpoint unavailable")
            return
        if self.path != "/api/config":
            self.send_error(404)
            return
        type(self).config_reads += 1
        body = json.dumps({"csrf": CSRF, "projectVersion": VERSION}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        assert self.path == "/api/update"
        assert self.headers["X-Pico-CSRF"] == CSRF
        length = int(self.headers["Content-Length"])
        type(self).payload = self.rfile.read(length)
        type(self).uploads += 1
        self.send_response(202)
        for key, value in (
            ("X-Pico-Partition", "ota_0"),
            ("X-Pico-Version", "aromatic-key-test-new"),
            ("X-Pico-Security-Version", "0"),
            ("X-Pico-Image-Bytes", str(length)),
        ):
            self.send_header(key, value)
        self.send_header("Content-Length", "0")
        self.end_headers()


def main() -> None:
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            with tempfile.TemporaryDirectory(prefix="ak-ota-offline-") as directory:
                image = Path(directory) / "signed-image-placeholder.bin"
                image.write_bytes(bytes(range(256)) * 65)

                config = dev_ota.wait_for_config_only(url, 2.0)
                assert config["projectVersion"] == VERSION
                assert Handler.status_reads == 0
                response = dev_ota.upload_firmware(url, image, 2.0, config)
                assert response["partition"] == "ota_0"
                assert Handler.payload == image.read_bytes()
                assert Handler.config_reads == 1
                assert Handler.uploads == 1
                print("OTA_CONFIG_ONLY_NO_STATUS_AND_SIGNED_UPLOAD_ROUTE: PASS")

                argv = sys.argv
                try:
                    sys.argv = [
                        "dev_ota.py", "--no-open", "--skip-status",
                        "--expect-current-version", "wrong-current-firmware",
                        "--portal", url, str(image),
                    ]
                    with contextlib.redirect_stdout(io.StringIO()):
                        try:
                            dev_ota.main()
                        except SystemExit as exc:
                            assert "version mismatch" in str(exc)
                        else:
                            raise AssertionError("incorrect current version accepted")
                    assert Handler.uploads == 1
                    assert Handler.status_reads == 0
                    print("OTA_VERSION_MISMATCH_REFUSES_UPLOAD: PASS")
                finally:
                    sys.argv = argv
        finally:
            server.shutdown()
            thread.join(timeout=2.0)


if __name__ == "__main__":
    main()
