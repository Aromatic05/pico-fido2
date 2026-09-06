#!/usr/bin/env python3
"""Reject product sdkconfig defaults that kconfgen would silently ignore."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    files = sorted(ROOT.glob("sdkconfig*.defaults"))
    if not files:
        raise AssertionError("no product sdkconfig defaults found")

    checked = 0
    for path in files:
        for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("CONFIG_") or "=" not in line:
                raise AssertionError(f"{path.name}:{lineno}: malformed sdkconfig line: {line}")
            checked += 1

    defaults = (ROOT / "sdkconfig.defaults").read_text(encoding="utf-8")
    if "CONFIG_COMPILER_OPTIMIZATION_DEBUG=y" not in defaults:
        raise AssertionError("validated bring-up baseline must explicitly retain debug optimization")
    if "IGNORE_UNKNOWN_FILES_FOR_MANAGED_COMPONENTS" in defaults:
        raise AssertionError("component-manager environment variables do not belong in sdkconfig.defaults")
    for deprecated in (
        "CONFIG_WPA_MBEDTLS_CRYPTO",
        "CONFIG_ESP32_WIFI_ENABLE_WPA3_SAE",
        "CONFIG_ESP32_WIFI_ENABLE_WPA3_OWE_STA",
    ):
        if deprecated in defaults:
            raise AssertionError(f"deprecated IDF Kconfig alias remains in sdkconfig.defaults: {deprecated}")

    print(f"sdkconfig defaults: PASS ({len(files)} files, {checked} Kconfig assignments)")


if __name__ == "__main__":
    main()
