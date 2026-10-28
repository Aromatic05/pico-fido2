#!/usr/bin/env python3
'Verify physical OpenPGP metadata against a public-key reference.'
import argparse
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from ykman.device import list_all_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.openpgp import OpenPgpSession, DO, KEY_REF, KEY_STATUS

parser = argparse.ArgumentParser()
parser.add_argument("--reference-public-state", type=Path, required=True)
args = parser.parse_args()
reference = json.loads(args.reference_public_state.read_text())
expected_pem = reference["public_pem"]["SIG"].encode()
devices = list_all_devices()
if len(devices) != 1:
    raise RuntimeError(f"expected 1 physical YubiKey-compatible USB device; got {len(devices)}")

with devices[0][0].open_connection(SmartCardConnection) as conn:
    card = OpenPgpSession(conn)
    live = card.get_public_key(KEY_REF.SIG)
    actual_pem = live.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert actual_pem == expected_pem, "stored RSA SIG public key has changed"
    assert live.key_size == 2048, "expected preserved RSA-2048 SIG key"
    print("OPENPGP_SIG_PUBLIC_KEY_PERSISTENCE: PASS")

    metadata = card.get_key_information()
    assert metadata.get(KEY_REF.SIG) == KEY_STATUS.GENERATED, metadata
    assert metadata == card.get_application_related_data().discretionary.key_information
    print("OPENPGP_KEY_INFORMATION_SIG_GENERATED: PASS")
    print("OPENPGP_METADATA_REFERENCES:", ",".join(sorted(x.name for x in metadata)))

    raw = card.get_data(DO.SECURITY_SUPPORT_TEMPLATE)
    assert raw[:4] == b"\x7a\x05\x93\x03", "constructed 7A/93 TLV missing"
    count = card.get_signature_counter()
    assert isinstance(count, int) and count > 0, count
    print("OPENPGP_SIGNATURE_COUNTER_TLV: PASS")
    print("OPENPGP_EXISTING_SIGNATURE_COUNTER:", count)

print("PHYSICAL_OPENPGP_READ_ONLY_METADATA: PASS")
