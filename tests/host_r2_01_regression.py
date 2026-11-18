#!/usr/bin/env python3
"""Verify large MakeCredential fields cannot produce an empty success response."""

import argparse
from pathlib import Path
import socket
import tempfile

from fido2 import cbor

from host_p1_regressions import running
from host_powercycle_durability import open_fido
from host_protocol_smoke import (
    CTAPHID_CBOR,
    CTAPHID_INIT,
    hid_init_packet,
    parse_hid_init,
    recv_frame,
    recv_hid_message,
    send_frame,
)


def make_credential(hid, cid, user_id_length):
    request = {
        1: bytes(32),
        2: {"id": "p0.invalid"},
        3: {"id": b"u" * user_id_length, "name": "p0"},
        4: [{"type": "public-key", "alg": -7}],
    }
    payload = b"\x01" + cbor.encode(request)
    initial = cid + bytes((CTAPHID_CBOR,)) + len(payload).to_bytes(2, "big") + payload[:57]
    send_frame(hid, initial.ljust(64, b"\0"))
    remaining = payload[57:]
    sequence = 0
    while remaining:
        chunk, remaining = remaining[:59], remaining[59:]
        send_frame(hid, (cid + bytes((sequence,)) + chunk).ljust(64, b"\0"))
        sequence += 1
    return recv_hid_message(hid, cid, CTAPHID_CBOR)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="r2-01-credential-id-") as tmp:
        with running(args.binary.resolve(), Path(tmp)):
            hid = socket.create_connection(("127.0.0.1", 35962), timeout=5)
            hid.settimeout(5)
            try:
                send_frame(hid, hid_init_packet(b"\xff" * 4, CTAPHID_INIT, b"12345678"))
                _, _, init = parse_hid_init(recv_frame(hid))
                cid = init[8:12]
                assert make_credential(hid, cid, 912) == b"\x21"
                accepted = rejected = 0
                for length in range(860, 915):
                    response = make_credential(hid, cid, length)
                    assert response != b"\x00", length
                    if response[0] == 0:
                        auth_data = cbor.decode(response[1:])[2]
                        credential_length = int.from_bytes(auth_data[53:55], "big")
                        assert 0 < credential_length <= 1024, length
                        accepted += 1
                    else:
                        assert response in (b"\x15", b"\x21"), (length, response.hex())
                        rejected += 1
                assert accepted > 0 and rejected > 0, (accepted, rejected)
            finally:
                hid.close()

            device, ctap = open_fido()
            with device:
                made = ctap.make_credential(
                    bytes(32), {"id": "p0.invalid"}, {"id": b"normal-user"},
                    [{"type": "public-key", "alg": -7}],
                )
                credential = made.auth_data.credential_data.credential_id
                assertion = ctap.get_assertion(
                    "p0.invalid", bytes(32),
                    allow_list=[{"type": "public-key", "id": credential}],
                )
                assert len(assertion.auth_data) == 37
    print("R2-01 large credential responses and normal assertion: PASS")


if __name__ == "__main__":
    main()
