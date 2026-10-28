#!/usr/bin/env python3
'Reproduce malformed metadata and interrupted capacity journal updates without hardware.'

import json
import tempfile
from pathlib import Path

from fido2.ctap2 import CredentialManagement

from hil import fido_capacity as full


COUNT = CredentialManagement.RESULT.EXISTING_CRED_COUNT
REMAINING = CredentialManagement.RESULT.MAX_REMAINING_COUNT


class MetadataSequence:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.reads = 0

    def get_metadata(self):
        self.reads += 1
        return next(self.responses)


def check_read_retry(folder):
    sequence = MetadataSequence([{REMAINING: 208}, {}, {COUNT: 48, REMAINING: 208}])
    result = full.verified_metadata(sequence, folder)
    assert result[COUNT] == 48 and result[REMAINING] == 208
    assert sequence.reads == 3
    assert len(list(folder.glob("f12-full-invalid-metadata-decoded-*.cbor"))) == 2
    print("F12_HOST_METADATA_MISSING_COUNT_READ_ONLY_RETRY_AND_PRIVATE_EVIDENCE: PASS")


def check_three_missing_stop(folder):
    sequence = MetadataSequence([{REMAINING: 208}] * 3)
    try:
        full.verified_metadata(sequence, folder)
    except RuntimeError as error:
        assert "missing required fields" in str(error)
    else:
        raise AssertionError("three malformed metadata replies were silently accepted")
    assert sequence.reads == 3
    print("F12_HOST_THREE_MALFORMED_METADATA_READS_STOP_WITHOUT_REGISTRATION: PASS")


def check_inflight_commit(folder):
    journal = folder / "inflight.json"
    actual = {i: f"test-id-{i}".encode() for i in range(48)}
    state = {
        "phase": "fill", "ids": {str(i): full.sha(actual[i]) for i in range(47)},
        "attestation_failures": [], "unconfirmed_writes": [],
        "inflight": {"index": 47, "credential_sha256": full.sha(actual[47]), "parse_error": None},
    }
    full.reconcile_inflight(actual, state, journal)
    assert state["ids"]["47"] == full.sha(actual[47])
    assert "inflight" not in state and state["unconfirmed_writes"] == []
    assert json.loads(journal.read_text())["ids"]["47"] == full.sha(actual[47])
    print("F12_HOST_PARSED_ATTESTATION_CHECKPOINT_RECOVERS_48_WITHOUT_DUPLICATE_WRITE: PASS")

    state = {
        "phase": "fill", "ids": {str(i): full.sha(actual[i]) for i in range(47)},
        "attestation_failures": [], "unconfirmed_writes": [],
        "inflight": {"index": 47, "credential_sha256": full.sha(b"wrong-id"), "parse_error": None},
    }
    try:
        full.reconcile_inflight(actual, state, journal)
    except AssertionError as error:
        assert "disagrees" in str(error)
    else:
        raise AssertionError("different persisted credential was incorrectly accepted")
    assert "47" not in state["ids"]
    print("F12_HOST_RESUME_REJECTS_CREDENTIAL_ID_MISMATCH: PASS")


def main():
    with tempfile.TemporaryDirectory(prefix="f12-full-recovery-") as tmp:
        directory = Path(tmp)
        check_read_retry(directory)
        check_three_missing_stop(directory)
        check_inflight_commit(directory)
    print("F12_HOST_METADATA_CRASH_RECOVERY_REGRESSION: PASS (host control flow only)")


if __name__ == "__main__":
    main()
