"""Score the deterministic payload used by the disposable smoke event."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SMOKE_PAYLOAD = b"smoke-exploit\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--team-id", required=True)
    parser.add_argument("--payload-sha256", required=True)
    parser.add_argument("--submission-sha256", required=True)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()

    bundle = arguments.bundle.read_bytes()
    payload_sha256 = hashlib.sha256(bundle).hexdigest()
    if payload_sha256 != arguments.payload_sha256:
        raise ValueError("bundle does not match the signed payload digest")
    accepted = bundle == SMOKE_PAYLOAD
    result = {
        "attempt_id": arguments.attempt_id,
        "kind": "smoke-score-result",
        "payload_sha256": payload_sha256,
        "score": 100 if accepted else 0,
        "scorer": {"id": "smoke-exact-match", "version": "1"},
        "status": "accepted" if accepted else "rejected",
        "submission_sha256": arguments.submission_sha256,
        "team_id": arguments.team_id,
        "v": 1,
    }
    arguments.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
