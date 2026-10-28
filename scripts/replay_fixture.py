"""Replay a labeled incident fixture against a running CloudShield core API.

    python scripts/replay_fixture.py detections/fixtures/s1_suspicious_process

Reads `replay_order` from expected.yaml and posts each file to /v1/ingest/<source>,
authenticating the same way real producers do.
"""

import argparse
import os
import sys
from pathlib import Path

import httpx
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services"))
from ingestion.auth import SIGNATURE_HEADER, sign  # noqa: E402

SOURCE_BY_PREFIX = {"falco": "falco", "guardduty": "guardduty", "wazuh": "wazuh"}


def headers_for(source: str, body: bytes) -> dict[str, str]:
    headers = {"content-type": "application/json"}
    if source == "falco":
        headers["authorization"] = f"Bearer {os.environ['CLOUDSHIELD_FALCO_TOKEN']}"
    elif source == "wazuh":
        headers[SIGNATURE_HEADER] = sign(os.environ["CLOUDSHIELD_WAZUH_HMAC_SECRET"], body)
    else:
        headers[SIGNATURE_HEADER] = sign(os.environ["CLOUDSHIELD_REPLAY_HMAC_SECRET"], body)
    return headers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture_dir", type=Path)
    parser.add_argument("--url", default=os.getenv("CLOUDSHIELD_URL", "http://localhost:8080"))
    args = parser.parse_args()

    expected = yaml.safe_load((args.fixture_dir / "expected.yaml").read_text(encoding="utf-8"))
    files = expected.get("replay_order") or sorted(p.name for p in args.fixture_dir.glob("*.json"))

    with httpx.Client(base_url=args.url, timeout=10) as client:
        for name in files:
            source = SOURCE_BY_PREFIX[name.split("_")[0]]
            body = (args.fixture_dir / name).read_bytes()
            response = client.post(f"/v1/ingest/{source}", content=body, headers=headers_for(source, body))
            print(f"{name:<28} -> {response.status_code} {response.json()}")
            response.raise_for_status()

        cases = client.get("/v1/cases").json()
        print(f"\n{len(cases)} case(s): " + ", ".join(f"{c['case_id']} ({c['event_count']} events)" for c in cases))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
