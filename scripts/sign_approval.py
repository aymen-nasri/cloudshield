"""Sign an approval on your own machine, so the API never sees your private key.

The proposal's hash is recomputed here, and what you're approving is printed from the same data, so a
tampered API can't show you one action and have you sign another.

    python scripts/sign_approval.py --generate --key bob.pem --approver analyst:bob
    curl -H "authorization: Bearer $TOKEN" $API/v1/proposals/$ID > proposal.json
    python scripts/sign_approval.py --key bob.pem --approver analyst:bob --proposal proposal.json

Send the "signature" and "signed_at" it prints to the approve route, along with your justification.
"""

import argparse
import base64
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from common.models import ResponseProposal  # noqa: E402
from policy.approvals import proposal_hash  # noqa: E402
from policy.signing import sign_approval  # noqa: E402


def generate(key_path: Path, approver: str) -> dict[str, dict[str, str]]:
    """Write a new private key, and return the public entry for the responder's key file."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    key_path.touch(mode=0o600, exist_ok=False)  # never overwrite a key
    key_path.write_bytes(pem)
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {approver: {"public_key": base64.b64encode(raw).decode(), "roles": ["incident-responder"]}}


def summary(proposal: ResponseProposal) -> str:
    target = proposal.target
    return "\n".join(
        [
            f"action:       {proposal.action_type}",
            f"target:       {target.kind} {target.namespace}/{target.name} (uid {target.uid})",
            f"environment:  {proposal.environment}",
            f"case:         {proposal.case_id}",
            f"requested by: {proposal.requested_by}",
            f"rationale:    {proposal.rationale}",
        ]
    )


def approve(
    view: dict, key: Ed25519PrivateKey, approver: str, *, now: datetime | None = None
) -> dict[str, str]:
    """`view` is the API's JSON for a proposal. Refuses if its stated hash isn't what its contents hash to."""
    proposal = ResponseProposal.model_validate(view)
    computed = proposal_hash(proposal)
    if view.get("proposal_hash") != computed:
        raise ValueError(
            f"the API says the hash is {view.get('proposal_hash')}, but these contents hash to {computed}"
        )
    if proposal.requested_by == approver:
        raise ValueError("you requested this action, so you can't approve it")
    signed_at = now or datetime.now(UTC)
    return {
        "proposal_hash": computed,
        "signed_at": signed_at.isoformat(),
        "signature": sign_approval(key, proposal, approver, signed_at),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--approver", required=True)
    parser.add_argument("--proposal", type=Path)
    parser.add_argument("--generate", action="store_true", help="create a key and print its public entry")
    parser.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    args = parser.parse_args()

    if args.generate:
        print(json.dumps(generate(args.key, args.approver), indent=2))
        return 0
    if args.proposal is None:
        parser.error("--proposal is required unless --generate is given")

    view = json.loads(args.proposal.read_text(encoding="utf-8"))
    print(summary(ResponseProposal.model_validate(view)), file=sys.stderr)
    if not args.yes and input("\nApprove exactly this? [y/N] ").strip().lower() != "y":
        print("not signed", file=sys.stderr)
        return 1
    key = load_pem_private_key(args.key.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        parser.error(f"{args.key} is not an Ed25519 key")
    print(json.dumps(approve(view, key, args.approver), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
