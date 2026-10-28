"""Regenerate /schemas from the Pydantic models. CI fails if the committed files are stale.

    python scripts/export_schemas.py          # write
    python scripts/export_schemas.py --check  # verify only
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

from common.models import Investigation, NormalizedEvent, ResponseProposal  # noqa: E402

MODELS = {
    "normalized-event.schema.json": NormalizedEvent,
    "investigation.schema.json": Investigation,
    "response-proposal.schema.json": ResponseProposal,
}


def render(model: type) -> str:
    schema = model.model_json_schema()  # type: ignore[attr-defined]
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"https://github.com/aymen-nasri/cloudshield/schemas/{model.__name__}"
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    stale = []
    for filename, model in MODELS.items():
        path = ROOT / "schemas" / filename
        content = render(model)
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(filename)
        else:
            path.parent.mkdir(exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    if stale:
        print("stale schemas (run scripts/export_schemas.py):", ", ".join(stale))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
