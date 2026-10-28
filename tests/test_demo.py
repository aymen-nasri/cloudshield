"""The README's demo must keep telling the truth: run it and check the outcomes it shows."""

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "demo.py"


def test_demo_runs_and_shows_the_safety_outcomes(capsys):
    spec = importlib.util.spec_from_file_location("cloudshield_demo", SCRIPT)
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)

    text = "\n".join(line for _, line in demo.run().lines)

    assert "202 duplicate" in text
    assert "2 events in one case" in text
    assert "409 refused" in text and "403 refused" in text
    assert "-> verified" in text
    assert "chain intact" in text
    assert demo.to_svg(demo.run()).startswith("<svg")
