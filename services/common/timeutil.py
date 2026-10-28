"""Timestamp parsing that tolerates the formats security tools actually emit."""

import re
from datetime import UTC, datetime

_FRACTION = re.compile(r"\.(\d+)")
_BASIC_OFFSET = re.compile(r"([+-]\d{2})(\d{2})$")


def utcnow() -> datetime:
    return datetime.now(UTC)


def parse_time(value: str) -> datetime:
    """Parse ISO-8601 with nanosecond fractions (Falco) or +0000 offsets (Wazuh); always returns UTC."""
    text = value.strip().replace("Z", "+00:00")
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    text = _BASIC_OFFSET.sub(r"\1:\2", text)
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
