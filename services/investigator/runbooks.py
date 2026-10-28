"""Runbook retrieval: the approved procedures that apply to a case, split into citable passages.

Selection is lexical and explainable on purpose: a runbook applies when its front matter lists one
of the case's event types or MITRE ATT&CK techniques. Vector search can come later (README, AI layer).
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from common.models import NormalizedEvent

MAX_PASSAGES = 6
MAX_PASSAGE_CHARS = 1500

_FRONT_MATTER = re.compile(r"\A---\n(.*?)\n---\n(.*)\Z", re.S)


@dataclass(frozen=True)
class Runbook:
    doc_id: str
    title: str
    applies_to: frozenset[str]
    mitre: frozenset[str]
    sections: tuple[tuple[str, str], ...]  # (heading, text)


def parse_runbook(text: str) -> Runbook | None:
    match = _FRONT_MATTER.match(text.replace("\r\n", "\n"))
    if not match:
        return None
    meta = yaml.safe_load(match.group(1)) or {}
    sections: list[tuple[str, str]] = []
    for chunk in re.split(r"^## ", match.group(2), flags=re.M)[1:]:
        heading, _, body = chunk.partition("\n")
        sections.append((heading.strip(), body.strip()[:MAX_PASSAGE_CHARS]))
    return Runbook(
        doc_id=str(meta["id"]),
        title=str(meta.get("title", meta["id"])),
        applies_to=frozenset(str(a) for a in meta.get("applies_to", [])),
        mitre=frozenset(str(t) for t in meta.get("mitre", [])),
        sections=tuple(sections),
    )


def _techniques(event: NormalizedEvent) -> set[str]:
    return {a["technique"]["uid"] for a in event.ocsf.get("attacks", []) if "technique" in a}


class RunbookLibrary:
    def __init__(self, runbooks: list[Runbook]) -> None:
        self.runbooks = runbooks

    @classmethod
    def from_dir(cls, path: Path | None) -> "RunbookLibrary":
        if path is None or not path.is_dir():
            return cls([])
        parsed = [parse_runbook(p.read_text(encoding="utf-8")) for p in sorted(path.glob("*.md"))]
        return cls([r for r in parsed if r is not None])

    def passages_for(self, events: list[NormalizedEvent]) -> list[dict[str, Any]]:
        """Passages from runbooks matching the events, best match first, at most MAX_PASSAGES."""
        types = {e.event_type for e in events}
        techniques = set().union(*(_techniques(e) for e in events)) if events else set()
        scored = []
        for book in self.runbooks:
            score = 2 * len(book.applies_to & types) + len(book.mitre & techniques)
            if score:
                scored.append((score, book))
        scored.sort(key=lambda pair: (-pair[0], pair[1].doc_id))

        passages: list[dict[str, Any]] = []
        for _, book in scored:
            for heading, text in book.sections:
                passages.append(
                    {"doc_id": book.doc_id, "title": book.title, "section": heading, "text": text}
                )
        return passages[:MAX_PASSAGES]
