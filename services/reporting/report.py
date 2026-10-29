"""Build a Markdown post-incident report from what CloudShield recorded.

Every sentence comes from stored data: events, the investigation, proposals, approvals, the
execution and the audit log. Nothing is summarized by a model at report time.

Much of that data is attacker-controlled (alert titles, command lines, AI statements quoting them).
Markdown renders links, images and HTML, so every recorded value is escaped as text or placed in a
code span: a planted `![x](https://evil.example/pixel)` shows up as characters, not as a request.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from cases.audit import AuditRecord
from cases.models import Case
from enrichment.graph import Entity
from investigator.records import InvestigationRecord
from response.records import ProposalRecord

_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+!|~])")
_CHAIN = ["pod", "deployment", "service_account", "iam_role", "ec2_instance"]


def text(value: object) -> str:
    """Untrusted text as inert Markdown: one line, every formatting character escaped."""
    flat = " ".join(str(value).split())
    return _SPECIAL.sub(r"\\\1", flat)


def code(value: object, *, in_table: bool = False) -> str:
    """Untrusted text as an inline code span that no backtick inside it can close."""
    flat = " ".join(str(value).split())
    if in_table:
        flat = flat.replace("|", "\\|")  # GFM splits table cells on | even inside code spans
    longest = max((len(run) for run in re.findall(r"`+", flat)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if flat.startswith("`") or flat.endswith("`") else ""
    return f"{fence}{pad}{flat}{pad}{fence}"


def _when(at: datetime | str | None) -> str:
    if at is None:
        return "n/a"
    stamp = at if isinstance(at, str) else at.isoformat()
    return stamp.replace("T", " ")[:19] + " UTC"


@dataclass
class ReportInputs:
    case: Case
    investigations: list[InvestigationRecord]
    proposals: list[ProposalRecord]
    audit: list[AuditRecord]
    chain_intact: bool
    entities: list[Entity] = field(default_factory=list)
    generated_at: datetime | None = None
    generated_by: str = "cloudshield"


def build_report(inputs: ReportInputs) -> str:
    case = inputs.case
    timeline = case.timeline()
    ids = {e.event_id for e in timeline}
    label = {e.event_id: f"{e.source} {e.event_time:%H:%M:%S}Z" for e in timeline}
    out: list[str] = []
    add = out.append

    add(f"# Incident report: {text(case.title)}")
    add("")
    add("| | |")
    add("|---|---|")
    for key, value in [
        ("Case", code(case.case_id, in_table=True)),
        ("Severity", case.severity.value),
        ("Status", text(case.status)),
        ("Scope", f"account {code(case.account_id or 'unknown', in_table=True)}, "
                  f"cluster {code(case.cluster or 'unknown', in_table=True)}"),
        ("Opened", _when(case.opened_at)),
        ("Report generated", f"{_when(inputs.generated_at)} by {code(inputs.generated_by, in_table=True)}"),
    ]:  # fmt: skip
        add(f"| **{key}** | {value} |")
    add("")

    accepted = [i for i in inputs.investigations if i.review_status == "accepted"]
    # Prefer the latest investigation an analyst accepted; else the latest one, flagged as unreviewed.
    candidates = accepted or inputs.investigations
    latest = candidates[-1] if candidates else None
    add("## Summary")
    add("")
    if latest is None:
        add("No investigation was run for this case.")
    else:
        add(text(latest.output.synopsis))
        add("")
        review = latest.review_status if latest.review_status == "unreviewed" else (
            f"{latest.review_status} by {code(latest.reviewed_by)}"
        )  # fmt: skip
        runbooks = ", ".join(code(d) for d in latest.retrieved_doc_ids) or "none"
        add(f"Investigation {code(latest.investigation_id)}, model {code(latest.model_id)}, prompt "
            f"{code(latest.prompt_version)}, runbooks {runbooks}; review: {review}.")  # fmt: skip
    add("")

    if inputs.entities:
        by_kind = {e.kind: e for e in inputs.entities}
        chain = [by_kind[k] for k in _CHAIN if k in by_kind]
        add("## Affected entity")
        add("")
        add(" → ".join(f"{k.kind.replace('_', ' ')} {code(k.entity_id.split('/')[-1])}" for k in chain))
        add("")
        missing = [k.replace("_", " ") for k in _CHAIN if k not in by_kind]
        if missing:
            add(f"Not resolved: {', '.join(missing)}.")
            add("")

    add("## Timeline")
    add("")
    add("| Time (event time) | Source | Event | Severity | Event ID |")
    add("|---|---|---|---|---|")
    for e in timeline:
        add(f"| {_when(e.event_time)} | {text(e.source)} | {code(e.title, in_table=True)} | "
            f"{e.severity.normalized.value} | {code(e.event_id, in_table=True)} |")  # fmt: skip
    add("")

    add("## Evidence index")
    add("")
    add("Raw payloads are stored unchanged; the checksum proves they were not altered.")
    add("")
    add("| Event ID | Source event ID | Raw evidence | SHA-256 |")
    add("|---|---|---|---|")
    for e in timeline:
        add(f"| {code(e.event_id, in_table=True)} | {code(e.source_event_id, in_table=True)} | "
            f"{code(e.raw_evidence_uri, in_table=True)} | {code(e.checksum, in_table=True)} |")  # fmt: skip
    add("")

    add("## Findings")
    add("")
    if latest is None:
        add("None recorded.")
    else:

        def cite(evidence: Iterable[str]) -> str:
            return ", ".join(code(label.get(i, i)) for i in evidence if i in ids) or "no valid citation"

        for f in latest.output.observed_facts:
            add(f"- **Fact:** {text(f.statement)} ({cite(f.evidence_ids)})")
        for h in latest.output.hypotheses:
            add(f"- **Hypothesis ({h.confidence}):** {text(h.statement)} ({cite(h.supporting_evidence)})")
        add("")
        add(f"Confidence limits: {text(latest.output.confidence_limits)}")
    add("")

    add("## Response")
    add("")
    if not inputs.proposals:
        add("No response action was proposed.")
        add("")
    for p in inputs.proposals:
        prop = p.proposal
        add(f"### {code(prop.action_type)} on {code(f'{prop.target.namespace}/{prop.target.name}')}")
        add("")
        add(f"- **Final state:** {p.state.value.replace('_', ' ')}")
        who = f"{code(prop.requested_by)} at {_when(prop.created_at)}"
        add(f"- **Requested by** {who}: {text(prop.rationale)}")
        if p.policy:
            decision = p.policy.decision.value.replace("_", " ")
            reasons = text("; ".join(p.policy.reasons))
            add(f"- **Policy:** {decision}, {p.policy.required_approvals} approval(s) required; {reasons}")
        lost = (prop.impact_preview or {}).get("allow_policies_lost")
        if lost is not None:
            names = ", ".join(code(x) for x in lost) or "nothing"
            add(f"- **Impact preview:** pod keeps running; loses {names}")
        for a in p.approvals:
            current = "this version" if a.bound_hash == p.proposal_hash else "an older version"
            verb = {"approve": "Approved", "reject": "Rejected"}[a.decision]
            add(f"- **{verb}** by {code(a.approver)} at {_when(a.decided_at)} "
                f"({current}): {text(a.justification)}")  # fmt: skip
        if p.execution:
            x = p.execution
            add(f"- **Executed** by {code(x.executor_identity)} at {_when(x.started_at)}: {text(x.status)}")
            marks = {True: "passed", False: "FAILED", None: "skipped"}
            for name, passed in x.checks.items():
                note = f" ({text(x.notes[name])})" if name in x.notes else ""
                add(f"    - {code(name)}: {marks[passed]}{note}")
        add("")

    add("## Open questions")
    add("")
    open_items = [text(m) for m in (latest.output.missing_evidence if latest else [])]
    for p in inputs.proposals:
        if p.execution:
            open_items += [
                f"verification check {code(n)} was skipped"
                for n, v in p.execution.checks.items()
                if v is None
            ]
    if latest is None:
        open_items.append("no investigation was run")
    elif latest.review_status == "unreviewed":
        open_items.append("the investigation has not been reviewed by an analyst")
    add("\n".join(f"- {item}" for item in open_items) if open_items else "None recorded.")
    add("")

    add("## Audit trail")
    add("")
    status = "intact" if inputs.chain_intact else "**BROKEN: the audit log was altered**"
    add(f"{len(inputs.audit)} hash-chained records for this case; chain {status}.")
    add("")
    add("| # | Time | Actor | Action |")
    add("|---|---|---|---|")
    for r in inputs.audit:
        actor = f"{r.actor_type} {code(r.actor_id, in_table=True)}"
        add(f"| {r.seq} | {_when(r.ts)} | {actor} | {code(r.action, in_table=True)} |")
    add("")
    add("---")
    add("")
    add(
        "Generated by CloudShield from recorded evidence. "
        "Nothing in this report was written by hand or by a model at report time."
    )
    return "\n".join(out) + "\n"
