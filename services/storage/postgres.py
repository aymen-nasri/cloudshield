"""PostgreSQL stores. Each method is one transaction; the database enforces the invariants the
in-memory stores only promise (unique dedup keys, one execution per proposal, append-only audit).
"""

from collections.abc import Callable
from datetime import datetime
from decimal import Decimal
from typing import Any

from psycopg import errors
from psycopg.types.json import Jsonb

from cases.audit import GENESIS_HASH, ActorType, AuditRecord, format_ts, make_record, verify_chain
from cases.models import Case, CaseLink
from common.models import CorrelationKeys, NormalizedEvent, SeverityInfo
from common.timeutil import utcnow
from enrichment.graph import Edge, Entity
from ingestion.pipeline import DuplicateEventError
from storage.database import Database

_AUDIT_LOCK = 0x0C1D5E1A


def _event_params(e: NormalizedEvent, dedup_key: str) -> dict[str, Any]:
    return {
        "event_id": e.event_id,
        "dedup_key": dedup_key,
        "source": e.source,
        "source_event_id": e.source_event_id,
        "schema_version": e.schema_version,
        "event_time": e.event_time,
        "ingest_time": e.ingest_time,
        "account_id": e.account_id,
        "cluster": e.cluster,
        "namespace": e.namespace,
        "resource_id": e.resource_id,
        "identity_id": e.identity_id,
        "event_type": e.event_type,
        "title": e.title,
        "severity": e.severity.normalized.value,
        "original_severity": e.severity.original,
        "pod_uid": e.keys.pod_uid,
        "instance_id": e.keys.instance_id,
        "principal_arn": e.keys.principal_arn,
        "raw_evidence_uri": e.raw_evidence_uri,
        "checksum_sha256": e.checksum,
        "ocsf": Jsonb(e.ocsf),
    }


_INSERT_EVENT = """
INSERT INTO event (
    event_id, dedup_key, source, source_event_id, schema_version, event_time, ingest_time,
    account_id, cluster, namespace, resource_id, identity_id, event_type, title, severity,
    original_severity, pod_uid, instance_id, principal_arn, raw_evidence_uri, checksum_sha256, ocsf
) VALUES (
    %(event_id)s, %(dedup_key)s, %(source)s, %(source_event_id)s, %(schema_version)s,
    %(event_time)s, %(ingest_time)s, %(account_id)s, %(cluster)s, %(namespace)s, %(resource_id)s,
    %(identity_id)s, %(event_type)s, %(title)s, %(severity)s, %(original_severity)s, %(pod_uid)s,
    %(instance_id)s, %(principal_arn)s, %(raw_evidence_uri)s, %(checksum_sha256)s, %(ocsf)s
)
"""


def _event_from_row(r: dict[str, Any]) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=r["event_id"],
        source=r["source"],
        source_event_id=r["source_event_id"],
        schema_version=r["schema_version"],
        event_time=r["event_time"],
        ingest_time=r["ingest_time"],
        account_id=r["account_id"],
        cluster=r["cluster"],
        namespace=r["namespace"],
        resource_id=r["resource_id"],
        identity_id=r["identity_id"],
        event_type=r["event_type"],
        title=r["title"],
        severity=SeverityInfo(normalized=r["severity"], original=r["original_severity"]),
        keys=CorrelationKeys(
            pod_uid=r["pod_uid"], instance_id=r["instance_id"], principal_arn=r["principal_arn"]
        ),
        raw_evidence_uri=r["raw_evidence_uri"],
        checksum=r["checksum_sha256"],
        ocsf=r["ocsf"],
    )


class PostgresEventStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    def exists(self, dedup_key: str) -> bool:
        with self.db.pool.connection() as conn:
            row = conn.execute("SELECT 1 AS hit FROM event WHERE dedup_key = %s", (dedup_key,)).fetchone()
        return row is not None

    def insert(self, event: NormalizedEvent, dedup_key: str) -> None:
        try:
            with self.db.pool.connection() as conn:
                conn.execute(_INSERT_EVENT, _event_params(event, dedup_key))
        except errors.UniqueViolation as exc:
            raise DuplicateEventError(dedup_key) from exc

    def get(self, event_id: str) -> NormalizedEvent | None:
        with self.db.pool.connection() as conn:
            row = conn.execute("SELECT * FROM event WHERE event_id = %s", (event_id,)).fetchone()
        return _event_from_row(row) if row else None


class PostgresCaseStore:
    """Cases with their linked events. Events must already be stored by PostgresEventStore."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def save(self, case: Case) -> None:
        with self.db.pool.connection() as conn:
            conn.execute(
                "INSERT INTO incident (id, title, status, account_id, cluster, opened_at)"
                " VALUES (%s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, status = EXCLUDED.status",
                (case.case_id, case.title, case.status, case.account_id, case.cluster, case.opened_at),
            )
            for link in case.links:
                conn.execute(
                    "INSERT INTO incident_event (incident_id, event_id, link_rule, confidence, rationale)"
                    " VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
                    (case.case_id, link.event_id, link.rule, link.confidence, link.rationale),
                )

    def _load(self, where: str, params: tuple[Any, ...]) -> list[Case]:
        with self.db.pool.connection() as conn:
            incidents = conn.execute(
                f"SELECT * FROM incident WHERE {where} ORDER BY opened_at DESC",  # noqa: S608 - fixed clauses
                params,
            ).fetchall()
            if not incidents:
                return []
            rows = conn.execute(
                "SELECT ie.incident_id, ie.link_rule, ie.confidence, ie.rationale, e.*"
                " FROM incident_event ie JOIN event e USING (event_id)"
                " WHERE ie.incident_id = ANY(%s) ORDER BY ie.linked_at, e.event_time",
                ([i["id"] for i in incidents],),
            ).fetchall()

        cases = {
            i["id"]: Case(
                case_id=i["id"],
                title=i["title"],
                account_id=i["account_id"],
                cluster=i["cluster"],
                opened_at=i["opened_at"],
                status=i["status"],
            )
            for i in incidents
        }
        for r in rows:
            confidence = r["confidence"]
            link = CaseLink(
                r["event_id"],
                r["link_rule"],
                float(confidence) if isinstance(confidence, Decimal) else confidence,
                r["rationale"],
            )
            cases[r["incident_id"]].add(_event_from_row(r), link)
        return list(cases.values())

    def open_cases(self) -> list[Case]:
        # TODO(M5): look up candidates by correlation key instead of loading every open case.
        return self._load("status = %s", ("open",))

    def get(self, case_id: str) -> Case | None:
        found = self._load("id = %s", (case_id,))
        return found[0] if found else None

    def list(self) -> list[Case]:
        return self._load("TRUE", ())


class PostgresEntityStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert(self, entities: list[Entity], edges: list[Edge]) -> None:
        with self.db.pool.connection() as conn:
            for e in entities:
                conn.execute(
                    "INSERT INTO entity (id, kind, external_id, account_id, cluster, namespace,"
                    " attributes, observed_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                    " ON CONFLICT (id) DO UPDATE SET attributes = EXCLUDED.attributes,"
                    " observed_at = EXCLUDED.observed_at",
                    (e.entity_id, e.kind, e.entity_id, e.account_id, e.cluster, e.namespace,
                     Jsonb(e.attributes), e.observed_at),
                )  # fmt: skip
            for edge in edges:
                conn.execute(
                    "INSERT INTO entity_edge (from_entity, to_entity, relation, assurance, evidence_ids)"
                    " VALUES (%s, %s, %s, %s, %s)"
                    " ON CONFLICT (from_entity, to_entity, relation) DO UPDATE SET"
                    " assurance = EXCLUDED.assurance,"
                    " evidence_ids = ARRAY(SELECT DISTINCT unnest("
                    "   entity_edge.evidence_ids || EXCLUDED.evidence_ids))",
                    (edge.from_entity, edge.to_entity, edge.relation, edge.assurance,
                     list(edge.evidence_ids)),
                )  # fmt: skip

    @staticmethod
    def _entity(r: dict[str, Any]) -> Entity:
        return Entity(
            entity_id=r["id"],
            kind=r["kind"],
            observed_at=r["observed_at"],
            account_id=r["account_id"],
            cluster=r["cluster"],
            namespace=r["namespace"],
            attributes=r["attributes"],
        )

    def get(self, entity_id: str) -> Entity | None:
        with self.db.pool.connection() as conn:
            row = conn.execute("SELECT * FROM entity WHERE id = %s", (entity_id,)).fetchone()
        return self._entity(row) if row else None

    def neighborhood(self, entity_id: str, depth: int = 2) -> tuple[list[Entity], list[Edge]]:
        seen = {entity_id}
        frontier = [entity_id]
        found: dict[tuple[str, str, str], Edge] = {}
        with self.db.pool.connection() as conn:
            for _ in range(depth):
                if not frontier:
                    break
                rows = conn.execute(
                    "SELECT * FROM entity_edge WHERE from_entity = ANY(%s) OR to_entity = ANY(%s)",
                    (frontier, frontier),
                ).fetchall()
                next_frontier = []
                for r in rows:
                    edge = Edge(r["from_entity"], r["to_entity"], r["relation"], r["assurance"],
                                tuple(r["evidence_ids"]))  # fmt: skip
                    found[(edge.from_entity, edge.to_entity, edge.relation)] = edge
                    for node in (edge.from_entity, edge.to_entity):
                        if node not in seen:
                            seen.add(node)
                            next_frontier.append(node)
                frontier = next_frontier
            rows = conn.execute(
                "SELECT * FROM entity WHERE id = ANY(%s) ORDER BY id", (sorted(seen),)
            ).fetchall()
        return [self._entity(r) for r in rows], list(found.values())


class PostgresAuditLog:
    """Hash-chained audit log. An advisory lock serializes appends so the chain never forks."""

    def __init__(self, db: Database, clock: Callable[[], datetime] = utcnow) -> None:
        self.db = db
        self.clock = clock

    def append(
        self, actor_type: ActorType, actor_id: str, action: str, details: dict[str, Any]
    ) -> AuditRecord:
        with self.db.pool.connection() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (_AUDIT_LOCK,))
            last = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
            record = make_record(
                (last["seq"] + 1) if last else 1,
                self.clock(),
                actor_type,
                actor_id,
                action,
                details,
                last["hash"] if last else GENESIS_HASH,
            )
            conn.execute(
                "INSERT INTO audit_log (seq, ts, actor_type, actor_id, action, details, prev_hash, hash)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (record.seq, record.ts, record.actor_type, record.actor_id, record.action,
                 Jsonb(record.details), record.prev_hash, record.hash),
            )  # fmt: skip
        return record

    @staticmethod
    def _record(r: dict[str, Any]) -> AuditRecord:
        return AuditRecord(
            seq=r["seq"],
            ts=format_ts(r["ts"]),
            actor_type=r["actor_type"],
            actor_id=r["actor_id"],
            action=r["action"],
            details=r["details"],
            prev_hash=r["prev_hash"],
            hash=r["hash"],
        )

    def records(self, case_id: str | None = None) -> list[AuditRecord]:
        with self.db.pool.connection() as conn:
            if case_id is None:
                rows = conn.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE details->>'case_id' = %s ORDER BY seq", (case_id,)
                ).fetchall()
        return [self._record(r) for r in rows]

    def verify(self) -> int | None:
        return verify_chain(self.records())
