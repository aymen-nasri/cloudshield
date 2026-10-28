"""Entities and typed relationships discovered by enrichment.

Every edge carries an assurance level. CloudShield never collapses "configured", "observed",
"possible" and "proven" into a single "attacker can reach X" claim.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Protocol

Assurance = Literal["configured", "observed", "possible", "proven"]


@dataclass(frozen=True)
class Entity:
    entity_id: str  # e.g. "k8s:pod/shop/checkout-7d9f6c-x2k8p", "aws:iam-role/arn:aws:iam::..."
    kind: str
    observed_at: datetime
    account_id: str | None = None
    cluster: str | None = None
    namespace: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Edge:
    from_entity: str
    to_entity: str
    relation: str  # runs_on, belongs_to, uses_identity, observed_communication, ...
    assurance: Assurance
    evidence_ids: tuple[str, ...] = ()


class EntityStore(Protocol):
    def upsert(self, entities: list[Entity], edges: list[Edge]) -> None: ...

    def get(self, entity_id: str) -> Entity | None: ...

    def neighborhood(self, entity_id: str, depth: int = 2) -> tuple[list[Entity], list[Edge]]: ...


class InMemoryEntityStore:
    def __init__(self) -> None:
        self.entities: dict[str, Entity] = {}
        self.edges: dict[tuple[str, str, str], Edge] = {}

    def upsert(self, entities: list[Entity], edges: list[Edge]) -> None:
        for entity in entities:
            self.entities[entity.entity_id] = entity
        for edge in edges:
            key = (edge.from_entity, edge.to_entity, edge.relation)
            previous = self.edges.get(key)
            merged = tuple(dict.fromkeys((previous.evidence_ids if previous else ()) + edge.evidence_ids))
            self.edges[key] = Edge(edge.from_entity, edge.to_entity, edge.relation, edge.assurance, merged)

    def get(self, entity_id: str) -> Entity | None:
        return self.entities.get(entity_id)

    def neighborhood(self, entity_id: str, depth: int = 2) -> tuple[list[Entity], list[Edge]]:
        return walk(entity_id, depth, list(self.edges.values()), self.entities)


def walk(
    start: str, depth: int, edges: list[Edge], entities: dict[str, Entity]
) -> tuple[list[Entity], list[Edge]]:
    """Breadth-first walk in both directions, up to `depth` hops."""
    seen = {start}
    frontier = {start}
    found: dict[tuple[str, str, str], Edge] = {}
    for _ in range(depth):
        next_frontier: set[str] = set()
        for edge in edges:
            if edge.from_entity in frontier or edge.to_entity in frontier:
                found[(edge.from_entity, edge.to_entity, edge.relation)] = edge
                for node in (edge.from_entity, edge.to_entity):
                    if node not in seen:
                        seen.add(node)
                        next_frontier.add(node)
        frontier = next_frontier
    return [entities[e] for e in sorted(seen) if e in entities], list(found.values())
