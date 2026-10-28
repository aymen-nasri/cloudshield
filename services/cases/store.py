from typing import Protocol

from cases.models import Case


class CaseStore(Protocol):
    def open_cases(self) -> list[Case]: ...

    def save(self, case: Case) -> None: ...

    def get(self, case_id: str) -> Case | None: ...

    def list(self) -> list[Case]: ...


class InMemoryCaseStore:
    """Dev/test store. TODO(M2): PostgreSQL implementation backed by migrations/001_init.sql."""

    def __init__(self) -> None:
        self._cases: dict[str, Case] = {}

    def open_cases(self) -> list[Case]:
        return [c for c in self._cases.values() if c.status == "open"]

    def save(self, case: Case) -> None:
        self._cases[case.case_id] = case

    def get(self, case_id: str) -> Case | None:
        return self._cases.get(case_id)

    def list(self) -> list[Case]:
        return sorted(self._cases.values(), key=lambda c: c.opened_at, reverse=True)
