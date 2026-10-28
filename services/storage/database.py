"""Connection pool and schema migrations."""

from importlib import resources
from typing import Any

from psycopg import Connection, sql
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

# Arbitrary constant: only one process applies migrations at a time.
_MIGRATION_LOCK = 0x0C1D5E1D


class Database:
    def __init__(self, conninfo: str, *, schema: str | None = None, max_size: int = 5) -> None:
        self.schema = schema
        self.pool: ConnectionPool[Connection[dict[str, Any]]] = ConnectionPool(
            conninfo,
            min_size=1,
            max_size=max_size,
            kwargs={"row_factory": dict_row},
            configure=self._configure,
            open=True,
        )

    def _configure(self, conn: Connection[Any]) -> None:
        # Timestamps come back in UTC, and tests can isolate themselves in their own schema.
        conn.execute("SET TIME ZONE 'UTC'")
        if self.schema:
            conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(self.schema)))
        conn.commit()

    def close(self) -> None:
        self.pool.close()


def apply_migrations(db: Database) -> list[str]:
    """Apply services/cases/migrations/*.sql in order, once each. Returns the versions applied now."""
    files = sorted(
        (f for f in resources.files("cases").joinpath("migrations").iterdir() if f.name.endswith(".sql")),
        key=lambda f: f.name,
    )
    applied_now: list[str] = []
    with db.pool.connection() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_LOCK,))
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        done = {row["version"] for row in conn.execute("SELECT version FROM schema_migrations")}
        for f in files:
            if f.name in done:
                continue
            # Migrations are trusted files shipped with the package, never user input.
            conn.execute(f.read_text(encoding="utf-8"))
            conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (f.name,))
            applied_now.append(f.name)
    return applied_now
