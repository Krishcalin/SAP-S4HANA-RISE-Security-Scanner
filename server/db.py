"""
Database access.

One connection pool, one schema bootstrap, and the row-scoping helper that every
finding query must go through.
"""
from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from server.config import settings

log = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).with_name("schema.sql")

_pool: Optional[ConnectionPool] = None


def pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        settings.validate()
        _pool = ConnectionPool(settings.db_dsn, min_size=1, max_size=10,
                               kwargs={"row_factory": dict_row}, open=True)
    return _pool


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


@contextmanager
def connection() -> Iterator[psycopg.Connection]:
    with pool().connection() as conn:
        yield conn


def init_schema() -> None:
    """Apply schema.sql. Idempotent — every statement is CREATE ... IF NOT EXISTS."""
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with connection() as conn:
        conn.execute(sql)
        conn.commit()
    log.info("schema applied")


# --------------------------------------------------------------------------- #
#  The single organization landscape                                          #
# --------------------------------------------------------------------------- #
#
# MonitorRisk is installed per company (on-prem / private cloud), so a deployment
# assesses exactly ONE organization = ONE landscape. The schema keeps landscape
# as a grouping key (see schema.sql:5-18) so this is enforced at the app layer,
# not by a DB constraint — a few test fixtures still insert extra landscape rows
# to prove row-scoping, which only works while the table can hold more than one.

#: Name and deployment mode of the org landscape, created on first use.
ORG_LANDSCAPE_NAME = os.getenv("ORG_NAME", "Organization")
#: Must be one of the landscape.deployment_mode CHECK values.
ORG_DEPLOYMENT_MODE = os.getenv("DEPLOYMENT_MODE", "on_prem")


def singleton_landscape_id(conn: Optional[psycopg.Connection] = None) -> int:
    """The id of the one organization landscape, created on first use if absent.

    Resolves deterministically when several rows exist (e.g. a demo database):
    the ORG_NAME match if present, otherwise the lowest id. A clean per-company
    install starts with none and this creates exactly one.
    """
    def _resolve(c: psycopg.Connection) -> int:
        row = c.execute("SELECT id FROM landscape WHERE name = %s",
                        (ORG_LANDSCAPE_NAME,)).fetchone()
        if row:
            return int(row["id"])
        row = c.execute("SELECT id FROM landscape ORDER BY id LIMIT 1").fetchone()
        if row:
            return int(row["id"])
        row = c.execute(
            "INSERT INTO landscape (name, deployment_mode) VALUES (%s, %s) "
            "ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
            (ORG_LANDSCAPE_NAME, ORG_DEPLOYMENT_MODE)).fetchone()
        return int(row["id"])

    if conn is not None:
        return _resolve(conn)
    with connection() as c:
        rid = _resolve(c)
        c.commit()
        return rid


def query(sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
    with connection() as conn:
        return conn.execute(sql, params).fetchall()


def one(sql: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
    with connection() as conn:
        return conn.execute(sql, params).fetchone()


def execute(sql: str, params: Sequence[Any] = ()) -> None:
    with connection() as conn:
        conn.execute(sql, params)
        conn.commit()


# --------------------------------------------------------------------------- #
#  Row scoping                                                                #
# --------------------------------------------------------------------------- #

def visible_system_ids(user_id: int) -> Optional[List[int]]:
    """Return the system ids a user may see, or None meaning "all".

    Absence of scope rows means unrestricted. That is the right default for a
    single-tenant deployment where most users legitimately see the whole estate,
    and it makes the restriction explicit where it exists.
    """
    rows = query("SELECT system_id FROM user_system_scope WHERE user_id = %s", (user_id,))
    return [r["system_id"] for r in rows] if rows else None


def scope_clause(system_ids: Optional[Sequence[int]],
                 column: str = "system_id") -> Tuple[str, List[Any]]:
    """Build the per-system row filter as a parameterized fragment.

    THE SINGLE PLACE row scoping is expressed. Every query that returns findings,
    graph nodes or runs composes this rather than writing its own predicate —
    a filter that exists in nine places is a filter that is missing from one.

    Never interpolates a value. `column` is the only interpolated token and is
    caller-supplied from a fixed set, never from user input; it is validated
    here anyway so a future careless caller cannot turn it into an injection.
    """
    if system_ids is None:
        return "TRUE", []
    if not system_ids:
        # An empty explicit scope means "nothing", not "everything". Returning
        # TRUE here would silently hand a deliberately-restricted user the whole
        # estate — the failure mode a row filter exists to prevent.
        return "FALSE", []
    if not column.replace("_", "").replace(".", "").isalnum():
        raise ValueError(f"unsafe column name: {column!r}")
    return f"{column} = ANY(%s)", [list(system_ids)]


# --------------------------------------------------------------------------- #
#  Audit                                                                      #
# --------------------------------------------------------------------------- #

def audit(conn: psycopg.Connection, actor: Optional[str], action: str,
          object_type: str = "", object_id: str = "",
          detail: Optional[Dict[str, Any]] = None) -> None:
    """Record an action. Takes the caller's connection so the audit entry commits
    in the same transaction as the thing it describes — an audit log that can
    disagree with the data it audits is worse than none."""
    from psycopg.types.json import Jsonb
    conn.execute(
        "INSERT INTO audit_log (actor, action, object_type, object_id, detail) "
        "VALUES (%s, %s, %s, %s, %s)",
        (actor, action, object_type, object_id, Jsonb(detail or {})),
    )
