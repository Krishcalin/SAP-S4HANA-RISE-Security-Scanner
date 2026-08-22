"""
Database access.

One connection pool, one schema bootstrap, and the row-scoping helper that every
finding query must go through.
"""
from __future__ import annotations

import logging
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
