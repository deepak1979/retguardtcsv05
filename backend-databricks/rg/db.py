"""Thin psycopg (Postgres/Lakebase) helpers: pooled connections, dict rows, inserts that return the new id.

Same public shape as v03's Oracle-backed rg/db.py (query/query_one/scalar/execute/insert/update/
transaction/ident) so every rg/* domain module calls this exactly the same way - only the dialect
underneath changed. Two real differences from the Oracle version, both simplifications:

  1. insert() uses Postgres's native `RETURNING id_col` as a plain result column instead of Oracle's
     OUT-bind-variable `RETURNING ... INTO :new_id__` trick - no `cur.var(int)` dance needed.
  2. Bind style: callers still write ':name' (same style as v03, so the ported SQL in ddl.py and every
     domain module needed no bind-syntax rewrite) - translated here to psycopg's native '%(name)s'
     pyformat style, the same translation this session already built for rg/engines/snowflake.py.
     Any literal '%' already in a SQL string (e.g. `LIKE 'llm.%'`) is escaped to '%%' first, so it
     survives psycopg's own %-substitution untouched. Discipline this relies on: never use Postgres's
     '::' cast operator in SQL passed through this module (':' followed by word chars would be
     misread as a bind name) - use `CAST(x AS type)` instead, which is ANSI-standard and unambiguous.
"""
from __future__ import annotations

import contextlib
import decimal
import re
import threading
import time
from typing import Any, Iterator

import psycopg
from psycopg_pool import ConnectionPool

from . import config

_pool: ConnectionPool | None = None
_pool_created_at = 0.0
_lock = threading.Lock()
_IDENT = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_BIND = re.compile(r":(\w+)")

# Lakebase OAuth tokens last ~1h (see databricks-lakebase skill); refresh a bit before that so a
# connection attempt never races an expiry. Only used when config.PG_PASSWORD is blank - i.e. in the
# deployed app, which has no static password, only LAKEBASE_ENDPOINT + its own service-principal auth.
_TOKEN_TTL_SECONDS = 2700


def _generate_token() -> str:
    from databricks.sdk import WorkspaceClient
    if not config.LAKEBASE_ENDPOINT:
        raise RuntimeError("Neither PGPASSWORD nor LAKEBASE_ENDPOINT is set - no way to authenticate to Lakebase")
    cred = WorkspaceClient().postgres.generate_database_credential(endpoint=config.LAKEBASE_ENDPOINT)
    return cred.token


def _conninfo() -> str:
    """The app's own role has CAN_CONNECT_AND_CREATE only - it cannot touch 'public' (see the
    databricks-lakebase skill's Schema Permissions notes), so every connection's search_path is
    pointed at a dedicated schema this app creates and owns. ddl.init_schema() creates it (CREATE
    SCHEMA IF NOT EXISTS) before anything else runs; 'public' stays as a fallback purely so
    current_schema() etc. keep working during that one-time bootstrap moment before it exists."""
    password = config.PG_PASSWORD or _generate_token()
    return (f"host={config.PG_HOST} port={config.PG_PORT} dbname={config.PG_DATABASE} "
            f"user={config.PG_USER} password={password} sslmode={config.PG_SSLMODE} "
            f"options='-c search_path={config.PG_SCHEMA},public'")


def pool() -> ConnectionPool:
    """Opens (or transparently recycles, once its OAuth token is near expiry) the connection pool.
    A static PGPASSWORD (local dev) never goes stale, so recycling only ever triggers for the
    token-based, deployed-app case."""
    global _pool, _pool_created_at
    with _lock:
        stale = (_pool is not None and not config.PG_PASSWORD
                 and time.time() - _pool_created_at > _TOKEN_TTL_SECONDS)
        if _pool is None or stale:
            if _pool is not None:
                _pool.close()
            _pool = ConnectionPool(conninfo=_conninfo(), min_size=1, max_size=8, open=True)
            _pool_created_at = time.time()
        return _pool


def close_pool() -> None:
    global _pool
    with _lock:
        if _pool is not None:
            _pool.close()
            _pool = None


@contextlib.contextmanager
def connection() -> Iterator[psycopg.Connection]:
    with pool().connection() as c:
        yield c


@contextlib.contextmanager
def transaction() -> Iterator[psycopg.Connection]:
    """One connection, commit on success, rollback on any error."""
    with connection() as c:
        try:
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise


def ident(name: str) -> str:
    """Validate a Postgres identifier before it is interpolated into SQL, and return it quoted."""
    n = (name or "").lower()
    if not _IDENT.match(n):
        raise ValueError(f"Invalid identifier: {name!r}")
    return f'"{n}"'


def _translate(sql: str, params: dict | None) -> tuple[str, dict | None]:
    """':name' -> '%(name)s' (psycopg's native pyformat style), escaping any literal '%' first so it
    isn't misread as a format directive."""
    s = sql.replace("%", "%%")
    s = _BIND.sub(lambda m: f"%({m.group(1)})s", s)
    return s, (params or None)


def _clean(key: str, value: Any) -> Any:
    if key.startswith("is_") and value is not None:
        return bool(value)
    if isinstance(value, decimal.Decimal):
        # psycopg maps NUMERIC columns to Decimal (oracledb mapped them to float); none of this app's
        # NUMERIC columns (classifier weights, confidences, ratios) need arbitrary-precision arithmetic,
        # and every call site already does plain float math - converting once here, at the one place
        # all rows pass through, is simpler than patching every arithmetic call site individually.
        return float(value)
    return value


def _rows(cur) -> list[dict]:
    cols = [d.name for d in cur.description]
    return [{k: _clean(k, v) for k, v in zip(cols, r)} for r in cur.fetchall()]


def query(sql: str, params: dict | None = None, conn: psycopg.Connection | None = None) -> list[dict]:
    s, p = _translate(sql, params)

    def run(c):
        with c.cursor() as cur:
            cur.execute(s, p)
            return _rows(cur)
    if conn is not None:
        return run(conn)
    with connection() as c:
        return run(c)


def query_one(sql: str, params: dict | None = None, conn=None) -> dict | None:
    r = query(sql, params, conn)
    return r[0] if r else None


def scalar(sql: str, params: dict | None = None, conn=None) -> Any:
    s, p = _translate(sql, params)

    def run(c):
        with c.cursor() as cur:
            cur.execute(s, p)
            row = cur.fetchone()
            v = row[0] if row else None
            return float(v) if isinstance(v, decimal.Decimal) else v
    if conn is not None:
        return run(conn)
    with connection() as c:
        return run(c)


def execute(sql: str, params: dict | None = None, conn=None) -> int:
    """Run DML/DDL. With `conn` the caller owns the transaction; otherwise it commits."""
    s, p = _translate(sql, params)

    def run(c, commit):
        with c.cursor() as cur:
            cur.execute(s, p)
            n = cur.rowcount
            if commit:
                c.commit()
            return n
    if conn is not None:
        return run(conn, False)
    with connection() as c:
        return run(c, True)


def insert(table: str, values: dict, id_col: str, conn=None) -> int:
    cols = ", ".join(values)
    binds = ", ".join(f":{k}" for k in values)
    sql = f"INSERT INTO {table} ({cols}) VALUES ({binds}) RETURNING {id_col}"

    def run(c, commit):
        s, p = _translate(sql, values)
        with c.cursor() as cur:
            cur.execute(s, p)
            new_id = cur.fetchone()[0]
            if commit:
                c.commit()
            return int(new_id)
    if conn is not None:
        return run(conn, False)
    with connection() as c:
        return run(c, True)


def update(table: str, id_col: str, id_value: Any, values: dict, conn=None) -> int:
    if not values:
        return 0
    sets = ", ".join(f"{k} = :v_{k}" for k in values)
    params = {f"v_{k}": v for k, v in values.items()}
    params["id__"] = id_value
    return execute(f"UPDATE {table} SET {sets} WHERE {id_col} = :id__", params, conn)
