"""Databricks SQL Warehouse engine for a dynamically-added source (rg/connectors.py's "Add a data source"
flow) - per-row credentials, its own connection, not shared with the Lakebase control-plane pool - talks
to Unity Catalog over the official databricks-sql-connector.

Field reuse on RG_DATA_SOURCE (no schema/UI change needed - see rg/connectors.py's CONNECTOR_TYPES entry
for the matching field labels the UI shows):
    host         -> server_hostname (the workspace host, e.g. "adb-....azuredatabricks.net")
    service_name -> http_path (the SQL Warehouse's HTTP path, e.g. "/sql/1.0/warehouses/xxxx")
    username     -> "catalog.schema" (Unity Catalog's two-level namespace above a table - there is no
                    database-login username in Databricks SQL's auth model, so this field is repurposed)
    password     -> a personal access token (PAT) - Databricks SQL has no username/password auth; the
                    token is the only credential
    port         -> unused (Databricks SQL is always https/443); kept only for the generic form's layout

Two real dialect differences from every other engine here, not glossed over:
  1. No multi-statement transactions. Databricks SQL (Delta) commits each statement as it runs; there is
     no BEGIN/COMMIT/ROLLBACK spanning several statements. transaction() below is therefore NOT atomic
     across more than one statement - it exists only so callers written against the Engine interface
     don't need a special case, not because rollback actually works here.
  2. UPDATE/DELETE need the target to be a Delta table (the Unity Catalog managed-table default). A plain
     external Parquet/CSV table will fail on those two methods - that's a Databricks-side table property,
     not something this engine can detect or work around.
"""
from __future__ import annotations

import contextlib
import re
import threading
from typing import Iterator

from databricks import sql as dbsql

from .. import config
from .base import Engine

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class DatabricksEngine(Engine):
    name = "DATABRICKS"

    def __init__(self, host: str, http_path: str, access_token: str, catalog_schema: str):
        self._host = host
        self._http_path = http_path
        self._token = access_token
        catalog, _, schema = (catalog_schema or "").partition(".")
        if not catalog or not schema:
            raise ValueError(
                f"Databricks source needs 'catalog.schema' in its Username field, got {catalog_schema!r}")
        self._catalog = catalog
        self._schema = schema
        self._conn: dbsql.client.Connection | None = None
        self._lock = threading.Lock()
        self._pushdown_ready = False

    @property
    def catalog(self) -> str:
        return self._catalog

    @property
    def schema(self) -> str:
        return self._schema

    # ---- classifier pushdown: SQL functions this app owns, deployed into the connected workspace's own
    # Unity Catalog metastore so a classifier's content check runs as native Databricks compute instead of
    # pulling raw values back - see rg/scanner.py's PUSHDOWN_PREDICATES. One governance schema per catalog,
    # shared by every table/source in that catalog; ensure_pushdown_udfs() is idempotent and cached per
    # engine instance, so it costs one deploy per source per backend-process-lifetime, not per scan.
    @property
    def governance_namespace(self) -> str:
        return f"{self._catalog}.rg_governance"

    @staticmethod
    def _luhn_sql(length_check: str) -> str:
        """The Luhn-check SQL body shared by rg_is_luhn_valid (13-19 digits, classifiers.py's _luhn() -
        credit cards) and rg_is_luhn_valid_flex (>=8 digits, _luhn_valid() - CA_SIN and similar shorter
        checksum IDs). Only the length gate differs between the two; everything else is identical."""
        return (
            "WITH d AS (SELECT regexp_replace(coalesce(s, ''), '[^0-9]', '') AS digits), "
            "n AS (SELECT digits, length(digits) AS len FROM d), "
            "scored AS ("
            "  SELECT len, aggregate("
            "    transform(sequence(0, len - 1), "
            "      i -> CASE WHEN i % 2 = 1 "
            "             THEN CASE WHEN CAST(substr(digits, len - i, 1) AS INT) * 2 > 9 "
            "                       THEN CAST(substr(digits, len - i, 1) AS INT) * 2 - 9 "
            "                       ELSE CAST(substr(digits, len - i, 1) AS INT) * 2 END "
            "             ELSE CAST(substr(digits, len - i, 1) AS INT) END), "
            "    0, (acc, x) -> acc + x) AS total "
            "  FROM n) "
            f"SELECT {length_check} AND total % 10 = 0 FROM scored")

    def ensure_pushdown_udfs(self) -> None:
        if self._pushdown_ready:
            return
        ns = self.governance_namespace
        self.execute(f"CREATE SCHEMA IF NOT EXISTS {ns}")
        self.execute(
            f"CREATE OR REPLACE FUNCTION {ns}.rg_is_email(s STRING) RETURNS BOOLEAN "
            "RETURN s RLIKE '^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\\\\.[A-Za-z0-9-]+)*\\\\.[A-Za-z]{2,}$'")
        self.execute(f"CREATE OR REPLACE FUNCTION {ns}.rg_is_luhn_valid(s STRING) RETURNS BOOLEAN "
                     f"RETURN {self._luhn_sql('len BETWEEN 13 AND 19')}")
        self.execute(f"CREATE OR REPLACE FUNCTION {ns}.rg_is_luhn_valid_flex(s STRING) RETURNS BOOLEAN "
                     f"RETURN {self._luhn_sql('len >= 8')}")
        self._pushdown_ready = True

    # ---- connection handling: one lazily-opened connection, reopened if the warehouse dropped it
    def _open(self) -> "dbsql.client.Connection":
        if self._token:
            return dbsql.connect(server_hostname=self._host, http_path=self._http_path,
                                 access_token=self._token, catalog=self._catalog, schema=self._schema)
        # No stored token (v04's default): authenticate as this process's own identity instead - the
        # app's service principal when deployed, or the developer's own CLI profile locally - via the
        # SDK's own auto-config, same pattern the databricks-apps skill documents for OBO/non-AppKit
        # apps. Avoids ever storing a Databricks PAT in RG_DATA_SOURCE at all.
        from databricks.sdk.core import Config
        cfg = Config(host=f"https://{self._host}") if self._host else Config()
        return dbsql.connect(server_hostname=cfg.host.replace("https://", ""), http_path=self._http_path,
                             credentials_provider=lambda: cfg.authenticate, catalog=self._catalog,
                             schema=self._schema)

    @contextlib.contextmanager
    def _connection(self) -> Iterator["dbsql.client.Connection"]:
        with self._lock:
            if self._conn is None:
                self._conn = self._open()
            c = self._conn
        try:
            yield c
        except Exception:
            # a dropped/expired session surfaces as a generic failure on next use - reopen once and retry
            with self._lock:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
            raise

    def query(self, sql, params=None, conn=None):
        def run(c):
            cur = c.cursor()
            try:
                cur.execute(sql, params or None)
                if cur.description is None:
                    return []
                cols = [d[0].lower() for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]
            finally:
                cur.close()
        if conn is not None:
            return run(conn)
        with self._connection() as c:
            return run(c)

    def scalar(self, sql, params=None, conn=None):
        rows = self.query(sql, params, conn)
        if not rows:
            return None
        return next(iter(rows[0].values()))

    def execute(self, sql, params=None, conn=None):
        def run(c):
            cur = c.cursor()
            try:
                cur.execute(sql, params or None)
                return cur.rowcount if cur.rowcount is not None else -1
            finally:
                cur.close()
        if conn is not None:
            return run(conn)
        with self._connection() as c:
            return run(c)

    @contextlib.contextmanager
    def transaction(self) -> Iterator["dbsql.client.Connection"]:
        """NOT atomic - see the module docstring. Exists so multi-statement callers (snapshot/remediation)
        still work; each statement commits as it runs regardless of how this block exits."""
        with self._connection() as c:
            yield c

    def ident(self, name: str) -> str:
        parts = name.split(".")
        if len(parts) not in (1, 2, 3) or not all(_IDENT.match(p) for p in parts):
            raise ValueError(f"Invalid Databricks identifier {name!r}")
        return ".".join(f"`{p}`" for p in parts)

    def backup_name(self, table):
        return f"{config.BACKUP_PREFIX}{table}"

    def view_name(self, table):
        return f"{config.MASK_VIEW_PREFIX}{table}"

    def now(self):
        return "current_timestamp()"

    def date_sub_days(self, expr, days):
        return f"date_sub({expr}, {days})"

    def year_trunc(self, expr):
        return f"date_trunc('YEAR', {expr})"

    def concat(self, *parts):
        return f"concat({', '.join(parts)})"

    def substr(self, expr, start, length=None):
        return f"substring({expr}, {start})" if length is None else f"substring({expr}, {start}, {length})"

    def instr(self, expr, needle):
        return f"instr({expr}, {needle})"

    def rpad_star(self, expr, n):
        return f"repeat('*', least(length({expr}), {n}))"

    def stars_like(self, expr):
        return f"repeat('*', length({expr}))"

    def right(self, expr, n):
        return f"right({expr}, {n})"

    def length_of(self, expr):
        return f"length({expr})"

    def hash_hex(self, expr):
        return f"sha2({expr}, 256)"

    def nvl(self, a, b):
        return f"coalesce({a}, {b})"

    def round_num(self, expr, ndigits):
        return f"round({expr}, {ndigits})"

    def to_char(self, expr):
        return f"CAST({expr} AS STRING)"

    def except_op(self):
        return "EXCEPT"

    def date_literal(self, iso):
        return f"DATE'{iso}'"

    def create_table_as(self, dst, src, conn=None):
        self.drop_table(dst, conn=conn)
        self.execute(f"CREATE TABLE {self.ident(dst)} AS SELECT * FROM {self.ident(src)}", conn=conn)

    def insert_select(self, dst, src, conn=None):
        self.execute(f"INSERT INTO {self.ident(dst)} SELECT * FROM {self.ident(src)}", conn=conn)

    def drop_table(self, name, conn=None):
        self.execute(f"DROP TABLE IF EXISTS {self.ident(name)}", conn=conn)

    def create_or_replace_view(self, name, select_sql, conn=None):
        self.execute(f"CREATE OR REPLACE VIEW {self.ident(name)} AS {select_sql}", conn=conn)

    def drop_view(self, name, conn=None):
        self.execute(f"DROP VIEW IF EXISTS {self.ident(name)}", conn=conn)

    def update_stmt(self, table, alias, sets, where):
        return f"UPDATE {self.ident(table)} {alias} SET {sets}" + (f" WHERE {where}" if where else "")

    def delete_stmt(self, table, alias, where):
        return f"DELETE FROM {self.ident(table)} {alias} WHERE {where}"

    def ensure_namespace(self, name, conn=None):
        pass   # tables live in the connection's own catalog.schema - nothing to create


def test_connection(host: str, http_path: str, catalog_schema: str, access_token: str) -> dict:
    """{"ok": bool, "message": str, "detail": str|None} - same shape rg/connectors.py's "Add a data
    source" flow expects from a connection test. Never raises; any failure (bad token, unreachable
    workspace, wrong http_path, warehouse stopped) comes back as ok=False with a human-readable message."""
    try:
        catalog, _, schema = (catalog_schema or "").partition(".")
        if not catalog or not schema:
            return {"ok": False, "message": "Username must be 'catalog.schema', e.g. 'deepak.insurance'.",
                    "detail": None}
        conn = dbsql.connect(server_hostname=host, http_path=http_path, access_token=access_token,
                             catalog=catalog, schema=schema, connect_timeout=15)
        try:
            cur = conn.cursor()
            cur.execute("SELECT current_version().dbsql_version")
            version = cur.fetchone()[0]
            cur.execute(f"SELECT COUNT(*) FROM information_schema.tables "
                       f"WHERE table_catalog = '{catalog}' AND table_schema = '{schema}'")
            table_count = cur.fetchone()[0]
        finally:
            conn.close()
        return {"ok": True, "message": f"Connected. {table_count} table(s) visible in {catalog}.{schema}.",
                "detail": f"Databricks SQL {version}"}
    except Exception as e:  # noqa: BLE001 - network/auth/warehouse-stopped errors, surfaced as-is
        return {"ok": False, "message": str(e), "detail": None}
