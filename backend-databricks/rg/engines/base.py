"""Engine abstraction: the dialect + connection boundary between the remediation/erasure/catalog algorithms and
whichever physical database actually holds the data being governed.

RG_* control tables (findings, policies, violations, tasks, evidence, audit log, snapshot/archive index) always
live in Lakebase and are read/written with rg/db.py directly, never through this abstraction - an Engine is only
used for SQL that targets a SOURCE table: the data being discovered, scanned, masked, deleted, archived or
anonymised. Which Engine to use for a given table is resolved once via RG_DATA_SOURCE.source_type, in
rg/engines/registry.py:for_source(source_id).

Every Engine exposes the same connection primitives rg/db.py already has - query/scalar/execute/transaction/ident,
the same ':name' bind-parameter style - plus a small set of dialect primitives the SQL-string builders in
common.py / remediation.py / catalog.py / snapshot.py use instead of hardcoding one engine's syntax. Adding a
second engine means writing one more module here, not touching those builders again.
"""
from __future__ import annotations

import abc
from typing import Any, ContextManager


class Engine(abc.ABC):
    name: str   # RG_DATA_SOURCE.source_type this engine serves - "DATABRICKS" today

    # ---- connection / query primitives (same shape + :name bind style as rg/db.py)
    @abc.abstractmethod
    def query(self, sql: str, params: dict | None = None, conn=None) -> list[dict]: ...

    def query_one(self, sql: str, params: dict | None = None, conn=None) -> dict | None:
        rows = self.query(sql, params, conn)
        return rows[0] if rows else None

    @abc.abstractmethod
    def scalar(self, sql: str, params: dict | None = None, conn=None) -> Any: ...

    @abc.abstractmethod
    def execute(self, sql: str, params: dict | None = None, conn=None) -> int: ...

    @abc.abstractmethod
    def transaction(self) -> ContextManager: ...

    @abc.abstractmethod
    def ident(self, name: str) -> str:
        """Validate + quote a (possibly schema-qualified, e.g. 'life_de.customer') identifier."""

    # ---- naming: where a table's backup / masked view lives for this engine
    @abc.abstractmethod
    def backup_name(self, table: str) -> str: ...

    @abc.abstractmethod
    def view_name(self, table: str) -> str: ...

    # ---- dialect primitives used by common.py / remediation.py / catalog.py / snapshot.py
    @abc.abstractmethod
    def now(self) -> str:
        """Current timestamp, as a SQL expression."""

    @abc.abstractmethod
    def date_sub_days(self, expr: str, days) -> str:
        """`expr` minus `days` days (`days` may be an int or a SQL expression)."""

    @abc.abstractmethod
    def year_trunc(self, expr: str) -> str:
        """The 1st of January of `expr`'s year."""

    @abc.abstractmethod
    def concat(self, *parts: str) -> str: ...

    @abc.abstractmethod
    def substr(self, expr: str, start: int, length: int | None = None) -> str: ...

    @abc.abstractmethod
    def instr(self, expr: str, needle: str) -> str:
        """1-based position of `needle` (a SQL string expression) in `expr`, 0 if absent."""

    @abc.abstractmethod
    def rpad_star(self, expr: str, n) -> str:
        """A run of '*' as long as `expr`, capped at `n` characters."""

    @abc.abstractmethod
    def stars_like(self, expr: str) -> str:
        """A run of '*' exactly as long as `expr` (uncapped)."""

    @abc.abstractmethod
    def right(self, expr: str, n: int) -> str:
        """The last `n` characters of `expr`."""

    @abc.abstractmethod
    def length_of(self, expr: str) -> str: ...

    @abc.abstractmethod
    def hash_hex(self, expr: str) -> str:
        """SHA-256 of `expr`, as a hex string."""

    @abc.abstractmethod
    def nvl(self, a: str, b: str) -> str: ...

    @abc.abstractmethod
    def round_num(self, expr: str, ndigits: int) -> str: ...

    @abc.abstractmethod
    def to_char(self, expr: str) -> str: ...

    @abc.abstractmethod
    def except_op(self) -> str:
        """The set-difference operator: 'MINUS' | 'EXCEPT'."""

    @abc.abstractmethod
    def date_literal(self, iso: str) -> str:
        """A date literal from an ISO 'YYYY-MM-DD' string."""

    @abc.abstractmethod
    def create_table_as(self, dst: str, src: str, conn=None) -> None:
        """CREATE TABLE dst AS a full copy of src (used for the demo-safety snapshot backup)."""

    @abc.abstractmethod
    def insert_select(self, dst: str, src: str, conn=None) -> None:
        """INSERT INTO dst SELECT * FROM src - same columns, same order (used by snapshot restore). Handles
        whatever a given engine needs for an explicit value in an identity/auto-increment column."""

    @abc.abstractmethod
    def drop_table(self, name: str, conn=None) -> None: ...

    @abc.abstractmethod
    def create_or_replace_view(self, name: str, select_sql: str, conn=None) -> None: ...

    @abc.abstractmethod
    def update_stmt(self, table: str, alias: str, sets: str, where: str | None) -> str:
        """An UPDATE of `table` (aliased `alias`, referenced by `where`) applying `sets`, in whatever
        exact syntax this engine's dialect needs for an aliased UPDATE."""

    @abc.abstractmethod
    def delete_stmt(self, table: str, alias: str, where: str) -> str:
        """A DELETE from `table` (aliased `alias`, referenced by `where`), in whatever exact syntax this
        engine's dialect needs for an aliased DELETE."""

    @abc.abstractmethod
    def drop_view(self, name: str, conn=None) -> None: ...

    @abc.abstractmethod
    def ensure_namespace(self, name: str, conn=None) -> None:
        """Make sure a schema/namespace used for backups or masked views exists. No-op where not needed."""
