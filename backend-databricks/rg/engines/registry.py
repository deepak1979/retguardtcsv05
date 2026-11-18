"""Which Engine serves a given data source. v04 has exactly one data-plane engine type - Databricks SQL
over Unity Catalog - so this always resolves a (per-source, credential-aware) DatabricksEngine, cached
like v03's registry.py did for its dynamic sources. No Oracle/SQL Server/Snowflake dispatch here; see
v03 for the multi-engine version this was forked from.

Cached like scope.index() - a request may ask many times."""
from __future__ import annotations

import threading
import time

from .. import db
from .base import Engine
from .databricks import DatabricksEngine

_lock = threading.Lock()
_cache: dict = {"t": 0.0, "by_source": None}
_dynamic: dict[int, Engine] = {}


def _load() -> dict[int, dict]:
    return {r["source_id"]: r for r in db.query(
        "SELECT source_id, source_type, host, port, service_name, username, password FROM rg_data_source")}


def for_source(source_id: int) -> Engine:
    with _lock:
        if _cache["by_source"] is None or time.time() - _cache["t"] > 5.0:
            _cache["by_source"], _cache["t"] = _load(), time.time()
        by_source = _cache["by_source"]
    row = by_source.get(source_id)
    if row is None:
        raise ValueError(f"Data source {source_id} not found")
    if row["source_type"] != "DATABRICKS":
        raise ValueError(f"No engine registered for source type {row['source_type']!r} (v04 is Databricks-only)")
    with _lock:
        if source_id not in _dynamic:
            _dynamic[source_id] = DatabricksEngine(row["host"], row["service_name"], row["password"], row["username"])
        return _dynamic[source_id]


def invalidate() -> None:
    with _lock:
        _cache["by_source"] = None
