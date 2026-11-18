"""JSON archival for the ARCHIVE remediation action: export rows to a file, then (and only then) delete them.

Folder structure, so a file can be found without the database (or reconciled against it):

    <UC_ARCHIVE_VOLUME>/<TABLE>/<YYYY>/<MM>/task<task_id>_<YYYYMMDD_HHMMSS>_<row_count>rows.json

v04 writes into a Unity Catalog Volume (config.UC_ARCHIVE_VOLUME) rather than v03's local-disk folder
beside the app's own code - Databricks Apps' filesystem is ephemeral (wiped on every restart/redeploy),
so a local folder would silently lose every archive the moment the app restarts.

Every file this writes is also indexed in RG_ARCHIVE (rg/ddl.py), so the app can list and open them without walking
the filesystem, and a task's evidence records the exact path. Nothing here ever deletes a database row - that stays
in remediation.py; this module only ever writes (and, on a failed delete, removes) one file.
"""
from __future__ import annotations

import datetime as dt
import json

from . import config, db, volumes
from .common import audit

ROOT = config.UC_ARCHIVE_VOLUME


def _default(v):
    if isinstance(v, (dt.date, dt.datetime)):
        return v.isoformat()
    return str(v)


def folder_for(table: str, when: dt.datetime) -> str:
    return f"{ROOT}/{table}/{when:%Y}/{when:%m}"


def write(table: str, rows: list[dict], rule: dict, task_id: int | None, pk_column: str | None, username: str,
         source_id: int = 1) -> dict:
    """Write one archive file for `rows` (already-fetched dicts, column name -> value) and index it in RG_ARCHIVE.
    Returns the RG_ARCHIVE row. Raises if the file cannot be written - callers must not delete anything
    from the database until this has returned successfully."""
    when = dt.datetime.now()
    folder = folder_for(table, when)
    name = f"task{task_id}_{when:%Y%m%d_%H%M%S}_{len(rows)}rows.json" if task_id else f"adhoc_{when:%Y%m%d_%H%M%S}_{len(rows)}rows.json"
    path = f"{folder}/{name}"
    payload = {
        "table": table, "row_count": len(rows), "primary_key_column": pk_column,
        "rule": {"rule_id": rule.get("rule_id"), "name": rule.get("name"), "policy_code": rule.get("policy_code")},
        "anchor_column": rule.get("anchor_column"), "retention_days": rule.get("retention_days"),
        "archived_at": when.isoformat(), "archived_by": username,
        "columns": list(rows[0]) if rows else [],
        "rows": rows,
    }
    volumes.write_bytes(path, json.dumps(payload, indent=2, default=_default).encode("utf-8"))
    rel = path[len(ROOT) + 1:]          # e.g. CLAIM_PAYMENT/2026/11/task150_....json
    try:
        aid = db.insert("RG_ARCHIVE", {
            "task_id": task_id, "rule_id": rule.get("rule_id"), "source_id": source_id, "policy_code": rule.get("policy_code"),
            "table_name": table, "anchor_column": rule.get("anchor_column"), "retention_days": rule.get("retention_days"),
            "file_path": rel, "row_count": len(rows), "primary_key_column": pk_column, "created_by": username}, "archive_id")
    except Exception:
        volumes.delete(path)                        # keep the file and the index row in lockstep
        raise
    audit(username, "archive", aid, "ARCHIVED", f"{len(rows)} row(s) of {table} -> {rel}"[:490])
    return db.query_one("SELECT * FROM RG_ARCHIVE WHERE archive_id = :i", {"i": aid})


def discard(entry: dict, username: str) -> None:
    """Best-effort cleanup after the matching DELETE failed to commit: the export was pointless, remove it."""
    volumes.delete(f"{ROOT}/{entry['file_path']}")
    db.execute("DELETE FROM RG_ARCHIVE WHERE archive_id = :i", {"i": entry["archive_id"]})
    audit(username, "archive", entry["archive_id"], "DISCARDED", f"delete failed, export of {entry['table_name']} removed")


def list_entries(table: str | None = None) -> list[dict]:
    sql = "SELECT * FROM RG_ARCHIVE"
    params = {}
    if table:
        sql += " WHERE UPPER(table_name) = UPPER(:t)"      # case-insensitive match, defensive either way
        params["t"] = table
    return db.query(sql + " ORDER BY archive_id DESC", params)


def get_entry(archive_id: int) -> dict | None:
    return db.query_one("SELECT * FROM RG_ARCHIVE WHERE archive_id = :i", {"i": archive_id})


def read_file(entry: dict) -> dict:
    """The full archived payload (metadata + rows) for one entry."""
    try:
        data = volumes.read_bytes(f"{ROOT}/{entry['file_path']}")
    except Exception as e:
        raise FileNotFoundError(f"{entry['file_path']} is indexed in RG_ARCHIVE but the file is missing") from e
    return json.loads(data.decode("utf-8"))
