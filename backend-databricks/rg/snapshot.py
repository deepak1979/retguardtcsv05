"""Safety snapshots, per data source. Remediation changes real rows, so before anything destructive a source's
tables are copied to a backup (engine.backup_name(table)). `restore` puts them back and resets that source's
lifecycle state, so the demo can be re-run. `restore_tables` does the same for just one or a few tables, so a
single scenario can be replayed (execute -> restore -> execute again) without disturbing anything else: other
tables, legal holds, erasure requests, other tasks. RG_SNAPSHOT (the index of backups) is a control table and
always lives in Lakebase, keyed by source_id - see rg/engines/base.py for the control-plane / data-plane split."""
from __future__ import annotations

from . import archive, db, engines, holds, vectorsearch, volumes
from .common import audit
from .policy import NotFound


def _topo_order(tables: list[str], edges: list[tuple[str, str]]) -> list[str]:
    """Parents before children (for inserts); reverse it for deletes. `edges` is a list of (child, parent)
    pairs; any table with no recorded dependency is treated as ready immediately (and tables not mentioned
    in `edges` at all just keep their alphabetical place among the other ready tables)."""
    deps = {t: set() for t in tables}
    for child, parent in edges:
        if child in deps and parent in deps and child != parent:
            deps[child].add(parent)
    ordered, ready = [], sorted(t for t, d in deps.items() if not d)
    while ready:
        t = ready.pop(0)
        ordered.append(t)
        for c, d in deps.items():
            if t in d:
                d.remove(t)
                if not d and c not in ordered and c not in ready:
                    ready.append(c)
        ready.sort()
    return ordered + [t for t in tables if t not in ordered]


def _fk_order(source_id: int, tables: list[str]) -> list[str]:
    rows = db.query("SELECT child_table, parent_table FROM RG_LINEAGE WHERE source_id = :s AND kind = 'FK'", {"s": source_id})
    return _topo_order(tables, [(e["child_table"], e["parent_table"]) for e in rows])


def _source_tables(source_id: int) -> list[str]:
    """Every table this source's catalog knows about - what gets backed up and what `restore` resets."""
    return [r["table_name"] for r in db.query("SELECT table_name FROM RG_CATALOG_TABLE WHERE source_id = :s", {"s": source_id})]


def ensure_snapshot(source_id: int = 1, username: str | None = None) -> int:
    """Create a backup for any of this source's tables that has none. Returns how many were created."""
    engine = engines.for_source(source_id)
    have = {r["table_name"] for r in db.query("SELECT table_name FROM RG_SNAPSHOT WHERE source_id = :s", {"s": source_id})}
    made = 0
    for t in _source_tables(source_id):
        if t in have:
            continue
        backup = engine.backup_name(t)
        engine.create_table_as(backup, t)
        n = engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(backup)}")
        try:
            db.insert("RG_SNAPSHOT", {"source_id": source_id, "table_name": t, "backup_table": backup, "row_count": n}, "snapshot_id")
        except Exception as e:
            # Tolerate a concurrent bootstrap (e.g. two app instances starting at once) already having
            # inserted this row between the SELECT above and this INSERT - rg_snapshot_uk already
            # guarantees no duplicate backup is recorded, this just stops that race from crashing startup.
            if "rg_snapshot_uk" not in str(e) and "UniqueViolation" not in type(e).__name__:
                raise
            continue
        made += 1
    if made:
        audit(username, "snapshot", None, "SNAPSHOT", f"{made} table(s) of source {source_id} backed up")
    return made


def status(source_id: int = 1) -> dict:
    engine = engines.for_source(source_id)
    snaps = db.query("SELECT table_name, backup_table, row_count, created_at FROM RG_SNAPSHOT WHERE source_id = :s ORDER BY table_name",
                     {"s": source_id})
    drift = []
    for s in snaps:
        now = engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(s['table_name'])}")
        except_op = engine.except_op()
        changed = (engine.scalar(f"SELECT COUNT(*) FROM (SELECT * FROM {engine.ident(s['table_name'])} {except_op} "
                                 f"SELECT * FROM {engine.ident(s['backup_table'])}) x")
                  + engine.scalar(f"SELECT COUNT(*) FROM (SELECT * FROM {engine.ident(s['backup_table'])} {except_op} "
                                  f"SELECT * FROM {engine.ident(s['table_name'])}) x"))
        s["current_rows"] = now
        s["differs"] = changed > 0
        if changed:
            drift.append(s["table_name"])
    # Masked views live in this source's own catalog.schema, found the same way catalog.py's
    # _discover_databricks reads information_schema. Spark SQL doesn't support Oracle's LIKE ... ESCAPE
    # syntax (PARSE_SYNTAX_ERROR), and since every masked view name follows the fixed RG_MV_<table>
    # shape, a plain LIKE with no ESCAPE is safe here - view names are always lower-case on Databricks,
    # so match against lower(table_name).
    views = [v["table_name"] for v in engine.query(
        f"SELECT table_name FROM {engine.ident(engine.catalog)}.information_schema.views "
        "WHERE table_schema = :s AND lower(table_name) LIKE 'rg_mv_%'", {"s": engine.schema})]
    return {"snapshots": snaps, "modified_tables": drift, "masked_views": views}


def retake(source_id: int, username: str) -> int:
    engine = engines.for_source(source_id)
    for s in db.query("SELECT backup_table FROM RG_SNAPSHOT WHERE source_id = :s", {"s": source_id}):
        engine.drop_table(s["backup_table"])
    db.execute("DELETE FROM RG_SNAPSHOT WHERE source_id = :s", {"s": source_id})
    n = ensure_snapshot(source_id, username)
    audit(username, "snapshot", None, "SNAPSHOT_RETAKE", f"{n} table(s) of source {source_id}")
    return n


def restore(username: str, source_id: int = 1) -> dict:
    """Restore every one of this source's tables from its snapshot and reset that source's lifecycle
    (tasks, violations, protections...)."""
    engine = engines.for_source(source_id)
    snaps = {s["table_name"]: s["backup_table"] for s in
            db.query("SELECT table_name, backup_table FROM RG_SNAPSHOT WHERE source_id = :s", {"s": source_id})}
    if not snaps:
        raise ValueError("No snapshot exists yet")
    order = _fk_order(source_id, list(snaps))
    with engine.transaction() as conn:
        for v in status(source_id)["masked_views"]:
            engine.drop_view(v, conn=conn)
        for t in reversed(order):
            engine.execute(f"DELETE FROM {engine.ident(t)}", conn=conn)
        for t in order:
            engine.insert_select(t, snaps[t], conn=conn)
    # control tables (always Lakebase): this source's own evidence, tasks, violations, protections, erasure
    # requests and legal holds - erasure/holds are only ever as multi-source as SUBJECT_MODEL/rg/holds.py is
    # configured for, same source_id scoping as everything else here now.
    db.execute("DELETE FROM RG_EVIDENCE WHERE ref_type = 'TASK' AND ref_id IN "
              "(SELECT task_id FROM RG_REMEDIATION_TASK WHERE source_id = :s)", {"s": source_id})
    db.execute("DELETE FROM RG_EVIDENCE WHERE ref_type = 'ERASURE' AND ref_id IN "
              "(SELECT request_id FROM RG_ERASURE_REQUEST WHERE source_id = :s)", {"s": source_id})
    db.execute("DELETE FROM RG_REMEDIATION_TASK WHERE source_id = :s", {"s": source_id})
    db.execute("DELETE FROM RG_VIOLATION WHERE source_id = :s", {"s": source_id})
    db.execute("DELETE FROM RG_PROTECTION WHERE source_id = :s", {"s": source_id})
    db.execute("DELETE FROM RG_ERASURE_REQUEST WHERE source_id = :s", {"s": source_id})
    db.execute("DELETE FROM RG_LEGAL_HOLD WHERE source_id = :s", {"s": source_id})
    holds.invalidate(source_id)
    db.execute("UPDATE RG_FINDING SET protection = 'NONE' WHERE source_id = :s", {"s": source_id})
    audit(username, "snapshot", None, "RESTORE", f"{len(order)} table(s) of source {source_id} restored; lifecycle reset")
    return {"tables_restored": len(order)}


def clear_all(username: str) -> dict:
    """The full demo reset, across every data source: everything `restore` resets, plus the findings, scans,
    catalog, lineage and archive it deliberately leaves alone. LLM opinions are tied to findings (which every
    source just had wiped) and are cleared once at the end rather than per source."""
    source_ids = [r["source_id"] for r in db.query("SELECT source_id FROM RG_DATA_SOURCE ORDER BY source_id")]
    total_restored = 0
    for sid in source_ids:
        engine = engines.for_source(sid)
        snaps = {s["table_name"]: s["backup_table"] for s in
                db.query("SELECT table_name, backup_table FROM RG_SNAPSHOT WHERE source_id = :s", {"s": sid})}
        order = _fk_order(sid, list(snaps)) if snaps else []
        with engine.transaction() as conn:
            for v in status(sid)["masked_views"]:
                engine.drop_view(v, conn=conn)
            for t in reversed(order):
                engine.execute(f"DELETE FROM {engine.ident(t)}", conn=conn)
            for t in order:
                engine.insert_select(t, snaps[t], conn=conn)
        total_restored += len(order)
        with db.transaction() as conn:
            db.execute("DELETE FROM RG_EVIDENCE WHERE ref_type = 'TASK' AND ref_id IN "
                      "(SELECT task_id FROM RG_REMEDIATION_TASK WHERE source_id = :s)", {"s": sid}, conn=conn)
            db.execute("DELETE FROM RG_EVIDENCE WHERE ref_type = 'ERASURE' AND ref_id IN "
                      "(SELECT request_id FROM RG_ERASURE_REQUEST WHERE source_id = :s)", {"s": sid}, conn=conn)
            for tbl in ("RG_PROTECTION", "RG_VIOLATION", "RG_REMEDIATION_TASK", "RG_ARCHIVE", "RG_FINDING",
                        "RG_CATALOG_COLUMN", "RG_CATALOG_TABLE", "RG_LINEAGE", "RG_SCAN_JOB",
                        "RG_ERASURE_REQUEST", "RG_LEGAL_HOLD"):
                db.execute(f"DELETE FROM {tbl} WHERE source_id = :s", {"s": sid}, conn=conn)
            db.execute("UPDATE RG_DATA_SOURCE SET last_discovered_at = NULL, last_scan_at = NULL WHERE source_id = :s", {"s": sid}, conn=conn)
        holds.invalidate(sid)

    # document (PDF folder) sources: same philosophy as the DB-source loop above - wipe everything a
    # discover+scan+index generated (findings, samples, the document catalog itself, scan/redaction/
    # indexing history, and the chunks those documents put in Chroma) so a doc source goes back to
    # "registered, never discovered" and the whole demo - including semantic search - replays from a
    # clean start. The *original* source PDFs on disk are never touched, same as a structured source's
    # table rows are restored rather than deleted; only generated output (redacted copies in
    # PDFREDACTED/, which also stops them being picked up as phantom source documents on the next
    # discover - see docscan.discover()'s docstring) and this app's own RG_DOC_* / Chroma records go.
    doc_sources = db.query("SELECT doc_source_id, folder_path FROM RG_DOC_SOURCE")
    total_chunks_cleared = 0
    for src in doc_sources:
        dsid = src["doc_source_id"]
        doc_ids = [d["document_id"] for d in db.query("SELECT document_id FROM RG_DOCUMENT WHERE doc_source_id = :s", {"s": dsid})]
        if doc_ids:
            total_chunks_cleared += vectorsearch.clear_for_documents(doc_ids).get("chunks_removed", 0)
        with db.transaction() as conn:
            db.execute("DELETE FROM RG_DOC_FINDING_SAMPLE WHERE doc_finding_id IN "
                      "(SELECT doc_finding_id FROM RG_DOC_FINDING WHERE document_id IN "
                      "(SELECT document_id FROM RG_DOCUMENT WHERE doc_source_id = :s))", {"s": dsid}, conn=conn)
            db.execute("DELETE FROM RG_DOC_FINDING WHERE document_id IN "
                      "(SELECT document_id FROM RG_DOCUMENT WHERE doc_source_id = :s)", {"s": dsid}, conn=conn)
            db.execute("DELETE FROM RG_DOC_REDACTION_BATCH WHERE doc_source_id = :s", {"s": dsid}, conn=conn)
            db.execute("DELETE FROM RG_DOCUMENT WHERE doc_source_id = :s", {"s": dsid}, conn=conn)
            db.execute("DELETE FROM RG_DOC_SCAN_JOB WHERE doc_source_id = :s", {"s": dsid}, conn=conn)
            db.execute("UPDATE RG_DOC_SOURCE SET last_discovered_at = NULL, last_scan_at = NULL "
                      "WHERE doc_source_id = :s", {"s": dsid}, conn=conn)
        volumes.delete_tree(f"{src['folder_path'].rstrip('/')}/PDFREDACTED")
    doc_source_ids = [s["doc_source_id"] for s in doc_sources]

    with db.transaction() as conn:
        db.execute("DELETE FROM RG_LLM_OPINION", conn=conn)
        audit(username, "snapshot", None, "CLEAR_ALL",
              f"{total_restored} table(s) restored across {len(source_ids)} source(s); findings, catalog, scans, "
              f"archive and lifecycle all cleared; {len(doc_source_ids)} document source(s) reset "
              f"({total_chunks_cleared} vector chunk(s) cleared)", conn)
    volumes.delete_tree(archive.ROOT)              # exported archive files are orphaned once RG_ARCHIVE is wiped
    return {"tables_restored": total_restored, "chunks_cleared": total_chunks_cleared}


def restore_tables(table_names: list[str], username: str, source_id: int = 1) -> dict:
    """Restore just the given source tables from their snapshots. Only their own violations, tasks and protections
    are reset; every other table, legal hold, erasure request and unrelated task is left exactly as it is. Lets
    one test scenario be replayed on its own, repeatedly, without resetting the whole app."""
    engine = engines.for_source(source_id)
    names = sorted(set(table_names))
    if not names:
        raise ValueError("Choose at least one table to restore")
    snaps = {s["table_name"]: s["backup_table"] for s in
            db.query("SELECT table_name, backup_table FROM RG_SNAPSHOT WHERE source_id = :s", {"s": source_id}) if s["table_name"] in names}
    missing = set(names) - set(snaps)
    if missing:
        raise ValueError(f"No snapshot exists for {', '.join(sorted(missing))}. Run a scan first (it takes one automatically).")
    order = _fk_order(source_id, list(snaps))
    ph = ", ".join(f":t{i}" for i in range(len(names)))
    binds = {f"t{i}": n for i, n in enumerate(names)}
    with engine.transaction() as conn:
        for t in names:
            engine.drop_view(engine.view_name(t), conn=conn)
        for t in reversed(order):
            engine.execute(f"DELETE FROM {engine.ident(t)}", conn=conn)
        for t in order:
            engine.insert_select(t, snaps[t], conn=conn)
    for tbl in ("RG_PROTECTION", "RG_VIOLATION", "RG_REMEDIATION_TASK"):
        db.execute(f"DELETE FROM {tbl} WHERE source_id = :s AND table_name IN ({ph})", {**binds, "s": source_id})
    db.execute(f"UPDATE RG_FINDING SET protection = 'NONE' WHERE source_id = :s AND table_name IN ({ph})", {**binds, "s": source_id})
    audit(username, "snapshot", None, "RESTORE_TABLE", f"{', '.join(order)} restored (source {source_id}); their own violations/tasks/protections reset")
    return {"tables_restored": order}


def delete_source(source_id: int, username: str) -> dict:
    """Permanently removes a data source and everything scoped to it: catalog, findings, scans, lineage,
    violations, tasks, protections, erasure requests, legal holds, its snapshot backups and masked views, and
    any RETENTION_EXPIRY/RETAIN rule that targets it (those rules can't do anything once their source is gone).

    Masked views and backup tables are torn down from THIS source's own catalog/snapshot rows, not a
    schema-wide listing: two RG_DATA_SOURCE rows can point at the identical physical schema (same host/port/
    service/schema - see rg/engines/registry.py's one-engine-per-type pooling), so a blind "drop everything
    in the schema" would reach into another source's objects. Source 1 is the hardcoded fallback almost every
    source_id-less piece of app logic defaults to (rule.get("source_id") or 1, ensure_snapshot(source_id=1),
    etc.) and is never deletable."""
    if source_id == 1:
        raise ValueError("Source 1 is the default every rule and snapshot operation falls back to - it can't be deleted.")
    src = db.query_one("SELECT * FROM RG_DATA_SOURCE WHERE source_id = :s", {"s": source_id})
    if not src:
        raise NotFound(f"Data source {source_id} not found")
    if db.scalar("SELECT COUNT(*) FROM RG_SCAN_JOB WHERE source_id = :s AND status IN ('QUEUED', 'RUNNING')", {"s": source_id}):
        # a running scan writes RG_FINDING rows as it goes, in its own thread - deleting the source out from
        # under it doesn't stop it, it just orphans whatever it writes afterward (source_id pointing nowhere,
        # invisible to this function's own cleanup, which already ran). Wait for it, or it'll still be
        # writing findings for a source that - as far as everything else in the app is concerned - is gone.
        raise ValueError("A scan is still running for this source - wait for it to finish (or fail) before deleting it.")
    engine = engines.for_source(source_id)

    own_tables = {r["table_name"] for r in db.query("SELECT table_name FROM RG_CATALOG_TABLE WHERE source_id = :s", {"s": source_id})}
    snaps = db.query("SELECT table_name, backup_table FROM RG_SNAPSHOT WHERE source_id = :s", {"s": source_id})
    own_tables |= {s["table_name"] for s in snaps}
    with engine.transaction() as conn:
        for t in own_tables:
            engine.drop_view(engine.view_name(t), conn=conn)
        for s in snaps:
            engine.drop_table(s["backup_table"], conn=conn)

    retention_rules = db.query("SELECT rule_id, name FROM RG_RULE WHERE source_id = :s AND "
                               "(action = 'RETAIN' OR trigger_event = 'RETENTION_EXPIRY')", {"s": source_id})
    with db.transaction() as conn:
        db.execute("DELETE FROM RG_EVIDENCE WHERE ref_type = 'TASK' AND ref_id IN "
                  "(SELECT task_id FROM RG_REMEDIATION_TASK WHERE source_id = :s)", {"s": source_id}, conn=conn)
        db.execute("DELETE FROM RG_EVIDENCE WHERE ref_type = 'ERASURE' AND ref_id IN "
                  "(SELECT request_id FROM RG_ERASURE_REQUEST WHERE source_id = :s)", {"s": source_id}, conn=conn)
        for tbl in ("RG_PROTECTION", "RG_VIOLATION", "RG_REMEDIATION_TASK", "RG_ARCHIVE", "RG_FINDING",
                    "RG_CATALOG_COLUMN", "RG_CATALOG_TABLE", "RG_LINEAGE", "RG_SCAN_JOB",
                    "RG_ERASURE_REQUEST", "RG_LEGAL_HOLD", "RG_SNAPSHOT"):
            db.execute(f"DELETE FROM {tbl} WHERE source_id = :s", {"s": source_id}, conn=conn)
        if retention_rules:
            db.execute("DELETE FROM RG_RULE WHERE source_id = :s AND (action = 'RETAIN' OR trigger_event = 'RETENTION_EXPIRY')",
                      {"s": source_id}, conn=conn)
        db.execute("DELETE FROM RG_DATA_SOURCE WHERE source_id = :s", {"s": source_id}, conn=conn)
        details = f"{src['name']} ({src['source_type']}) removed"
        if retention_rules:
            details += f"; {len(retention_rules)} rule(s) removed with it: " + ", ".join(r["name"] for r in retention_rules)
        audit(username, "source", source_id, "DELETE", details, conn)
    holds.invalidate(source_id)
    return {"deleted_source": src["name"], "rules_removed": [r["name"] for r in retention_rules]}
