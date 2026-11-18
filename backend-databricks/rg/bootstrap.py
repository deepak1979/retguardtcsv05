"""Idempotent start-up: create RG_ tables, seed reference data, take the safety snapshot, discover the catalog."""
from __future__ import annotations

from . import catalog, db, ddl, seed, snapshot


def bootstrap() -> dict:
    created = ddl.init_schema()
    migrated = ddl.migrate()
    seed.seed()
    source_id = db.scalar("SELECT MIN(source_id) FROM RG_DATA_SOURCE")
    made = snapshot.ensure_snapshot(source_id, "system")
    discovered = None
    if not db.scalar("SELECT COUNT(*) FROM RG_CATALOG_TABLE WHERE source_id = :s", {"s": source_id}):
        discovered = catalog.discover(source_id, "system")
    return {"tables_created": created, "columns_added": migrated, "snapshots_made": made, "discovered": discovered, "source_id": source_id}
