"""Connection settings, read from backend-databricks/.env (never committed) or the process environment.

v04 is Databricks-only: the control plane lives in Lakebase (Postgres-compatible) and the one seeded
data-plane source is a Databricks SQL Warehouse over Unity Catalog. There is no Oracle/SQL
Server/Snowflake configuration here at all - see RETENTIONGUARD_V4_FUNCTIONALITY.md (once written) for
why, and the v03 app for the multi-engine version this was forked from.
"""
from __future__ import annotations

import os
from pathlib import Path


def _load_env() -> None:
    env = Path(__file__).resolve().parent.parent / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_env()

# --- Lakebase (Postgres Autoscaling) control plane ---------------------------------------------------
# The platform's documented auto-injection of PGHOST/PGUSER/LAKEBASE_ENDPOINT etc. from the app's
# `postgres` resource did not actually happen for this app (confirmed via a real deployed-app crash:
# LAKEBASE_ENDPOINT came through empty) - rather than keep depending on that working, every value below
# defaults to this project's one real project/branch/endpoint, hardcoded (these are resource paths, not
# secrets - the only actual secret, the OAuth token, is still always generated fresh by rg/db.py, never
# stored). Env vars still override these, e.g. for a future second environment/branch.
PG_HOST = os.environ.get("PGHOST", "ep-withered-water-d4c8djjs.database.ap-south-1.cloud.databricks.com")
PG_PORT = int(os.environ.get("PGPORT", "5432"))
PG_DATABASE = os.environ.get("PGDATABASE", "databricks_postgres")
# The deployed app connects as its own service principal (client id); local dev overrides this via
# .env to the project owner's own username instead (see .env.example).
PG_USER = os.environ.get("PGUSER", "84ae08ed-e722-450b-8c80-db3baed62c8c")
# Either a static password (local dev, databricks_superuser grant) or left blank so rg/db.py generates
# and auto-refreshes a short-lived OAuth token itself via the Databricks SDK (what the deployed app uses).
PG_PASSWORD = os.environ.get("PGPASSWORD", "")
PG_SSLMODE = os.environ.get("PGSSLMODE", "require")
LAKEBASE_ENDPOINT = os.environ.get("LAKEBASE_ENDPOINT",
                                    "projects/retentionguard-v04/branches/production/endpoints/primary")
# Dedicated schema this app creates and owns - the app's role has CAN_CONNECT_AND_CREATE only, which
# does not include access to Postgres's default 'public' schema (see rg/db.py's _conninfo()).
PG_SCHEMA = os.environ.get("PGSCHEMA", "rg_v04")

# --- Databricks workspace (used to seed the one data-plane source, and for Model Serving/Volumes) ----
# Host and warehouse HTTP path are workspace identifiers, not secrets (both already appear in every
# generated SQL endpoint URL), so they're safe to default here. DATABRICKS_TOKEN stays blank by
# default - rg/engines/databricks.py's DatabricksEngine authenticates as this process's own identity
# (the deployed app's service principal, or the developer's own CLI profile locally) via the SDK's
# own auto-config when no token is stored, so RG_DATA_SOURCE never needs a plaintext PAT at all. Set
# DATABRICKS_TOKEN in .env only if you specifically want PAT-based auth for local development instead.
DATABRICKS_HOST = os.environ.get("DATABRICKS_HOST", "dbc-603856c9-19e0.cloud.databricks.com")
DATABRICKS_TOKEN = os.environ.get("DATABRICKS_TOKEN", "")
DBX_HTTP_PATH = os.environ.get("DBX_HTTP_PATH", "/sql/1.0/warehouses/fbdbcb17a3e62497")  # Serverless Starter Warehouse
# This workspace's metastore only allows catalog creation via the UI (Default Storage is UI-only, the
# CLI/API is blocked outright), so v04 reuses the existing 'deepak' catalog (already proven, already
# used by v3 for its own 'insurance' schema) with its OWN dedicated schemas instead of a new catalog -
# 'insurance_v04' (data plane, a fresh copy of v3's structure, never v3's live data) and 'rg_v04_app'
# (holds the documents/redacted UC Volumes). Nothing here is shared with or written by v03.
DBX_CATALOG = os.environ.get("DBX_CATALOG", "deepak")
DBX_SCHEMA = os.environ.get("DBX_SCHEMA", "insurance_v04")
DBX_APP_SCHEMA = os.environ.get("DBX_APP_SCHEMA", "rg_v04_app")

# The schema that holds the scanned insurance (business) tables, for discovery/scan filtering - same
# role config.SOURCE_SCHEMA played in v03, just always a Unity Catalog schema name here.
SOURCE_SCHEMA = DBX_SCHEMA.upper()
META_PREFIX = "RG_"
BACKUP_PREFIX = "RG_BKP_"
MASK_VIEW_PREFIX = "RG_MV_"

EXCLUDED_TABLE_PREFIXES = [p.strip().upper() for p in
                           os.environ.get("EXCLUDED_TABLE_PREFIXES", f"{META_PREFIX}").split(",") if p.strip()]

# Unity Catalog Volumes for document governance (rg/docscan.py, rg/redact.py, rg/archive.py) - mounted
# as plain POSIX paths on any Databricks compute context, including this app's own container.
UC_DOCUMENTS_VOLUME = os.environ.get("UC_DOCUMENTS_VOLUME", f"/Volumes/{DBX_CATALOG}/{DBX_APP_SCHEMA}/documents")
UC_REDACTED_VOLUME = os.environ.get("UC_REDACTED_VOLUME", f"/Volumes/{DBX_CATALOG}/{DBX_APP_SCHEMA}/redacted")
# rg/archive.py's policy-archival JSON exports - a local-disk folder beside the app's own code in v03,
# which would be wiped on every restart/redeploy on Databricks Apps (ephemeral filesystem).
UC_ARCHIVE_VOLUME = os.environ.get("UC_ARCHIVE_VOLUME", f"/Volumes/{DBX_CATALOG}/{DBX_APP_SCHEMA}/archive")
