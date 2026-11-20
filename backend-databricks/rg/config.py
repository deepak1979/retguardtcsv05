"""Connection settings, read from backend-databricks/.env (never committed) or the process environment.

v05 is a TCS-workspace port of v04: same Databricks-only architecture (control plane in Lakebase,
data plane in Unity Catalog over a Databricks SQL Warehouse, no Oracle/SQL Server/Snowflake), just
pointed at a different Databricks account - the `retguard` catalog and `rglkbase` Lakebase project on
the TCS Azure workspace, instead of v04's `deepak` catalog and `retentionguard-v04` project. v04
itself (and its own workspace/resources) is untouched by this fork.
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
# `postgres` resource did not actually happen for v04 (confirmed via a real deployed-app crash:
# LAKEBASE_ENDPOINT came through empty) - rather than keep depending on that working, every value below
# defaults to this project's one real project/branch/endpoint, hardcoded (these are resource paths, not
# secrets - the only actual secret, the OAuth token, is still always generated fresh by rg/db.py, never
# stored). Env vars still override these, e.g. for a future second environment/branch.
PG_HOST = os.environ.get("PGHOST", "ep-super-mud-e9p2vh28.database.eastus.azuredatabricks.net")
PG_PORT = int(os.environ.get("PGPORT", "5432"))
PG_DATABASE = os.environ.get("PGDATABASE", "databricks_postgres")
# TODO once a Databricks App exists on the TCS workspace and is wired to the rglkbase `postgres`
# resource: replace this default with that app's own service principal client id (deploy-first
# ownership model, same as v04 - see rg/db.py's _conninfo()). Until then this defaults to the project
# owner's own identity, same as v04's local-dev override.
PG_USER = os.environ.get("PGUSER", "123323@tcs.com")
# Either a static password (local dev, databricks_superuser grant) or left blank so rg/db.py generates
# and auto-refreshes a short-lived OAuth token itself via the Databricks SDK (what the deployed app uses).
PG_PASSWORD = os.environ.get("PGPASSWORD", "")
PG_SSLMODE = os.environ.get("PGSSLMODE", "require")
LAKEBASE_ENDPOINT = os.environ.get("LAKEBASE_ENDPOINT",
                                    "projects/rglkbase/branches/production/endpoints/primary")
# Dedicated schema this app creates and owns - the app's role has CAN_CONNECT_AND_CREATE only, which
# does not include access to Postgres's default 'public' schema (see rg/db.py's _conninfo()). All 36
# rg_ tables + pgvector + HNSW indexes already created here via ddl.init_schema().
PG_SCHEMA = os.environ.get("PGSCHEMA", "rg_tcs")

# --- Databricks workspace (used to seed the one data-plane source, and for Model Serving/Volumes) ----
# Host and warehouse HTTP path are workspace identifiers, not secrets (both already appear in every
# generated SQL endpoint URL), so they're safe to default here. DATABRICKS_TOKEN stays blank by
# default - rg/engines/databricks.py's DatabricksEngine authenticates as this process's own identity
# (the deployed app's service principal, or the developer's own CLI profile locally) via the SDK's
# own auto-config when no token is stored, so RG_DATA_SOURCE never needs a plaintext PAT at all. Set
# DATABRICKS_TOKEN in .env only if you specifically want PAT-based auth for local development instead.
DATABRICKS_HOST = os.environ.get("DATABRICKS_HOST", "adb-7405616218084323.3.azuredatabricks.net")
DATABRICKS_TOKEN = os.environ.get("DATABRICKS_TOKEN", "")
DBX_HTTP_PATH = os.environ.get("DBX_HTTP_PATH", "/sql/1.0/warehouses/9ed46e1b64adee1e")  # dqx-studio-sql-warehouse
# Unlike v04's workspace (Default Storage UI-only), this TCS metastore had no usable Default Storage
# root at all (broken at the account level) - 'retguard' was created via CLI with an explicit
# --storage-root under an existing external location instead. Two dedicated schemas: 'data' (data
# plane - 9 insurance tables, synthetic, FK-consistent, already seeded) and 'app' (holds the
# documents/redacted/archive UC Volumes, already created).
DBX_CATALOG = os.environ.get("DBX_CATALOG", "retguard")
DBX_SCHEMA = os.environ.get("DBX_SCHEMA", "data")
DBX_APP_SCHEMA = os.environ.get("DBX_APP_SCHEMA", "app")

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
