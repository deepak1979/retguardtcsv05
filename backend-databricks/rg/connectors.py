"""Live connection testing for newly-registered data sources.

v04 is Databricks-only (no Oracle/SQL Server/Snowflake connector surface - see v03 for the
multi-engine version this was forked from). Credentials are stored in RG_DATA_SOURCE.password in
plain text, same local/demo-only caveat v03 carried: do not reuse this pattern for a real deployment
without encryption-at-rest or a secrets manager.
"""
from __future__ import annotations

CONNECTOR_TYPES = [
    {"code": "DATABRICKS", "label": "Databricks", "default_port": 443, "service_label": "HTTP path", "live": True,
     "host_label": "Server hostname", "username_label": "Catalog.Schema (e.g. retentionguard_v04.insurance_v04)",
     "password_label": "Access token (PAT)"},
]


def _databricks_test(host: str, http_path: str, catalog_schema: str, access_token: str) -> dict:
    from .engines.databricks import test_connection as _test
    return _test(host, http_path, catalog_schema, access_token)


def test_connection(source_type: str, host: str | None, port: int | None, service_name: str | None,
                     username: str | None, password: str | None) -> dict:
    """{"ok": bool, "message": str, "detail": str|None}. Never raises - any failure (bad credentials,
    unreachable host) comes back as ok=False with a human-readable message."""
    if source_type == "DATABRICKS":
        if not (host and service_name and username and password):
            return {"ok": False, "message": "Server hostname, HTTP path, Catalog.Schema and access token "
                                            "are all required.", "detail": None}
        return _databricks_test(host, service_name, username, password)
    label = next((t["label"] for t in CONNECTOR_TYPES if t["code"] == source_type), source_type)
    return {"ok": False, "detail": None,
            "message": f"{label} connections aren't supported in this app - Databricks is the only "
                       "data-plane connector v04 ships with."}
