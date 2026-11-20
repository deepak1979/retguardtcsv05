"""REST API. Roles: viewer (read), steward (drive the lifecycle), admin (approve / execute / restore)."""
from __future__ import annotations

import contextlib
import re
import secrets
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import archive, catalog, config, connectors, db, docscan, engines, erasure, holds, llm, name_llm, org, policy, redact, remediation, scanner, scope, seed, snapshot, vectorsearch
from .bootstrap import bootstrap
from .common import audit
from .policy import NotFound, ValidationError

# Session storage lives in rg_session (Lakebase), not an in-memory dict - see rg/ddl.py's table
# comment for why: this app can run as more than one instance.


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    print("bootstrap:", bootstrap())
    yield
    db.close_pool()


app = FastAPI(title="RetentionGuard API (Databricks)", version="0.4.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:4203",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- models
class LoginIn(BaseModel):
    username: str
    password: str


class UserCreateIn(BaseModel):
    username: str = Field(min_length=2, max_length=60)
    password: str = Field(min_length=6, max_length=200)
    full_name: Optional[str] = None
    role: str = Field(pattern="^(admin|steward|viewer)$")


class PolicyIn(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    policy_code: Optional[str] = None
    description: str = ""
    data_category: str
    regulation: str = "INTERNAL"
    status: str = "DRAFT"
    effective_from: Optional[str] = None
    scope_level: str = "GLOBAL"
    region_id: Optional[int] = None
    country_id: Optional[int] = None
    override_parent: bool = False


class RuleIn(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    description: str = ""
    trigger_event: str
    action: str
    masking_method: Optional[str] = None
    enforcement_mode: Optional[str] = None
    min_confidence: Optional[float] = None
    element_filter: Optional[str] = None
    table_filter: Optional[str] = None
    source_id: Optional[int] = None   # which data source target_table lives in (RETAIN/RETENTION_EXPIRY only) - defaults to source 1
    target_table: Optional[str] = None
    anchor_column: Optional[str] = None
    retention_days: Optional[int] = None
    cascade_scope: Optional[str] = None
    anonymization_level: Optional[str] = None
    is_active: bool = True


class ScanIn(BaseModel):
    source_id: int = 1
    mode: str = "FULL"
    sample_size: Optional[int] = 200
    tables: Optional[list[str]] = None


class SourceTestIn(BaseModel):
    source_type: str
    host: Optional[str] = None
    port: Optional[int] = None
    service_name: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


class SourceCreateIn(SourceTestIn):
    name: str = Field(min_length=2, max_length=80)
    domain: Optional[str] = None


class PushdownIn(BaseModel):
    enabled: bool


class DecisionIn(BaseModel):
    status: str


class DocSourceCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    folder_path: str = Field(min_length=1, max_length=500)
    domain: Optional[str] = None


class ClassifierIn(BaseModel):
    code: str = Field(min_length=2, max_length=40)
    name: str = Field(min_length=2, max_length=80)
    category: str = "PII"
    pii_class: str = "DIRECT"
    applies_to: str = "STRING"
    method: str = "REGEX"                  # REGEX (content_pattern is a regular expression) or KEYWORD (comma separated terms)
    name_pattern: Optional[str] = None
    content_pattern: str
    min_match_ratio: Optional[float] = None
    name_weight: float = 0.3
    content_weight: float = 0.7
    description: str = ""
    scope_level: str = "GLOBAL"
    region_id: Optional[int] = None
    country_id: Optional[int] = None


class ScopeIn(BaseModel):
    scope_level: str = "GLOBAL"
    region_id: Optional[int] = None
    country_id: Optional[int] = None


class OrgIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    code: Optional[str] = None
    tagline: Optional[str] = None
    logo_url: Optional[str] = None
    logo_data: Optional[str] = None
    clear_logo: bool = False
    banner_color: str = "#ffffff"
    primary_color: str = "#0f766e"
    seed_hierarchy: bool = True


class RegionIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    code: Optional[str] = None
    description: Optional[str] = None
    is_active: bool = True


class CountryIn(BaseModel):
    region_id: int
    iso2: str = Field(min_length=2, max_length=2)
    name: str = Field(min_length=2, max_length=80)
    regulation: Optional[str] = None
    regulator: Optional[str] = None
    notes: Optional[str] = None
    is_active: bool = True


class ClassifierActiveIn(BaseModel):
    is_active: bool


class ErasureIn(BaseModel):
    search_value: str
    reason: str = ""


class SubjectIn(BaseModel):
    root_table: str
    key: str


class HoldIn(BaseModel):
    source_id: int
    root_table: str
    key_value: str
    reason: str = ""
    matter_ref: str = ""


class HoldFlagIn(BaseModel):
    source_id: int
    root_table: str
    key_value: str
    flag: str                       # Y = place a hold, N = release the active hold
    reason: str = ""
    matter_ref: str = ""


class ReleaseIn(BaseModel):
    reason: str = ""


class LlmIn(BaseModel):
    enabled: Optional[bool] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    base_url: Optional[str] = None
    sample_level: Optional[str] = None     # NONE | MASKED | REAL
    timeout: Optional[int] = None


class DocNameLlmIn(BaseModel):
    enabled: Optional[bool] = None
    model: Optional[str] = None
    timeout: Optional[int] = None


class VectorSearchIn(BaseModel):
    enabled: Optional[bool] = None
    embed_endpoint: Optional[str] = None


class UcTaggingIn(BaseModel):
    enabled: bool


class VectorQueryIn(BaseModel):
    query: str
    doc_source_id: Optional[int] = None


class NoteIn(BaseModel):
    note: str = ""


# --------------------------------------------------------------------------- auth
# v05 (TCS): identity + role come from Databricks itself wherever possible, not this app's own
# username/password store. Databricks Apps' reverse proxy already gates every request behind Entra ID
# before it ever reaches this container; once On-Behalf-Of is declared (user_api_scopes in
# databricks.yml), it also forwards that signed-in visitor's own OAuth token via
# `x-forwarded-access-token` on every request. A user-scoped WorkspaceClient built from that token can
# call current_user.me() - which returns both identity (email) AND the visitor's real Databricks group
# memberships in one call - so role comes from workspace group membership (retguard-admins/
# retguard-stewards/retguard-viewers), never a column this app manages itself.
#
# The OLD username/password/RG_SESSION path (still below) is NOT removed - by Deepak's explicit
# request it's kept as his own personal fallback login only (one RG_USER row: deepak/deepak123,
# role=admin - see seed.py). Every other person goes through OBO+groups exclusively; nobody else gets
# an RG_USER row or a password. v04's comment about X-Rg-Token surviving the reverse proxy (a custom
# header name isn't reserved the way `Authorization` is) still applies to that one fallback path.
_GROUP_ROLES = {"retguard-admins": "admin", "retguard-stewards": "steward", "retguard-viewers": "viewer"}


def _obo_identity(token: str) -> dict:
    """The signed-in visitor's own identity + every Databricks group they belong to, resolved via a
    user-scoped WorkspaceClient built from their OBO token. Raises (never swallows) - current_user()
    below needs to tell 'no OBO header at all' apart from 'a header was there but resolving it failed',
    which a blanket except-and-return-None here would make indistinguishable (both looked like a plain
    401 in an earlier version of this function - exactly what hid the real cause the first time)."""
    from databricks.sdk import WorkspaceClient
    from databricks.sdk.core import Config
    # auth_type="pat" is required here, not optional: the container always has DATABRICKS_CLIENT_ID/
    # DATABRICKS_CLIENT_SECRET set too (the app's own SP credentials, injected by the platform by
    # default), so passing just `token=` without pinning the auth type makes the SDK see two
    # candidate auth methods and refuse to pick, raising exactly this error - confirmed live.
    w = WorkspaceClient(config=Config(host=config.DATABRICKS_HOST, token=token, auth_type="pat"))
    me = w.current_user.me()
    groups = sorted({g.display for g in (me.groups or []) if g.display})
    return {"username": me.user_name, "full_name": me.display_name or me.user_name, "groups": groups}


def current_user(request: Request, x_rg_token: str | None = Header(default=None)) -> dict:
    obo_token = request.headers.get("x-forwarded-access-token")
    identity = None
    obo_error = None
    if obo_token:
        try:
            identity = _obo_identity(obo_token)
        except Exception as e:
            obo_error = f"{type(e).__name__}: {e}"
    if identity:
        role = next((r for g, r in _GROUP_ROLES.items() if g in identity["groups"]), None)
        if role:
            return {"user_id": None, "username": identity["username"], "full_name": identity["full_name"],
                    "role": role, "token": None}
    # No role from OBO (or no OBO at all, or OBO errored) - try the password fallback before giving up.
    # This matters: OBO is present on essentially every real browser request once enabled, so treating
    # "no matching group" as an immediate, unconditional failure would silently break the
    # deepak/deepak123 fallback too, for every visitor, every time - exactly the regression this fixes.
    token = (x_rg_token or "").strip()
    user = db.query_one("SELECT user_id, username, full_name, role FROM RG_SESSION WHERE token = :t",
                        {"t": token}) if token else None
    if user:
        return {**user, "token": token}
    if identity:
        groups_txt = ", ".join(identity["groups"]) or "(none seen)"
        raise HTTPException(403, f"Signed in as {identity['username']} - Databricks groups: {groups_txt}. "
                            "Not a member of retguard-admins, retguard-stewards, or retguard-viewers yet - "
                            "ask an admin to add you to one, or use the deepak login as a fallback.")
    if obo_token:
        raise HTTPException(403, f"Databricks sent an OBO token, but resolving it failed: {obo_error}. "
                            "Use the deepak login as a fallback.")
    # 403, not 401: a blank /login page with no banner (confirmed live) suggests the Apps reverse
    # proxy may intercept a plain 401 from this app as its own "needs auth" signal rather than passing
    # it through untouched - 403 unambiguously means "authenticated, just not authorized" and can't be
    # confused with that.
    raise HTTPException(403, "No OBO token was present on this request at all - Databricks Apps "
                        "'user authorization' is likely not enabled for this workspace. Use the "
                        "deepak login as a fallback.")


def _need(*roles: str):
    def dep(user: dict = Depends(current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(403, f"This needs the role: {' or '.join(roles)}")
        return user
    return dep


editor = _need("admin", "steward")
admin = _need("admin")


def _run(fn, *args, **kw):
    try:
        return fn(*args, **kw)
    except NotFound as e:
        raise HTTPException(404, str(e))
    except (ValidationError, ValueError) as e:
        raise HTTPException(422, str(e))
    except HTTPException:
        raise
    except Exception as e:
        # Anything else (a database driver error, an SDK error, ...) used to fall through to
        # Starlette's default plain-text 500, which has no `detail` field - the frontend's
        # errorMessage() can't read a message out of it and always showed the generic
        # "Something went wrong", with no way to tell what actually broke. Log the full
        # traceback server-side (for debugging) and surface a real message to the caller too.
        import traceback
        traceback.print_exc()
        raise HTTPException(500, f"{type(e).__name__}: {e}")


@app.post("/api/auth/login")
def login(body: LoginIn):
    u = db.query_one("SELECT * FROM RG_USER WHERE username = :u AND is_active = 1", {"u": body.username})
    if not u or not secrets.compare_digest(seed.hash_pw(body.password, u["salt"]), u["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    token = secrets.token_urlsafe(32)
    user = {"user_id": u["user_id"], "username": u["username"], "full_name": u["full_name"], "role": u["role"]}
    # Not db.insert(): token is a pre-generated string primary key here, not an auto-increment id for
    # the database to generate and hand back.
    db.execute("INSERT INTO RG_SESSION (token, user_id, username, full_name, role) "
              "VALUES (:token, :user_id, :username, :full_name, :role)", {"token": token, **user})
    audit(u["username"], "user", u["user_id"], "LOGIN")
    return {"token": token, "user": user}


@app.post("/api/auth/logout", status_code=204)
def logout(user: dict = Depends(current_user)):
    db.execute("DELETE FROM RG_SESSION WHERE token = :t", {"t": user["token"]})


@app.get("/api/auth/me")
def me(user: dict = Depends(current_user)):
    return {k: v for k, v in user.items() if k != "token"}


@app.post("/api/users", status_code=201)
def create_user(body: UserCreateIn, user: dict = Depends(admin)):
    """Admin-only: add a RetentionGuard login for a teammate. Separate from Databricks Apps access
    (which only gates whether someone can reach the app at all) - this is what actually governs what
    they can see and do once they're in, via the existing admin/steward/viewer roles."""
    salt = secrets.token_hex(8)
    try:
        uid = db.insert("RG_USER", {"username": body.username, "password_hash": seed.hash_pw(body.password, salt),
                                    "salt": salt, "full_name": body.full_name, "role": body.role}, "user_id")
    except Exception as e:
        if "rg_user_uk" in str(e) or "UniqueViolation" in type(e).__name__:
            raise HTTPException(422, f"A user named {body.username!r} already exists") from e
        raise
    audit(user["username"], "user", uid, "CREATE", f"{body.username} ({body.role})")
    return db.query_one("SELECT user_id, username, full_name, role, is_active FROM RG_USER WHERE user_id = :i", {"i": uid})


@app.get("/api/lookups")
def lookups(_: dict = Depends(current_user)):
    return policy.lookups()


# --------------------------------------------------------------------------- dashboard
@app.get("/api/dashboard")
def dashboard(_: dict = Depends(current_user)):
    active = "status IN ('AUTO', 'CONFIRMED')"
    # a finding whose source_id no longer has an RG_DATA_SOURCE row is an orphan (e.g. a scan still writing
    # after its source was deleted mid-run) - never count it, rather than rely on every deletion path having
    # caught every in-flight writer.
    live_source = "source_id IN (SELECT source_id FROM RG_DATA_SOURCE)"
    kpi = db.query_one(f"""SELECT
        (SELECT COUNT(*) FROM RG_CATALOG_TABLE) tables_cataloged,
        (SELECT COUNT(*) FROM RG_CATALOG_COLUMN) columns_cataloged,
        (SELECT COUNT(*) FROM RG_FINDING WHERE {active} AND category IN ('PII', 'PHI') AND {live_source}) sensitive_findings,
        (SELECT COUNT(*) FROM RG_FINDING WHERE status = 'NEEDS_REVIEW' AND {live_source}) needs_review,
        (SELECT COUNT(*) FROM RG_FINDING WHERE {active} AND category IN ('PII', 'PHI') AND protection <> 'NONE' AND {live_source}) sensitive_protected,
        (SELECT COUNT(*) FROM RG_POLICY WHERE status = 'ACTIVE') active_policies,
        (SELECT COUNT(*) FROM RG_RULE r JOIN RG_POLICY p ON p.policy_id = r.policy_id WHERE p.status = 'ACTIVE' AND r.is_active = 1) active_rules,
        (SELECT COUNT(*) FROM RG_VIOLATION WHERE status = 'OPEN') open_violations,
        (SELECT COUNT(*) FROM RG_REMEDIATION_TASK WHERE status = 'PROPOSED') tasks_awaiting_approval,
        (SELECT COUNT(*) FROM RG_REMEDIATION_TASK WHERE status = 'EXECUTED' AND verified = 1) tasks_verified,
        (SELECT COUNT(*) FROM RG_ERASURE_REQUEST) erasure_requests,
        (SELECT COUNT(*) FROM RG_ERASURE_REQUEST WHERE status = 'EXECUTED' AND verified = 1) erasure_verified,
        (SELECT COUNT(*) FROM RG_LEGAL_HOLD WHERE status = 'ACTIVE') active_holds""")
    by_table = db.query(f"""SELECT table_name, COUNT(*) findings,
                            SUM(CASE WHEN protection = 'NONE' THEN 1 ELSE 0 END) unprotected,
                            SUM(CASE WHEN category = 'PHI' THEN 1 ELSE 0 END) health
                            FROM RG_FINDING WHERE {active} AND category IN ('PII', 'PHI') AND {live_source}
                            GROUP BY table_name ORDER BY findings DESC""")
    tasks = {r["status"]: r["n"] for r in db.query("SELECT status, COUNT(*) n FROM RG_REMEDIATION_TASK GROUP BY status")}
    return {**kpi, "by_table": by_table, "tasks_by_status": tasks,
            "last_scan": (scanner.list_scans(1) or [None])[0],
            "recent_activity": db.query("SELECT ts, username, entity_type, action, details FROM RG_AUDIT_LOG "
                                        "ORDER BY audit_id DESC FETCH FIRST 8 ROWS ONLY")}


# --------------------------------------------------------------------------- data sources, catalog, scans
@app.get("/api/sources")
def sources(_: dict = Depends(current_user)):
    rows = db.query("SELECT * FROM RG_DATA_SOURCE ORDER BY source_id")
    for s in rows:
        s.pop("password", None)   # never sent to the frontend, even though admins can set it
        s["tables"] = db.scalar("SELECT COUNT(*) FROM RG_CATALOG_TABLE WHERE source_id = :s", {"s": s["source_id"]})
        s["columns"] = db.scalar("SELECT COUNT(*) FROM RG_CATALOG_COLUMN WHERE source_id = :s", {"s": s["source_id"]})
    return rows


@app.get("/api/sources/connector-types")
def source_connector_types(_: dict = Depends(current_user)):
    return connectors.CONNECTOR_TYPES


@app.post("/api/sources/test")
def source_test(body: SourceTestIn, user: dict = Depends(admin)):
    result = connectors.test_connection(body.source_type, body.host, body.port, body.service_name,
                                        body.username, body.password)
    audit(user["username"], "source", None, "TEST_CONNECTION",
          f"{body.source_type} {body.host}:{body.port}/{body.service_name or ''} -> "
          f"{'ok' if result['ok'] else 'failed: ' + result['message']}"[:490])
    return result


@app.post("/api/sources", status_code=201)
def source_create(body: SourceCreateIn, user: dict = Depends(admin)):
    tested = connectors.test_connection(body.source_type, body.host, body.port, body.service_name,
                                        body.username, body.password)
    domain = body.domain if body.domain in ("Insurance", "Banking") else None
    source_id = db.insert("RG_DATA_SOURCE", {
        "name": body.name, "source_type": body.source_type, "host": body.host, "port": body.port,
        "service_name": body.service_name, "schema_name": body.username, "username": body.username,
        "password": body.password, "status": "CONNECTED" if tested["ok"] else "NOT_VERIFIED", "domain": domain,
    }, "source_id")
    audit(user["username"], "source", source_id, "CREATE",
          f"{body.name} ({body.source_type}) - {'verified' if tested['ok'] else 'saved without a verified connection'}")
    row = db.query_one("SELECT * FROM RG_DATA_SOURCE WHERE source_id = :i", {"i": source_id})
    row.pop("password", None)
    row["tested"] = tested
    return row


@app.delete("/api/sources/{source_id}")
def source_delete(source_id: int, user: dict = Depends(admin)):
    return _run(snapshot.delete_source, source_id, user["username"])


@app.put("/api/sources/{source_id}/pushdown")
def source_set_pushdown(source_id: int, body: PushdownIn, user: dict = Depends(admin)):
    return _run(scanner.set_pushdown_enabled, source_id, body.enabled, user["username"])


@app.post("/api/sources/{source_id}/discover")
def discover(source_id: int, user: dict = Depends(editor)):
    return _run(catalog.discover, source_id, user["username"])


@app.get("/api/sources/{source_id}/catalog")
def get_catalog(source_id: int, _: dict = Depends(current_user)):
    return catalog.get_catalog(source_id)


@app.post("/api/scans", status_code=202)
def start_scan(body: ScanIn, user: dict = Depends(editor)):
    scan_id = _run(scanner.start_scan, body.source_id, body.mode, body.sample_size, body.tables, user["username"])
    return scanner.get_scan(scan_id)


@app.get("/api/scans")
def scans(_: dict = Depends(current_user)):
    return scanner.list_scans()


@app.get("/api/scans/{scan_id}")
def scan(scan_id: int, _: dict = Depends(current_user)):
    s = scanner.get_scan(scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    return s


# --------------------------------------------------------------------------- findings + classifiers
@app.get("/api/findings")
def findings(status: Optional[str] = None, category: Optional[str] = None, table: Optional[str] = None,
             min_conf: float = 0.0, include_low: bool = False, _: dict = Depends(current_user)):
    return scanner.list_findings(status, category, table, min_conf, include_low)


@app.put("/api/findings/{finding_id}")
def decide(finding_id: int, body: DecisionIn, user: dict = Depends(editor)):
    return _run(scanner.decide, finding_id, body.status, user["username"])


# --------------------------------------------------------------------------- document (PDF folder) sources
# Parallel to /api/sources + /api/scans + /api/findings above, not built on them - see RG_DOC_SOURCE etc.
# in rg/ddl.py and rg/docscan.py's own docstring for why a folder of PDFs doesn't fit that shape.
@app.get("/api/doc-sources")
def doc_sources(_: dict = Depends(current_user)):
    return docscan.list_doc_sources()


@app.post("/api/doc-sources", status_code=201)
def doc_source_create(body: DocSourceCreateIn, user: dict = Depends(admin)):
    return _run(docscan.create_doc_source, body.name, body.folder_path, user["username"], body.domain)


@app.delete("/api/doc-sources/{doc_source_id}")
def doc_source_delete(doc_source_id: int, user: dict = Depends(admin)):
    return _run(docscan.delete_doc_source, doc_source_id, user["username"])


@app.post("/api/doc-sources/{doc_source_id}/discover")
def doc_source_discover(doc_source_id: int, user: dict = Depends(editor)):
    return _run(docscan.discover, doc_source_id, user["username"])


@app.post("/api/doc-sources/{doc_source_id}/scan", status_code=202)
def doc_source_scan(doc_source_id: int, user: dict = Depends(editor)):
    scan_id = _run(docscan.start_scan, doc_source_id, user["username"])
    return {"doc_scan_id": scan_id}


@app.get("/api/doc-scans")
def doc_scans(doc_source_id: Optional[int] = None, _: dict = Depends(current_user)):
    return docscan.list_doc_scans(doc_source_id)


@app.get("/api/doc-findings")
def doc_findings(doc_source_id: Optional[int] = None, status: Optional[str] = None, category: Optional[str] = None,
                 include_low: bool = False, _: dict = Depends(current_user)):
    return docscan.list_doc_findings(doc_source_id, status, category, include_low)


@app.put("/api/doc-findings/{doc_finding_id}")
def doc_finding_decide(doc_finding_id: int, body: DecisionIn, user: dict = Depends(editor)):
    return _run(docscan.decide_doc_finding, doc_finding_id, body.status, user["username"])


# --------------------------------------------------------------------------- document redaction
# Its own lifecycle, own tab - parallel to /api/tasks (table remediation) above, not built on it. The
# source PDF is never touched; see rg/redact.py.
@app.get("/api/doc-redaction/eligible")
def doc_redaction_eligible(doc_source_id: int, _: dict = Depends(current_user)):
    return redact.eligible_documents(doc_source_id)


@app.post("/api/doc-redaction/evaluate")
def doc_redaction_evaluate(doc_source_id: int, user: dict = Depends(editor)):
    return _run(redact.evaluate, doc_source_id, user["username"])


@app.get("/api/doc-redaction/tasks")
def doc_redaction_tasks(doc_source_id: Optional[int] = None, _: dict = Depends(current_user)):
    return redact.list_tasks(doc_source_id)


@app.post("/api/doc-redaction/tasks/{task_id}/approve")
def doc_redaction_approve(task_id: int, user: dict = Depends(admin)):
    return _run(redact.approve, task_id, user["username"])


@app.post("/api/doc-redaction/tasks/{task_id}/reject")
def doc_redaction_reject(task_id: int, body: NoteIn, user: dict = Depends(admin)):
    return _run(redact.reject, task_id, user["username"], body.note)


@app.post("/api/doc-redaction/tasks/{task_id}/execute")
def doc_redaction_execute(task_id: int, user: dict = Depends(admin)):
    return _run(redact.execute, task_id, user["username"])


# "Redact all": propose + approve + execute every eligible document for a source in one background job -
# admin-only, same as approve()/execute() themselves, since the batch performs exactly those actions.
@app.post("/api/doc-redaction/batch", status_code=202)
def doc_redaction_batch_start(doc_source_id: int, user: dict = Depends(admin)):
    batch_id = _run(redact.start_batch, doc_source_id, user["username"])
    return {"redaction_batch_id": batch_id}


@app.get("/api/doc-redaction/batches")
def doc_redaction_batches(doc_source_id: Optional[int] = None, _: dict = Depends(current_user)):
    return redact.list_batches(doc_source_id)


# --------------------------------------------------------------------------- semantic (vector) search over documents
# Own tab, own lifecycle - built on redaction's output (rg/vectorsearch.py), not a new PII-detection pass.
# Role is the gate: every authenticated role can search the redacted ("safe") index; only admin's search
# also reaches the unredacted ("pii") index - decided server-side per request, not filtered afterward.
def _vs(fn, *args, **kw):
    try:
        return fn(*args, **kw)
    except vectorsearch.VectorSearchOff as e:
        raise HTTPException(409, str(e))
    except vectorsearch.VectorSearchError as e:
        raise HTTPException(502, str(e))
    except (ValidationError, ValueError) as e:
        raise HTTPException(422, str(e))


@app.get("/api/vector-search/settings")
def vs_settings(_: dict = Depends(current_user)):
    return vectorsearch.get_settings()


@app.put("/api/vector-search/settings")
def vs_save(body: VectorSearchIn, user: dict = Depends(admin)):
    return _vs(vectorsearch.save_settings, body.model_dump(), user["username"])


@app.post("/api/vector-search/test")
def vs_test(user: dict = Depends(admin)):
    return _vs(vectorsearch.test_connection, user["username"])


@app.get("/api/vector-search/index-status")
def vs_index_status(doc_source_id: Optional[int] = None, _: dict = Depends(current_user)):
    return vectorsearch.index_status(doc_source_id)


@app.post("/api/vector-search/index/{document_id}")
def vs_index_document(document_id: int, user: dict = Depends(editor)):
    return _vs(vectorsearch.index_document, document_id, user["username"])


@app.post("/api/vector-search/search")
def vs_search(body: VectorQueryIn, user: dict = Depends(current_user)):
    return _vs(vectorsearch.search, body.query, user["username"], user["role"], body.doc_source_id)


# --------------------------------------------------------------------------- Unity Catalog governed-tag write-back
# Off by default - writes real UC governance metadata (ALTER TABLE ... SET TAGS), not just app-internal
# state. See rg/catalog.py's sync_uc_tag()/uc_tagging_stats() module docstring section for the design.
@app.get("/api/uc-tagging/settings")
def uc_tagging_settings(_: dict = Depends(current_user)):
    return {"enabled": catalog.uc_tagging_enabled()}


@app.put("/api/uc-tagging/settings")
def uc_tagging_save(body: UcTaggingIn, user: dict = Depends(admin)):
    return catalog.save_uc_tagging_setting(body.enabled, user["username"])


@app.get("/api/uc-tagging/stats")
def uc_tagging_stats(source_id: Optional[int] = None, _: dict = Depends(current_user)):
    return catalog.uc_tagging_stats(source_id)


@app.post("/api/uc-tagging/commit")
def uc_tagging_commit(source_id: Optional[int] = None, user: dict = Depends(admin)):
    return catalog.commit_uc_tags(user["username"], source_id)


@app.get("/api/classifiers")
def classifiers(_: dict = Depends(current_user)):
    ix = scope.ScopeIndex()
    rows = db.query("SELECT * FROM RG_CLASSIFIER ORDER BY is_builtin DESC, code")
    for r in rows:
        r["scope_label"], r["scope_valid"] = ix.label(r), ix.valid(r)
    return rows


@app.post("/api/classifiers", status_code=201)
def create_classifier(body: ClassifierIn, user: dict = Depends(editor)):
    code = re.sub(r"[^A-Z0-9_]", "_", body.code.upper())
    if body.method not in ("REGEX", "KEYWORD"):
        raise HTTPException(422, "Method must be REGEX or KEYWORD")
    if body.pii_class not in ("DIRECT", "IDENTIFIER", "QUASI", "SENSITIVE"):
        raise HTTPException(422, "Unknown class")
    patterns = [body.name_pattern] + ([body.content_pattern] if body.method == "REGEX" else [])
    for pat in patterns:
        if pat:
            try:
                re.compile(pat)
            except re.error as e:
                raise HTTPException(422, f"Invalid regular expression: {e}")
    if body.method == "KEYWORD":
        terms = [t.strip() for t in body.content_pattern.split(",") if t.strip()]
        if not terms:
            raise HTTPException(422, "Give at least one keyword")
        body.content_pattern = ",".join(terms)[:390]
    if body.min_match_ratio is not None and not 0 < body.min_match_ratio <= 1:
        raise HTTPException(422, "Minimum match ratio must be between 0 and 1")
    sc = {"scope_level": body.scope_level, "region_id": body.region_id, "country_id": body.country_id}
    _run(policy.normalise_scope, sc)
    if body.category not in policy.CATEGORIES or body.applies_to not in ("STRING", "NUMBER", "DATE"):
        raise HTTPException(422, "Unknown category or data type")
    if db.scalar("SELECT COUNT(*) FROM RG_CLASSIFIER WHERE code = :c", {"c": code}):
        raise HTTPException(422, f"A classifier with code {code} already exists")
    cid = db.insert("RG_CLASSIFIER", {"code": code, "name": body.name, "category": body.category, "pii_class": body.pii_class,
                                      "applies_to": body.applies_to, "name_pattern": body.name_pattern,
                                      "content_method": body.method, "content_pattern": body.content_pattern,
                                      "min_match_ratio": body.min_match_ratio, "scope_level": sc["scope_level"],
                                      "region_id": sc["region_id"], "country_id": sc["country_id"],
                                      "name_weight": body.name_weight, "content_weight": body.content_weight,
                                      "description": body.description, "is_builtin": 0, "is_active": 1}, "classifier_id")
    audit(user["username"], "classifier", cid, "CREATE", code)
    return db.query_one("SELECT * FROM RG_CLASSIFIER WHERE classifier_id = :i", {"i": cid})


@app.put("/api/classifiers/{classifier_id}")
def toggle_classifier(classifier_id: int, body: ClassifierActiveIn, user: dict = Depends(editor)):
    if not db.execute("UPDATE RG_CLASSIFIER SET is_active = :a WHERE classifier_id = :i", {"a": int(body.is_active), "i": classifier_id}):
        raise HTTPException(404, "Classifier not found")
    audit(user["username"], "classifier", classifier_id, "ENABLE" if body.is_active else "DISABLE")
    return db.query_one("SELECT * FROM RG_CLASSIFIER WHERE classifier_id = :i", {"i": classifier_id})


@app.put("/api/classifiers/{classifier_id}/scope")
def classifier_scope(classifier_id: int, body: ScopeIn, user: dict = Depends(editor)):
    c = db.query_one("SELECT * FROM RG_CLASSIFIER WHERE classifier_id = :i", {"i": classifier_id})
    if not c:
        raise HTTPException(404, "Classifier not found")
    if c["is_builtin"]:
        raise HTTPException(422, "Built-in classifiers keep the scope of their pack. Disable one, or add a custom classifier")
    sc = body.model_dump()
    _run(policy.normalise_scope, sc)
    db.update("RG_CLASSIFIER", "classifier_id", classifier_id, {"scope_level": sc["scope_level"], "region_id": sc["region_id"], "country_id": sc["country_id"]})
    audit(user["username"], "classifier", classifier_id, "SCOPE", c["code"])
    return db.query_one("SELECT * FROM RG_CLASSIFIER WHERE classifier_id = :i", {"i": classifier_id})


@app.delete("/api/classifiers/{classifier_id}", status_code=204)
def delete_classifier(classifier_id: int, user: dict = Depends(editor)):
    c = db.query_one("SELECT * FROM RG_CLASSIFIER WHERE classifier_id = :i", {"i": classifier_id})
    if not c:
        raise HTTPException(404, "Classifier not found")
    if c["is_builtin"]:
        raise HTTPException(422, "Built-in classifiers can be disabled but not deleted")
    db.execute("DELETE FROM RG_CLASSIFIER WHERE classifier_id = :i", {"i": classifier_id})
    audit(user["username"], "classifier", classifier_id, "DELETE", c["code"])


# --------------------------------------------------------------------------- policies + rules
@app.get("/api/policies")
def list_policies(q: Optional[str] = None, status: Optional[str] = None, category: Optional[str] = None,
                  scope_level: Optional[str] = None, region_id: Optional[int] = None, country_id: Optional[int] = None,
                  _: dict = Depends(current_user)):
    rows = policy.list_policies(q, status, category)
    if scope_level:
        rows = [r for r in rows if r["scope_level"] == scope_level]
    if region_id:
        rows = [r for r in rows if r["region_id"] == region_id]
    if country_id:
        rows = [r for r in rows if r["country_id"] == country_id]
    return rows


@app.post("/api/policies", status_code=201)
def create_policy(body: PolicyIn, user: dict = Depends(editor)):
    return _run(policy.create_policy, body.model_dump(), user["username"])


@app.get("/api/policies/{policy_id}")
def get_policy(policy_id: int, _: dict = Depends(current_user)):
    return _run(policy.get_policy, policy_id)


@app.put("/api/policies/{policy_id}")
def update_policy(policy_id: int, body: PolicyIn, user: dict = Depends(editor)):
    return _run(policy.update_policy, policy_id, body.model_dump(exclude_unset=True), user["username"])


@app.delete("/api/policies/{policy_id}", status_code=204)
def delete_policy(policy_id: int, user: dict = Depends(editor)):
    _run(policy.delete_policy, policy_id, user["username"])


@app.post("/api/policies/{policy_id}/rules", status_code=201)
def create_rule(policy_id: int, body: RuleIn, user: dict = Depends(editor)):
    return _run(policy.create_rule, policy_id, body.model_dump(), user["username"])


@app.put("/api/rules/{rule_id}")
def update_rule(rule_id: int, body: RuleIn, user: dict = Depends(editor)):
    return _run(policy.update_rule, rule_id, body.model_dump(), user["username"])


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: int, user: dict = Depends(editor)):
    return _run(policy.delete_rule, rule_id, user["username"])


# --------------------------------------------------------------------------- evaluation, violations, remediation tasks
class EvaluateIn(BaseModel):
    rule_ids: Optional[list[int]] = None       # None = every active rule (the normal run); a list = just these rules
    source_id: Optional[int] = None            # None = every data source; an id = just that one (composes with rule_ids)


@app.get("/api/evaluate/scope")
def evaluate_scope(_: dict = Depends(current_user)):
    """Policies and rules the evaluation picker can offer: what evaluate() would act on right now."""
    return remediation.evaluable_rules()


@app.post("/api/evaluate")
def evaluate(body: EvaluateIn, user: dict = Depends(editor)):
    ids = set(body.rule_ids) if body.rule_ids is not None else None
    return _run(remediation.evaluate, user["username"], ids, body.source_id)


@app.get("/api/violations")
def violations(status: Optional[str] = None, _: dict = Depends(current_user)):
    return remediation.list_violations(status)


@app.get("/api/tasks")
def tasks(status: Optional[str] = None, _: dict = Depends(current_user)):
    return remediation.list_tasks(status)


@app.get("/api/tasks/{task_id}")
def task(task_id: int, _: dict = Depends(current_user)):
    return _run(remediation.get_task, task_id)


@app.get("/api/tasks/{task_id}/preview")
def task_preview(task_id: int, limit: int = 20, _: dict = Depends(current_user)):
    return _run(remediation.preview_rows, task_id, limit)


@app.post("/api/tasks/{task_id}/plan")
def task_plan(task_id: int, _: dict = Depends(editor)):
    return _run(remediation.refresh_plan, task_id)


@app.post("/api/tasks/{task_id}/approve")
def task_approve(task_id: int, user: dict = Depends(admin)):
    return _run(remediation.approve, task_id, user["username"])


@app.post("/api/tasks/{task_id}/reject")
def task_reject(task_id: int, body: NoteIn, user: dict = Depends(admin)):
    return _run(remediation.reject, task_id, user["username"], body.note)


@app.post("/api/tasks/{task_id}/repropose")
def task_repropose(task_id: int, user: dict = Depends(editor)):
    return _run(remediation.repropose, task_id, user["username"])


@app.post("/api/tasks/{task_id}/execute")
def task_execute(task_id: int, user: dict = Depends(admin)):
    return _run(remediation.execute, task_id, user["username"])


# --------------------------------------------------------------------------- erasure + legal holds
@app.get("/api/erasure")
def erasure_list(_: dict = Depends(current_user)):
    return erasure.list_requests()


@app.post("/api/erasure", status_code=201)
def erasure_create(body: ErasureIn, user: dict = Depends(editor)):
    return _run(erasure.create_request, body.search_value, body.reason, user["username"])


@app.get("/api/erasure-samples")
def erasure_samples(_: dict = Depends(editor)):
    """Demo helper: real identifiers from the data, labelled with the outcome the plan should show.

    FIX (was a real bug): every query here used to go through `db` (rg/db.py, the Lakebase CONTROL
    plane connection) against CUSTOMER/POLICY/CLAIM/AGENT - the governed DATA plane tables, which only
    exist in Unity Catalog via the Databricks engine, never in Lakebase/Postgres. Each lookup always
    raised (table not found), was silently swallowed by contextlib.suppress(Exception), and this
    endpoint returned an empty list every time. Switched to the DATABRICKS engine (source 1, same
    default every other source_id-less call in this app uses - see remediation.source_id())."""
    out = []
    engine = engines.for_source(remediation.source_id())
    q = [("Customer with no contracts - expect a full delete",
          "SELECT email FROM CUSTOMER c WHERE email IS NOT NULL AND NOT EXISTS (SELECT 1 FROM POLICY p WHERE p.customer_id = c.customer_id) "
          "AND NOT EXISTS (SELECT 1 FROM CLAIM l WHERE l.customer_id = c.customer_id) ORDER BY customer_id FETCH FIRST 1 ROWS ONLY"),
         ("Customer with policies and claims - expect anonymise, records retained",
          "SELECT email FROM CUSTOMER c WHERE email IS NOT NULL AND EXISTS (SELECT 1 FROM CLAIM l WHERE l.customer_id = c.customer_id) "
          "ORDER BY customer_id FETCH FIRST 1 ROWS ONLY"),
         ("Agent who sold policies - expect anonymise, business records retained",
          "SELECT email FROM AGENT a WHERE email IS NOT NULL AND EXISTS (SELECT 1 FROM POLICY p WHERE p.agent_id = a.agent_id) "
          "ORDER BY agent_id FETCH FIRST 1 ROWS ONLY")]
    for label, sql in q:
        with contextlib.suppress(Exception):
            v = engine.scalar(sql)
            if v:
                out.append({"label": label, "search_value": v})
    return out


@app.get("/api/erasure/{request_id}")
def erasure_get(request_id: int, _: dict = Depends(current_user)):
    return _run(erasure.get_request, request_id)


@app.post("/api/erasure/{request_id}/subject")
def erasure_subject(request_id: int, body: SubjectIn, user: dict = Depends(editor)):
    return _run(erasure.select_subject, request_id, body.root_table, body.key, user["username"])


@app.post("/api/erasure/{request_id}/approve")
def erasure_approve(request_id: int, user: dict = Depends(admin)):
    return _run(erasure.approve, request_id, user["username"])


@app.post("/api/erasure/{request_id}/reject")
def erasure_reject(request_id: int, user: dict = Depends(admin)):
    return _run(erasure.reject, request_id, user["username"])


@app.post("/api/erasure/{request_id}/execute")
def erasure_execute(request_id: int, user: dict = Depends(admin)):
    return _run(erasure.execute, request_id, user["username"])


# Legal hold register: stewards and admins set the flag (Y / N) on a customer, policy or claim.
@app.get("/api/legal-holds")
def hold_list(status: Optional[str] = None, customer: Optional[str] = None, _: dict = Depends(current_user)):
    return holds.list_holds(status, customer)


@app.get("/api/legal-holds/customers")
def hold_customers(q: str = "", _: dict = Depends(current_user)):
    return _run(holds.search_customers, q)


@app.get("/api/legal-holds/customer/{customer_id}")
def hold_customer(customer_id: int, source_id: int = 1, _: dict = Depends(current_user)):
    return _run(holds.customer_tree, source_id, customer_id)


@app.post("/api/legal-holds", status_code=201)
def hold_create(body: HoldIn, user: dict = Depends(editor)):
    return _run(holds.create_hold, body.source_id, body.root_table, body.key_value, body.reason, user["username"], body.matter_ref)


@app.post("/api/legal-holds/flag")
def hold_flag(body: HoldFlagIn, user: dict = Depends(editor)):
    return _run(holds.set_flag, body.source_id, body.root_table, body.key_value, body.flag, body.reason, user["username"], body.matter_ref)


@app.post("/api/legal-holds/{hold_id}/release")
def hold_release(hold_id: int, body: ReleaseIn, user: dict = Depends(editor)):
    return _run(holds.release_hold, hold_id, user["username"], body.reason)


# --------------------------------------------------------------------------- optional LLM second opinion (off by default)
def _llm(fn, *args, **kw):
    try:
        return fn(*args, **kw)
    except llm.LlmOff as e:
        raise HTTPException(409, str(e))                 # the switch is off: nothing was called
    except llm.LlmError as e:
        raise HTTPException(502, str(e))                 # the model could not be reached or did not answer usably
    except NotFound as e:
        raise HTTPException(404, str(e))
    except (ValidationError, ValueError) as e:
        raise HTTPException(422, str(e))


@app.get("/api/llm/settings")
def llm_settings(_: dict = Depends(current_user)):
    return llm.get_settings()


@app.put("/api/llm/settings")
def llm_save(body: LlmIn, user: dict = Depends(admin)):
    return _llm(llm.save_settings, body.model_dump(), user["username"])


@app.post("/api/llm/test")
def llm_test(user: dict = Depends(admin)):
    return _llm(llm.test_connection, user["username"])


@app.get("/api/llm/opinions")
def llm_opinions(_: dict = Depends(current_user)):
    return llm.opinions()


@app.post("/api/llm/opinion/{finding_id}")
def llm_opinion(finding_id: int, refresh: bool = False, user: dict = Depends(editor)):
    return _llm(llm.second_opinion, finding_id, user["username"], refresh)


# --------------------------------------------------------------------------- LLM-assisted name detection for documents
# A second, complementary source of FULL_NAME candidates in docscan.py's body-text sweep - see rg/name_llm.py.
# Gated by the same llm.enabled() master switch as the second opinion above, plus its own toggle here.
@app.get("/api/doc-name-llm/settings")
def doc_name_llm_settings(_: dict = Depends(current_user)):
    return name_llm.get_settings()


@app.put("/api/doc-name-llm/settings")
def doc_name_llm_save(body: DocNameLlmIn, user: dict = Depends(admin)):
    return _llm(name_llm.save_settings, body.model_dump(), user["username"])


@app.post("/api/doc-name-llm/test")
def doc_name_llm_test(user: dict = Depends(admin)):
    return _llm(name_llm.test_connection, user["username"])


# --------------------------------------------------------------------------- demo data + audit
@app.get("/api/snapshot")
def snapshot_status(source_id: int = 1, _: dict = Depends(current_user)):
    return snapshot.status(source_id)


@app.post("/api/snapshot/restore")
def snapshot_restore(source_id: int = 1, user: dict = Depends(admin)):
    res = _run(snapshot.restore, user["username"], source_id)
    scanner.start_scan(source_id, "FULL", None, None, user["username"])
    return res


@app.post("/api/snapshot/clear-all")
def snapshot_clear_all(user: dict = Depends(admin)):
    """Full demo reset: restore every data source's tables and wipe findings, catalog, scans, archive and
    lifecycle state entirely, across every source. No scan is started automatically - switch organisation
    (or discover/scan) next, on purpose."""
    return _run(snapshot.clear_all, user["username"])


@app.post("/api/snapshot/retake")
def snapshot_retake(source_id: int = 1, user: dict = Depends(admin)):
    return {"tables": _run(snapshot.retake, source_id, user["username"])}


class RestoreTablesIn(BaseModel):
    tables: list[str]
    source_id: int = 1


@app.post("/api/snapshot/restore-tables")
def snapshot_restore_tables(body: RestoreTablesIn, user: dict = Depends(admin)):
    """Restore just the given tables - for replaying one scenario without resetting the whole demo."""
    res = _run(snapshot.restore_tables, body.tables, user["username"], body.source_id)
    scanner.start_scan(body.source_id, "FULL", None, res["tables_restored"], user["username"])
    return res


@app.get("/api/audit")
def audit_log(limit: int = 200, _: dict = Depends(current_user)):
    return db.query("SELECT * FROM RG_AUDIT_LOG ORDER BY audit_id DESC FETCH FIRST :n ROWS ONLY", {"n": limit})


# --------------------------------------------------------------------------- archive (ARCHIVE remediation action)
@app.get("/api/archive")
def archive_list(table: Optional[str] = None, _: dict = Depends(current_user)):
    return archive.list_entries(table)


@app.get("/api/archive/{archive_id}")
def archive_get(archive_id: int, _: dict = Depends(current_user)):
    e = archive.get_entry(archive_id)
    if not e:
        raise HTTPException(404, f"Archive entry {archive_id} not found")
    return e


@app.get("/api/archive/{archive_id}/file")
def archive_file(archive_id: int, _: dict = Depends(current_user)):
    e = archive.get_entry(archive_id)
    if not e:
        raise HTTPException(404, f"Archive entry {archive_id} not found")
    try:
        return archive.read_file(e)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc))


# --------------------------------------------------------------------------- branding, organisation, hierarchy
@app.get("/api/branding")
def branding():
    """Public: the login page needs the company name and logo before anyone is signed in."""
    return org.branding()


@app.get("/api/organizations")
def organizations(_: dict = Depends(current_user)):
    return org.list_orgs()


@app.post("/api/organizations", status_code=201)
def organization_create(body: OrgIn, user: dict = Depends(admin)):
    return _run(org.create_org, body.model_dump(), user["username"])


@app.put("/api/organizations/{org_id}")
def organization_update(org_id: int, body: OrgIn, user: dict = Depends(admin)):
    res = _run(org.update_org, org_id, body.model_dump(), user["username"])
    return {k: v for k, v in res.items() if k != "logo_data"} | {"has_logo_data": bool(res.get("logo_data"))}


@app.post("/api/organizations/{org_id}/activate")
def organization_activate(org_id: int, user: dict = Depends(admin)):
    res = _run(org.activate_org, org_id, user["username"])
    seed.sync_classifiers()                # point the country / region classifier packs at the newly active hierarchy
    return {k: v for k, v in res.items() if k != "logo_data"}


@app.delete("/api/organizations/{org_id}", status_code=204)
def organization_delete(org_id: int, user: dict = Depends(admin)):
    _run(org.delete_org, org_id, user["username"])


@app.get("/api/hierarchy")
def hierarchy(_: dict = Depends(current_user)):
    return org.hierarchy()


@app.post("/api/regions", status_code=201)
def region_create(body: RegionIn, user: dict = Depends(admin)):
    return _run(org.create_region, body.model_dump(), user["username"])


@app.put("/api/regions/{region_id}")
def region_update(region_id: int, body: RegionIn, user: dict = Depends(admin)):
    return _run(org.update_region, region_id, body.model_dump(), user["username"])


@app.delete("/api/regions/{region_id}", status_code=204)
def region_delete(region_id: int, user: dict = Depends(admin)):
    _run(org.delete_region, region_id, user["username"])


@app.post("/api/countries", status_code=201)
def country_create(body: CountryIn, user: dict = Depends(admin)):
    return _run(org.create_country, body.model_dump(), user["username"])


@app.put("/api/countries/{country_id}")
def country_update(country_id: int, body: CountryIn, user: dict = Depends(admin)):
    return _run(org.update_country, country_id, body.model_dump(), user["username"])


@app.delete("/api/countries/{country_id}", status_code=204)
def country_delete(country_id: int, user: dict = Depends(admin)):
    _run(org.delete_country, country_id, user["username"])


@app.get("/api/coverage")
def coverage(country: Optional[str] = None, _: dict = Depends(current_user)):
    """What applies to a country (or, without one, to the organisation as a whole)."""
    return _run(org.coverage, country)


@app.get("/api/jurisdiction")
def jurisdiction(_: dict = Depends(current_user)):
    return org.jurisdiction_report()
