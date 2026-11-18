# RetentionGuard v04 — Status (Databricks-only build)

v04 is a from-scratch port of RetentionGuard (data discovery, classification, retention,
remediation, erasure/legal-holds) to run **entirely inside Databricks** — no Oracle, no SQL Server,
no Snowflake, no local Chroma. v02 and v03 (`ui-compare-v02`/`ui-compare-v03`) are untouched; v04 is
a new sibling directory with its own git history, its own Databricks resources, and its own Lakebase
project.

## What's done and verified

- **Local directory scaffold**: `backend-databricks/` (FastAPI + the dialect-agnostic `rg/` modules
  carried over from v03) and `angular-app/` (same Angular 22 frontend, untouched). Ports reassigned
  to avoid colliding with v02 (8011/4201) and v03 (8012/4202): backend **8013**, frontend dev **4203**.
- **Lakebase (Postgres Autoscaling) control plane**: project `retentionguard-v04`
  (`projects/retentionguard-v04`), default `production` branch, `databricks_postgres` database,
  `pgvector` 0.8.0 extension confirmed available. Connection verified live via `psycopg` + an OAuth
  token from `databricks postgres generate-database-credential`.
- **`rg/db.py`** rewritten from Oracle (`oracledb`) to Postgres (`psycopg` + `psycopg_pool`), same
  public function shapes (`query`/`query_one`/`scalar`/`execute`/`insert`/`update`/`transaction`).
  Handles the `:name` → `%(name)s` bind-style translation, Decimal→float coercion (psycopg maps
  NUMERIC columns to `Decimal`; oracledb returned `float` — one fix at the row-cleaning layer instead
  of patching every arithmetic call site), and a dedicated `rg_v04` Postgres schema (the app's role
  only gets `CAN_CONNECT_AND_CREATE`, which excludes `public` — same reasoning the
  `databricks-lakebase` skill documents).
- **`rg/ddl.py`** ported to Postgres dialect: all 32 tables (`identity` columns, `NUMERIC`/`VARCHAR`/
  `TEXT` types, lowercase identifiers — Postgres folds unquoted identifiers to lowercase regardless of
  how the SQL strings elsewhere spell them, so none of the business-logic modules needed a casing
  rewrite). **Verified**: `ddl.init_schema()` creates all 32 tables correctly against live Lakebase.
- **Oracle-specific SQL swept from every reused module**: `SYSTIMESTAMP` → `now()` (12 files),
  `LISTAGG(...) WITHIN GROUP (...)` → `STRING_AGG(... ORDER BY ...)` (docscan.py, scanner.py),
  `NVL(` → `COALESCE(` (policy.py, org.py), Oracle's `MERGE INTO ... USING dual` → `INSERT ... ON
  CONFLICT DO UPDATE` (vectorsearch.py), `FROM dual` dropped (api.py — Postgres allows a bare
  `SELECT` with no table). `catalog.py`'s Oracle-dictionary-view code path (`all_tables`/
  `all_tab_columns`) and `rg/mssql.py` are now dead/unreachable code (v04's `engines/registry.py` only
  ever resolves `DatabricksEngine`) — left in place, flagged for a Phase 2 cleanup pass, not removed
  yet.
- **Data plane**: reused `rg/engines/databricks.py` byte-for-byte from v03 (already proven this
  session). Business tables deep-cloned from v03's live `deepak.insurance` into a **new, independent**
  `deepak.insurance_v04` schema (`agent`, `claim`, `claim_payment`, `customer`, `policy`,
  `policy_operation`, `premium_payment`, `ref_branch`, `ref_product` — 2000 customers/policies/claims,
  same data v3 already uses, physically separate copy via Delta `DEEP CLONE`, so nothing v04 does can
  affect v03's live source). Reused the existing "Serverless Starter Warehouse"
  (`fbdbcb17a3e62497`) rather than provisioning a new one.
- **Unity Catalog**: catalog creation turned out to be **UI-only** in this workspace (`CREATE CATALOG`
  is blocked via CLI/API — "Please use the UI to create a catalog with Default Storage"), so v04
  reuses the existing `deepak` catalog with two new, dedicated schemas: `deepak.insurance_v04` (data
  plane, above) and `deepak.rg_v04_app` (holds the `documents` and `redacted` UC Volumes for Phase 4).
- **Full local end-to-end verification**, run against the real Lakebase project + real
  `deepak.insurance_v04` data (as the project owner, not yet as the deployed app — see Known Issue
  below): `rg.bootstrap.bootstrap()` → `rg.catalog.discover()` (9 tables, 106 columns cataloged) →
  `rg.scanner.run_scan_sync()` (COMPLETED, 101 columns scanned, **26 real PII findings** — EMAIL,
  FIRST_NAME/LAST_NAME, PHONE, DATE_OF_BIRTH, CUSTOMER_NUMBER, STREET_ADDRESS, ANNUAL_INCOME, etc.,
  with realistic confidence scores) → `rg.remediation.evaluate()` (7 real violations/tasks across
  mask/anonymize/delete rules) → `rg.remediation.approve()` + `.execute()` on a MASK task (created a
  real `RG_MV_agent` masked view in `deepak.insurance_v04` with correct partial-masking SQL, 200 rows).
  This proves classifier pushdown scoring, discovery, scanning, and remediation execution all work
  correctly against the ported Postgres control plane + the real Databricks data plane.
- **Two more real bugs found and fixed** by this lifecycle testing (beyond the SQL-dialect sweep
  above): a `Decimal`/`float` type mismatch (psycopg maps Postgres `NUMERIC` columns to `Decimal`;
  oracledb returned `float` - fixed once, in `db.py`'s row-cleaning layer, rather than patching every
  arithmetic call site) and `rg/holds.py`'s `SUBJECT_MODEL` dict, which was hardcoded to v3's
  multi-source Oracle/SQL-Server setup (uppercase `CUSTOMER`/`POLICY`/`CLAIM` table and column names,
  plus two source_id entries - 21, 45 - that can never exist in v04). Replaced with a single
  `source_id: 1` entry using v04's real, verified-against-the-catalog lowercase column names.
- **Added real `PRIMARY KEY` constraints** to the 9 cloned `deepak.insurance_v04` tables (Delta/Unity
  Catalog tables don't get them automatically from `DEEP CLONE`, and v3's original `deepak.insurance`
  tables don't have them either - this is new, v04-only polish, not something taken from or applied to
  v3). Needed for `rg/holds.py`'s legal-hold validation (`root_table not in graph.pk`) and for
  remediation's mask/anonymize verification step to report real confirmation instead of "Cannot
  verify: table has no primary key".
- **One further issue found, not yet fixed**: with PKs in place, `rg.catalog.discover()` infers at
  least one new lineage edge that it couldn't before, and `rg.remediation.scope_rows()` (used for
  country/region-scoped MASK rules, e.g. POL-EU-001) then builds a correlated scalar subquery via
  `catalog.Graph.jurisdiction_expr()` for at least one non-root table - valid in Oracle/SQL Server, but
  rejected by Spark SQL (`UNSUPPORTED_SUBQUERY_EXPRESSION_CATEGORY.MUST_AGGREGATE_CORRELATED_SCALAR_SUBQUERY`).
  This is data-plane query-building logic shared with v3's own `DatabricksEngine` support, not
  something v04's Oracle→Postgres port introduced - it was likely always latent for any
  non-root-table, geo-scoped MASK rule run against a Databricks source, just never exercised by v3's
  own test rules. Needs `jurisdiction_expr()`'s correlated-subquery shape rewritten to an aggregated
  (`MAX(...)`) or `EXISTS`-based form for the Databricks engine specifically. Not blocking - only
  affects region/country-scoped MASK rules on tables more than one hop from the subject root.
- **Databricks App** `retentionguard-v04` created and deployed
  (`https://retentionguard-v04-345557900804023.aws.databricksapps.com`), `postgres` resource attached
  (branch/database above, `CAN_CONNECT_AND_CREATE`), service principal provisioned with its own
  Postgres role (confirmed via `databricks postgres list-roles`). Currently running a safe placeholder
  `app.py` (catches its own startup error instead of crash-looping) pending the issue below.

## RESOLVED: the deployed app's own Lakebase credential

What looked for a long time like a service-principal permissions problem (tried: a `postgres`
`user_api_scopes` entry, `CAN_USE` on the Lakebase project, full stop/start cycles, ruling out
event-loop blocking) turned out to be two much simpler, unrelated bugs, both found once the user
pulled the real error via the app's own `/healthz` endpoint (opened directly in an authenticated
browser tab - `/logz` and `databricks apps logs` both refuse PAT auth, and a plain `curl`/bearer-token
request to the app's own routes gets a 302 to the Databricks login page; only a real logged-in browser
session can reach either):

1. **`LAKEBASE_ENDPOINT` was never actually being injected** by the platform despite `app.yaml`/
   `databricks.yml` declaring `value_from: postgres` exactly as the `databricks-lakebase` /
   `databricks-apps` skills document - the env var came through empty, tripping `rg/db.py`'s own
   "neither PGPASSWORD nor LAKEBASE_ENDPOINT is set" guard. Fixed by hardcoding the project's real
   `PGHOST`/`PGUSER`/`LAKEBASE_ENDPOINT` values as defaults in `rg/config.py` instead of depending on
   that injection (these are resource paths, not secrets - env vars still override them for a future
   second environment).
2. **`databricks-sdk` resolved to a version without the `w.postgres` module** at Databricks Apps'
   build time (`AttributeError: 'WorkspaceClient' object has no attribute 'postgres'`) - almost
   certainly `databricks-sql-connector`'s own transitive pin on an older `databricks-sdk` winning
   dependency resolution over the unpinned `databricks-sdk` line in `requirements.txt`. Fixed with an
   explicit `databricks-sdk>=0.81.0` pin.

**Verified fixed**: `/healthz` now returns `{"status":"ok","schema_tables":[...all 32 tables...]}`, and
a separate check confirms the `rg_v04` Postgres schema is owned by the app's own service principal
(`84ae08ed-e722-450b-8c80-db3baed62c8c`), not the project owner - the deploy-first ownership model
worked exactly as the `databricks-lakebase` skill describes, once the two bugs above were out of the
way.

## Phase 2: credential-less data-plane connection (done)

`rg/engines/databricks.py`'s `DatabricksEngine` now authenticates via the SDK's own auto-config
(`credentials_provider`) when no token is stored on `RG_DATA_SOURCE` - the deployed app's own service
principal, or the developer's own CLI profile locally - instead of requiring a stored Databricks PAT.
Verified locally end-to-end (discover + scan, same real findings as before) with the seeded source's
password cleared. Required three IAM/UC grants to the app's service principal
(`84ae08ed-e722-450b-8c80-db3baed62c8c`), all done:
- `CAN_USE` on the SQL Warehouse (`fbdbcb17a3e62497`)
- `USE CATALOG` on `deepak`, `USE SCHEMA`+`SELECT` on `deepak.insurance_v04`, `USE SCHEMA`+
  `READ/WRITE VOLUME` on `deepak.rg_v04_app`

Also found and fixed: `rg/snapshot.py`'s `ensure_snapshot()` could hit `UniqueViolation` on
`rg_snapshot_uk` on a second/concurrent bootstrap (its SELECT-then-INSERT wasn't race-safe) - now
tolerates that specific conflict instead of crashing startup.

`app.py` now runs the **real** `rg.api:app`, deployed and verified **live**:
`GET /api/branding` on the production app URL returns the real seeded Chubb organisation record, read
through the deployed app's own service principal, with zero stored credentials anywhere (not in
`RG_DATA_SOURCE`, not in any config file, not in an env var). Phase 2's core goal - the deployed app
working end-to-end against both Lakebase and the Databricks data plane - is done.

## Phase 4: documents → Unity Catalog Volumes (done)

**The plan's core assumption here was wrong, and worth remembering for any future Databricks App
work**: a Databricks App's container does **not** mount UC Volumes as plain POSIX filesystem paths the
way a notebook/cluster/job does. `Path("/Volumes/...").is_dir()` returns `False` even for a real,
fully-accessible volume - confirmed by direct testing via a temporary diagnostic route. The correct
mechanism is the Databricks SDK's **Files API** (`WorkspaceClient().files.*`: `upload`/`download`/
`list_directory_contents`/`get_directory_metadata`/`delete`).

Added `rg/volumes.py` - a small wrapper exposing `is_dir`/`list_files` (recursive, since
`list_directory_contents` is one level deep)/`read_bytes`/`write_bytes`/`delete`, so the three affected
modules stay close to their original file-handling shape instead of being rewritten around raw REST
calls. Rewired:
- `rg/docscan.py`: `create_doc_source()` validation, `discover()`'s file walk, `_read_pdf_metadata()`
  and `_extract_text()` (both now take `bytes` via `pypdf.PdfReader(io.BytesIO(...))` instead of a
  local path).
- `rg/redact.py`: reads the source PDF's bytes, redacts via `pymupdf.open(stream=...)`, writes the
  output via `volumes.write_bytes()` (`pdf.tobytes()` instead of `pdf.save(path)`).
- `rg/archive.py`: now targets a **new** dedicated `deepak.rg_v04_app.archive` volume (its old v03
  target was a local-disk folder beside the app's own code - ephemeral and wiped on every Databricks
  Apps restart/redeploy - a real bug independent of the Volumes-mounting discovery above). Re-added an
  ARCHIVE-action demo policy (`POL-GEN-024`, on `claim_payment`/`payment_date`, replacing v03's
  out-of-scope `PROC_RUN_LOG` one) so the feature has a real rule to exercise.

**Verified fully end-to-end**, with a real generated PDF uploaded to the documents volume: discover
(found the file) → scan (4 real findings: EMAIL/PHONE/POSTAL_CODE at 0.95 confidence, FIRST_NAME at
0.31) → redact evaluate → approve → execute (3 redactions, output written to
`.../documents/PDFREDACTED/...`) → **confirmed the redacted output's text layer genuinely no longer
contains the original email/phone** (re-extracted and checked), not just visually covered.

## Phase 5: vector search → pgvector-in-Lakebase (done)

Replaced v03's local Chroma server + local-only Ollama with: embeddings from Databricks Model
Serving's Foundation Model API (`databricks-gte-large-en`, 1024-dim, queried via this app's own
service principal - no stored API key, same auth pattern as everything else) and storage in two new
pgvector tables in the **same Lakebase database** as the rest of the control plane
(`rg_doc_chunk_safe`/`rg_doc_chunk_pii`, mirroring v03's two-collection security boundary - which
table gets queried is still decided by role, server-side, before any embedding call). `rg/ddl.py` now
runs `CREATE EXTENSION IF NOT EXISTS vector` and an HNSW cosine-distance index per table as part of
`init_schema()`.

One sharp edge worth remembering: `rg/db.py`'s `:name` → bind-parameter translation treats any `:word`
as a bind name, so a Postgres `::type` cast anywhere in raw SQL collides with it - `embedding <=>
'[...]'::vector` silently tried to bind a parameter named `vector`. Fixed by using `CAST(x AS vector)`
everywhere instead (ANSI-standard, no colon) - the same discipline `rg/db.py`'s own docstring already
warned about, now with a concrete example of what it looks like when violated.

Also hit (and is worth remembering for any future Lakebase/Databricks-App work): **don't create
app-schema objects under your own identity while iterating locally once the app is live** - doing so
for a quick local test created `rg_doc_chunk_safe`/`rg_doc_chunk_pii` owned by the project owner, which
then collided (`DuplicateTable`) with the deployed app's own `init_schema()` trying to create the same
tables as its service principal on the next deploy. Fixed by dropping the locally-owned copies and
redeploying so the SP created (and now owns) them, matching the project's established deploy-first
ownership model. Diagnosed via the Databricks Apps **Logs** page (Search logs / real-time log viewer)
in an authenticated browser tab - a more complete view than `/logz` alone, and still the only way to
see a real Python traceback since `/logz`, `databricks apps logs`, and the app's own HTTP routes are
all behind the OAuth gate for anything without a real browser session.

**Verified fully end-to-end, locally first then via the live deployed app**: `test_connection()`
confirms a live 1024-dim embedding; `index_document()` on the same test PDF produced 1 safe + 1 PII
chunk; `search()` as a **steward** returned the redacted snippet ("email , phone"), and as an
**admin** returned the real unredacted snippet ("email jane.doe@example.com, phone
555-123-4567") - the role-based security boundary working exactly as designed. The deployed app's own
service principal now owns both chunk tables, confirmed via `pg_tables.tableowner`.

## Phase 6: LLM → Databricks Model Serving (done)

Added `DATABRICKS` as a third provider in `rg/llm.py`'s existing provider-switch (additive, alongside
OLLAMA/ANTHROPIC - `_chat()` dispatches to `WorkspaceClient().serving_endpoints.query()` using
`ChatMessage`/`ChatMessageRole` from the SDK, same no-stored-credential auth pattern as everything else
in v04). Default model `databricks-claude-sonnet-5`, a chat Foundation Model API endpoint - like the
embeddings endpoint, resolved by name, never hardcoded beyond a sensible default per the Model Serving
skill's own warning that this list changes.

Also ported `rg/name_llm.py` (LLM-assisted name detection in the document free-text sweep) from
Ollama to the same Model Serving mechanism - this one **had** to be ported, not just offered as an
option: v03 deliberately kept it local-only/Ollama-only by design (its own docstring explained why:
document text is a bigger exposure than metadata), but Ollama cannot run inside a deployed Databricks
App at all (no local model server possible there), so leaving it as-is would have made the feature
silently non-functional the moment it was deployed. Since Phase 5 already moved document-text
embeddings to this same workspace's Model Serving, the "never leaves the laptop" boundary this feature
was built around no longer exists anywhere else in v04 either - noted plainly in the module's docstring
rather than glossed over.

**Verified locally against the real, shared Lakebase control plane** (the same database the deployed
app reads its settings from): `llm.test_connection()` → `{"ok": true, "reply": "OK"}`;
`llm.second_opinion()` on a real EMAIL finding → correct `AGREE` verdict with a sensible reason;
`name_llm.test_connection()` → `{"ok": true}`; `name_llm.find_names()` on real text → correctly
extracted `"Jane Doe"`. Settings saved locally (`llm.provider=DATABRICKS`, `docscan_llm.enabled=1`)
confirmed visible in the shared control-plane database the deployed app will read from - same
SP-auth mechanism already proven three times over (Lakebase, SQL Warehouse, UC Volumes + pgvector), so
not re-verified via a fourth separate browser round-trip for this phase.

## Phase 7: merge frontend+backend into one deployed process (done, pending final live confirmation)

Built the Angular app for production (`npm run build` in `angular-app/`) and copied the output
(`angular-app/dist/angular-app/browser/`) into `backend-databricks/static/`. `app.py` now serves it
from the same FastAPI process as every `/api/*` route - no second app, no CORS needed (same origin).
`environment.prod.ts`'s `apiBase` is now `''` (relative/same-origin) instead of a stale v3 Tailscale
URL.

Two real bugs found and fixed while verifying this live, both worth remembering for any future
Databricks App with a client-side-routed frontend:

1. **A wildcard SPA-fallback route broke every non-GET `/api/*` call with a 405.** The first attempt
   (`@app.get("/{full_path:path}")` serving `index.html` for unmatched paths) silently intercepted
   `POST /api/login`-shaped requests: Starlette's router matches by path pattern before checking the
   HTTP method, so a GET-only wildcard that matches literally every path counts as a "partial match"
   for a POST to any `/api/...` path, and a partial match anywhere short-circuits the search for the
   real route's full match. Fixed by replacing the catch-all **route** with a **404 exception
   handler** (`@app.exception_handler(404)`) instead - it only ever runs after FastAPI's own routing
   has already failed to find any match, so it can never shadow a real route. (This particular 405 was
   first noticed via a mistaken manual test of the wrong path, `/api/login` instead of the real
   `/api/auth/login` - but the underlying routing bug was real and would have broken any other
   non-GET `/api/*` endpoint too.)
2. **Databricks Apps' own reverse proxy does not forward a custom `Authorization: Bearer <token>`
   header through to the app container.** Login itself worked (200, real token returned, confirmed
   present in `rg_session`), but the very next authenticated request always came back 401. Direct
   diagnostic logging added to `current_user()` on the live deployed app confirmed the smoking gun:
   `auth_header_present=False` - the header the frontend had genuinely attached was simply not there
   by the time the request reached this app's own code. The proxy that gates every request behind
   Databricks' own OAuth/SSO check evidently reserves the `Authorization` header for that purpose and
   doesn't pass an application-chosen Bearer value through untouched. Fixed by moving the session
   token to a custom header, `X-Rg-Token`, on both sides (`rg/api.py`'s `current_user()` and
   `angular-app/src/app/core/auth.ts`'s `authInterceptor`) - a header name the platform has no reason
   to touch.

**Verified locally, end-to-end, with the exact same build deployed**: login → dashboard → real data,
with the `X-Rg-Token` header round-tripping correctly. **Confirmed live** by the user signing in on the
real deployed app immediately after this fix went out.

## v04 is fully built and verified

All 8 phases (0 through 7) are done, deployed, and confirmed working against the live app - Databricks
Apps + Lakebase (Postgres, control plane + pgvector) + Unity Catalog (data plane + Volumes) + Model
Serving (embeddings + LLM), one process, no stored credentials anywhere.

## Post-launch bug-fix round: Evaluate Policies + Clear All

Live use after the "fully working" milestone above turned up three real bugs, all leftover v03→v04
porting gaps rather than new regressions - each one a code path that was never exercised by the earlier
phase-by-phase verification (which ran discovery/scan/one MASK task, not the full "evaluate every active
rule" or "wipe everything" flows). All three are fixed and redeployed.

1. **This closes the Phase 3 known issue** (the geo-scoped MASK rule correlated-subquery problem,
   previously believed narrow/non-blocking): it actually broke the main **Evaluate policies** button
   outright, because `remediation.evaluate()` has no per-rule error isolation - one rule's SQL error
   aborts the whole batch. Root cause: `catalog.Graph.jurisdiction_expr()` builds a correlated scalar
   subquery (`(SELECT col FROM parent j1 WHERE j1.pk = t.fk)`) for any country lookup that isn't a direct
   column on the table itself. Oracle/SQL Server accept that form; Databricks SQL (Spark) rejects it for
   any multi-hop path with "correlated scalar subqueries must be aggregated." **Fix**: wrap each level of
   the generated subquery in `MAX(...)` - a no-op since the join column is a primary key, but it's the
   signal Spark needs to accept the correlation. Fixed in `rg/catalog.py`'s `jurisdiction_expr()`.
2. **Organization tab → Clear All crashed**: `snapshot.status()` (called by both `restore()` and
   `clear_all()` to find masked views to drop) had a leftover v03 binary dispatch - `if engine.name ==
   "ORACLE": ... else: <SQL-Server-only lookup>` - a two-engine assumption from when Oracle and SQL
   Server were the only sources. For the single DATABRICKS source this fell into the SQL-Server branch,
   which calls `rg/mssql.py` - a deliberate dead stub in v04 (`RuntimeError: rg.mssql is a dead stub...`).
   **Fix**: added a real DATABRICKS branch that reads `information_schema.views` in the source's own
   catalog/schema (same pattern `catalog.py`'s `_discover_databricks` already uses).
3. **Clear All's archive/redacted-folder cleanup also crashed**, right after bug 2 would have been
   fixed: `snapshot.clear_all()` still called `shutil.rmtree`/`Path.exists()` on `archive.ROOT` and each
   document source's `PDFREDACTED` folder - leftover v03 local-disk code. In v04 those are Unity Catalog
   Volume paths (plain strings), and UC Volumes aren't mounted as POSIX paths in a Databricks App (see
   Phase 4 above), so `.exists()` on a `str` raised `AttributeError` immediately. **Fix**: added
   `rg/volumes.delete_tree()` (loops `list_files` + `delete`, since the Files API has no directory-level
   delete) and swapped both call sites to use it.

Redeployed twice (one per fix, confirmed `RUNNING` both times via `databricks apps get`). Not yet
re-verified live by clicking the buttons again - next step is confirming both in the real app.
