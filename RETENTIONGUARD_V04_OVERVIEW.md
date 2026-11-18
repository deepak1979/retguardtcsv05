# RetentionGuard v04 — Product & Technical Overview

*Prepared for cross-project knowledge sharing (e.g. RFP compatibility analysis). Reflects the state of the `ui-compare-v04` build as of November 2026.*

## 1. What it is

RetentionGuard is a **data governance product**: it discovers sensitive data across an organisation's systems, classifies it, and enforces policy-driven protection (masking/anonymisation), retention and erasure — with full audit evidence for every action.

v04 is a from-scratch rebuild of an earlier local prototype (v03), re-architected to run **natively and entirely inside Databricks**, with no infrastructure or dependency outside the lakehouse.

## 2. Core capabilities

- **Discovery & cataloging** — reads a data source's own metadata (tables, columns, types, primary/foreign keys, inferred lineage) into an internal catalog. Reconciles with a platform's native column tagging (e.g. Unity Catalog classification tags) where available.
- **Classification** — pattern, dictionary and name-based PII/PHI detection with confidence scoring. Classifier logic can push down into the native compute engine (runs as SQL on Databricks) instead of pulling raw values back to the app.
- **Policy engine** — policies and rules scoped **Global / Region / Country**, with an override hierarchy (a country-level policy can replace or extend a broader one). Actions: `MASK` (partial, hash, tokenize or full — either as a non-destructive view or destructive in-place update), `ANONYMIZE`, `ARCHIVE` (export-then-delete, with a recoverable JSON export), and retention-driven `DELETE`.
- **Remediation lifecycle** — evaluate policies against findings → violations raised → remediation tasks proposed with a full dry-run SQL plan → human approval (admin) → execution → automatic post-execution verification. Every destructive action is preceded by an automatic table-level snapshot/backup, so a demo (or a real run) can be restored and replayed.
- **Legal holds** — exempt specific rows from retention/erasure actions; holds are respected everywhere a retention or erasure action would otherwise touch that data.
- **Erasure / subject-rights requests** — DSAR-style erasure that walks the foreign-key/lineage graph to find and remove (or report) every row belonging to a subject across related tables. Also purges that subject's footprint from document governance: their source/redacted PDFs in the Unity Catalog Volume, and every embedded chunk belonging to them in **both** pgvector semantic-search tables (safe and PII) — so an erased subject leaves no residual trace in the vector index either, not just the relational tables.
- **Document governance** — discovers PDF documents in a folder/volume, scans both metadata fields and free-text body for PII (not just discrete columns), and performs **genuine text-layer redaction** (content is actually removed, not painted over) with a tracked redaction-batch history.
- **Semantic search** — natural-language search over classified documents, backed by vector embeddings, with role-gated results (a non-privileged role never sees PII-bearing search results, only the redacted/safe index).
- **LLM "second opinion"** — an on-demand LLM review of a classifier's finding, to help a reviewer confirm or dispute a flagged column/field.
- **Multi-domain support** — fully independent business domains (currently **Insurance** and **Banking**) with their own data sources, catalogs and findings, switchable from the UI.
- **Multi-tenant branding** — multiple "companies" can be configured (logo, banner colour, accent colour) and switched live, useful for running the same instance as a demo for different prospective customers.
- **Role-based access** — `admin` / `steward` / `viewer` roles control who can edit policies, approve/execute remediation, or only view.
- **Full audit trail** — every create/update/delete/login/execute/evaluate action is logged with who, what and when.

## 3. Architecture & tech stack

| Layer | Technology |
|---|---|
| Frontend | Angular 22 SPA |
| Backend | FastAPI (Python), single process serves both the UI (static build) and the REST API |
| Control plane (app state) | **Lakebase** — Databricks' managed Postgres (Postgres Autoscaling). Holds users, sessions, policies, findings, violations, remediation tasks, audit log, and pgvector embeddings for semantic search |
| Data plane (governed business data) | **Unity Catalog + Delta**, queried through a Databricks **SQL Warehouse** |
| Documents | **Unity Catalog Volumes**, accessed via the Databricks SDK's Files API (not a mounted filesystem) |
| Vector search | `pgvector` extension inside the same Lakebase Postgres database — no separate vector database |
| LLM / embeddings | **Databricks Model Serving** (Foundation Model APIs) — no external AI vendor dependency |
| Deployment | One **Databricks App** (single process, platform-managed compute) with its own auto-provisioned service principal |
| Demo/test data refresh | An optional, reusable **Databricks Job** that clones/refreshes demo tables from a source schema, safe to re-run (skips tables already present) |

### Why this matters for compatibility analysis
- **No external dependencies**: no Oracle/SQL Server/Snowflake, no external vector database, no external LLM API key required (though one can still be configured as an alternative provider).
- **Single deployable unit**: one Databricks App, one URL, one process — not a multi-service deployment to orchestrate.
- **Everything is Delta/Unity-Catalog-native** on the data-plane side, so it sits directly on data already governed by a Databricks lakehouse, with no ingestion/ETL step needed to bring data "into" the tool.

## 4. Security & access model

Access works in two independent layers, with **no credential sharing**:

1. **Databricks sign-in gate** — a person is invited as their own identity into the Databricks account/workspace (by email), then granted `CAN_USE` on just this one app — nothing else in the workspace. This is the only account-admin action required; it's account-wide (there's no way to invite "for one app only"), but what they can actually reach *is* scoped to the app.
2. **RetentionGuard's own sign-in** — a separate username/password/role, created via an admin-only API endpoint. The app always reaches the underlying data using its **own service-principal identity**, never the signed-in viewer's Databricks permissions — so a person's Databricks access level has no bearing on what data they can see inside the app. That's governed entirely by their RetentionGuard role (`admin` / `steward` / `viewer`).

Zero credentials are stored for the primary data source — Unity Catalog, Lakebase and Model Serving are all reached via the app's own service-principal, OAuth-based, credential-less authentication. (A dynamically-added *secondary* data source, added through the "Add a data source" UI, does store a plain-text access token for that one connection — documented as a demo-only caveat, not hardened for production use.)

## 5. Portability (moving to a new workspace)

Nothing is hard-coded to a specific workspace. Catalog name, schema, SQL Warehouse, Lakebase project and endpoint, and Volume paths are all configuration values (environment variables), never baked into application code. Porting to a brand-new, separate Databricks workspace is a bounded, scriptable checklist:

1. Provision the resources (a Unity Catalog catalog + schema, a Lakebase Postgres project, a SQL Warehouse, three UC Volumes)
2. Deploy the Databricks App (it scaffolds its own service principal automatically)
3. Grant that service principal a handful of UC privileges (`SELECT`, `MODIFY`, `CREATE TABLE` on the schema; `READ VOLUME`/`WRITE VOLUME`)
4. Point configuration at the new workspace's resource names
5. Load/migrate the source data
6. Let the app bootstrap its own 30+ control-plane tables and seed policies on first start

Every step above is a well-defined CLI/SQL/config operation — the kind of task that was in fact carried out end-to-end by an AI coding agent (Claude Code) during this project, including the original build, several rounds of live bug fixes, two full data-domain migrations (adding Banking alongside Insurance), and workspace permission/user management.

## 6. Current data sources configured (this instance)

| Domain | Catalog.Schema | Notes |
|---|---|---|
| Insurance | `deepak.insurance_v04` | 14 tables (customer, policy, claim, claim_payment, agent, actuarial/commission/marketing tables, etc.) |
| Banking | `bank.banking_v04` | 13 tables (account, customer, card, loan, loan_payment, beneficiary, branch, relationship_manager, etc.) |
| Documents | UC Volumes (`.../rg_v04_app/documents`, `/redacted`, `/archive`) | PDF case-file documents |

Deployed app URL: `https://retentionguard-v04-345557900804023.aws.databricksapps.com`

## 7. Known limitations / maturity notes (read before an RFP compatibility claim)

- **PoC / demo maturity, not a hardened production product.** No formal compliance certification (SOC2, ISO 27001, etc.) has been pursued — this is an internal proof of concept.
- **Databricks-only data plane.** Earlier versions supported Oracle, SQL Server and Snowflake as secondary engines; v04 intentionally dropped that in favour of being fully Databricks-native. A target environment not already on Databricks would need its data migrated or federated in first.
- **Dynamically-added secondary data sources** (via the UI's "Add a data source" flow) store their access token in plain text in the control-plane database — acceptable for a demo, not for production without adding encryption-at-rest or a secrets-manager integration.
- **No enterprise identity sync.** RetentionGuard's own user accounts (username/password/role) are created manually (currently via a direct API call); there's no SCIM/SSO provisioning into the app's own user table. The Databricks-level access gate does use real workspace/account identity, but that's a separate system from the app's own login.
- **Single SQL Warehouse / single Lakebase project dependency** per deployment — no documented high-availability or multi-region failover story.
- **Document governance is PDF-only** today.
- **Row-level security is purpose-built** (country/region jurisdiction masking), not a general-purpose RLS engine — it won't out-of-the-box express arbitrary row-level policies unrelated to geography.

## 8. Supporting artifacts

- `RETENTIONGUARD_V4_STATUS.md` — full build/phase log and every bug found and fixed, in this same repo
- `RetentionGuard_v04_Architecture.pptx` — a 10-slide deck covering the v03→v04 journey, both architectures, the local→Databricks tech mapping, portability, access model, and sign-in steps
