"""Semantic (vector) search over document text, with role-gated access to PII.

Two parallel pgvector tables, not one index filtered at display time:
  rg_doc_chunk_safe   embedded from the REDACTED PDF (PDFREDACTED/) - every authenticated role can
                       search this. As safe as whatever redact.py's last execute() actually removed;
                       this module does not re-decide what counts as PII, it reuses that output.
  rg_doc_chunk_pii     embedded from the ORIGINAL, unredacted PDF - only ever queried for an admin.

The role check decides WHICH TABLE GETS QUERIED AT ALL, server-side, before any embedding call - not
"search everything, then hide bits of the response". A steward or viewer's request never touches
rg_doc_chunk_pii, so there is no response-shaping bug that could leak a PII snippet to the wrong role;
the enforcement boundary is structural, the same way llm.ensure_enabled() stops every LLM entry point
before a client is built, rather than filtering what a client returns.

v04: both the vector store (pgvector, in the same Lakebase database as the rest of the control plane)
and the embedding model (Databricks Model Serving's Foundation Model API, queried via this app's own
service principal - no stored API key, same auth story as rg/engines/databricks.py) are Databricks-
native, replacing v03's local Chroma server + local-only Ollama. The document text these embed can
include real PII (the PII table embeds the ORIGINAL unredacted text) - this now travels to this
workspace's own Model Serving endpoint rather than staying strictly on the laptop the way v03's
"Ollama, loopback only" design guaranteed; that trust boundary moved from "this machine" to "this
Databricks workspace", matching how every other data-plane read in this app already works.

Indexing requires the document to already have an EXECUTED redaction task (rg/redact.py) - this module
is a read-time capability layered on top of that pipeline, not a parallel PII-detection pass. If the
underlying redacted file is re-generated later (a steward confirms a finding, redaction re-runs), the
old chunks are stale; index_status() reports that by comparing the indexed redaction_task_id against the
document's current latest EXECUTED one, so the UI can prompt a re-index rather than silently serving
chunks embedded from since-superseded text.
"""
from __future__ import annotations

import re

from . import db, docscan, volumes
from .common import audit
from .policy import ValidationError

TABLE_SAFE = "rg_doc_chunk_safe"
TABLE_PII = "rg_doc_chunk_pii"
CHUNK_CHARS = 800
CHUNK_OVERLAP = 100
# Confirmed by a real query against this workspace: 1024-dim. Any other Foundation Model API embedding
# endpoint must match this dimension (rg_doc_chunk_safe/_pii's VECTOR(1024) columns are fixed at create
# time) or the table needs recreating - never just swap the model name in isolation.
EMBED_ENDPOINT = "databricks-gte-large-en"

DEFAULTS = {
    "vectorsearch.enabled": "0",
    "vectorsearch.embed_endpoint": EMBED_ENDPOINT,
}


class VectorSearchOff(ValidationError):
    """The switch is off, or the caller's role cannot reach the table it asked for."""


class VectorSearchError(RuntimeError):
    """The Model Serving endpoint could not be reached or did not answer usably."""


# --------------------------------------------------------------------------- settings (RG_SETTING, vectorsearch.*)
def _get_all() -> dict[str, str]:
    have = {r["setting_key"]: r["setting_value"]
            for r in db.query("SELECT setting_key, setting_value FROM RG_SETTING WHERE setting_key LIKE 'vectorsearch.%'")}
    return {**DEFAULTS, **have}


def _put(key: str, value: str, username: str) -> None:
    n = db.execute("UPDATE RG_SETTING SET setting_value = :v, updated_by = :u, updated_at = now() WHERE setting_key = :k",
                   {"v": value, "u": username, "k": key})
    if not n:
        db.execute("INSERT INTO RG_SETTING (setting_key, setting_value, updated_by) VALUES (:k, :v, :u)", {"k": key, "v": value, "u": username})


def get_settings() -> dict:
    s = _get_all()
    return {"enabled": s["vectorsearch.enabled"] == "1", "embed_endpoint": s["vectorsearch.embed_endpoint"]}


def enabled() -> bool:
    return _get_all()["vectorsearch.enabled"] == "1"


def ensure_enabled() -> dict:
    st = get_settings()
    if not st["enabled"]:
        raise VectorSearchOff("Semantic search is switched off. No document text is embedded or searched.")
    return st


def save_settings(d: dict, username: str) -> dict:
    cur = get_settings()
    new = {**{k: cur[k] for k in ("enabled", "embed_endpoint")}, **{k: v for k, v in d.items() if v is not None}}
    endpoint = str(new["embed_endpoint"]).strip()
    if not endpoint or len(endpoint) > 100:
        raise ValidationError("Enter the Model Serving endpoint name")
    changes = []
    for key, val in (("enabled", "1" if new["enabled"] else "0"), ("embed_endpoint", endpoint)):
        if _get_all()[f"vectorsearch.{key}"] != val:
            _put(f"vectorsearch.{key}", val, username)
            changes.append(f"{key}={val}")
    if changes:
        audit(username, "vectorsearch", None, "SETTING", ", ".join(changes)[:490])
    return get_settings()


def test_connection(username: str) -> dict:
    st = ensure_enabled()
    vec = _embed(st, "connection test")
    audit(username, "vectorsearch", None, "TEST", f"{st['embed_endpoint']} -> {len(vec)}-dim vector")
    return {"ok": True, "embed_endpoint": st["embed_endpoint"], "dimensions": len(vec)}


# --------------------------------------------------------------------------- embeddings (Databricks Model Serving)
def _embed(st: dict, text: str) -> list[float]:
    from databricks.sdk import WorkspaceClient
    from databricks.sdk.errors import DatabricksError
    try:
        r = WorkspaceClient().serving_endpoints.query(name=st["embed_endpoint"], input=[text])
        vec = r.data[0].embedding
        if not vec:
            raise VectorSearchError("The endpoint returned no embedding")
        return vec
    except VectorSearchError:
        raise
    except DatabricksError as e:
        raise VectorSearchError(f"Model Serving endpoint '{st['embed_endpoint']}' error: {e}")


def _vec_literal(vec: list[float]) -> str:
    return "[" + ",".join(repr(float(x)) for x in vec) + "]"


# --------------------------------------------------------------------------- chunking
def _chunks(text: str) -> list[str]:
    text = re.sub(r"[ \t]+", " ", text).strip()
    if not text:
        return []
    if len(text) <= CHUNK_CHARS:
        return [text]
    out, i = [], 0
    while i < len(text):
        out.append(text[i:i + CHUNK_CHARS])
        i += CHUNK_CHARS - CHUNK_OVERLAP
    return out


# --------------------------------------------------------------------------- indexing
def _latest_executed_task(document_id: int) -> dict | None:
    return db.query_one(
        "SELECT * FROM RG_DOC_REDACTION_TASK WHERE document_id = :d AND status = 'EXECUTED' "
        "ORDER BY executed_at DESC FETCH FIRST 1 ROWS ONLY", {"d": document_id})


def index_status(doc_source_id: int | None = None) -> list[dict]:
    """One row per document that has at least one findable (AUTO/CONFIRMED) finding - whether indexed,
    never indexed, or STALE (redacted again since it was last indexed).

    Excludes a document whose own file_path sits inside a PDFREDACTED/ folder: docscan.discover() walks
    a source folder recursively, which also picks up redact.py's own output files as if they were
    newly-discovered source PDFs - a pre-existing issue in discovery, not something this module
    introduces or fixes, but indexing one of those phantom copies would be indexing an already-redacted
    file's redacted copy, which is never useful - so they are filtered out here defensively."""
    sql = ["SELECT d.document_id, d.file_name, d.doc_source_id, "
          "(SELECT MAX(t.redaction_task_id) FROM RG_DOC_REDACTION_TASK t "
          " WHERE t.document_id = d.document_id AND t.status = 'EXECUTED') AS latest_task_id, "
          "ix.status AS index_status, ix.redaction_task_id AS indexed_task_id, "
          "ix.safe_chunk_count, ix.pii_chunk_count, ix.indexed_at, ix.message "
          "FROM RG_DOCUMENT d "
          "LEFT JOIN RG_DOC_INDEX_STATUS ix ON ix.document_id = d.document_id "
          "WHERE EXISTS (SELECT 1 FROM RG_DOC_FINDING f WHERE f.document_id = d.document_id AND f.status IN ('AUTO','CONFIRMED')) "
          "AND UPPER(d.file_path) NOT LIKE '%PDFREDACTED%'"]
    p: dict = {}
    if doc_source_id:
        sql.append("AND d.doc_source_id = :s")
        p["s"] = doc_source_id
    sql.append("ORDER BY d.file_name")
    rows = db.query(" ".join(sql), p)
    out = []
    for r in rows:
        if r["latest_task_id"] is None:
            state = "NOT_REDACTED"
        elif r["index_status"] is None:
            state = "NOT_INDEXED"
        elif r["indexed_task_id"] != r["latest_task_id"]:
            state = "STALE"
        else:
            state = r["index_status"]
        out.append({**r, "state": state})
    return out


def index_document(document_id: int, username: str) -> dict:
    st = ensure_enabled()
    doc = db.query_one("SELECT * FROM RG_DOCUMENT WHERE document_id = :i", {"i": document_id})
    if not doc:
        raise ValueError(f"Document {document_id} not found")
    if "PDFREDACTED" in doc["file_path"].upper():
        raise ValidationError("This document record points at a redaction output file, not a source document - see index_status()'s docstring")
    task = _latest_executed_task(document_id)
    if not task:
        raise ValidationError("Run redaction for this document first (Redaction tab) - semantic search is built on its output")

    db.execute(f"DELETE FROM {TABLE_SAFE} WHERE document_id = :d", {"d": document_id})
    db.execute(f"DELETE FROM {TABLE_PII} WHERE document_id = :d", {"d": document_id})

    safe_text = docscan._extract_text(volumes.read_bytes(task["output_path"])) if task.get("output_path") else ""
    pii_text = docscan._extract_text(volumes.read_bytes(doc["file_path"]))

    def _upsert(table: str, text: str) -> int:
        chunks = _chunks(text)
        for i, chunk in enumerate(chunks):
            vec = _vec_literal(_embed(st, chunk))
            db.execute(
                f"INSERT INTO {table} (document_id, file_name, doc_source_id, redaction_task_id, "
                f"chunk_index, chunk_text, embedding) VALUES (:d, :f, :s, :rt, :ci, :txt, CAST('{vec}' AS vector))",
                {"d": document_id, "f": doc["file_name"], "s": doc["doc_source_id"],
                 "rt": task["redaction_task_id"], "ci": i, "txt": chunk})
        return len(chunks)

    try:
        safe_n = _upsert(TABLE_SAFE, safe_text)
        pii_n = _upsert(TABLE_PII, pii_text)
    except VectorSearchError as e:
        db.execute("INSERT INTO RG_DOC_INDEX_STATUS (document_id, status, message, indexed_by, indexed_at) "
                  "VALUES (:d, 'FAILED', :m, :u, now()) "
                  "ON CONFLICT (document_id) DO UPDATE SET status = 'FAILED', message = EXCLUDED.message, "
                  "indexed_by = EXCLUDED.indexed_by, indexed_at = EXCLUDED.indexed_at",
                  {"d": document_id, "m": str(e)[:490], "u": username})
        raise

    db.execute(
        "INSERT INTO RG_DOC_INDEX_STATUS (document_id, status, redaction_task_id, safe_chunk_count, pii_chunk_count, indexed_by, indexed_at) "
        "VALUES (:d, 'INDEXED', :rt, :sc, :pc, :u, now()) "
        "ON CONFLICT (document_id) DO UPDATE SET status = 'INDEXED', redaction_task_id = EXCLUDED.redaction_task_id, "
        "safe_chunk_count = EXCLUDED.safe_chunk_count, pii_chunk_count = EXCLUDED.pii_chunk_count, "
        "message = NULL, indexed_by = EXCLUDED.indexed_by, indexed_at = EXCLUDED.indexed_at",
        {"d": document_id, "rt": task["redaction_task_id"], "sc": safe_n, "pc": pii_n, "u": username})
    audit(username, "vectorsearch", document_id, "INDEXED", f"{doc['file_name']}: {safe_n} safe chunk(s), {pii_n} PII chunk(s)")
    return {"document_id": document_id, "safe_chunks": safe_n, "pii_chunks": pii_n}


# --------------------------------------------------------------------------- search
def search(query: str, username: str, role: str, doc_source_id: int | None = None, top_k: int = 8) -> list[dict]:
    st = ensure_enabled()
    query = (query or "").strip()
    if not query:
        return []
    qvec = _vec_literal(_embed(st, query))

    def _run(table: str, tag: str) -> list[dict]:
        sql = [f"SELECT document_id, file_name, doc_source_id, chunk_index, chunk_text, "
              f"1 - (embedding <=> CAST('{qvec}' AS vector)) AS score FROM {table} WHERE 1=1"]
        p: dict = {}
        if doc_source_id:
            sql.append("AND doc_source_id = :s")
            p["s"] = doc_source_id
        sql.append(f"ORDER BY embedding <=> CAST('{qvec}' AS vector) FETCH FIRST :n ROWS ONLY")
        p["n"] = top_k
        rows = db.query(" ".join(sql), p)
        return [{"document_id": r["document_id"], "file_name": r["file_name"], "doc_source_id": r["doc_source_id"],
                "chunk_index": r["chunk_index"], "snippet": r["chunk_text"][:400],
                "score": round(r["score"], 4), "source": tag} for r in rows]

    results: list[dict] = []
    if role == "admin":
        # An admin is allowed to see everything unredacted, so only the PII table is ever queried for
        # them - never a mix. Searching both and merging after the fact doesn't work: the two tables
        # rank chunks independently (the redacted and unredacted text of the same chunk embed
        # differently), so a chunk can land in one table's top_k and not the other's.
        results.extend(_run(TABLE_PII, "pii"))
        audit(username, "vectorsearch", None, "PII_SEARCH", query[:480])
    else:
        results.extend(_run(TABLE_SAFE, "safe"))

    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:top_k]


# --------------------------------------------------------------------------- erasure's counterpart to index_document()
def delete_for_customer(customer_no: str, username: str) -> dict:
    """A GDPR erasure's document-side cleanup: removes every RG_DOCUMENT row, file in the UC Volume
    (original and any redacted copy), and embedded chunk (both tables) belonging to one customer.

    The link is the filename convention scripts/generate_customer_pdfs.py writes -
    "CUST_<customer_no>_..." - matched here, not a foreign key: RG_DOCUMENT has no column tying a file to
    a subject, so the filename is the only identity a document carries today. customer_no is the business
    number (e.g. "CU10000126"), not the numeric CUSTOMER_ID primary key, because more than one data
    source in this app has a CUSTOMER table - a raw numeric id could collide across sources where the
    business number realistically won't.

    Called from erasure.execute() AFTER its own transaction has already committed the relational
    DELETE/ANONYMIZE. Never raises: a storage hiccup here must not undo, or be mistaken for a failure
    of, an erasure that has already happened to the structured data.
    """
    customer_no = (customer_no or "").strip()
    if not customer_no:
        return {"documents_removed": 0}
    docs = db.query("SELECT document_id, file_name, file_path FROM RG_DOCUMENT WHERE UPPER(file_name) LIKE :p ESCAPE '\\'",
                    {"p": f"CUST\\_{customer_no.upper()}\\_%"})
    if not docs:
        return {"documents_removed": 0}

    chunks_removed = files_removed = 0
    for doc in docs:
        for table in (TABLE_SAFE, TABLE_PII):
            try:
                chunks_removed += db.execute(f"DELETE FROM {table} WHERE document_id = :d", {"d": doc["document_id"]})
            except Exception:  # noqa: BLE001 - one table failing must not skip the rest
                pass
        for row in db.query("SELECT output_path FROM RG_DOC_REDACTION_TASK WHERE document_id = :d AND output_path IS NOT NULL",
                            {"d": doc["document_id"]}):
            volumes.delete(row["output_path"])
            files_removed += 1
        volumes.delete(doc["file_path"])
        files_removed += 1
        db.execute("DELETE FROM RG_DOCUMENT WHERE document_id = :d", {"d": doc["document_id"]})

    audit(username, "vectorsearch", None, "ERASURE_PURGE",
          f"customer {customer_no}: {len(docs)} document(s), {chunks_removed} chunk(s), {files_removed} file(s) removed"[:490])
    return {"documents_removed": len(docs), "chunks_removed": chunks_removed, "files_removed": files_removed}


def clear_for_documents(document_ids: list[int]) -> dict:
    """Removes every embedded chunk (both tables) for the given RG_DOCUMENT ids - the vector-index
    counterpart to snapshot.clear_all()'s wipe of RG_DOCUMENT/RG_DOC_FINDING, called from there right
    before those rows are deleted, so a demo reset leaves no stale embeddings behind for a document whose
    catalog row is about to disappear."""
    if not document_ids:
        return {"chunks_removed": 0}
    removed = 0
    placeholders = ", ".join(f":id{i}" for i in range(len(document_ids)))
    params = {f"id{i}": v for i, v in enumerate(document_ids)}
    for table in (TABLE_SAFE, TABLE_PII):
        try:
            removed += db.execute(f"DELETE FROM {table} WHERE document_id IN ({placeholders})", params)
        except Exception:  # noqa: BLE001 - one table failing must not skip the rest of the reset
            pass
    return {"chunks_removed": removed}
