"""Document redaction - a separate lifecycle (PROPOSED -> APPROVED -> EXECUTED, its own tab) from the
Documents/scan pipeline in docscan.py, same split Remediation already has from Discovery/Findings for
database tables. The source PDF is NEVER modified: every execution opens it read-only and writes a NEW
file into a PDFREDACTED/ subfolder beside the registered folder, named the same as the source.

Redaction is done with PyMuPDF's add_redact_annot() + apply_redactions(), which genuinely strips the
text/graphics under the redacted area from the output - not a black box painted over text that is still
there underneath (the classic naive-redaction failure: a "redacted" PDF whose text layer still contains
the supposedly-removed content, extractable by anyone who selects/copies it). Verified by re-extracting
text from a redacted output and confirming the original string is gone, not just visually covered.

Only AUTO or CONFIRMED findings are ever redacted - a NEEDS_REVIEW or LOW finding is left alone until a
steward confirms it on the Findings page (same two-step trust boundary Remediation already applies via
approve() before execute()). What gets searched for and blacked out comes from docscan._raw_matches(),
the exact same matching pass that produced the finding in the first place - so "what Findings reported"
and "what got redacted" can never drift apart into two different sets of logic.

start_batch() ("Redact all") runs evaluate() + approve() + execute() for every eligible document in one
background job instead of one admin click per step per document - see its own docstring for why that
still goes through the same approve()/execute() functions and the same approved_by audit trail, not a
shortcut around either.
"""
from __future__ import annotations

import threading

import pymupdf

from . import db, docscan, volumes
from .common import audit
from .scanner import active_classifiers

REDACTED_SUBFOLDER = "PDFREDACTED"
ELIGIBLE_STATUSES = ("AUTO", "CONFIRMED")
_METADATA_KEYS = {"AUTHOR": "author", "TITLE": "title", "SUBJECT": "subject"}


def _redacted_folder(doc_source: dict) -> str:
    # No explicit mkdir needed on a UC Volume - upload() creates any missing parent path implicitly
    # (confirmed by direct testing), unlike a local filesystem.
    return f"{doc_source['folder_path']}/{REDACTED_SUBFOLDER}"


# --------------------------------------------------------------------------- propose
def eligible_documents(doc_source_id: int) -> list[dict]:
    """Documents with at least one AUTO/CONFIRMED finding, excluded only while a task for them is
    genuinely mid-flight (PROPOSED/APPROVED - don't propose a duplicate on top of one already pending).
    A document whose only task(s) reached a terminal state (EXECUTED/REJECTED/FAILED) is eligible again:
    confirming more findings after an EXECUTED redaction (e.g. a name a steward reviewed and confirmed
    on the Findings page after the first pass) is exactly the case where a second, more complete round
    should be proposable - it just overwrites the same PDFREDACTED output with a fresher one."""
    return db.query("""
        SELECT d.document_id, d.file_name, d.doc_source_id, COUNT(f.doc_finding_id) AS pending_findings
        FROM RG_DOCUMENT d JOIN RG_DOC_FINDING f ON f.document_id = d.document_id
        WHERE d.doc_source_id = :s AND f.status IN ('AUTO', 'CONFIRMED')
        AND d.document_id NOT IN (
            SELECT document_id FROM RG_DOC_REDACTION_TASK WHERE status IN ('PROPOSED', 'APPROVED')
        )
        GROUP BY d.document_id, d.file_name, d.doc_source_id
        ORDER BY d.file_name
    """, {"s": doc_source_id})


def evaluate(doc_source_id: int, username: str) -> dict:
    """Propose one redaction task per eligible document - mirrors remediation.evaluate()'s
    violation -> task flow, simplified: a document either has redactable PII or it doesn't, there's no
    separate 'violation' concept the way a RETAIN rule needs one to outrank."""
    docs = eligible_documents(doc_source_id)
    for d in docs:
        findings = db.query("SELECT DISTINCT data_element FROM RG_DOC_FINDING WHERE document_id = :i "
                           "AND status IN ('AUTO', 'CONFIRMED')", {"i": d["document_id"]})
        elements = sorted({f["data_element"] for f in findings})
        db.insert("RG_DOC_REDACTION_TASK", {
            "document_id": d["document_id"], "status": "PROPOSED",
            "element_summary": ", ".join(elements)[:490], "requested_by": username,
        }, "redaction_task_id")
    audit(username, "doc_redaction", None, "EVALUATE", f"{len(docs)} document(s) proposed for redaction")
    return {"proposed": len(docs)}


# --------------------------------------------------------------------------- tasks
def list_tasks(doc_source_id: int | None = None) -> list[dict]:
    sql = ["SELECT t.*, d.file_name, d.file_path, d.doc_source_id FROM RG_DOC_REDACTION_TASK t "
          "JOIN RG_DOCUMENT d ON d.document_id = t.document_id WHERE 1=1"]
    p: dict = {}
    if doc_source_id:
        sql.append("AND d.doc_source_id = :s")
        p["s"] = doc_source_id
    sql.append("ORDER BY t.redaction_task_id DESC")
    return db.query(" ".join(sql), p)


def get_task(task_id: int) -> dict | None:
    return db.query_one(
        "SELECT t.*, d.file_name, d.file_path, d.doc_source_id FROM RG_DOC_REDACTION_TASK t "
        "JOIN RG_DOCUMENT d ON d.document_id = t.document_id WHERE t.redaction_task_id = :i", {"i": task_id})


def approve(task_id: int, username: str) -> dict:
    t = get_task(task_id)
    if not t:
        raise ValueError(f"Redaction task {task_id} not found")
    if t["status"] != "PROPOSED":
        raise ValueError(f"Task is {t['status']}, only PROPOSED tasks can be approved")
    db.execute("UPDATE RG_DOC_REDACTION_TASK SET status = 'APPROVED', approved_by = :u, "
              "approved_at = now() WHERE redaction_task_id = :i", {"u": username, "i": task_id})
    audit(username, "doc_redaction", task_id, "APPROVED", t["file_name"])
    return get_task(task_id)


def reject(task_id: int, username: str, note: str = "") -> dict:
    t = get_task(task_id)
    if not t:
        raise ValueError(f"Redaction task {task_id} not found")
    if t["status"] not in ("PROPOSED", "APPROVED"):
        raise ValueError(f"Task is {t['status']} and cannot be rejected")
    db.execute("UPDATE RG_DOC_REDACTION_TASK SET status = 'REJECTED', approved_by = :u, note = :n "
              "WHERE redaction_task_id = :i", {"u": username, "n": note[:490], "i": task_id})
    audit(username, "doc_redaction", task_id, "REJECTED", t["file_name"])
    return get_task(task_id)


# --------------------------------------------------------------------------- execute
def execute(task_id: int, username: str) -> dict:
    t = get_task(task_id)
    if not t:
        raise ValueError(f"Redaction task {task_id} not found")
    if t["status"] != "APPROVED":
        raise ValueError("Only APPROVED tasks can be executed")

    src_path = t["file_path"]
    try:
        src_data = volumes.read_bytes(src_path)
    except Exception:
        db.execute("UPDATE RG_DOC_REDACTION_TASK SET status = 'FAILED', note = :n WHERE redaction_task_id = :i",
                  {"n": "Source file no longer exists at its registered path", "i": task_id})
        raise ValueError("Source file no longer exists")

    doc_source = db.query_one("SELECT * FROM RG_DOC_SOURCE WHERE doc_source_id = :i", {"i": t["doc_source_id"]})
    out_path = f"{_redacted_folder(doc_source)}/{src_path.rsplit('/', 1)[-1]}"

    findings = db.query("SELECT DISTINCT data_element FROM RG_DOC_FINDING WHERE document_id = :i "
                       "AND status IN ('AUTO', 'CONFIRMED')", {"i": t["document_id"]})
    wanted_codes = {f["data_element"] for f in findings}
    classifiers = [c for c in active_classifiers() if c["code"] in wanted_codes]
    meta_findings = {f["field_name"] for f in db.query(
        "SELECT field_name FROM RG_DOC_FINDING WHERE document_id = :i AND source = 'METADATA' "
        "AND status IN ('AUTO', 'CONFIRMED')", {"i": t["document_id"]})}

    try:
        total = _redact_pdf(src_data, out_path, classifiers, meta_findings)
    except Exception as e:  # noqa: BLE001 - must record the failure, same as remediation.execute()'s own try/except
        db.execute("UPDATE RG_DOC_REDACTION_TASK SET status = 'FAILED', note = :n WHERE redaction_task_id = :i",
                  {"n": str(e)[:490], "i": task_id})
        raise

    db.execute("UPDATE RG_DOC_REDACTION_TASK SET status = 'EXECUTED', executed_at = now(), "
              "output_path = :p, redaction_count = :c WHERE redaction_task_id = :i",
              {"p": out_path, "c": total, "i": task_id})
    audit(username, "doc_redaction", task_id, "EXECUTED", f"{t['file_name']} -> {out_path} ({total} redaction(s))")
    return get_task(task_id)


def _redact_pdf(src_data: bytes, out_path: str, classifiers: list[dict], meta_findings: set[str]) -> int:
    """Opens src_data read-only (never writes back to the source path), writes the redacted copy to
    out_path (a UC Volume path) and returns the number of individual text occurrences actually blacked
    out."""
    pdf = pymupdf.open(stream=src_data, filetype="pdf")
    total = 0
    for page in pdf:
        text = page.get_text()
        raw = docscan._raw_matches(text, classifiers)
        targets = {s for strings in raw.values() for s in strings if "\n" not in s}  # a match spanning a
        # line break (a loose classifier pattern's own artifact, not something to fix here) can't be
        # located by page.search_for(), which matches within a single line - skip it rather than error.
        for s in targets:
            for rect in page.search_for(s):
                page.add_redact_annot(rect, fill=(0, 0, 0))
                total += 1
        page.apply_redactions()

    meta = pdf.metadata or {}
    changed = False
    for code, key in _METADATA_KEYS.items():
        if code in meta_findings and meta.get(key):
            meta[key] = "[REDACTED]"
            changed = True
    if changed:
        pdf.set_metadata(meta)

    volumes.write_bytes(out_path, pdf.tobytes())
    pdf.close()
    return total


# --------------------------------------------------------------------------- batch ("Redact all")
def start_batch(doc_source_id: int, username: str) -> int:
    """Propose, approve and execute every eligible document for this source in one background job -
    the Redaction tab's "Redact all" button. Returns immediately with the new batch id; the UI polls
    list_batches() for progress and shows a toast on completion, same pattern as docscan.start_scan()/
    RG_DOC_SCAN_JOB. Requires the admin role (see api.py) because it performs the same approve() and
    execute() actions an admin would otherwise click one by one - the username passed in becomes
    approved_by on every task, exactly as if each had been approved individually."""
    src = db.query_one("SELECT * FROM RG_DOC_SOURCE WHERE doc_source_id = :i", {"i": doc_source_id})
    if not src:
        raise ValueError(f"Document source {doc_source_id} not found")
    batch_id = db.insert("RG_DOC_REDACTION_BATCH", {"doc_source_id": doc_source_id, "status": "QUEUED",
                                                     "requested_by": username}, "redaction_batch_id")
    audit(username, "doc_redaction_batch", batch_id, "BATCH_START", src["name"])
    threading.Thread(target=_run_batch, args=(batch_id, doc_source_id, username), daemon=True).start()
    return batch_id


def _run_batch(batch_id: int, doc_source_id: int, username: str) -> None:
    db.execute("UPDATE RG_DOC_REDACTION_BATCH SET status = 'RUNNING', started_at = now() "
              "WHERE redaction_batch_id = :i", {"i": batch_id})
    try:
        evaluate(doc_source_id, username)   # propose any eligible document not already proposed
        tasks = [t for t in list_tasks(doc_source_id) if t["status"] in ("PROPOSED", "APPROVED")]
        total = len(tasks)
        db.execute("UPDATE RG_DOC_REDACTION_BATCH SET documents_total = :n WHERE redaction_batch_id = :i",
                  {"n": total, "i": batch_id})

        done = failed = redactions = 0
        for t in tasks:
            try:
                if t["status"] == "PROPOSED":
                    approve(t["redaction_task_id"], username)
                res = execute(t["redaction_task_id"], username)
                redactions += res["redaction_count"] or 0
            except Exception:  # noqa: BLE001 - approve()/execute() already record the failure on the
                               # task itself (status FAILED, note set); one bad document must not stop
                               # the rest of the batch, same resilience _run_scan() already has per-document
                failed += 1
            done += 1
            db.execute("UPDATE RG_DOC_REDACTION_BATCH SET documents_done = :d, documents_failed = :f, "
                      "redactions_total = :r WHERE redaction_batch_id = :i",
                      {"d": done, "f": failed, "r": redactions, "i": batch_id})

        if total == 0:
            msg = "Nothing to redact"
        else:
            msg = f"{done - failed} document(s) redacted" + (f", {failed} failed" if failed else "")
        db.execute("UPDATE RG_DOC_REDACTION_BATCH SET status = 'COMPLETED', finished_at = now(), "
                  "message = :m WHERE redaction_batch_id = :i", {"m": msg, "i": batch_id})
        audit(username, "doc_redaction_batch", batch_id, "BATCH_DONE", msg)
    except Exception as e:  # noqa: BLE001 - background thread: record the failure, nothing to re-raise to
        db.execute("UPDATE RG_DOC_REDACTION_BATCH SET status = 'FAILED', finished_at = now(), "
                  "message = :m WHERE redaction_batch_id = :i", {"m": str(e)[:490], "i": batch_id})


def list_batches(doc_source_id: int | None = None, limit: int = 20) -> list[dict]:
    if doc_source_id:
        return db.query("SELECT * FROM RG_DOC_REDACTION_BATCH WHERE doc_source_id = :s "
                        "ORDER BY redaction_batch_id DESC FETCH FIRST :n ROWS ONLY", {"s": doc_source_id, "n": limit})
    return db.query("SELECT * FROM RG_DOC_REDACTION_BATCH ORDER BY redaction_batch_id DESC FETCH FIRST :n ROWS ONLY", {"n": limit})
