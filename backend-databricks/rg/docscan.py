"""Document (PDF folder) governance: parallel to rg/catalog.py + rg/scanner.py, not built on either -
see RG_DOC_SOURCE/RG_DOCUMENT/RG_DOC_FINDING in rg/ddl.py for why a document doesn't fit the existing
source/table/column shape. Reuses exactly two things from the existing pipeline, deliberately nothing
else: the classifier library itself (RG_CLASSIFIER rows, rg/classifiers.py, scanner.active_classifiers()'s
scope filtering) and clf_lib.score_column() for a PDF's metadata fields, which are naturally "one column,
one value" - no new matching logic needed there.

A PDF's extracted BODY TEXT is not one column's worth of discrete values though - it's free prose that
may embed many separate PII instances of different kinds anywhere in it (an address in paragraph two, a
phone number in a footer). classifiers.py's methods are built to score a LIST OF DISCRETE VALUES, each
matched as a WHOLE against an anchored pattern - not to find occurrences embedded inside a block of text.
_sweep_text() below adapts the same classifier definitions (content_pattern text, the built-in
EMAIL/PHONE/IBAN/Luhn validators, the FIRST_NAMES/LAST_NAMES dictionaries - imported from classifiers.py,
including its two underscore-prefixed pattern constants, deliberately: keeping this in lock-step with
that module rather than forking copies of the same three regexes) to that different job, so the PII
vocabulary and taxonomy (category, pii_class, data_element codes) stay identical between structured and
document findings - only the matching mechanics differ.

FULL_NAME also gets a second, complementary source of candidates when switched on: a local LLM reads the
text for names it recognises from context rather than a fixed dictionary - see rg/name_llm.py, called
from _raw_matches()'s FULL_NAME branch. Off by default; the dictionary pairing alone still runs either way.
"""
from __future__ import annotations

import datetime as dt
import io
import re
import threading
import traceback
from typing import Any

import pypdf

from . import classifiers as clf_lib
from . import db
from . import name_llm
from . import volumes
from .common import audit, sample_mask
from .scanner import active_classifiers

BODY_FIELD = "__BODY__"  # RG_DOC_FINDING.field_name for a CONTENT-sourced finding - see ddl.py's comment
METADATA_FIELDS = ("AUTHOR", "TITLE", "SUBJECT", "PRODUCER")
MAX_TEXT_CHARS = 2_000_000  # safety cap per document - a huge scanned-book PDF shouldn't hang a scan


# --------------------------------------------------------------------------- doc sources
def list_doc_sources() -> list[dict]:
    return db.query(
        "SELECT s.*, "
        "(SELECT COUNT(*) FROM RG_DOCUMENT d WHERE d.doc_source_id = s.doc_source_id) AS documents, "
        "(SELECT COUNT(*) FROM RG_DOC_FINDING f JOIN RG_DOCUMENT d ON d.document_id = f.document_id "
        " WHERE d.doc_source_id = s.doc_source_id AND f.status NOT IN ('LOW','RESOLVED')) AS findings "
        "FROM RG_DOC_SOURCE s ORDER BY s.name")


def get_doc_source(doc_source_id: int) -> dict | None:
    return db.query_one("SELECT * FROM RG_DOC_SOURCE WHERE doc_source_id = :i", {"i": doc_source_id})


def create_doc_source(name: str, folder_path: str, username: str, domain: str | None = None) -> dict:
    name = (name or "").strip()
    folder_path = (folder_path or "").strip().rstrip("/")
    if not name or not folder_path:
        raise ValueError("Name and folder path are both required")
    if not volumes.is_dir(folder_path):
        raise ValueError(f"Not a Unity Catalog Volume folder, or not reachable from the server running "
                         f"this app: {folder_path}")
    try:
        sid = db.insert("RG_DOC_SOURCE", {"name": name, "folder_path": folder_path, "domain": domain or None}, "doc_source_id")
    except Exception as e:
        if "rg_doc_source_uk" in str(e) or "UniqueViolation" in type(e).__name__:
            raise ValueError(f"A document source already points at {folder_path} - use that one instead "
                             f"of adding it again") from e
        raise
    audit(username, "doc_source", sid, "CREATE", f"{name}: {folder_path}" + (f" ({domain})" if domain else ""))
    return get_doc_source(sid)


def delete_doc_source(doc_source_id: int, username: str) -> None:
    src = get_doc_source(doc_source_id)
    if not src:
        raise ValueError(f"Document source {doc_source_id} not found")
    # same reason snapshot.clear_all() clears a document source's chunks before wiping its RG_DOCUMENT
    # rows: nothing else ever removes a deleted document's embeddings from Chroma, so skipping this would
    # leave them searchable (including the unredacted PII collection) long after the source is "gone".
    doc_ids = [d["document_id"] for d in db.query("SELECT document_id FROM RG_DOCUMENT WHERE doc_source_id = :s", {"s": doc_source_id})]
    if doc_ids:
        from . import vectorsearch
        vectorsearch.clear_for_documents(doc_ids)
    db.execute("DELETE FROM RG_DOC_SOURCE WHERE doc_source_id = :i", {"i": doc_source_id})  # cascades documents/findings
    audit(username, "doc_source", doc_source_id, "DELETE", src["name"])


# --------------------------------------------------------------------------- discovery
def discover(doc_source_id: int, username: str) -> dict:
    src = get_doc_source(doc_source_id)
    if not src:
        raise ValueError(f"Document source {doc_source_id} not found")
    folder_path = src["folder_path"]
    if not volumes.is_dir(folder_path):
        raise ValueError(f"Folder no longer reachable: {folder_path}")

    found = 0
    for entry in volumes.list_files(folder_path, ".pdf"):
        data = volumes.read_bytes(entry["path"])
        meta = _read_pdf_metadata(data)
        values = {
            "doc_source_id": doc_source_id, "file_path": entry["path"], "file_name": entry["name"],
            "file_size": entry["size"], "page_count": meta["page_count"],
            "pdf_author": meta["author"], "pdf_title": meta["title"], "pdf_subject": meta["subject"],
            "pdf_producer": meta["producer"], "pdf_created_at": meta["created_at"], "pdf_modified_at": meta["modified_at"],
            "file_modified_at": entry["modified_at"],
        }
        existing = db.query_one("SELECT document_id FROM RG_DOCUMENT WHERE doc_source_id = :s AND file_path = :f",
                                {"s": doc_source_id, "f": entry["path"]})
        if existing:
            db.update("RG_DOCUMENT", "document_id", existing["document_id"], values)
        else:
            db.insert("RG_DOCUMENT", values, "document_id")
        found += 1

    db.execute("UPDATE RG_DOC_SOURCE SET last_discovered_at = now() WHERE doc_source_id = :i", {"i": doc_source_id})
    audit(username, "doc_source", doc_source_id, "DISCOVER", f"{found} PDF(s)")
    return {"documents": found}


def _read_pdf_metadata(data: bytes) -> dict:
    out: dict[str, Any] = {"page_count": None, "author": None, "title": None, "subject": None,
                           "producer": None, "created_at": None, "modified_at": None}
    try:
        reader = pypdf.PdfReader(io.BytesIO(data))
        out["page_count"] = len(reader.pages)
        info = reader.metadata or {}
        out["author"] = _trim(info.get("/Author"), 200)
        out["title"] = _trim(info.get("/Title"), 400)
        out["subject"] = _trim(info.get("/Subject"), 400)
        out["producer"] = _trim(info.get("/Producer"), 200)
        out["created_at"] = _pdf_date(info.get("/CreationDate"))
        out["modified_at"] = _pdf_date(info.get("/ModDate"))
    except Exception:  # noqa: BLE001 - a corrupt/encrypted/unreadable PDF must not abort the whole discovery
        pass
    return out


def _trim(v, n: int) -> str | None:
    return str(v).strip()[:n] if v else None


def _pdf_date(v) -> dt.datetime | None:
    """A PDF date looks like D:20230114153045+01'00' - parsed by hand (pypdf's own date helper wants the
    raw dictionary object, not the plain dict this metadata access already gives); anything that doesn't
    match the common shape is left unset rather than guessed at."""
    if not v:
        return None
    m = re.match(r"D:(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?", str(v))
    if not m:
        return None
    y, mo, d, h, mi, se = (int(x) if x else 0 for x in m.groups())
    try:
        return dt.datetime(y, mo or 1, d or 1, h, mi, se)
    except ValueError:
        return None


# --------------------------------------------------------------------------- scanning
def start_scan(doc_source_id: int, username: str) -> int:
    """Returns immediately with the new doc_scan_id; the batch itself runs on a background thread, same
    pattern as scanner.start_scan() - PDF text extraction across many files is slow enough that a
    synchronous request would time out or just feel broken. Poll RG_DOC_SCAN_JOB (list_doc_scans()) for
    progress and completion, same as the existing table/column scan's RG_SCAN_JOB."""
    src = get_doc_source(doc_source_id)
    if not src:
        raise ValueError(f"Document source {doc_source_id} not found")
    docs = db.query("SELECT document_id FROM RG_DOCUMENT WHERE doc_source_id = :s", {"s": doc_source_id})
    if not docs:
        raise ValueError("Run discovery first: no documents found")

    scan_id = db.insert("RG_DOC_SCAN_JOB", {"doc_source_id": doc_source_id, "status": "QUEUED",
                                            "documents_total": len(docs), "requested_by": username}, "doc_scan_id")
    audit(username, "doc_scan", scan_id, "SCAN_START", f"{len(docs)} document(s)")
    threading.Thread(target=_run_scan, args=(scan_id, doc_source_id), daemon=True).start()
    return scan_id


def _run_scan(scan_id: int, doc_source_id: int) -> None:
    docs = db.query("SELECT * FROM RG_DOCUMENT WHERE doc_source_id = :s ORDER BY file_name", {"s": doc_source_id})
    db.execute("UPDATE RG_DOC_SCAN_JOB SET status = 'RUNNING', started_at = now() WHERE doc_scan_id = :i", {"i": scan_id})
    classifiers = active_classifiers()
    docs_done = findings_total = new = resolved = 0

    try:
        for doc in docs:
            new_t, res_t, tot_t = _scan_one(doc, classifiers, scan_id)
            new += new_t
            resolved += res_t
            findings_total += tot_t
            docs_done += 1
            db.execute("UPDATE RG_DOC_SCAN_JOB SET documents_done = :d, findings_total = :f, findings_new = :n, "
                      "findings_resolved = :r WHERE doc_scan_id = :i",
                      {"d": docs_done, "f": findings_total, "n": new, "r": resolved, "i": scan_id})
        db.execute("UPDATE RG_DOC_SCAN_JOB SET status = 'COMPLETED', finished_at = now(), "
                  "message = :m WHERE doc_scan_id = :i", {"m": f"{docs_done} document(s) scanned", "i": scan_id})
        db.execute("UPDATE RG_DOC_SOURCE SET last_scan_at = now() WHERE doc_source_id = :s", {"s": doc_source_id})
    except Exception as e:  # noqa: BLE001 - background thread: must record the failure, nothing to re-raise to
        traceback.print_exc()
        db.execute("UPDATE RG_DOC_SCAN_JOB SET status = 'FAILED', finished_at = now(), "
                  "message = :m WHERE doc_scan_id = :i", {"m": str(e)[:490], "i": scan_id})


def _scan_one(doc: dict, classifiers: list[dict], scan_id: int) -> tuple[int, int, int]:
    document_id = doc["document_id"]
    existing = {(f["field_name"], f["data_element"]): f for f in
               db.query("SELECT * FROM RG_DOC_FINDING WHERE document_id = :d", {"d": document_id})}
    seen: set[tuple] = set()
    new = resolved = total = 0

    # metadata fields: each is naturally "one column, one value" - clf_lib.score_column() needs no adapting.
    field_values = {"AUTHOR": doc.get("pdf_author"), "TITLE": doc.get("pdf_title"),
                    "SUBJECT": doc.get("pdf_subject"), "PRODUCER": doc.get("pdf_producer")}
    cands: list[dict] = []
    for field, value in field_values.items():
        for clf in classifiers:
            res = clf_lib.score_column(clf, field, "VARCHAR2", [value] if value else [], False)
            if res and res["confidence"] >= clf_lib.LOW_THRESHOLD:
                cands.append({"field": field, "clf": clf, "confidence": res["confidence"],
                             "match_count": 1 if res["name_hit"] or res["match_ratio"] else 0,
                             "samples": [sample_mask(str(value))] if value else []})

    # body text: the free-text sweep (see module docstring).
    text = _extract_text(volumes.read_bytes(doc["file_path"]))
    if text:
        cands.extend(_sweep_text(text, classifiers))

    for x in cands:
        clf, field = x["clf"], x["field"]
        status = clf_lib.status_for(x["confidence"])
        if status is None:
            continue
        key = (field, clf["code"])
        seen.add(key)
        ex = existing.get(key)
        values = {
            "document_id": document_id, "source": "METADATA" if field != BODY_FIELD else "CONTENT",
            "field_name": field, "data_element": clf["code"], "category": clf["category"],
            "pii_class": clf["pii_class"], "confidence": x["confidence"], "match_count": x["match_count"],
            "status": status, "last_scan_id": scan_id,
        }
        if ex is None:
            values["first_scan_id"] = scan_id
            fid = db.insert("RG_DOC_FINDING", values, "doc_finding_id")
            new += 1
        else:
            fid = ex["doc_finding_id"]
            keep = ex["status"] in ("CONFIRMED", "REJECTED")
            if keep:
                values["status"] = ex["status"]
            db.update("RG_DOC_FINDING", "doc_finding_id", fid, values)
            db.execute("UPDATE RG_DOC_FINDING SET updated_at = now() WHERE doc_finding_id = :i", {"i": fid})
        total += 1
        if x.get("samples"):
            db.execute("DELETE FROM RG_DOC_FINDING_SAMPLE WHERE doc_finding_id = :i", {"i": fid})
            for smp in x["samples"][:3]:
                db.insert("RG_DOC_FINDING_SAMPLE", {"doc_finding_id": fid, "masked_value": smp}, "doc_sample_id")

    for (field, element), ex in existing.items():
        if (field, element) not in seen and ex["status"] != "RESOLVED":
            db.update("RG_DOC_FINDING", "doc_finding_id", ex["doc_finding_id"], {"status": "RESOLVED", "last_scan_id": scan_id})
            resolved += 1

    db.execute("UPDATE RG_DOCUMENT SET last_scanned_at = now() WHERE document_id = :i", {"i": document_id})
    return new, resolved, total


def _extract_text(data: bytes) -> str:
    try:
        reader = pypdf.PdfReader(io.BytesIO(data))
        parts = []
        length = 0
        for page in reader.pages:
            t = page.extract_text() or ""
            parts.append(t)
            length += len(t)
            if length >= MAX_TEXT_CHARS:
                break
        return "\n".join(parts)
    except Exception:  # noqa: BLE001 - encrypted/corrupt/scanned-image-only PDF: no text, not a scan failure
        return ""


# --------------------------------------------------------------------------- free-text sweep
def _split_top_level_alternation(pattern: str) -> list[str]:
    """Splits on '|' only where it isn't inside a character class ([...]) or a group ((...)) - so
    STREET_ADDRESS's `^A$|^B$` (two independently-anchored whole-cell alternatives) splits into ['^A$',
    '^B$'], while POSTAL_CODE's `^(A|B)$` (one pattern, alternation nested inside a group) stays as a
    single piece ['^(A|B)$']. Respects backslash-escapes so `\\|` is never treated as a split point."""
    parts: list[str] = []
    depth = 0
    in_class = False
    buf: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            buf.append(c)
            buf.append(pattern[i + 1])
            i += 2
            continue
        if c == "[" and not in_class:
            in_class = True
        elif c == "]" and in_class:
            in_class = False
        elif not in_class:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c == "|" and depth == 0:
                parts.append("".join(buf))
                buf = []
                i += 1
                continue
        buf.append(c)
        i += 1
    parts.append("".join(buf))
    return parts


def _unanchored(pattern: str) -> re.Pattern:
    """Strips a leading '^' and trailing '$' from EVERY top-level alternative, not just the first and
    last character of the whole pattern string. A whole-cell pattern like EMAIL's or PHONE's has one
    ^...$ wrapping everything, and stripping just the outer edges is enough - but a pattern written as
    several self-anchored alternatives (STREET_ADDRESS's `^A$|^B$`, ES_DNI's `^A$|^B$`) keeps its INNER
    anchors after only the outer ones are stripped, so swept across free text each alternative then only
    matches when it happens to land at the very start or the very end of the document - never embedded
    mid-paragraph, which is where a real address or ID usually is. Splitting on top-level '|' first and
    stripping each alternative individually (then rejoining with '|') fixes every alternative, not just
    the outermost one."""
    cleaned = []
    for part in _split_top_level_alternation(pattern):
        if part.startswith("^"):
            part = part[1:]
        if part.endswith("$"):
            part = part[:-1]
        cleaned.append(part)
    return re.compile("|".join(cleaned))


_WORD = re.compile(r"[A-Za-z][A-Za-z'\-]+")
_ADJACENT_PAIR = re.compile(r"\b([A-Z][a-z'\-]+)\s+([A-Z][a-z'\-]+)\b")
_CARD_RUN = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_CPF_RUN = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
_CN_ID_RUN = re.compile(r"\b\d{17}[\dXx]\b")

# A "NUMERIC" classifier (e.g. ANNUAL_INCOME) has no column name to lean on in free text, and a bare
# amount is meaningless on its own - every claim, premium and sum-insured figure in a document looks
# identical to a salary figure as a number. _MONEY finds amount-shaped substrings; NUMERIC_WINDOW_CHARS
# is how close one of the classifier's own name_pattern words (its only other signal) must appear for
# that amount to count as a candidate - the free-text equivalent of "the column was named SALARY".
_MONEY = re.compile(
    r"(?:USD|GBP|EUR|CHF|AUD|CAD|[$£€])\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?"
    r"|\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s?(?:USD|GBP|EUR|CHF|AUD|CAD|dollars|pounds|euros)\b", re.I)
NUMERIC_WINDOW_CHARS = 60


# Checksum/structure-validated methods run before plain REGEX/PHONE and claim their matched spans - a
# content_pattern written for a dedicated column (e.g. DE_TAX_ID's bare \d{11}, POSTAL_CODE's \d{4,5})
# is written assuming the surrounding column name already ruled out the wrong kind of number; swept
# across free text with no name evidence at all, a loose digit-count pattern like that will trivially
# match INSIDE a 16-digit credit card number too. Letting a validated hit (Luhn/IBAN/CPF/CN-ID checked)
# claim its span first, and skipping a plain regex match that overlaps one, is the free-text equivalent
# of the name-weight damping those classifiers would get in the structured column case.
_VALIDATED_METHODS = ("LUHN", "REGEX_LUHN", "IBAN", "CPF", "CN_ID")


def _overlaps(span: tuple[int, int], claimed: list[tuple[int, int]]) -> bool:
    return any(span[0] < c[1] and c[0] < span[1] for c in claimed)


def _raw_matches(text: str, classifiers: list[dict]) -> dict[str, list[str]]:
    """classifier code -> every raw (unmasked) matched substring found in `text`, by the same 3-pass,
    span-claiming logic _sweep_text() scores from. Pulled out as its own function so redact.py's
    execute() - which needs the real strings to locate and black out on the PDF page, not a masked
    preview - can never drift from what the Findings page actually reported as detected; both read
    from this single pass over the text."""
    lower = text.lower()
    words_lower = [w.lower() for w in _WORD.findall(text)]
    claimed: list[tuple[int, int]] = []
    out: dict[str, list[str]] = {}

    # pass 1: validated methods, in isolation, claiming spans as they go
    for clf in classifiers:
        method = clf["content_method"]
        if method not in _VALIDATED_METHODS:
            continue
        if method == "IBAN":
            hits = [h for h in _unanchored(clf_lib._IBAN.pattern).finditer(text) if clf_lib._iban_ok(h.group(0))]
        elif method in ("LUHN", "REGEX_LUHN"):
            pat = _unanchored(clf["content_pattern"]) if method == "REGEX_LUHN" and clf.get("content_pattern") else _CARD_RUN
            hits = [h for h in pat.finditer(text) if clf_lib._luhn(h.group(0).replace(" ", "").replace("-", ""))]
        elif method == "CPF":
            hits = [h for h in _CPF_RUN.finditer(text) if clf_lib._cpf_ok(h.group(0))]
        else:  # CN_ID
            hits = [h for h in _CN_ID_RUN.finditer(text) if clf_lib._cn_id_ok(h.group(0))]
        claimed.extend(h.span() for h in hits)
        if hits:
            out[clf["code"]] = [h.group(0) for h in hits]

    # pass 2: plain regex/phone - only counts a match that doesn't land inside an already-claimed span
    for clf in classifiers:
        method = clf["content_method"]
        if method == "REGEX":
            pat = _unanchored(clf["content_pattern"]) if clf.get("content_pattern") else _unanchored(clf_lib._EMAIL.pattern)
            hits = [h for h in pat.finditer(text) if not _overlaps(h.span(), claimed)]
            if hits:
                out[clf["code"]] = [h.group(0) for h in hits]
        elif method == "PHONE":
            hits = [h for h in _unanchored(clf_lib._PHONE_INTL.pattern).finditer(text) if not _overlaps(h.span(), claimed)] or \
                   [h for h in _unanchored(clf_lib._PHONE_LOCAL.pattern).finditer(text) if not _overlaps(h.span(), claimed)]
            if hits:
                out[clf["code"]] = [h.group(0) for h in hits]

    # pass 3: word/phrase-level signals - operate on alphabetic tokens, so they don't contend for the
    # same spans as the digit-pattern passes above
    for clf in classifiers:
        method = clf["content_method"]
        if method == "DICT_FIRST":
            hits = [w for w in words_lower if w in clf_lib.FIRST_NAMES]
            if hits:
                out[clf["code"]] = hits
        elif method == "DICT_LAST":
            hits = [w for w in words_lower if w in clf_lib.LAST_NAMES]
            if hits:
                out[clf["code"]] = hits
        elif method == "FULL_NAME":
            hits = [m.group(0) for m in _ADJACENT_PAIR.finditer(text)
                   if m.group(1).lower() in clf_lib.FIRST_NAMES and m.group(2).lower() in clf_lib.LAST_NAMES]
            # LLM-assisted pass (name_llm.py): catches a real name the dictionary pairing structurally
            # can't, e.g. "Anna Kowalski" when the surname isn't in LAST_NAMES. A no-op (immediate []) when
            # the feature is off, so this costs nothing when not enabled.
            seen_lower = {h.lower() for h in hits}
            for n in name_llm.find_names(text):
                if n.lower() not in seen_lower:
                    hits.append(n)
                    seen_lower.add(n.lower())
            if hits:
                out[clf["code"]] = hits
        elif method == "KEYWORD":
            terms = [t.strip().lower() for t in (clf.get("content_pattern") or "").split(",") if t.strip()]
            hits = [m.group(0) for t in terms for m in re.finditer(re.escape(t), text, re.I)]
            if hits:
                out[clf["code"]] = hits
        elif method == "NUMERIC" and clf["applies_to"] == "NUMBER" and clf.get("name_pattern"):
            # No column name to check here, so the classifier's own name_pattern (e.g. ANNUAL_INCOME's
            # "INCOME|SALARY|WAGE|EARNINGS|REMUNERATION") is reused as the free-text context signal: an
            # amount only counts if one of those words appears within NUMERIC_WINDOW_CHARS of it, so a
            # claim amount or premium figure elsewhere in the document doesn't get swept in too.
            name_re = re.compile(clf["name_pattern"], re.I)
            hits = []
            for m in _MONEY.finditer(text):
                lo, hi = max(0, m.start() - NUMERIC_WINDOW_CHARS), min(len(text), m.end() + NUMERIC_WINDOW_CHARS)
                if name_re.search(text[lo:hi]):
                    hits.append(m.group(0))
            if hits:
                out[clf["code"]] = hits
        # ENUM, DOB, NONE: statistical/typed-value concepts, meaningless for free text - skipped
    return out


def _sweep_text(text: str, classifiers: list[dict]) -> list[dict]:
    """One candidate per (classifier, text) with the method's own match count - confidence is set by
    method family, not classifier.content_weight (there is no name evidence here to weigh it against):
    a validated structural pattern (regex/phone/IBAN/Luhn-checked/CPF/CN ID) has a very low false-positive
    rate once it matches at all, so it goes straight to AUTO; a dictionary/keyword hit is a much weaker
    single-token signal (common words collide with first names), so it climbs with repetition instead of
    jumping to AUTO on one hit."""
    raw = _raw_matches(text, classifiers)
    out: list[dict] = []
    for clf in classifiers:
        hits = raw.get(clf["code"])
        if not hits:
            continue
        method, count = clf["content_method"], len(hits)
        if method in ("REGEX", "PHONE", "IBAN", "LUHN", "REGEX_LUHN", "CPF", "CN_ID"):
            confidence = 0.95
        elif method == "FULL_NAME":
            confidence = min(0.85, 0.5 + 0.05 * count)
        elif method == "KEYWORD":
            confidence = min(0.75, 0.3 + 0.1 * count)
        elif method == "NUMERIC":
            confidence = min(0.80, 0.5 + 0.1 * count)  # keyword-proximity heuristic, not structurally validated
        elif method in ("DICT_FIRST", "DICT_LAST"):
            confidence = min(0.55, 0.15 + 0.08 * count)
        else:
            continue
        out.append({"field": BODY_FIELD, "clf": clf, "confidence": round(confidence, 3),
                   "match_count": count, "samples": [sample_mask(h) for h in hits[:3]]})
    return out

    return out


# --------------------------------------------------------------------------- findings / scans
def list_doc_findings(doc_source_id: int | None = None, status: str | None = None,
                      category: str | None = None, include_low: bool = False) -> list[dict]:
    sql = ["SELECT f.*, d.file_name, d.file_path, d.doc_source_id, "
          "(SELECT STRING_AGG(masked_value, ' | ' ORDER BY doc_sample_id) FROM RG_DOC_FINDING_SAMPLE s "
          " WHERE s.doc_finding_id = f.doc_finding_id) AS samples "
          "FROM RG_DOC_FINDING f JOIN RG_DOCUMENT d ON d.document_id = f.document_id WHERE 1=1"]
    p: dict = {}
    if doc_source_id:
        sql.append("AND d.doc_source_id = :s")
        p["s"] = doc_source_id
    if status:
        sql.append("AND f.status = :status")
        p["status"] = status
    elif not include_low:
        sql.append("AND f.status NOT IN ('LOW', 'RESOLVED')")
    if category:
        sql.append("AND f.category = :cat")
        p["cat"] = category
    sql.append("ORDER BY d.file_name, f.confidence DESC")
    return db.query(" ".join(sql), p)


def decide_doc_finding(doc_finding_id: int, status: str, username: str) -> dict:
    if status not in ("CONFIRMED", "REJECTED"):
        raise ValueError("Decision must be CONFIRMED or REJECTED")
    f = db.query_one("SELECT * FROM RG_DOC_FINDING WHERE doc_finding_id = :i", {"i": doc_finding_id})
    if not f:
        raise LookupError(f"Finding {doc_finding_id} not found")
    db.execute("UPDATE RG_DOC_FINDING SET status = :s, decided_by = :u, decided_at = now(), "
              "updated_at = now() WHERE doc_finding_id = :i", {"s": status, "u": username, "i": doc_finding_id})
    audit(username, "doc_finding", doc_finding_id, status, f"{f['field_name']} as {f['data_element']}")
    return db.query_one("SELECT * FROM RG_DOC_FINDING WHERE doc_finding_id = :i", {"i": doc_finding_id})


def list_doc_scans(doc_source_id: int | None = None, limit: int = 20) -> list[dict]:
    if doc_source_id:
        return db.query("SELECT * FROM RG_DOC_SCAN_JOB WHERE doc_source_id = :s ORDER BY doc_scan_id DESC "
                        "FETCH FIRST :n ROWS ONLY", {"s": doc_source_id, "n": limit})
    return db.query("SELECT * FROM RG_DOC_SCAN_JOB ORDER BY doc_scan_id DESC FETCH FIRST :n ROWS ONLY", {"n": limit})
