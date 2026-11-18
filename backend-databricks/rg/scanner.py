"""Scanning: read column values, run the classifier library, and persist findings.

Modes (RetentionGuard's scan types):
  METADATA  column names only - no data is read. Fast, low confidence (always needs review).
  SAMPLE    a random sample of rows per table (default 200).
  FULL      every row.

Findings persist across scans. A steward's CONFIRMED / REJECTED decision survives a re-scan; a finding
that stops being detected (e.g. after masking) becomes RESOLVED, which is how remediation is verified.
"""
from __future__ import annotations

import threading
import traceback

from . import classifiers as clf_lib
from . import db, engines, scope
from .common import audit, sample_mask

READ_TYPES = {"VARCHAR2", "CHAR", "NVARCHAR2", "NCHAR", "NUMBER", "DATE", "TIMESTAMP"}
MODES = ("METADATA", "SAMPLE", "FULL")

# classification_source label pair (confirmed, overridden) per source platform's native tag reconciliation -
# see the "pass 1.6" comment in _run() below.
_NATIVE_LABELS = {"DATABRICKS": ("UC_CONFIRMED", "UC_OVERRIDE"), "SNOWFLAKE": ("SF_CONFIRMED", "SF_OVERRIDE")}

# ---------------------------------------------------------------- classifier pushdown
# Runs a classifier's content check as a query on the source's own compute (Databricks/Snowflake only)
# instead of pulling raw values back - see rg/engines/databricks.py / rg/engines/snowflake.py's
# ensure_pushdown_udfs() for the two checksum UDFs this needs (EMAIL and PHONE's patterns are Python-only
# constants, not stored on RG_CLASSIFIER; Luhn isn't expressible as a single regex). Every OTHER REGEX
# classifier (country ID formats, postal codes, VAT numbers...) and every ENUM classifier push down
# generically straight from the classifier's own stored content_pattern - no per-classifier deployment,
# and a steward editing a pattern in RG_CLASSIFIER takes effect on the very next scan, same as local.
#
# Deliberately NOT pushed down: DICT_FIRST/DICT_LAST/FULL_NAME (checking a few hundred names locally is
# already cheap; replicating the dictionary server-side means syncing a reference table), DOB (a
# population statistic - stdev/plausibility - not a per-row predicate, a different query shape entirely),
# KEYWORD (HEALTH_CLAIM, LEGAL_TEXT - token-prefix matching has no exact LIKE equivalent without real
# semantic drift: 'nonmedical' would false-positive on LIKE '%medical%' but not on the real startswith
# check), NUMERIC/NONE (trivial or name-evidence-only - nothing worth a round trip for).
_REGEX_OP = {"DATABRICKS": "RLIKE", "SNOWFLAKE": "REGEXP"}


def _regex_literal(pattern: str) -> str:
    """A regex pattern as a SQL string literal, for either platform. Two confirmed, real dialect gaps
    from the Python `re` syntax RG_CLASSIFIER patterns are written in:
      1. Both Databricks' and Snowflake's regular single-quoted string literals interpret backslash
         escapes (Snowflake's $$-quoted UDF bodies in ensure_pushdown_udfs() are the one exception -
         those are raw), so every backslash is doubled here or the regex engine never sees them.
      2. Snowflake's REGEXP rejects non-capturing groups '(?:...)' outright ('no argument for repetition
         operator: ?'). We only ever need a boolean match, never a captured group, so '(?:' -> '(' is
         exactly equivalent for matching purposes and safe on Databricks too - done unconditionally
         rather than tracked per-engine."""
    return pattern.replace("(?:", "(").replace("'", "''").replace("\\", "\\\\")


def _pushdown_predicate(engine, clf: dict, col_ident: str) -> str | None:
    """A SQL boolean expression testing `col_ident` against `clf`'s content check, or None if this
    classifier has no pushdown equivalent on this engine."""
    name, code = engine.name, clf["code"]
    op = _REGEX_OP.get(name)
    if op is None:
        return None
    ns = engine.governance_namespace
    luhn_fn = f"{ns}.{'rg_is_luhn_valid' if name == 'DATABRICKS' else 'RG_IS_LUHN_VALID'}"
    # classifiers.py's CA_SIN uses _luhn_valid() (>=8 digits, no upper bound), not _luhn() (13-19 digits,
    # credit cards) - a 9-digit SIN would always fail the credit-card UDF's length gate regardless of its
    # checksum, so this needs the separately-deployed, correctly-ranged flex UDF, not luhn_fn above.
    luhn_flex_fn = f"{ns}.{'rg_is_luhn_valid_flex' if name == 'DATABRICKS' else 'RG_IS_LUHN_VALID_FLEX'}"
    if code == "EMAIL":
        email_fn = f"{ns}.{'rg_is_email' if name == 'DATABRICKS' else 'RG_IS_EMAIL'}"
        return f"{email_fn}({col_ident})"
    if code == "CREDIT_CARD":
        return f"{luhn_fn}({col_ident})"
    if code == "CA_SIN":    # REGEX_LUHN: a 9-digit shape AND a passing Luhn check digit
        pat = _regex_literal(r"^\d{3}[- ]?\d{3}[- ]?\d{3}$")
        return f"({col_ident} {op} '{pat}' AND {luhn_flex_fn}({col_ident}))"
    if code == "PHONE":    # two composed patterns, same as classifiers.py's _PHONE_INTL / _PHONE_LOCAL
        intl = _regex_literal(r"^\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?([\s.\-]?\d{2,}){1,4}$")
        local = _regex_literal(r"^\(?\d{2,5}\)?[\s.\-]\d{3,}([\s.\-]\d{2,})*$")
        return f"({col_ident} {op} '{intl}' OR {col_ident} {op} '{local}')"
    if clf["content_method"] == "REGEX" and clf.get("content_pattern"):
        pat = _regex_literal(clf["content_pattern"])
        return f"{col_ident} {op} '{pat}'"
    if clf["content_method"] == "ENUM" and clf.get("content_pattern"):
        allowed = [x.strip().upper() for x in clf["content_pattern"].split(",") if x.strip()]
        if not allowed:
            return None
        in_list = ", ".join("'" + a.replace("'", "''") + "'" for a in allowed)
        return f"UPPER(TRIM({col_ident})) IN ({in_list})"
    return None


def active_classifiers() -> list[dict]:
    """Enabled classifiers whose region / country is active for the organisation (a country pack is off with its country)."""
    ix = scope.ScopeIndex()
    return [c for c in db.query("SELECT * FROM RG_CLASSIFIER WHERE is_active = 1 ORDER BY classifier_id") if ix.valid(c)]


def set_pushdown_enabled(source_id: int, enabled: bool, username: str) -> dict:
    """The per-source on/off switch _run() checks before ever calling _pushdown_score_column() - see
    RG_DATA_SOURCE.IS_PUSHDOWN_ENABLED in rg/ddl.py."""
    from .policy import NotFound
    row = db.query_one("SELECT source_id FROM RG_DATA_SOURCE WHERE source_id = :i", {"i": source_id})
    if not row:
        raise NotFound(f"Data source {source_id} not found")
    db.execute("UPDATE RG_DATA_SOURCE SET is_pushdown_enabled = :e WHERE source_id = :i",
              {"e": 1 if enabled else 0, "i": source_id})
    audit(username, "source", source_id, "PUSHDOWN_TOGGLE",
          "enabled" if enabled else "disabled - scans will use the local classifier path only")
    out = db.query_one("SELECT * FROM RG_DATA_SOURCE WHERE source_id = :i", {"i": source_id})
    out.pop("password", None)
    return out


def start_scan(source_id: int, mode: str, sample_size: int | None, tables: list[str] | None, username: str) -> int:
    if mode not in MODES:
        raise ValueError(f"Unknown scan mode '{mode}'")
    if not db.scalar("SELECT COUNT(*) FROM RG_CATALOG_TABLE WHERE source_id = :s", {"s": source_id}):
        raise ValueError("Run discovery first: the catalog is empty")
    scan_id = db.insert("RG_SCAN_JOB", {"source_id": source_id, "scan_mode": mode,
                                        "sample_size": sample_size if mode == "SAMPLE" else None,
                                        "status": "QUEUED", "requested_by": username}, "scan_id")
    audit(username, "scan", scan_id, "SCAN_START", f"{mode}" + (f" n={sample_size}" if mode == "SAMPLE" else ""))
    threading.Thread(target=_run, args=(scan_id, source_id, mode, sample_size or 200, tables), daemon=True).start()
    return scan_id


def run_scan_sync(source_id: int, mode: str = "FULL", sample_size: int = 200, tables: list[str] | None = None,
                  username: str = "system") -> int:
    scan_id = db.insert("RG_SCAN_JOB", {"source_id": source_id, "scan_mode": mode, "sample_size": sample_size,
                                        "status": "QUEUED", "requested_by": username}, "scan_id")
    _run(scan_id, source_id, mode, sample_size, tables)
    return scan_id


def _run(scan_id: int, source_id: int, mode: str, sample_size: int, only_tables: list[str] | None) -> None:
    try:
        db.execute("UPDATE RG_SCAN_JOB SET status='RUNNING', started_at=now() WHERE scan_id=:i", {"i": scan_id})
        engine = engines.for_source(source_id)
        cat_tables = db.query("SELECT table_name, row_count FROM RG_CATALOG_TABLE WHERE source_id=:s ORDER BY table_name",
                              {"s": source_id})
        if only_tables:
            wanted = {t.upper() for t in only_tables}
            cat_tables = [t for t in cat_tables if t["table_name"].upper() in wanted]
        db.execute("UPDATE RG_SCAN_JOB SET tables_total=:n WHERE scan_id=:i", {"n": len(cat_tables), "i": scan_id})
        classifiers = active_classifiers()
        pushdown_enabled = bool(db.scalar("SELECT is_pushdown_enabled FROM RG_DATA_SOURCE WHERE source_id=:s",
                                          {"s": source_id}))
        cols_scanned = findings_total = new = resolved = uc_reconciled = uc_override = pushed_down = 0

        for t in cat_tables:
            tname = t["table_name"]
            cols = [c for c in db.query("SELECT column_name, data_type, data_length, is_nullable, is_pk, "
                                        "uc_classification FROM RG_CATALOG_COLUMN "
                                        "WHERE source_id=:s AND table_name=:t ORDER BY ordinal", {"s": source_id, "t": tname})
                    if c["data_type"] in READ_TYPES]
            data: dict[str, list] = {c["column_name"]: [] for c in cols}
            if mode != "METADATA" and cols:
                for row in _read_rows(engine, tname, [c["column_name"] for c in cols], mode, sample_size):
                    for c, v in zip(cols, row):
                        data[c["column_name"]].append(v)

            existing = {(f["column_name"], f["data_element"]): f for f in db.query(
                "SELECT * FROM RG_FINDING WHERE source_id=:s AND table_name=:t", {"s": source_id, "t": tname})}
            seen: set[tuple] = set()

            # pass 1: score every column with every classifier
            cands: list[dict] = []
            for c in cols:
                cols_scanned += 1
                vals = data[c["column_name"]]
                if vals:
                    nn = [v for v in vals if v is not None]
                    null_ratio = round(1 - len(nn) / len(vals), 4)
                    distinct_ratio = round(len({str(v) for v in nn}) / len(nn), 4) if nn else 0
                    db.execute("UPDATE RG_CATALOG_COLUMN SET null_ratio=:a, distinct_ratio=:b WHERE source_id=:s "
                               "AND table_name=:t AND column_name=:c",
                               {"a": null_ratio, "b": distinct_ratio, "s": source_id, "t": tname, "c": c["column_name"]})
                pushdown_results = {}
                if mode != "METADATA" and pushdown_enabled:
                    applicable = [clf for clf in classifiers if clf_lib.applies(clf, c["data_type"])]
                    pushdown_results = _pushdown_score_column(engine, tname, c["column_name"], c["data_type"], applicable)
                for clf in classifiers:
                    res = pushdown_results.get(clf["code"])
                    if res:
                        pushed_down += 1
                    else:
                        res = clf_lib.score_column(clf, c["column_name"], c["data_type"], vals, mode == "METADATA")
                    if res:
                        cands.append({"col": c["column_name"], "clf": clf, "res": res})

            # context: a quasi-identifier (city, occupation, region ...) only identifies a person in a table that is
            # about people, i.e. one that also holds a direct identifier. REF_BRANCH.CITY is a place, not a person.
            about_people = any(x["clf"]["pii_class"] in ("DIRECT", "IDENTIFIER") and x["clf"]["category"] == "PII"
                               and x["res"]["confidence"] >= clf_lib.AUTO_THRESHOLD for x in cands)
            if not about_people:
                for x in cands:
                    if x["clf"]["pii_class"] == "QUASI":
                        x["res"]["confidence"] = round(x["res"]["confidence"] * 0.5, 3)
            for x in cands:
                x["res"].setdefault("classification_source", "CLASSIFIER")

            # pass 1.6: native-tag reconciliation. A column tagged with a `pii_classification` value by the
            # source platform's own tagging/classification system (read at discovery time - see
            # rg/catalog.py::_discover_databricks / _discover_snowflake) is that column's primary
            # classification. If our own classifier already agrees, its finding just gets confirmed (bumped
            # to AUTO - a steward does not need to review something the platform itself also attests to).
            # If it disagrees, or found nothing at all for that column, the platform's value wins and
            # becomes the finding, superseding whatever else the classifier proposed for that same column.
            # Columns with no native tag are untouched: the classifier's own output remains the sole source.
            native_map = {c["column_name"]: c["uc_classification"] for c in cols if c.get("uc_classification")}
            if native_map:
                confirmed_label, override_label = _NATIVE_LABELS.get(engine.name, ("NATIVE_CONFIRMED", "NATIVE_OVERRIDE"))
                by_col: dict[str, list[dict]] = {}
                for x in cands:
                    by_col.setdefault(x["col"], []).append(x)
                classifier_by_code = {c["code"]: c for c in db.query("SELECT * FROM RG_CLASSIFIER")}
                reconciled: list[dict] = [x for x in cands if x["col"] not in native_map]
                for col, native_value in native_map.items():
                    code = (native_value or "").strip().upper()
                    if not code:
                        continue
                    agree = next((x for x in by_col.get(col, []) if x["clf"]["code"] == code), None)
                    if agree:
                        agree["res"]["confidence"] = max(agree["res"]["confidence"], clf_lib.AUTO_THRESHOLD)
                        agree["res"]["classification_source"] = confirmed_label
                        reconciled.append(agree)
                    else:
                        meta = classifier_by_code.get(code) or {"code": code, "category": "PII", "pii_class": "DIRECT"}
                        reconciled.append({"col": col, "clf": meta, "res": {
                            "confidence": 1.0, "name_hit": False, "match_ratio": None,
                            "rows_sampled": len(data.get(col, [])), "samples": [],
                            "classification_source": override_label}})
                        uc_override += 1
                    uc_reconciled += 1
                cands = reconciled

            # pass 2: persist
            for x in cands:
                clf, res, col = x["clf"], x["res"], x["col"]
                status = clf_lib.status_for(res["confidence"])
                if status is None:
                    continue
                key = (col, clf["code"])
                seen.add(key)
                ex = existing.get(key)
                if ex is None:
                    fid = db.insert("RG_FINDING", {
                        "source_id": source_id, "table_name": tname, "column_name": col,
                        "data_element": clf["code"], "category": clf["category"], "pii_class": clf["pii_class"],
                        "confidence": res["confidence"], "name_hit": int(res["name_hit"]),
                        "match_ratio": res["match_ratio"], "rows_sampled": res["rows_sampled"], "status": status,
                        "classification_source": res["classification_source"],
                        "first_scan_id": scan_id, "last_scan_id": scan_id}, "finding_id")
                    new += 1
                else:
                    fid = ex["finding_id"]
                    keep = ex["status"] in ("CONFIRMED", "REJECTED")
                    db.update("RG_FINDING", "finding_id", fid, {
                        "confidence": res["confidence"], "name_hit": int(res["name_hit"]),
                        "match_ratio": res["match_ratio"], "rows_sampled": res["rows_sampled"],
                        "category": clf["category"], "pii_class": clf["pii_class"],
                        "classification_source": res["classification_source"],
                        "status": ex["status"] if keep else status, "last_scan_id": scan_id})
                    db.execute("UPDATE RG_FINDING SET updated_at=now() WHERE finding_id=:i", {"i": fid})
                findings_total += 1
                if res["samples"]:
                    db.execute("DELETE FROM RG_FINDING_SAMPLE WHERE finding_id=:i", {"i": fid})
                    for smp in res["samples"]:
                        db.insert("RG_FINDING_SAMPLE", {"finding_id": fid, "masked_value": sample_mask(_display(smp))}, "sample_id")
            if mode != "METADATA":
                # anything previously found in the columns we just read but no longer detected is resolved
                scanned_cols = {c["column_name"] for c in cols}
                for (col, el), ex in existing.items():
                    if col in scanned_cols and (col, el) not in seen and ex["status"] not in ("RESOLVED",):
                        db.update("RG_FINDING", "finding_id", ex["finding_id"], {"status": "RESOLVED", "last_scan_id": scan_id})
                        resolved += 1
            db.execute("UPDATE RG_SCAN_JOB SET tables_done=tables_done+1, columns_scanned=:c, findings_total=:f, "
                       "findings_new=:n, findings_resolved=:r WHERE scan_id=:i",
                       {"c": cols_scanned, "f": findings_total, "n": new, "r": resolved, "i": scan_id})

        db.execute("UPDATE RG_SCAN_JOB SET status='COMPLETED', finished_at=now(), message=:m WHERE scan_id=:i",
                   {"m": f"{mode} scan finished", "i": scan_id})
        db.execute("UPDATE RG_DATA_SOURCE SET last_scan_at=now() WHERE source_id=:s", {"s": source_id})
        if uc_reconciled or pushed_down:
            requested_by = db.scalar("SELECT requested_by FROM RG_SCAN_JOB WHERE scan_id=:i", {"i": scan_id}) or "system"
            if uc_reconciled:
                audit(requested_by, "scan", scan_id, "UC_RECONCILE",
                      f"{uc_reconciled} column(s) carried a native platform classification: "
                      f"{uc_reconciled - uc_override} confirmed, {uc_override} overrode the classifier")
            if pushed_down:
                audit(requested_by, "scan", scan_id, "PUSHDOWN",
                      f"{pushed_down} column-classifier evaluation(s) ran as native {engine.name} compute "
                      f"instead of pulling raw values back")
    except Exception as e:  # noqa: BLE001 - job runner must record any failure
        traceback.print_exc()
        db.execute("UPDATE RG_SCAN_JOB SET status='FAILED', finished_at=now(), message=:m WHERE scan_id=:i",
                   {"m": str(e)[:490], "i": scan_id})


def _read_rows(engine, table: str, columns: list[str], mode: str, sample_size: int) -> list[tuple]:
    """FULL = every row; SAMPLE = a random `sample_size` rows, via Spark SQL's rand(). Goes through this
    source's own engine (rg/engines/registry.py), not a hardcoded shared connection."""
    select = ", ".join(engine.ident(c) for c in columns)
    tbl = engine.ident(table)
    sql = f"SELECT {select} FROM {tbl}" if mode == "FULL" else \
          f"SELECT {select} FROM {tbl} ORDER BY rand() LIMIT {int(sample_size)}"
    rows = engine.query(sql)
    lower_cols = [c.lower() for c in columns]
    return [tuple(r.get(lc) for lc in lower_cols) for r in rows]


def _pushdown_score_column(engine, table: str, column: str, dtype: str, classifiers: list[dict]) -> dict:
    """Score every pushdown-eligible classifier for ONE column in a single pair of queries - one combined
    aggregate (every classifier's match count, plus a shared COUNT(*)/COUNT(DISTINCT) - the WHERE clause
    and those two stats are identical across every classifier on this column, so they're computed once,
    not once per classifier) and one combined samples query - instead of a separate query pair per
    classifier. With ~20+ classifiers often applying to a single STRING column by data type alone, that
    was the dominant cost of pushdown scanning; this cuts it to at most 2 round trips per column,
    regardless of how many classifiers apply.

    Unlike the local path, every ratio here reflects the WHOLE table, not just whatever sample
    _read_rows() happened to pull - a real accuracy improvement under SAMPLE mode, not just less traffic.

    Returns {classifier_code: res} for whichever classifiers had a pushdown predicate; never raises - any
    failure (no predicate, missing grant, unreachable governance schema, platform quirk) just leaves that
    classifier (or the whole column) out of the result, so the caller falls back to local scoring."""
    if engine.name not in ("DATABRICKS", "SNOWFLAKE"):
        return {}
    try:
        engine.ensure_pushdown_udfs()
        col_ident, tbl_ident = engine.ident(column), engine.ident(table)
        clf_by_code = {c["code"]: c for c in classifiers}
        preds: dict[str, str] = {}
        enum_codes: set[str] = set()
        for clf in classifiers:
            pred = _pushdown_predicate(engine, clf, col_ident)
            if pred:
                preds[clf["code"]] = pred
                if clf["content_method"] == "ENUM":
                    enum_codes.add(clf["code"])
        if not preds:
            return {}
        codes = list(preds.keys())
        need_distinct = bool(enum_codes)

        select_parts = ["COUNT(*) AS total"]
        if need_distinct:
            select_parts.append(f"COUNT(DISTINCT {col_ident}) AS distinct_n")
        select_parts += [f"SUM(CASE WHEN {preds[code]} THEN 1 ELSE 0 END) AS m{i}" for i, code in enumerate(codes)]
        row = engine.query(
            f"SELECT {', '.join(select_parts)} FROM {tbl_ident} "
            f"WHERE {col_ident} IS NOT NULL AND TRIM({col_ident}) <> ''")[0]
        total = row["total"] or 0
        if not total:
            return {code: clf_lib.score_from_ratio(clf_by_code[code], column, dtype, 0.0, 0, [], False)
                    for code in codes}
        distinct_n = (row.get("distinct_n") or 0) if need_distinct else 0

        ratios = {}
        for i, code in enumerate(codes):
            ratio = (row[f"m{i}"] or 0) / total
            if code in enum_codes and distinct_n > 8:
                ratio *= 0.3
            ratios[code] = ratio

        matched_codes = [code for code in codes if ratios[code] > 0]
        samples_by_code: dict[str, list] = {}
        if matched_codes:
            p_alias = {code: f"p{i}" for i, code in enumerate(matched_codes)}
            select2 = [f"{col_ident} AS v"] + [f"CASE WHEN {preds[code]} THEN 1 ELSE 0 END AS {p_alias[code]}"
                                               for code in matched_codes]
            where_or = " OR ".join(preds[code] for code in matched_codes)
            srows = engine.query(
                f"SELECT {', '.join(select2)} FROM {tbl_ident} "
                f"WHERE {col_ident} IS NOT NULL AND TRIM({col_ident}) <> '' AND ({where_or}) LIMIT 50")
            for code in matched_codes:
                alias = p_alias[code]
                samples_by_code[code] = [r["v"] for r in srows if r.get(alias)][:3]

        return {code: clf_lib.score_from_ratio(clf_by_code[code], column, dtype, ratios[code], total,
                                               samples_by_code.get(code, []), False) for code in codes}
    except Exception:
        return {}


def _display(v) -> str:
    return v.strftime("%Y-%m-%d") if hasattr(v, "strftime") else str(v)


def list_scans(limit: int = 20) -> list[dict]:
    return db.query("SELECT * FROM RG_SCAN_JOB ORDER BY scan_id DESC FETCH FIRST :n ROWS ONLY", {"n": limit})


def get_scan(scan_id: int) -> dict | None:
    return db.query_one("SELECT * FROM RG_SCAN_JOB WHERE scan_id=:i", {"i": scan_id})


# --------------------------------------------------------------------------- findings
def list_findings(status: str | None = None, category: str | None = None, table: str | None = None,
                  min_conf: float = 0.0, include_low: bool = False) -> list[dict]:
    sql = ["SELECT f.*, (SELECT STRING_AGG(masked_value, ' | ' ORDER BY sample_id) FROM RG_FINDING_SAMPLE s "
           "WHERE s.finding_id = f.finding_id) AS samples FROM RG_FINDING f "
           "WHERE f.source_id IN (SELECT source_id FROM RG_DATA_SOURCE)"]  # never show an orphaned finding (deleted source)
    p: dict = {}
    if status:
        sql.append("AND f.status = :status")
        p["status"] = status
    elif not include_low:
        sql.append("AND f.status NOT IN ('LOW', 'RESOLVED')")
    if category:
        sql.append("AND f.category = :cat")
        p["cat"] = category
    if table:
        sql.append("AND UPPER(f.table_name) = :tbl")           # case-insensitive match, defensive either way
        p["tbl"] = table.upper()
    if min_conf:
        sql.append("AND f.confidence >= :mc")
        p["mc"] = min_conf
    sql.append("ORDER BY f.table_name, f.confidence DESC, f.column_name")
    return db.query(" ".join(sql), p)


def decide(finding_id: int, status: str, username: str) -> dict:
    if status not in ("CONFIRMED", "REJECTED"):
        raise ValueError("Decision must be CONFIRMED or REJECTED")
    f = db.query_one("SELECT * FROM RG_FINDING WHERE finding_id=:i", {"i": finding_id})
    if not f:
        raise LookupError(f"Finding {finding_id} not found")
    db.execute("UPDATE RG_FINDING SET status=:s, decided_by=:u, decided_at=now(), updated_at=now() "
               "WHERE finding_id=:i", {"s": status, "u": username, "i": finding_id})
    audit(username, "finding", finding_id, status, f"{f['table_name']}.{f['column_name']} as {f['data_element']}")
    return db.query_one("SELECT * FROM RG_FINDING WHERE finding_id=:i", {"i": finding_id})
