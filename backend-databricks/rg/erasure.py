"""GDPR erasure requests (right to be forgotten), the RetentionGuard data-rights workflow in miniature:

  submit  ->  find the person (search classified PII columns, across every data source)  ->  correlate hits into
          one subject  ->  build a dependency-ordered plan (retention and legal holds applied)  ->  approve  ->
          execute  ->  verify

Plan rules
  * Dependents are deleted before the rows they reference (FKs are NO ACTION, on any engine here).
  * A table under an active RETAIN rule keeps that person's rows while they are inside the retention period,
    and so does every table on the path back to the subject. The subject row is then ANONYMISED, not deleted.
  * Derived copies with no declared FK (inferred lineage) are removed.
  * Rows under a legal hold (see holds.py) are left untouched, and so is the person's identity row. Everything else in the
    request carries on, and each skip is written to the audit log. The request is only blocked when nothing is left to do.

Multi-source: a search looks across every registered data source (each with its own catalog.Graph - see
rg/engines/base.py for the control-plane/data-plane split); once a subject is picked, its source_id is fixed for
the rest of that request's lifecycle (stored on RG_ERASURE_REQUEST) and every subsequent step resolves its own
graph/engine from it. The "business number to show alongside a candidate" (e.g. CUSTOMER_NO) is read from a
classified CUSTOMER_NUMBER finding on the root table instead of being hardcoded to one table name, so it works
for any source's customer-equivalent table.
"""
from __future__ import annotations

import json

from . import catalog, db, holds, policy, remediation, scanner, scope, vectorsearch
from .common import audit, sample_mask
from .policy import NotFound, ValidationError

SEARCH_ELEMENTS = ("EMAIL", "PHONE", "FULL_NAME", "LICENSE_ID", "NATIONAL_ID_US")


# --------------------------------------------------------------------------- identity search + correlation
def _key(graph: catalog.Graph, table: str, value):
    dtype = remediation.table_cols(graph.source_id, table)[graph.pk[table]]["data_type"]
    return int(value) if dtype == "NUMBER" else str(value)


def _root_of(graph: catalog.Graph, table: str) -> str:
    """Follow PK-to-PK lineage upward: MKT_CUSTOMER_360 -> CUSTOMER."""
    pk = graph.pk.get(table)
    seen = {table}
    while pk:
        e = next((e for e in graph.edges if e["child_table"] == table and e["child_column"] == pk
                  and e["parent_table"] not in seen), None)
        if not e:
            break
        table = e["parent_table"]
        seen.add(table)
        pk = graph.pk.get(table)
    return table


def _graphs() -> dict[int, catalog.Graph]:
    return {r["source_id"]: catalog.Graph(r["source_id"]) for r in db.query("SELECT source_id FROM RG_DATA_SOURCE")}


def search_hits_in(value: str, graph: catalog.Graph) -> list[dict]:
    """Find rows of one source whose classified PII columns equal `value` (case-insensitive).
    Returns {table, key, column, element}."""
    v = " ".join(value.split())
    engine = graph.engine
    hits: list[dict] = []
    findings = db.query("SELECT table_name, column_name, data_element FROM RG_FINDING WHERE source_id = :s AND category = 'PII' "
                        "AND status IN ('AUTO', 'CONFIRMED') AND confidence >= 0.8", {"s": graph.source_id})
    by_table: dict[str, dict[str, str]] = {}
    for f in findings:
        by_table.setdefault(f["table_name"], {})[f["data_element"]] = f["column_name"]
        if f["data_element"] in SEARCH_ELEMENTS and f["table_name"] in graph.pk:
            pk = engine.ident(graph.pk[f["table_name"]])
            cond = f"UPPER(TRIM({engine.ident(f['column_name'])})) = UPPER(:v)"
            for r in engine.query(f"SELECT {pk} k FROM {engine.ident(f['table_name'])} WHERE {cond}", {"v": v}):
                hits.append({"table": f["table_name"], "key": r["k"], "column": f["column_name"], "element": f["data_element"]})
    for table, els in by_table.items():         # first + last name held in separate columns
        if "FIRST_NAME" in els and "LAST_NAME" in els and table in graph.pk:
            pk = engine.ident(graph.pk[table])
            fn, ln = engine.ident(els["FIRST_NAME"]), engine.ident(els["LAST_NAME"])
            full = engine.concat(f"UPPER(TRIM({fn}))", "' '", f"UPPER(TRIM({ln}))")
            for r in engine.query(f"SELECT {pk} k FROM {engine.ident(table)} WHERE {full} = UPPER(:v)", {"v": v}):
                hits.append({"table": table, "key": r["k"], "column": f"{els['FIRST_NAME']} + {els['LAST_NAME']}", "element": "FULL_NAME"})
    return hits


def search_hits(value: str) -> list[tuple[int, dict]]:
    """Same as search_hits_in, across every data source. Returns (source_id, hit) pairs."""
    out: list[tuple[int, dict]] = []
    for sid, graph in _graphs().items():
        for h in search_hits_in(value, graph):
            out.append((sid, h))
    return out


def find_candidates(value: str) -> list[dict]:
    subjects: dict[tuple, dict] = {}
    graphs = _graphs()
    for sid, h in search_hits(value):
        graph = graphs[sid]
        root = _root_of(graph, h["table"])
        key = (sid, root, str(h["key"]))
        s = subjects.setdefault(key, {"source_id": sid, "root_table": root, "key": h["key"], "found_in": []})
        s["found_in"].append({"table": h["table"], "column": h["column"], "element": h["element"]})
    out = []
    source_names = {r["source_id"]: r["name"] for r in db.query("SELECT source_id, name FROM RG_DATA_SOURCE")}
    for s in subjects.values():
        graph = graphs[s["source_id"]]
        engine = graph.engine
        s["source_name"] = source_names.get(s["source_id"])
        pii = remediation.pii_findings(s["source_id"], s["root_table"], 0.5)
        pk = engine.ident(graph.pk[s["root_table"]])
        row = engine.query_one(f"SELECT * FROM {engine.ident(s['root_table'])} WHERE {pk} = :k", {"k": _key(graph, s["root_table"], s["key"])})
        s["preview"] = {f["column_name"]: sample_mask(_disp(row.get(f["column_name"].lower()))) for f in pii if row and row.get(f["column_name"].lower()) is not None}
        s["country"] = subject_country(graph, s["root_table"], s["key"])
        # shown in clear (not masked): whoever is deciding an erasure needs to see exactly who they are picking.
        # Read from a classified CUSTOMER_NUMBER finding on the root table, whatever that table/column is called.
        number_finding = next((f for f in remediation.pii_findings(s["source_id"], s["root_table"], 0.5) if f["data_element"] == "CUSTOMER_NUMBER"), None)
        s["customer_no"] = row.get(number_finding["column_name"].lower()) if row and number_finding else None
        s["key"] = str(s["key"])
        out.append(s)
    return out


def _disp(v) -> str:
    return v.strftime("%Y-%m-%d") if hasattr(v, "strftime") else str(v)


# --------------------------------------------------------------------------- jurisdiction of a subject
def subject_country(graph: catalog.Graph, root: str, key) -> str | None:
    """ISO code of the country the person belongs to (None when the table gives no country)."""
    jur = graph.jurisdiction_expr(root, "r")
    if not jur:
        return None
    engine = graph.engine
    return engine.scalar(f"SELECT {jur} FROM {engine.ident(root)} r WHERE r.{engine.ident(graph.pk[root])} = :k", {"k": _key(graph, root, key)})


def _customer_number(graph: catalog.Graph, root: str, key) -> str | None:
    """The subject's business customer number, read the same way find_candidates() shows it - used to
    find their documents (vectorsearch.delete_for_customer()) before the row it comes from is deleted or
    anonymised. None when the root table has no classified CUSTOMER_NUMBER column (e.g. erasing an
    AGENT), which simply means there is nothing for vectorsearch to look for."""
    nf = next((f for f in remediation.pii_findings(graph.source_id, root, 0.5) if f["data_element"] == "CUSTOMER_NUMBER"), None)
    if not nf:
        return None
    engine = graph.engine
    row = engine.query_one(f"SELECT {engine.ident(nf['column_name'])} v FROM {engine.ident(root)} WHERE {engine.ident(graph.pk[root])} = :k",
                           {"k": _key(graph, root, key)})
    return str(row["v"]) if row and row.get("v") is not None else None


# --------------------------------------------------------------------------- plan
def build_plan(root: str, key: str, graph: catalog.Graph | None = None) -> dict:
    graph = graph or catalog.Graph(remediation._finding_source(root))
    engine = graph.engine
    if root not in graph.pk:
        raise ValidationError(f"{root} has no single-column primary key in the catalog")
    kv = _key(graph, root, key)
    ix = scope.index()
    rules = [r for r in policy.active_rules(trigger="GDPR_ERASURE_REQUEST") if r["data_category"] == "PII"]
    iso2 = subject_country(graph, root, key)
    plan = {"source_id": graph.source_id, "root_table": root, "root_key": str(key), "blocked": None, "rule": None,
            "level": None, "steps": [], "notes": [],
            "jurisdiction": {"iso2": iso2, "name": (ix.active_iso.get(iso2) or {}).get("name") if iso2 else None}}
    if not rules:
        plan["blocked"] = "No active policy rule authorises erasure (needs an ACTIVE PII policy with an erasure rule)"
        return plan
    applicable = [r for r in rules if ix.applies(r, iso2)]
    if not applicable:
        plan["blocked"] = f"No erasure rule applies to {iso2 or 'a subject with no known country'}"
        return plan
    rule = max(applicable, key=lambda r: (ix.spec(r), -r["rule_id"]))          # the most specific rule wins
    plan["rule"] = {"rule_id": rule["rule_id"], "name": rule["name"], "policy": rule["policy_code"],
                    "action": rule["action"], "cascade_scope": rule["cascade_scope"], "scope": ix.label(rule),
                    "anonymization_level": rule.get("anonymization_level") or "FULL"}
    if len(applicable) > 1:
        plan["notes"].append(f"{len(applicable)} erasure rules cover {iso2 or 'this subject'}; the most specific one "
                             f"({ix.label(rule)}) is used.")
    if not engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(root)} WHERE {engine.ident(graph.pk[root])} = :k", {"k": kv}):
        plan["blocked"] = f"{root} {key} no longer exists"
        return plan

    hidx = holds.index(graph.source_id, fresh=True)       # legal holds: read fresh, this plan may be about to run
    paths = graph.paths_from(root)
    info: dict[str, dict] = {}
    for table, ps in paths.items():
        pred = graph.subject_predicate(table, ps, root)
        total = engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(table)} WHERE {pred}", {"k": kv})
        rc = remediation.retained_cond(graph.source_id, table, "t", graph)
        kept = engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(table)} t WHERE {pred} AND {rc}", {"k": kv}) if rc and total else 0
        hp = hidx.predicate(table, "t")
        held_keys = ([r["k"] for r in engine.query(f"SELECT t.{engine.ident(graph.pk[table])} k FROM {engine.ident(table)} t WHERE {pred} AND {hp}", {"k": kv})]
                     if hp and total else [])
        depth = max(len(p) for p in ps)
        info[table] = {"pred": pred, "total": total, "retained": kept, "depth": depth, "paths": ps,
                       "kinds": {p[-1]["kind"] for p in ps}, "held": len(held_keys), "held_ids": hidx.hold_ids(table, held_keys)}
    root_hold_ids = sorted(hidx.keys(root).get(str(key), {}))
    root_held = bool(root_hold_ids) or any(i["held"] for i in info.values())      # a held row below keeps its parent identity too
    plan["root_held"] = root_held
    plan["hold_ids"] = sorted({h for i in info.values() for h in i["held_ids"]} | set(root_hold_ids))
    plan["held"] = [{"table": t, "rows": i["held"], "holds": i["held_ids"]} for t, i in info.items() if i["held"]]

    keep: dict[str, str] = {}      # table -> reason it must stay
    for table, i in info.items():
        if i["retained"]:
            keep[table] = f"{i['retained']} of {i['total']} row(s) still inside the statutory retention period"
    for table in list(keep):
        for p in info[table]["paths"]:
            for e in p[:-1]:
                if info[e["child_table"]]["total"]:
                    keep.setdefault(e["child_table"], f"holds rows that reference retained data in {table}")
    if rule["cascade_scope"] == "NONE":
        for table, i in info.items():
            if i["total"] and "FK" in i["kinds"] and table not in keep:
                keep[table] = "cascade is switched off for this rule, so dependent rows are left in place"

    anonymise_root = rule["action"] == "ANONYMIZE" or any(info[t]["total"] for t in keep)
    for table in sorted(info, key=lambda t: -info[t]["depth"]):
        i = info[table]
        if not i["total"]:
            continue
        if table in keep:
            plan["steps"].append({"table": table, "operation": "RETAIN", "rows": i["total"], "sql": None,
                                  "reason": keep[table] + (f"; {i['held']} also under legal hold" if i["held"] else "")})
        elif i["held"] >= i["total"]:
            plan["steps"].append({"table": table, "operation": "HELD", "rows": i["held"], "sql": None,
                                  "reason": "under legal hold " + ", ".join(f"#{h}" for h in i["held_ids"]) + ": left untouched"})
        else:
            hp = hidx.predicate(table, None)
            plan["steps"].append({"table": table, "operation": "DELETE", "rows": i["total"] - i["held"],
                                  "sql": engine.delete_stmt(table, "t", i["pred"] + (f" AND NOT {hp}" if hp else "")),
                                  "reason": "derived copy of the person's data (inferred lineage)" if "INFERRED" in i["kinds"]
                                  else "dependent record with no retention requirement",
                                  **({"held_rows": i["held"]} if i["held"] else {})})
    pk = engine.ident(graph.pk[root])
    if root_held:
        first = (next((h for h in hidx.holds if h["root_table"] == root and h["key_value"] == str(key)), None)
                 or next((h for h in hidx.holds if h["hold_id"] in plan["hold_ids"]), None))
        plan["steps"].append({"table": root, "operation": "HELD", "rows": 1, "sql": None,
                              "reason": "the person's identity row stays while records about them are under legal hold"})
        if not any(s["sql"] for s in plan["steps"]):
            plan["blocked"] = (f"Legal hold #{first['hold_id']} ({first.get('entity_label') or root}) covers everything to erase for "
                               f"this person: {first['reason']}. Nothing is changed until it is released." if first else "Legal hold")
            return plan
        plan["notes"].append("Legal hold: held records are left untouched and the person's identity row is kept, so this erasure is "
                             "partial. Everything else is processed. Run the request again after the hold is released.")
    elif anonymise_root:
        level = rule.get("anonymization_level") or "FULL"
        set_clause, info = remediation.anon_plan(engine, graph.source_id, root, level, rule.get("min_confidence") or 0.8, graph.pk[root])
        if not set_clause:
            plan["blocked"] = f"No classified personal columns in {root} to anonymise. Run a scan first."
            return plan
        plan["level"] = level
        plan["steps"].append({"table": root, "operation": "ANONYMIZE", "rows": 1,
                              "sql": engine.update_stmt(root, "t", set_clause, f"t.{pk} = :k"),
                              "reason": f"the row must stay because other records depend on it; identifying values are irreversibly replaced (level {level})",
                              "columns": [i["column"] for i in info if i["treatment"] != "KEEP"], "treatments": info})
        plan["notes"].append("Outcome: identity removed, business records kept where the law requires them.")
    else:
        plan["steps"].append({"table": root, "operation": "DELETE", "rows": 1, "sql": engine.delete_stmt(root, "t", f"t.{pk} = :k"),
                              "reason": "no retained records depend on this person"})
        plan["notes"].append("Outcome: the person and all their data are fully deleted.")
    return plan


# --------------------------------------------------------------------------- request lifecycle
def _row(r: dict) -> dict:
    for k in ("candidates_json", "plan_json", "result_json"):
        r[k[:-5]] = json.loads(r.pop(k)) if r.get(k) else None
    return r


def list_requests() -> list[dict]:
    return db.query("SELECT r.request_id, r.search_value, r.reason, r.status, r.root_table, r.root_key, r.verified, "
                    "r.requested_by, r.approved_by, r.executed_at, r.created_at, r.source_id, d.name AS source_name "
                    "FROM RG_ERASURE_REQUEST r JOIN RG_DATA_SOURCE d ON d.source_id = r.source_id ORDER BY r.request_id DESC")


def get_request(request_id: int) -> dict:
    r = db.query_one("SELECT r.*, d.name AS source_name FROM RG_ERASURE_REQUEST r "
                     "JOIN RG_DATA_SOURCE d ON d.source_id = r.source_id WHERE r.request_id = :i", {"i": request_id})
    if not r:
        raise NotFound(f"Erasure request {request_id} not found")
    r = _row(r)
    r["evidence"] = db.query("SELECT evidence_id, summary, verification, created_by, created_at FROM RG_EVIDENCE "
                             "WHERE ref_type = 'ERASURE' AND ref_id = :i ORDER BY evidence_id", {"i": request_id})
    return r


def _set(request_id: int, **vals) -> None:
    sets = ", ".join(f"{k} = :{k}" for k in vals) + ", updated_at = now()"
    db.execute(f"UPDATE RG_ERASURE_REQUEST SET {sets} WHERE request_id = :rid", {**vals, "rid": request_id})


def create_request(search_value: str, reason: str, username: str) -> dict:
    value = " ".join((search_value or "").split())
    if len(value) < 3:
        raise ValidationError("Enter an email, phone number, licence ID or full name to search for")
    rid = db.insert("RG_ERASURE_REQUEST", {"search_value": value[:200], "reason": reason[:290], "status": "SUBMITTED",
                                           "requested_by": username}, "request_id")
    audit(username, "erasure", rid, "SUBMITTED", reason or "")
    cands = find_candidates(value)         # searches every data source
    if not cands:
        _set(rid, status="NO_MATCH", candidates_json="[]")
    else:
        _set(rid, status="CANDIDATES_FOUND", candidates_json=json.dumps(cands, default=str))
        if len(cands) == 1:
            select_subject(rid, cands[0]["root_table"], cands[0]["key"], username)
    return get_request(rid)


def select_subject(request_id: int, root_table: str, key: str, username: str) -> dict:
    r = get_request(request_id)
    if r["status"] not in ("CANDIDATES_FOUND", "PLAN_READY", "BLOCKED"):
        raise ValidationError(f"Request is {r['status']}: the subject can no longer be changed")
    match = next((c for c in (r["candidates"] or []) if c["root_table"] == root_table and str(c["key"]) == str(key)), None)
    if not match:
        raise ValidationError("That subject is not one of the candidates found for this request")
    graph = catalog.Graph(match["source_id"])
    plan = build_plan(root_table, key, graph)
    _set(request_id, source_id=match["source_id"], root_table=root_table, root_key=str(key), plan_json=json.dumps(plan, default=str),
         status="BLOCKED" if plan["blocked"] else "PLAN_READY")
    audit(username, "erasure", request_id, "SUBJECT_SELECTED", f"{root_table} #{key}")
    if plan["blocked"] and plan.get("hold_ids"):
        audit(username, "legal_hold", plan["hold_ids"][0], "SKIPPED", f"erasure #{request_id}: {plan['blocked']}"[:490])
    return get_request(request_id)


def refresh_plan(request_id: int) -> dict:
    r = get_request(request_id)
    if r["status"] in ("PLAN_READY", "BLOCKED", "APPROVED") and r["root_table"]:
        plan = build_plan(r["root_table"], r["root_key"], catalog.Graph(r["source_id"]))
        _set(request_id, plan_json=json.dumps(plan, default=str), status="BLOCKED" if plan["blocked"] else ("APPROVED" if r["status"] == "APPROVED" else "PLAN_READY"))
    return get_request(request_id)


def approve(request_id: int, username: str) -> dict:
    r = refresh_plan(request_id)
    if r["status"] != "PLAN_READY":
        raise ValidationError(f"Request is {r['status']}: only requests with a ready plan can be approved")
    _set(request_id, status="APPROVED", approved_by=username)
    audit(username, "erasure", request_id, "APPROVED", f"{r['root_table']} #{r['root_key']}")
    return get_request(request_id)


def reject(request_id: int, username: str) -> dict:
    r = get_request(request_id)
    if r["status"] in ("EXECUTED", "REJECTED"):
        raise ValidationError(f"Request is already {r['status']}")
    _set(request_id, status="REJECTED", approved_by=username)
    audit(username, "erasure", request_id, "REJECTED", "")
    return get_request(request_id)


def execute(request_id: int, username: str) -> dict:
    r = get_request(request_id)
    if r["status"] != "APPROVED":
        raise ValidationError("Only APPROVED requests can be executed")
    graph = catalog.Graph(r["source_id"])
    engine = graph.engine
    plan = build_plan(r["root_table"], r["root_key"], graph)
    if plan["blocked"]:
        _set(request_id, status="BLOCKED", plan_json=json.dumps(plan, default=str))
        raise ValidationError(f"Blocked at execution time: {plan['blocked']}")
    kv = _key(graph, r["root_table"], r["root_key"])
    # Read before the transaction below deletes or anonymises the row this comes from.
    customer_no = _customer_number(graph, r["root_table"], r["root_key"])
    done = []
    try:
        with engine.transaction() as conn:
            for s in plan["steps"]:
                if s["sql"]:
                    n = engine.execute(s["sql"], {"k": kv}, conn=conn)
                    done.append({"table": s["table"], "operation": s["operation"], "rows": n, "sql": s["sql"]})
                else:
                    done.append({"table": s["table"], "operation": s["operation"], "rows": s["rows"], "sql": None})
    except Exception as e:  # noqa: BLE001
        _set(request_id, status="APPROVED")
        raise ValidationError(f"Execution failed and was rolled back: {e}")

    # verification: the identifier must no longer resolve to this person, and deleted tables hold none of their rows
    left = [h for h in search_hits_in(r["search_value"], graph)
            if _root_of(graph, h["table"]) == r["root_table"] and str(h["key"]) == str(r["root_key"])]
    stray = 0
    for s in plan["steps"]:
        if s["operation"] == "DELETE" and s["table"] != r["root_table"]:
            paths = graph.paths_from(r["root_table"]).get(s["table"], [])
            hp = holds.predicate(graph.source_id, s["table"], None)
            stray += engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(s['table'])} WHERE {graph.subject_predicate(s['table'], paths, r['root_table'])}"
                                   + (f" AND NOT {hp}" if hp else ""), {"k": kv})
    root_held = bool(plan.get("root_held"))
    verified = (not left or root_held) and stray == 0
    verification = (f"searching again for the identifier finds {len(left)} row(s) for this person; "
                    f"{stray} row(s) remain in deleted tables")
    if root_held:
        verification += "; the identity row and held records are kept under legal hold"
    for h in plan.get("held", []):
        ids = ", ".join(f"#{x}" for x in h["holds"])
        audit(username, "legal_hold", (h["holds"] or [0])[0], "SKIPPED",
              f"erasure #{request_id}: {h['rows']} row(s) of {h['table']} left untouched (legal hold {ids})")
    if root_held:
        audit(username, "legal_hold", (plan.get("hold_ids") or [0])[0], "SKIPPED",
              f"erasure #{request_id}: identity row of {r['root_table']} #{r['root_key']} kept under legal hold; rest processed")
    # Document-side cleanup: the structured erasure above never touched any PDF this person is named in,
    # or its embeddings in the vector-search index - a genuine gap otherwise (see rg/vectorsearch.py's
    # delete_for_customer() docstring). Skipped when a legal hold kept the identity row, for the same
    # reason the structured data is left alone in that case. Never allowed to fail the erasure itself:
    # it runs after the transaction above has already committed.
    doc_cleanup = None
    if customer_no and not root_held:
        try:
            doc_cleanup = vectorsearch.delete_for_customer(customer_no, username)
        except Exception as e:  # noqa: BLE001 - the structured erasure already succeeded; this is best-effort
            doc_cleanup = {"error": str(e)[:300]}

    result = {"steps": done, "verified": verified, "verification": verification, "held": plan.get("held", []), "documents": doc_cleanup}
    masked = sample_mask(r["search_value"])
    _set(request_id, status="EXECUTED", result_json=json.dumps(result, default=str), verified=int(verified),
         search_value=masked)
    db.execute("UPDATE RG_ERASURE_REQUEST SET executed_at = now() WHERE request_id = :i", {"i": request_id})
    doc_note = ""
    if doc_cleanup and doc_cleanup.get("documents_removed"):
        doc_note = (f"; {doc_cleanup['documents_removed']} document(s), {doc_cleanup.get('chunks_removed', 0)} "
                    f"vector chunk(s) and {doc_cleanup.get('files_removed', 0)} file(s) removed")
    db.insert("RG_EVIDENCE", {"ref_type": "ERASURE", "ref_id": request_id,
                              "summary": f"Erasure of {r['root_table']} #{r['root_key']}: " +
                                         "; ".join(f"{d['operation']} {d['table']} ({d['rows']})" for d in done) + doc_note,
                              "statements_json": json.dumps(done, default=str), "verification": verification[:490],
                              "created_by": username}, "evidence_id")
    audit(username, "erasure", request_id, "EXECUTED", f"{r['root_table']} #{r['root_key']} verified={verified}")
    scanner.run_scan_sync(graph.source_id, "FULL", tables=list({s["table"] for s in plan["steps"]}), username=username)
    return get_request(request_id)
