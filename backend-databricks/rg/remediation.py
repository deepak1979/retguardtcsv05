"""Evaluate policies against classification output, and remediate.

  evaluate()      rules x findings  ->  RG_VIOLATION  ->  RG_REMEDIATION_TASK (PROPOSED, with a dry-run plan)
  approve()       a human (admin) approves the plan
  execute()       runs the SQL against the right engine, records evidence, verifies the result

Nothing destructive runs without an APPROVED task. Every plan is regenerated at execution time from the
current data, never replayed from what was stored at proposal time.

Multi-source: RG_* control tables (findings, violations, tasks, evidence, protection) always live in Lakebase and
are read/written with rg/db.py directly - only the SQL that targets a SOURCE table (the data being governed) goes
through an rg/engines Engine, resolved from that row's own source_id. A MASK rule has no single source: it matches
classifier output from every source (policy.rule_findings()), and work is grouped by (source_id, table) so each
group runs against its own engine. A RETAIN / RETENTION_EXPIRY rule names one explicit target_table, whose source
is RG_RULE.source_id (resolved once, at rule save time - see policy._resolve_table).
"""
from __future__ import annotations

import json

from . import archive, catalog, db, engines, holds, policy, scanner, scope
from .common import ANON_LEVELS, ANON_MARKER, anon_treatment, anonymize_expr, audit, describe_treatment, mask_expr
from .engines.base import Engine
from .policy import NotFound, ValidationError


# --------------------------------------------------------------------------- catalog helpers
def source_id() -> int:
    """The default data source. v04 seeds exactly one (source_id 1, see rg/seed.py) - same hardcoded
    fallback every other source_id-less piece of app logic defaults to (rule.get("source_id") or 1,
    snapshot.ensure_snapshot(source_id=1), etc. - see snapshot.delete_source()'s docstring).

    FIX (was a real bug): this used to filter `WHERE source_type = 'ORACLE'`, a leftover from this
    app's earlier multi-engine lineage - since seed.py only ever creates a DATABRICKS row, that query
    always returned None, and this function's one caller (org.jurisdiction_report(), wired to a live
    GET /api/jurisdiction endpoint) crashed every time with "Data source None not found"."""
    return 1


def table_cols(source_id: int, table: str) -> dict[str, dict]:
    rows = db.query("SELECT column_name, data_type, data_length, is_nullable, is_pk FROM RG_CATALOG_COLUMN "
                    "WHERE source_id = :s AND table_name = :t ORDER BY ordinal", {"s": source_id, "t": table})
    return {r["column_name"]: r for r in rows}


def pk_cols(source_id: int, table: str) -> list[str]:
    return [c for c, r in table_cols(source_id, table).items() if r["is_pk"]]


def row_count(engine: Engine, table: str) -> int:
    return engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(table)}")


def pii_findings(source_id: int, table: str, min_conf: float = 0.8) -> list[dict]:
    rows = db.query("SELECT * FROM RG_FINDING WHERE source_id = :s AND table_name = :t AND category = 'PII' "
                    "AND status IN ('AUTO','CONFIRMED') AND confidence >= :m ORDER BY confidence DESC",
                    {"s": source_id, "t": table, "m": min_conf})
    seen, out = set(), []
    for r in rows:
        if r["column_name"] not in seen:
            seen.add(r["column_name"])
            out.append(r)
    return out


def marker_column(source_id: int, table: str) -> str | None:
    """A NOT NULL name column that anonymisation overwrites with ERASED - lets us tell anonymised rows apart."""
    cols = table_cols(source_id, table)
    for f in pii_findings(source_id, table, 0.5):
        c = cols.get(f["column_name"])
        if f["data_element"] in ("FIRST_NAME", "LAST_NAME", "FULL_NAME") and c and not c["is_nullable"]:
            return f["column_name"]
    return None


def anon_findings(source_id: int, table: str, min_conf: float = 0.8) -> list[dict]:
    """Classified columns that an anonymisation may touch: personal data, plus personal financial quasi-identifiers."""
    rows = db.query("SELECT * FROM RG_FINDING WHERE source_id = :s AND table_name = :t AND category IN ('PII', 'FINANCIAL') "
                    "AND pii_class IN ('DIRECT', 'IDENTIFIER', 'QUASI') AND status IN ('AUTO','CONFIRMED') "
                    "AND confidence >= :m ORDER BY confidence DESC, column_name", {"s": source_id, "t": table, "m": min_conf})
    seen, out = set(), []
    for r in rows:
        if r["column_name"] not in seen:
            seen.add(r["column_name"])
            out.append(r)
    return out


def anon_plan(engine: Engine, source_id: int, table: str, level: str, min_conf: float, pk_col: str | None) -> tuple[str, list[dict]]:
    """(SET clause, per-column treatment) for anonymising `table` at `level`."""
    level = level if level in ANON_LEVELS else "FULL"
    cols = table_cols(source_id, table)
    parts, info = [], []
    for f in anon_findings(source_id, table, min_conf):
        c = cols[f["column_name"]]
        t = anon_treatment(f["data_element"], f["pii_class"], level)
        expr = anonymize_expr(engine, f["column_name"], f["data_element"], c["data_type"], bool(c["is_nullable"]),
                              c["data_length"], t, pk_col)
        info.append({"column": f["column_name"], "element": f["data_element"], "confidence": f["confidence"],
                     "treatment": t, "note": describe_treatment(f["data_element"], t)})
        if expr is not None:
            parts.append(f"{engine.ident(f['column_name'])} = {expr}")
    return ", ".join(parts), info


# --------------------------------------------------------------------------- retention conditions (shared with erasure)
def retained_cond(source_id: int, table: str, alias: str, graph: catalog.Graph | None = None) -> str | None:
    """SQL condition true for rows of `table` still protected by an active RETAIN rule.

    With region / country policies the retention period depends on the country the row belongs to, so the condition
    becomes a CASE over that country (and collapses to the plain condition when every rule is global)."""
    rules = [r for r in policy.active_rules(action="RETAIN") if r["target_table"] == table and (r.get("source_id") or 1) == source_id]
    if not rules:
        return None
    g = graph or catalog.Graph(source_id)
    engine = g.engine
    branches, default = scope.index().branches(rules, scope.retention_kind)

    def cond(rs: list[dict]) -> str:
        if not rs:
            return "1 = 0"
        parts = []
        for r in rs:
            a = engine.ident(r["anchor_column"])
            parts.append(f"({alias}.{a} IS NULL OR {alias}.{a} > {engine.date_sub_days(engine.now(), int(r['retention_days']))})")
        return "(" + " OR ".join(parts) + ")"

    jur = g.jurisdiction_expr(table, alias) if branches else None
    if not branches or not jur:                 # no country-specific rules, or rows with no known country: global rules only
        return cond(default)
    whens = " ".join(f"WHEN {jur} IN ({scope.sql_list(cs)}) THEN CASE WHEN {cond(rs)} THEN 1 ELSE 0 END" for cs, rs in branches)
    return f"(CASE {whens} ELSE CASE WHEN {cond(default)} THEN 1 ELSE 0 END END = 1)"


def retention_where(rule: dict, graph: catalog.Graph, alias: str = "t", include_holds: bool = True) -> str:
    """WHERE clause for the rows a RETENTION_EXPIRY rule may act on, after applying precedence."""
    table = rule["target_table"]
    engine = graph.engine
    anchor = engine.ident(rule["anchor_column"])
    parts = [f"{alias}.{anchor} < {engine.date_sub_days(engine.now(), int(rule['retention_days']))}"]
    rc = retained_cond(graph.source_id, table, alias, graph)
    if rc:
        parts.append(f"NOT {rc}")                                    # RETAIN outranks expiry actions
    same_kind = [r for r in policy.active_rules(trigger="RETENTION_EXPIRY")
                if r["target_table"] == table and r["action"] == rule["action"] and (r.get("source_id") or 1) == graph.source_id]
    spec = scope.index().rule_countries(rule, same_kind, scope.retention_kind)   # where does THIS rule act?
    if spec is not None:
        jur = graph.jurisdiction_expr(table, alias)
        pred = scope.country_predicate(jur, spec) if jur else ("1 = 0" if (rule.get("scope_level") or "GLOBAL") != "GLOBAL" else None)
        if pred:
            parts.append(pred)
    if include_holds:
        hp = holds.predicate(graph.source_id, table, alias)
        if hp:
            parts.append(f"NOT {hp}")
    if rule["action"] == "ANONYMIZE":
        marker = marker_column(graph.source_id, table)
        if marker:
            marker_col, sql_x = f"{alias}.{engine.ident(marker)}", "'x'"
            parts.append(f"{engine.nvl(marker_col, sql_x)} <> '{ANON_MARKER}'")
        for dtable, paths in graph.paths_from(table).items():
            rc_d = retained_cond(graph.source_id, dtable, "{a}", graph)
            if rc_d:
                for path in paths:
                    parts.append("NOT " + graph.exists_from_row(path, alias, rc_d))
    return " AND ".join(parts)


def expired_count(rule: dict, graph: catalog.Graph) -> int:
    engine = graph.engine
    return engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(rule['target_table'])} t WHERE {retention_where(rule, graph)}")


# --------------------------------------------------------------------------- plans (dry run)
def _rule_info(rule: dict) -> dict:
    return {"rule_id": rule["rule_id"], "rule": rule["name"], "policy": rule.get("policy_code"), "action": rule["action"],
            "scope": scope.index().label(rule), "scope_level": rule.get("scope_level") or "GLOBAL"}


def _protected(rule_id: int, source_id: int, table: str, column: str) -> bool:
    return bool(db.scalar("SELECT COUNT(*) FROM RG_PROTECTION WHERE rule_id = :r AND source_id = :s AND table_name = :t AND column_name = :c",
                          {"r": rule_id, "s": source_id, "t": table, "c": column}))


def _mask_spec(rule: dict):
    """The countries a MASK rule acts on after overrides: None = everywhere, else ('IN'|'NOT_IN', set of ISO codes)."""
    same = [r for r in policy.active_rules(action="MASK") if r["trigger_event"] == "ALWAYS"]
    return scope.index().rule_countries(rule, same, scope.category_kind)


def scope_rows(rule: dict, table: str, graph: catalog.Graph) -> int | None:
    """Rows of `table` inside a scoped MASK rule's countries. None when the rule acts everywhere."""
    spec = _mask_spec(rule)
    if spec is None:
        return None
    engine = graph.engine
    jur = graph.jurisdiction_expr(table, "t")
    pred = scope.country_predicate(jur, spec) if jur else "1 = 0"
    return engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(table)} t WHERE {pred}") if pred else None


def _strongest(entries: list[dict]) -> dict | None:
    if not entries:
        return None
    return max(entries, key=lambda e: (scope.METHOD_STRENGTH.get(e["method"], 0), scope.SPECIFICITY[e.get("scope_level") or "GLOBAL"]))


def _column_mask_expr(engine: Engine, name: str, entries: list[dict], cdef: dict, jur: str | None) -> str:
    """One column of a masked view: the strongest applicable method for the row's country, or the raw value."""
    branches, default = scope.index().branches(entries, scope.category_kind)

    def m(e: dict | None) -> str:
        return engine.ident(name) if e is None else mask_expr(engine, name, e["element"], e["method"], cdef["data_type"],
                                                               bool(cdef["is_nullable"]), cdef["data_length"])
    base = m(_strongest(default))
    if not branches or not jur:
        return base
    whens = " ".join(f"WHEN {jur} IN ({scope.sql_list(cs)}) THEN {m(_strongest(rs))}" for cs, rs in branches)
    return f"CASE {whens} ELSE {base} END"


def plan_mask(rule: dict, sid: int, table: str) -> dict:
    graph = catalog.Graph(sid)
    engine = graph.engine
    fnds = [f for f in policy.rule_findings(rule["data_category"], rule)
            if f["source_id"] == sid and f["table_name"] == table and not _protected(rule["rule_id"], sid, table, f["column_name"])]
    cols = table_cols(sid, table)
    mode = rule.get("enforcement_mode") or "VIEW"
    method = rule["masking_method"]
    spec = _mask_spec(rule)
    jur_t = graph.jurisdiction_expr(table, "t")
    plan = {"kind": "MASK", **_rule_info(rule), "source_id": sid, "table": table, "mode": mode, "method": method,
            "blocked": None, "notes": [], "steps": [], "scope_filter": None,
            "columns": [{"column": f["column_name"], "element": f["data_element"], "confidence": f["confidence"]} for f in fnds]}
    if spec is not None:
        plan["scope_filter"] = {"mode": spec[0], "codes": sorted(spec[1])}
    if not fnds:
        plan["blocked"] = "No unprotected classified columns remain in this table"
        return plan
    in_scope = row_count(engine, table)
    if spec is not None:
        info = graph.jurisdiction_info(table)
        if not jur_t:
            plan["blocked"] = (f"{table} has no country column and no link to one, so a rule scoped to {plan['scope']} "
                               f"cannot tell which rows it covers")
            return plan
        pred = scope.country_predicate(jur_t, spec)
        in_scope = engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(table)} t WHERE {pred}") if pred else in_scope
        if not in_scope:
            plan["blocked"] = f"No rows of {table} belong to {plan['scope']}, so there is nothing to mask"
            return plan
        plan["notes"].append(f"Scoped to {plan['scope']}: applies to {in_scope} of {row_count(engine, table)} rows "
                             f"(country taken from {info['country_table']}.{info['country_column']}). "
                             f"Rows of other countries are not touched by this rule.")

    if mode == "VIEW":
        rules_by_id = {r["rule_id"]: r for r in policy.active_rules(action="MASK")}
        entries: dict[str, list[dict]] = {}
        new_cols = {f["column_name"] for f in fnds}
        for pr in db.query("SELECT column_name, method, data_element, rule_id FROM RG_PROTECTION "
                           "WHERE source_id = :s AND table_name = :t AND protect_mode = 'VIEW'", {"s": sid, "t": table}):
            r = rules_by_id.get(pr["rule_id"])
            if not r:
                continue
            if pr["rule_id"] == rule["rule_id"] and pr["column_name"] in new_cols:
                continue
            entries.setdefault(pr["column_name"], []).append({**r, "method": pr["method"], "element": pr["data_element"]})
        for f in fnds:
            entries.setdefault(f["column_name"], []).append({**rule, "method": method, "element": f["data_element"]})
        jur_view = graph.jurisdiction_expr(table, "t")
        select = []
        for name, c in cols.items():
            select.append(f"{_column_mask_expr(engine, name, entries[name], c, jur_view)} AS {engine.ident(name)}" if name in entries else engine.ident(name))
        view = engine.view_name(table)
        plan["view"] = view
        plan["steps"].append({"table": view, "operation": "CREATE VIEW", "est_rows": in_scope, "columns": list(entries),
                              "sql": "SELECT " + ", ".join(select) + f" FROM {engine.ident(table)} t"})
        plan["notes"].append(f"Non-destructive: source rows are untouched. Consumers should read {view} instead of {table}.")
        if any(len({e['rule_id'] for e in es}) > 1 for es in entries.values()):
            plan["notes"].append("Several policies mask the same column: for each row the strongest method of the policies "
                                 "that apply to its country is used.")
    else:
        sets = ", ".join(f"{engine.ident(f['column_name'])} = " + mask_expr(engine,
            f["column_name"], f["data_element"], method, cols[f["column_name"]]["data_type"],
            bool(cols[f["column_name"]]["is_nullable"]), cols[f["column_name"]]["data_length"]) for f in fnds)
        conds = []
        if spec is not None and scope.country_predicate(jur_t, spec):
            conds.append(scope.country_predicate(jur_t, spec))
        hp = holds.predicate(sid, table, "t")
        held_n = 0
        if hp:                                                        # legal hold: held rows are not overwritten
            held_n = engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(table)} t WHERE " + " AND ".join(conds + [hp]))
            conds.append(f"NOT {hp}")
            plan["held_rows"] = held_n
            plan["hold_ids"] = holds.index(sid).hold_ids(table, [r["k"] for r in engine.query(
                f"SELECT t.{engine.ident(graph.pk[table])} k FROM {engine.ident(table)} t WHERE " + " AND ".join(conds[:-1] + [hp]))]) if table in graph.pk else []
        where = " AND ".join(conds) if conds else None
        plan["steps"].append({"table": table, "operation": "UPDATE", "est_rows": in_scope - held_n,
                              "columns": [f["column_name"] for f in fnds], "sql": engine.update_stmt(table, "t", sets, where)})
        plan["notes"].append(f"DESTRUCTIVE: values are overwritten in place. A snapshot exists as {engine.backup_name(table)}.")
        if held_n:
            plan["notes"].append(f"{held_n} row(s) of {table} are under legal hold and are not overwritten.")
    return plan


def plan_retention(rule: dict, graph: catalog.Graph) -> dict:
    table, action, engine = rule["target_table"], rule["action"], graph.engine
    plan = {"kind": "RETENTION", **_rule_info(rule), "source_id": graph.source_id, "table": table, "mode": action,
            "blocked": None, "notes": [], "steps": [], "columns": []}
    where = retention_where(rule, graph)
    n = engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(table)} t WHERE {where}")
    if plan["scope_level"] != "GLOBAL":
        plan["notes"].append(f"Scoped to {plan['scope']}: only rows belonging to that jurisdiction are considered.")
    plan["notes"].append(f"{n} row(s) of {table} are older than {rule['retention_days']} days on {rule['anchor_column']} "
                         f"and not protected by a retention rule or legal hold.")
    hp = holds.predicate(graph.source_id, table, "t")
    if hp and table in graph.pk:                                     # expired rows that a legal hold keeps out
        held = engine.query(f"SELECT t.{engine.ident(graph.pk[table])} k FROM {engine.ident(table)} t WHERE "
                            f"{retention_where(rule, graph, include_holds=False)} AND {hp}")
        if held:
            plan["held_rows"] = len(held)
            plan["hold_ids"] = holds.index(graph.source_id).hold_ids(table, [r["k"] for r in held])
            plan["notes"].append(f"{len(held)} more expired row(s) are under legal hold and are left untouched.")
    if n == 0:
        plan["blocked"] = "Nothing to do: no expired rows" + (f" outside legal hold ({plan['held_rows']} held)" if plan.get("held_rows") else "")
        return plan
    if action == "DELETE":
        for e in graph.children(table):
            dep = engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(e['child_table'])} WHERE {engine.ident(e['child_column'])} IN "
                                f"(SELECT {engine.ident(e['parent_column'])} FROM {engine.ident(table)} t WHERE {where})")
            if dep:
                plan["blocked"] = (f"{dep} dependent row(s) in {e['child_table']} reference these rows; deleting would "
                                   f"violate {e['child_table']}.{e['child_column']}. Use ANONYMIZE or remove the dependents first.")
                return plan
        plan["steps"].append({"table": table, "operation": "DELETE", "est_rows": n, "columns": [],
                              "sql": engine.delete_stmt(table, "t", where)})
    elif action == "ARCHIVE":
        for e in graph.children(table):
            dep = engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(e['child_table'])} WHERE {engine.ident(e['child_column'])} IN "
                                f"(SELECT {engine.ident(e['parent_column'])} FROM {engine.ident(table)} t WHERE {where})")
            if dep:
                plan["blocked"] = (f"{dep} dependent row(s) in {e['child_table']} reference these rows; archiving would "
                                   f"violate {e['child_table']}.{e['child_column']}. Remove the dependents first.")
                return plan
        pk = graph.pk.get(table)
        select = f"SELECT * FROM {engine.ident(table)} t WHERE {where}"
        plan["steps"].append({"table": table, "operation": "ARCHIVE", "est_rows": n, "columns": [],
                              "select_sql": select, "sql": engine.delete_stmt(table, "t", where),
                              "primary_key_column": pk})
        plan["notes"].append(f"Every matching row is exported to a JSON file under archive/{table}/<year>/<month>/ "
                             "before being deleted - not overwritten in place, not simply dropped. "
                             "The exact file is recorded on the task's evidence once it runs.")
    else:
        level = rule.get("anonymization_level") or "FULL"
        pk = graph.pk.get(table)
        set_clause, info = anon_plan(engine, graph.source_id, table, level, rule.get("min_confidence") or 0.8, pk)
        if not set_clause:
            plan["blocked"] = f"No classified personal columns in {table} to anonymise at level {level}. Run a scan and confirm findings first."
            return plan
        plan["level"] = level
        for e in graph.children(table):     # derived copies (no declared FK) hold the same person - remove them first
            if e["kind"] == "INFERRED" and not retained_cond(graph.source_id, e["child_table"], "x", graph) and pk:
                cnt = engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(e['child_table'])} WHERE {engine.ident(e['child_column'])} IN "
                                    f"(SELECT {engine.ident(e['parent_column'])} FROM {engine.ident(table)} t WHERE {where})")
                plan["steps"].append({"table": e["child_table"], "operation": "DELETE", "est_rows": cnt, "columns": [],
                                      "sql": f"DELETE FROM {engine.ident(e['child_table'])} WHERE {engine.ident(e['child_column'])} IN "
                                             f"(SELECT {engine.ident(e['parent_column'])} FROM {engine.ident(table)} t WHERE {where})"})
                plan["notes"].append(f"{e['child_table']} is a derived copy of {table} (inferred lineage): its rows for these people are removed too.")
        plan["notes"].append(f"Anonymisation level {level}: " + {"BASIC": "direct identifiers only.", "GENERALISE": "quasi-identifiers coarsened or removed.",
                                                                 "FULL": "direct and quasi-identifiers removed."}.get(level, ""))
        plan["columns"] = info
        plan["steps"].append({"table": table, "operation": "UPDATE (anonymise)", "est_rows": n,
                              "columns": [i["column"] for i in info if i["treatment"] != "KEEP"],
                              "sql": engine.update_stmt(table, "t", set_clause, where)})
    return plan


def build_plan(rule: dict, table: str | None = None, graph: catalog.Graph | None = None) -> dict:
    """`table` is only needed for MASK rules (one plan per table a rule matches); a RETAIN/RETENTION_EXPIRY rule
    already names its one target_table + source via RG_RULE."""
    if rule["action"] == "MASK":
        sid = (graph.source_id if graph else None) or _finding_source(table)
        return plan_mask(rule, sid, table)
    if rule["trigger_event"] == "RETENTION_EXPIRY":
        g = graph or catalog.Graph(rule.get("source_id") or 1)
        return plan_retention(rule, g)
    raise ValidationError("This rule does not produce remediation tasks")


def _finding_source(table: str) -> int:
    """Which source a (MASK-matched) table belongs to - tables are unique per source in practice, so the
    first match is unambiguous."""
    row = db.query_one("SELECT source_id FROM RG_CATALOG_TABLE WHERE table_name = :t", {"t": table})
    if not row:
        raise ValidationError(f"{table} is not in any data source's catalog")
    return row["source_id"]


# --------------------------------------------------------------------------- evaluation
def evaluable_rules() -> list[dict]:
    """Policies and rules evaluate() can act on right now: active rules of active policies, valid for the active
    organisation (the same universe active_rules() resolves to). Used to build the selection picker.

    Each rule carries the source it will actually run against, so the picker can show it: RETENTION_EXPIRY
    rules always target one fixed source_id (default 1, same fallback evaluate() uses) and target_table;
    MASK rules don't have a fixed source at all - they match wherever their data_category's findings turn up,
    across every source - so source_name is None for those rather than a misleading single value."""
    source_names = {s["source_id"]: s["name"] for s in db.query("SELECT source_id, name FROM RG_DATA_SOURCE")}
    by_policy: dict[int, dict] = {}
    for r in policy.active_rules():
        p = by_policy.setdefault(r["policy_id"], {
            "policy_id": r["policy_id"], "policy_code": r["policy_code"], "policy_name": r["policy_name"],
            "data_category": r["data_category"], "scope_level": r.get("scope_level") or "GLOBAL",
            "scope": scope.index().label(r), "rules": []})
        if r["trigger_event"] == "RETENTION_EXPIRY":
            source_name = source_names.get(r.get("source_id") or 1)
            target_table = r.get("target_table")
        else:
            source_name, target_table = None, None
        p["rules"].append({"rule_id": r["rule_id"], "name": r["name"], "trigger_event": r["trigger_event"],
                           "action": r["action"], "source_name": source_name, "target_table": target_table})
    return sorted(by_policy.values(), key=lambda p: p["policy_code"])


def evaluate(username: str, rule_ids: set[int] | None = None, source_id: int | None = None) -> dict:
    """rule_ids=None evaluates every active rule (the normal run). A set restricts evaluation to just those rules:
    only their violations are raised, resolved or turned into tasks - everything outside the selection is left as is.

    source_id further restricts evaluation to just that data source, same "leave everything outside the
    selection untouched" principle - composes with rule_ids. A RETENTION_EXPIRY rule has one fixed source
    (RG_RULE.source_id), so a non-matching rule is simply skipped entirely, same as being outside rule_ids.
    A MASK rule has no fixed source - its findings can span every source - so the rule itself still runs,
    but only the selected source's (source_id, table) groups raise/resolve violations; other sources'
    existing violations for that same rule are left exactly as they were, not resolved as "no longer seen"."""
    graphs: dict[int, catalog.Graph] = {}

    def graph_for(sid: int) -> catalog.Graph:
        if sid not in graphs:
            graphs[sid] = catalog.Graph(sid)
        return graphs[sid]

    all_rules = policy.active_rules()
    if rule_ids is not None:
        considered = [r for r in all_rules if r["rule_id"] in rule_ids]
        if not considered:
            raise ValidationError("None of the selected rules are active right now. Activate their policy, or pick different rules.")
    else:
        considered = all_rules
    if source_id is not None:
        considered = [r for r in considered
                     if r["action"] == "MASK" or (r.get("source_id") or 1) == source_id]
        if not considered:
            raise ValidationError("None of the selected rules apply to that data source.")
    considered_ids = {r["rule_id"] for r in considered}
    seen: set[tuple] = set()          # (rule_id, source_id, table)
    for rule in considered:
        if rule["action"] == "MASK":
            by_table: dict[tuple[int, str], list[dict]] = {}
            for f in policy.rule_findings(rule["data_category"], rule):
                if source_id is not None and f["source_id"] != source_id:
                    continue                                   # this rule also covers other sources - not this run
                by_table.setdefault((f["source_id"], f["table_name"]), []).append(f)
            for (sid, table), fl in by_table.items():
                unprot = [f for f in fl if not _protected(rule["rule_id"], sid, table, f["column_name"])]
                in_scope = scope_rows(rule, table, graph_for(sid))          # None = the rule acts everywhere
                if unprot and in_scope != 0:                       # a scoped rule with no rows in its countries has nothing to do
                    seen.add((rule["rule_id"], sid, table))
                    where = f" for {scope.index().label(rule)}" if (rule.get("scope_level") or "GLOBAL") != "GLOBAL" else ""
                    _upsert_violation(rule, sid, "UNPROTECTED_DATA", table,
                                      f"{len(unprot)} of {len(fl)} {rule['data_category']} column(s) in {table} are readable unmasked{where}",
                                      [f"{f['column_name']} ({f['data_element']})" for f in unprot],
                                      row_count(graph_for(sid).engine, table) if in_scope is None else in_scope)
        elif rule["trigger_event"] == "RETENTION_EXPIRY":
            sid = rule.get("source_id") or 1
            n = expired_count(rule, graph_for(sid))
            if n:
                seen.add((rule["rule_id"], sid, rule["target_table"]))
                _upsert_violation(rule, sid, "RETENTION_EXPIRED", rule["target_table"],
                                  f"{n} row(s) past {rule['retention_days']} days on {rule['anchor_column']} - action: {rule['action']}",
                                  [rule["anchor_column"]], n)
    resolved = 0
    for v in db.query("SELECT violation_id, rule_id, source_id, table_name FROM RG_VIOLATION WHERE status = 'OPEN'"):
        if v["rule_id"] not in considered_ids:
            continue                                          # a rule outside the selection: leave its violations untouched
        if source_id is not None and v["source_id"] != source_id:
            continue                                          # a different source under the same (MASK) rule: untouched
        if (v["rule_id"], v["source_id"], v["table_name"]) not in seen:
            db.execute("UPDATE RG_VIOLATION SET status='RESOLVED', resolved_at=now() WHERE violation_id=:i", {"i": v["violation_id"]})
            resolved += 1
    created = 0
    rules_by_id = {r["rule_id"]: r for r in all_rules}
    for v in db.query("""SELECT * FROM RG_VIOLATION v WHERE v.status = 'OPEN' AND NOT EXISTS (
                            SELECT 1 FROM RG_REMEDIATION_TASK t WHERE t.violation_id = v.violation_id
                            AND t.status IN ('PROPOSED', 'APPROVED', 'REJECTED'))"""):
        if v["rule_id"] not in considered_ids:
            continue
        if source_id is not None and v["source_id"] != source_id:
            continue
        rule = rules_by_id.get(v["rule_id"])
        if rule:
            _create_task(v, rule, username, graph_for(v["source_id"]))
            created += 1
    open_n = db.scalar("SELECT COUNT(*) FROM RG_VIOLATION WHERE status = 'OPEN'")
    scope_bits = []
    if rule_ids is not None:
        scope_bits.append(f"{len(considered)} of {len(all_rules)} active rule(s)")
    if source_id is not None:
        name = db.scalar("SELECT name FROM RG_DATA_SOURCE WHERE source_id = :s", {"s": source_id})
        scope_bits.append(f"source: {name or source_id}")
    scope_note = f" - selective run, {', '.join(scope_bits)}" if scope_bits else ""
    audit(username, "evaluation", None, "EVALUATE", f"{open_n} open violation(s), {created} task(s) proposed, {resolved} resolved{scope_note}")
    return {"open_violations": open_n, "tasks_proposed": created, "resolved": resolved, "rules_evaluated": len(considered), "rules_total": len(all_rules)}


def _upsert_violation(rule: dict, source_id: int, vtype: str, table: str, detail: str, columns: list[str], rows: int) -> None:
    vals = {"detail": detail[:990], "columns_json": json.dumps(columns)[:1990], "rows_affected": rows, "vtype": vtype}
    cur = db.query_one("SELECT violation_id FROM RG_VIOLATION WHERE rule_id = :r AND source_id = :s AND table_name = :t",
                       {"r": rule["rule_id"], "s": source_id, "t": table})
    if cur:
        db.execute("UPDATE RG_VIOLATION SET detail=:detail, columns_json=:columns_json, rows_affected=:rows_affected, "
                   "violation_type=:vtype, status='OPEN', resolved_at=NULL WHERE violation_id=:i",
                   {**vals, "i": cur["violation_id"]})
    else:
        db.insert("RG_VIOLATION", {"policy_id": rule["policy_id"], "rule_id": rule["rule_id"], "source_id": source_id,
                                   "violation_type": vtype, "table_name": table, "detail": vals["detail"],
                                   "columns_json": vals["columns_json"], "rows_affected": rows}, "violation_id")


def _task_title(rule: dict, table: str, plan: dict, rows: int) -> str:
    if rule["action"] == "MASK":
        t = (f"Mask {len(plan['columns'])} {rule['data_category']} column(s) in {table} "
             f"({rule['masking_method'].lower()}, {'masked view' if plan['mode'] == 'VIEW' else 'in place'})")
    elif rule["action"] == "DELETE":
        t = f"Delete expired rows from {table} ({rows} rows)"
    elif rule["action"] == "ARCHIVE":
        t = f"Archive expired rows from {table} ({rows} rows)"
    else:
        t = f"Anonymise expired rows in {table} ({rows} rows)"
    sc = plan.get("scope")
    return f"{t} - {sc}" if sc and plan.get("scope_level") != "GLOBAL" else t


def _create_task(v: dict, rule: dict, username: str, graph: catalog.Graph) -> int:
    plan = build_plan(rule, v["table_name"], graph)
    title = _task_title(rule, v["table_name"], plan, v["rows_affected"])
    tid = db.insert("RG_REMEDIATION_TASK", {"violation_id": v["violation_id"], "rule_id": rule["rule_id"], "source_id": v["source_id"],
                                            "action": rule["action"], "table_name": v["table_name"], "title": title[:198],
                                            "status": "PROPOSED", "plan_json": json.dumps(plan, default=str), "requested_by": username},
                    "task_id")
    audit(username, "task", tid, "PROPOSED", title)
    return tid


# --------------------------------------------------------------------------- tasks
def _task_row(t: dict) -> dict:
    for k in ("plan_json", "result_json"):
        t[k[:-5]] = json.loads(t.pop(k)) if t.get(k) else None
    return t


def list_violations(status: str | None = None) -> list[dict]:
    sql = ("SELECT v.*, p.policy_code, p.name AS policy_name, r.name AS rule_name, d.name AS source_name, "
           "(SELECT MAX(task_id) FROM RG_REMEDIATION_TASK t WHERE t.violation_id = v.violation_id) AS task_id "
           "FROM RG_VIOLATION v JOIN RG_POLICY p ON p.policy_id = v.policy_id JOIN RG_RULE r ON r.rule_id = v.rule_id "
           "JOIN RG_DATA_SOURCE d ON d.source_id = v.source_id")
    params = {}
    if status:
        sql += " WHERE v.status = :s"
        params["s"] = status
    rows = db.query(sql + " ORDER BY v.violation_id", params)
    for r in rows:
        r["columns"] = json.loads(r.pop("columns_json") or "[]")
    return rows


def list_tasks(status: str | None = None) -> list[dict]:
    sql = ("SELECT t.task_id, t.violation_id, t.rule_id, t.source_id, d.name AS source_name, t.action, t.table_name, "
          "t.title, t.status, t.verified, t.requested_by, t.approved_by, t.executed_at, t.created_at, t.note "
          "FROM RG_REMEDIATION_TASK t JOIN RG_DATA_SOURCE d ON d.source_id = t.source_id")
    params = {}
    if status:
        sql += " WHERE t.status = :s"
        params["s"] = status
    return db.query(sql + " ORDER BY t.task_id DESC", params)


def get_task(task_id: int) -> dict:
    t = db.query_one("SELECT * FROM RG_REMEDIATION_TASK WHERE task_id = :i", {"i": task_id})
    if not t:
        raise NotFound(f"Task {task_id} not found")
    t = _task_row(t)
    t["evidence"] = db.query("SELECT evidence_id, summary, verification, created_by, created_at FROM RG_EVIDENCE "
                             "WHERE ref_type = 'TASK' AND ref_id = :i ORDER BY evidence_id", {"i": task_id})
    return t


def preview_rows(task_id: int, limit: int = 20) -> dict:
    """The actual rows a DELETE/ARCHIVE task's dry-run plan would act on, for a quick human check before
    approving - the primary key, the rule's own anchor date, and up to a few more columns, never a column
    already classified as PII/PHI (an approver reviewing "will this delete the right rows" needs enough to
    recognise them, not a second PII exposure). Reuses retention_where() - the exact predicate execute()
    will run - so what's shown here is never a separate guess at what the plan means."""
    t = get_task(task_id)
    if t["action"] not in ("DELETE", "ARCHIVE"):
        raise ValidationError("Row preview is only available for DELETE and ARCHIVE tasks")
    rule = db.query_one("SELECT * FROM RG_RULE WHERE rule_id = :i", {"i": t["rule_id"]})
    if not rule or rule["trigger_event"] != "RETENTION_EXPIRY":
        raise ValidationError("Row preview is only available for retention-expiry rules")
    graph = catalog.Graph(t["source_id"])
    engine = graph.engine
    table = t["table_name"]
    if table not in graph.pk:
        raise ValidationError(f"{table} has no single-column primary key in the catalog")
    where = retention_where(rule, graph)

    pii_cols = {f["column_name"] for f in db.query(
        "SELECT column_name FROM RG_FINDING WHERE source_id = :s AND table_name = :t AND category IN ('PII', 'PHI') "
        "AND status IN ('AUTO', 'CONFIRMED')", {"s": t["source_id"], "t": table})}
    cat_cols = [c["column_name"] for c in db.query(
        "SELECT column_name FROM RG_CATALOG_COLUMN WHERE source_id = :s AND table_name = :t ORDER BY ordinal",
        {"s": t["source_id"], "t": table})]
    picked = [c for c in (graph.pk[table], rule.get("anchor_column")) if c]
    for name in cat_cols:
        if len(picked) >= 6:
            break
        if name not in picked and name not in pii_cols:
            picked.append(name)
    masked = [c for c in cat_cols if c in pii_cols]

    select = ", ".join(engine.ident(c) for c in picked)
    n = max(1, min(int(limit), 100))
    sql = f"SELECT {select} FROM {engine.ident(table)} t WHERE {where} FETCH FIRST {n} ROWS ONLY"
    rows = engine.query(sql)
    total = engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(table)} t WHERE {where}")
    return {"table": table, "columns": picked, "masked_columns": masked,
           "rows": [[r.get(c.lower()) for c in picked] for r in rows], "total": total, "shown": len(rows)}


def refresh_plan(task_id: int) -> dict:
    """Dry run: regenerate the plan from current data."""
    t = get_task(task_id)
    if t["status"] not in ("PROPOSED", "APPROVED"):
        return t
    rule = next((r for r in policy.active_rules() if r["rule_id"] == t["rule_id"]), None)
    if not rule:
        raise ValidationError("The rule behind this task is no longer active")
    plan = build_plan(rule, t["table_name"], catalog.Graph(t["source_id"]))
    rows = db.scalar("SELECT rows_affected FROM RG_VIOLATION WHERE violation_id = :v", {"v": t["violation_id"]}) if t["violation_id"] else 0
    db.execute("UPDATE RG_REMEDIATION_TASK SET plan_json = :p, title = :t WHERE task_id = :i",
               {"p": json.dumps(plan, default=str), "t": _task_title(rule, t["table_name"], plan, rows or 0)[:198], "i": task_id})
    return get_task(task_id)


def approve(task_id: int, username: str) -> dict:
    t = refresh_plan(task_id)
    if t["status"] != "PROPOSED":
        raise ValidationError(f"Task is {t['status']}, only PROPOSED tasks can be approved")
    if t["plan"]["blocked"]:
        raise ValidationError(f"The plan is blocked: {t['plan']['blocked']}")
    db.execute("UPDATE RG_REMEDIATION_TASK SET status='APPROVED', approved_by=:u, approved_at=now() WHERE task_id=:i",
               {"u": username, "i": task_id})
    audit(username, "task", task_id, "APPROVED", t["title"])
    return get_task(task_id)


def reject(task_id: int, username: str, note: str = "") -> dict:
    t = get_task(task_id)
    if t["status"] not in ("PROPOSED", "APPROVED"):
        raise ValidationError(f"Task is {t['status']} and cannot be rejected")
    db.execute("UPDATE RG_REMEDIATION_TASK SET status='REJECTED', approved_by=:u, note=:n WHERE task_id=:i",
               {"u": username, "n": note[:490], "i": task_id})
    audit(username, "task", task_id, "REJECTED", t["title"])
    return get_task(task_id)


def repropose(task_id: int, username: str) -> dict:
    t = get_task(task_id)
    if t["status"] not in ("REJECTED", "FAILED"):
        raise ValidationError("Only rejected or failed tasks can be re-proposed")
    db.execute("UPDATE RG_REMEDIATION_TASK SET status='PROPOSED', approved_by=NULL, note=NULL WHERE task_id=:i", {"i": task_id})
    audit(username, "task", task_id, "REPROPOSED", t["title"])
    return refresh_plan(task_id)


def execute(task_id: int, username: str) -> dict:
    t = get_task(task_id)
    if t["status"] != "APPROVED":
        raise ValidationError("Only APPROVED tasks can be executed")
    rule = next((r for r in policy.active_rules() if r["rule_id"] == t["rule_id"]), None)
    if not rule:
        raise ValidationError("The rule behind this task is no longer active")
    sid = t["source_id"]
    graph = catalog.Graph(sid)
    engine = graph.engine
    holds.invalidate(sid)                                            # legal holds are read fresh at execution time
    plan = build_plan(rule, t["table_name"], graph)
    if plan["blocked"]:
        _fail(task_id, plan["blocked"])
        raise ValidationError(f"Plan blocked at execution time: {plan['blocked']}")

    results = []
    try:
        views = [s for s in plan["steps"] if s["operation"] == "CREATE VIEW"]
        for s in views:
            engine.create_or_replace_view(s["table"], s["sql"])
            results.append({"table": s["table"], "operation": s["operation"], "rows": s["est_rows"], "sql": s["sql"]})
        for s in [x for x in plan["steps"] if x["operation"] == "ARCHIVE"]:
            rows = engine.query(s["select_sql"])
            if not rows:
                results.append({"table": s["table"], "operation": "ARCHIVE", "rows": 0, "sql": s["sql"]})
                continue
            entry = archive.write(s["table"], rows, rule, task_id, s.get("primary_key_column"), username, sid)   # file exists from here on
            try:
                with engine.transaction() as conn:
                    n = engine.execute(s["sql"], conn=conn)           # only now are the exported rows deleted
            except Exception:
                archive.discard(entry, username)                      # nothing was actually removed: the export was pointless
                raise
            note = None if n == entry["row_count"] else f"exported {entry['row_count']} row(s) but deleted {n} - reconcile manually"
            results.append({"table": s["table"], "operation": "ARCHIVE", "rows": n, "sql": s["sql"],
                            "archive_id": entry["archive_id"], "archive_file": entry["file_path"], **({"note": note} if note else {})})
        dml = [s for s in plan["steps"] if s["operation"] not in ("CREATE VIEW", "ARCHIVE")]
        if dml:
            with engine.transaction() as conn:
                for s in dml:
                    n = engine.execute(s["sql"], conn=conn)
                    results.append({"table": s["table"], "operation": s["operation"], "rows": n, "sql": s["sql"]})
    except Exception as e:  # noqa: BLE001
        _fail(task_id, str(e))
        raise ValidationError(f"Execution failed and was rolled back: {e}")

    if plan["kind"] == "MASK":
        _record_protection(plan, rule, task_id)
        if plan["mode"] == "IN_PLACE":
            scanner.run_scan_sync(sid, "FULL", tables=[plan["table"]], username=username)
        verified, verification = _verify_mask(graph, plan)
    else:
        left = expired_count(rule, graph)
        verified, verification = left == 0, f"{left} expired row(s) remain after execution"
        if plan["mode"] == "ANONYMIZE":
            scanner.run_scan_sync(sid, "FULL", tables=[plan["table"]], username=username)

    result = {"steps": results, "verified": verified, "verification": verification, "held_rows": plan.get("held_rows", 0)}
    if plan.get("held_rows"):
        ids = plan.get("hold_ids") or []
        audit(username, "legal_hold", (ids or [0])[0], "SKIPPED",
              f"task #{task_id}: {plan['held_rows']} row(s) of {plan['table']} left untouched (legal hold "
              + ", ".join(f"#{i}" for i in ids) + ")")
    db.execute("UPDATE RG_REMEDIATION_TASK SET status='EXECUTED', executed_at=now(), verified=:v, result_json=:r "
               "WHERE task_id=:i", {"v": int(verified), "r": json.dumps(result, default=str), "i": task_id})
    def _fmt(r: dict) -> str:
        base = f"{r['operation']} {r['table']}: {r['rows']} row(s)"
        return f"{base}, archived to {r['archive_file']}" if r.get("archive_file") else base
    db.insert("RG_EVIDENCE", {"ref_type": "TASK", "ref_id": task_id,
                              "summary": f"{t['title']} - " + "; ".join(_fmt(r) for r in results),
                              "statements_json": json.dumps(results, default=str), "verification": verification[:490],
                              "created_by": username}, "evidence_id")
    if verified and t["violation_id"]:
        db.execute("UPDATE RG_VIOLATION SET status='RESOLVED', resolved_at=now() WHERE violation_id=:i", {"i": t["violation_id"]})
    audit(username, "task", task_id, "EXECUTED", f"{t['title']} | verified={verified}")
    return get_task(task_id)


def _fail(task_id: int, note: str) -> None:
    db.execute("UPDATE RG_REMEDIATION_TASK SET status='FAILED', note=:n WHERE task_id=:i", {"n": note[:490], "i": task_id})


def _record_protection(plan: dict, rule: dict, task_id: int) -> None:
    sid = plan["source_id"]
    for c in plan["columns"]:
        db.execute("DELETE FROM RG_PROTECTION WHERE source_id=:s AND table_name=:t AND column_name=:c AND rule_id=:r",
                   {"s": sid, "t": plan["table"], "c": c["column"], "r": rule["rule_id"]})
        db.insert("RG_PROTECTION", {"source_id": sid, "table_name": plan["table"], "column_name": c["column"],
                                    "data_element": c["element"], "method": plan["method"], "protect_mode": plan["mode"],
                                    "view_name": plan.get("view"), "rule_id": rule["rule_id"], "task_id": task_id},
                  "protection_id")
        db.execute("UPDATE RG_FINDING SET protection = :p, updated_at = now() WHERE source_id = :s AND table_name = :t "
                   "AND column_name = :c AND status IN ('AUTO','CONFIRMED','NEEDS_REVIEW')",
                   {"p": "MASKED_VIEW" if plan["mode"] == "VIEW" else "IN_PLACE", "s": sid, "t": plan["table"], "c": c["column"]})


def _verify_mask(graph: catalog.Graph, plan: dict) -> tuple[bool, str]:
    """Compare masked output with the original values: at least 90% of non-null values must differ."""
    table, engine = plan["table"], graph.engine
    pks = pk_cols(graph.source_id, table)
    if not pks:
        return False, "Cannot verify: table has no primary key"
    if plan["mode"] == "VIEW":
        left, right = plan["view"], table
    else:
        left, right = table, engine.backup_name(table)
    join = " AND ".join(f"l.{engine.ident(p)} = r.{engine.ident(p)}" for p in pks)
    scope_sql = ""
    sf = plan.get("scope_filter")
    if sf:                               # a scoped rule only changes the rows of its countries
        jur = graph.jurisdiction_expr(table, "r")
        pred = scope.country_predicate(jur, (sf["mode"], set(sf["codes"]))) if jur else None
        scope_sql = f" AND {pred}" if pred else ""
    parts, ok = [], True
    for c in plan["columns"]:
        q = engine.ident(c["column"])
        row = engine.query(f"SELECT COUNT(*) n, SUM(CASE WHEN l.{q} IS NULL OR l.{q} <> r.{q} THEN 1 ELSE 0 END) ch "
                           f"FROM {engine.ident(left)} l JOIN {engine.ident(right)} r ON {join} WHERE r.{q} IS NOT NULL{scope_sql}")[0]
        n, changed = row["n"], row["ch"]
        ratio = (changed or 0) / n if n else 1.0
        ok = ok and ratio >= 0.9
        parts.append(f"{c['column']}: {ratio:.0%} of {n} values differ from the original")
    return ok, "; ".join(parts)
