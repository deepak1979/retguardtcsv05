"""Legal hold register, multi-source.

A steward or admin marks a customer, a policy or a claim as ON HOLD (flag Y) or releases it (flag N). The register is
RG_LEGAL_HOLD: one row per hold, never overwritten, so the history of who held what and why stays intact.

What a hold protects (every remediation and erasure path asks `predicate()` / `index()`):

  the held row itself            SELF
  everything that belongs to it  BELOW   (a hold on a customer covers their policies, claims, payments, derived copies)
  the rows it hangs off          ABOVE   (a hold on a claim also keeps its policy and customer: the identity
                                          is needed to pursue the matter, and an FK parent cannot go while a child stays)

Held rows are not deleted, anonymised or overwritten in place. Masked views are left alone: they hide data and change
nothing, so a hold is no reason to expose it. Anything else in the same task or request carries on, and every skip is
written to the audit log.

Multi-source: which table is "the customer", "a policy", "a claim" - and what its business-number column is called -
differs per source, so it can't be hardcoded the way the original Oracle-only build was. SUBJECT_MODEL below is the
declarative answer: one entry per source_id, read by every function in this module instead of literal table/column
names. Adding a third source later means adding one more SUBJECT_MODEL entry (plus its own rg/engines adapter,
already in place) - not touching the functions themselves again. Everything that needs "which rows belong to this
customer" (counts, the tree listing, ancestor lookups) is built from the already-discovered lineage graph
(catalog.Graph.paths_from / subject_predicate - the same machinery rg/erasure.py uses), not hand-written joins.
"""
from __future__ import annotations

import threading
import time

from . import catalog, db
from .common import audit, sample_mask
from .policy import NotFound, ValidationError

# v04 has exactly one seeded data source (source_id=1, the deepak.insurance_v04 Databricks source) -
# v03's other entries here (21: life_de/SQL Server, 45: a second, dynamically-added Oracle banking
# source) described sources that don't and can't exist in v04 (Databricks-only, one source), so they're
# dropped rather than carried forward as dead config. Table/column names are lowercase to match Unity
# Catalog's own naming (v03's Oracle source used uppercase - see rg/db.py's module docstring for why
# Postgres identifiers don't need this distinction, but these are DATA-PLANE table/column names read
# back from RG_CATALOG_TABLE/RG_CATALOG_COLUMN, which store whatever casing the source system itself
# uses - Unity Catalog's information_schema always reports lowercase).
SUBJECT_MODEL: dict[int, dict] = {
    1: {  # deepak.insurance_v04 (Databricks)
        "root": "customer", "policy_table": "policy", "claim_table": "claim",
        "label_column": {"customer": "customer_no", "policy": "policy_no", "claim": "claim_no"},
        "nice": {"customer": "Customer", "policy": "Policy", "claim": "Claim"},
        "root_columns": {"number": "customer_no", "first_name": "first_name", "last_name": "last_name",
                         "email": "email", "country": "country_code", "city": "city", "status": "status"},
        "sub_columns": {"policy": {"status": "status", "date": "expiry_date"},
                        "claim": {"status": "status", "date": "settled_date", "kind": "claim_type"}},
        "search_tables": ("policy", "claim"),
    },
}

_TTL = 1.5
_lock = threading.Lock()
_cache: dict[int, dict] = {}   # source_id -> {"at": float, "idx": HeldIndex}


def configured_sources() -> list[int]:
    return sorted(SUBJECT_MODEL)


def _norm(v) -> str:
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return str(v).strip()


def _kv(graph: catalog.Graph, table: str, value):
    """The key as the database type wants it (numbers as numbers)."""
    dtype = graph.columns[table][graph.pk[table]]["data_type"]
    return int(float(value)) if dtype == "NUMBER" else str(value)


def _path_to_root(graph: catalog.Graph, table: str, root: str, max_depth: int = 4) -> list[dict] | None:
    """Shortest chain of parent edges from `table` up to `root` (possibly several hops, e.g. life_de.claim ->
    life_de.policy -> life_de.customer), or None if `table` isn't a descendant of `root` at all."""
    if table == root:
        return []
    level: list[tuple[str, list[dict]]] = [(table, [])]
    seen = {table}
    for _ in range(max_depth):
        nxt: list[tuple[str, list[dict]]] = []
        for t, path in level:
            for e in graph.edges:
                if e["child_table"] != t or e["parent_table"] in seen:
                    continue
                p = path + [e]
                if e["parent_table"] == root:
                    return p
                seen.add(e["parent_table"])
                nxt.append((e["parent_table"], p))
        level = nxt
        if not level:
            break
    return None


def _ancestor_value(graph: catalog.Graph, table: str, key_value, root: str, column: str) -> str | None:
    """Value of `column` on the `root` ancestor of the `table` row identified by `key_value` (None if the two
    tables aren't connected, or the root has no such column)."""
    if column not in graph.columns.get(root, {}):
        return None
    path = _path_to_root(graph, table, root)
    if path is None:
        return None
    engine = graph.engine

    def build(i: int, outer: str) -> str:
        if i == len(path):
            return f"{outer}.{engine.ident(column)}"
        e = path[i]
        a = f"h{i + 1}"
        return (f"(SELECT {build(i + 1, a)} FROM {engine.ident(e['parent_table'])} {a} "
                f"WHERE {a}.{engine.ident(e['parent_column'])} = {outer}.{engine.ident(e['child_column'])})")
    expr = build(0, "x")
    pk = engine.ident(graph.pk[table])
    row = engine.query_one(f"SELECT {expr} AS v FROM {engine.ident(table)} x WHERE x.{pk} = :k", {"k": key_value})
    return row["v"] if row else None


# --------------------------------------------------------------------------- the index of everything on hold
class HeldIndex:
    """Which rows of one source are covered by an active hold: table -> key -> {hold_id: SELF | BELOW | ABOVE}."""

    def __init__(self, graph: catalog.Graph):
        self.graph = graph
        self.by_table: dict[str, dict[str, dict[int, str]]] = {}
        self.holds = db.query("SELECT * FROM RG_LEGAL_HOLD WHERE source_id = :s AND status = 'ACTIVE' ORDER BY hold_id",
                              {"s": graph.source_id})
        for h in self.holds:
            try:
                self._expand(h)
            except Exception:                    # a hold on a table that vanished must never break a remediation run
                self._add(h["root_table"], h["key_value"], h["hold_id"], "SELF")

    def _add(self, table: str, key, hold_id: int, rel: str) -> None:
        cur = self.by_table.setdefault(table, {}).setdefault(_norm(key), {})
        if cur.get(hold_id) != "SELF":
            cur[hold_id] = rel

    def _expand(self, h: dict) -> None:
        g, root, key, hid = self.graph, h["root_table"], h["key_value"], h["hold_id"]
        engine = g.engine
        if root not in g.pk:
            self._add(root, key, hid, "SELF")
            return
        kv = _kv(g, root, key)
        self._add(root, key, hid, "SELF")
        for table, paths in g.paths_from(root).items():                       # everything that belongs to the row
            if table not in g.pk:
                continue
            pred = g.subject_predicate(table, paths, root)
            for r in engine.query(f"SELECT {engine.ident(g.pk[table])} k FROM {engine.ident(table)} WHERE {pred}", {"k": kv}):
                self._add(table, r["k"], hid, "BELOW")
        frontier = {root: {_norm(key)}}                                        # the rows it hangs off
        seen = {(root, _norm(key))}
        for _ in range(5):
            nxt: dict[str, set[str]] = {}
            for x, keys in frontier.items():
                for e in g.edges:
                    p = e["parent_table"]
                    if e["child_table"] != x or p == x or p not in g.pk:
                        continue
                    binds = {f"k{i}": _kv(g, x, k) for i, k in enumerate(sorted(keys))}
                    ph = ", ".join(f":{b}" for b in binds)
                    rows = engine.query(
                        f"SELECT DISTINCT {engine.ident(g.pk[p])} k FROM {engine.ident(p)} WHERE {engine.ident(e['parent_column'])} IN "
                        f"(SELECT {engine.ident(e['child_column'])} FROM {engine.ident(x)} WHERE {engine.ident(g.pk[x])} IN ({ph}))", binds)
                    for r in rows:
                        k = _norm(r["k"])
                        if (p, k) in seen:
                            continue
                        seen.add((p, k))
                        self._add(p, k, hid, "ABOVE")
                        nxt.setdefault(p, set()).add(k)
            if not nxt:
                break
            frontier = nxt

    # ---- questions the remediation code asks
    def keys(self, table: str) -> dict[str, dict[int, str]]:
        return self.by_table.get(table, {})

    def is_held(self, table: str, key) -> bool:
        return _norm(key) in self.keys(table)

    def hold_ids(self, table: str, keys) -> list[int]:
        ks = self.keys(table)
        return sorted({hid for k in keys for hid in ks.get(_norm(k), {})})

    def predicate(self, table: str, alias: str | None = "t") -> str | None:
        """SQL condition true for the rows of `table` that are under a hold, or None when nothing in it is held."""
        ks = self.keys(table)
        if not ks or table not in self.graph.pk:
            return None
        engine = self.graph.engine
        col = engine.ident(self.graph.pk[table])
        col = f"{alias}.{col}" if alias else col
        numeric = self.graph.columns[table][self.graph.pk[table]]["data_type"] == "NUMBER"
        keys = sorted(ks)
        chunks = []
        for i in range(0, len(keys), 500):                                     # chunked IN list, any engine's limit
            part = keys[i:i + 500]
            lit = ", ".join(str(int(float(k))) if numeric else "'" + k.replace("'", "''") + "'" for k in part)
            chunks.append(f"{col} IN ({lit})")
        return "(" + " OR ".join(chunks) + ")"


def invalidate(source_id: int | None = None) -> None:
    with _lock:
        if source_id is None:
            _cache.clear()
        else:
            _cache.pop(source_id, None)


def index(source_id: int, fresh: bool = False) -> HeldIndex:
    """The current hold index for one source. Cached for a moment (a run asks many times); fresh=True before
    anything destructive."""
    with _lock:
        entry = _cache.get(source_id)
        if not fresh and entry is not None and time.monotonic() - entry["at"] < _TTL:
            return entry["idx"]
    idx = HeldIndex(catalog.Graph(source_id))
    with _lock:
        _cache[source_id] = {"at": time.monotonic(), "idx": idx}
    return idx


def predicate(source_id: int, table: str, alias: str | None = "t") -> str | None:
    """None (no holds apply) for a source with no SUBJECT_MODEL entry - legal holds are opt-in per source."""
    if source_id not in SUBJECT_MODEL:
        return None
    return index(source_id).predicate(table, alias)


# --------------------------------------------------------------------------- the register
def _model(source_id: int) -> dict:
    model = SUBJECT_MODEL.get(source_id)
    if not model:
        raise ValidationError("Legal holds aren't configured for this data source")
    return model


def _require(graph: catalog.Graph) -> dict:
    model = _model(graph.source_id)
    for t in {model["root"], model.get("policy_table"), model.get("claim_table")} - {None}:
        if t not in graph.pk:
            raise ValidationError(f"The legal hold screen needs {t} (with a single-column primary key) in the catalog - run discovery")
    return model


def _describe(graph: catalog.Graph, table: str, key: str) -> tuple[str, str | None]:
    """(label such as 'Claim CLM-1001', customer number the record belongs to)."""
    model = _model(graph.source_id)
    engine = graph.engine
    pk = graph.pk[table]
    kv = _kv(graph, table, key)
    lc = model["label_column"].get(table)
    label_sql = engine.ident(lc) if lc and lc in graph.columns[table] else engine.ident(pk)
    row = engine.query_one(f"SELECT {label_sql} AS lbl FROM {engine.ident(table)} WHERE {engine.ident(pk)} = :k", {"k": kv})
    if not row:
        raise NotFound(f"{table} {key} does not exist")
    label = f"{model['nice'].get(table, table.title())} {row['lbl']}"
    root = model["root"]
    if table == root:
        cust = row["lbl"]
    else:
        number_col = model["label_column"].get(root) or model["root_columns"].get("number")
        cust = _ancestor_value(graph, table, kv, root, number_col) if number_col else None
    return label, cust


def list_holds(status: str | None = None, customer_ref: str | None = None) -> list[dict]:
    sql, params = "SELECT * FROM RG_LEGAL_HOLD WHERE 1 = 1", {}
    if status:
        sql += " AND status = :s"
        params["s"] = status
    if customer_ref:
        sql += " AND customer_ref = :c"
        params["c"] = customer_ref
    return db.query(sql + " ORDER BY hold_id DESC", params)


def create_hold(source_id: int, root_table: str, key_value, reason: str, username: str, matter_ref: str = "") -> dict:
    root_table = (root_table or "").strip()
    model = SUBJECT_MODEL.get(source_id)
    if not model or root_table not in {model["root"], model.get("policy_table"), model.get("claim_table")}:
        # same table name can mean a different source (e.g. "CUSTOMER" exists in more than one source) -
        # source_id must come from the caller's own search/tree context, never be guessed from the table
        # name alone, or a hold placed on one source's record lands on a different source's same-keyed row
        raise ValidationError(f"{root_table or 'That table'} is not a holdable table on this data source")
    graph = catalog.Graph(source_id)
    if root_table not in graph.pk:
        raise ValidationError(f"{root_table or 'That table'} has no single-column primary key in the catalog")
    key = _norm(key_value)
    reason = (reason or "").strip()
    if len(reason) < 3:
        raise ValidationError("Give a reason for the legal hold (for example the matter or court reference)")
    label, cust = _describe(graph, root_table, key)
    if db.scalar("SELECT COUNT(*) FROM RG_LEGAL_HOLD WHERE source_id = :s AND root_table = :t AND key_value = :k AND status = 'ACTIVE'",
                 {"s": source_id, "t": root_table, "k": key}):
        raise ValidationError(f"{label} is already on legal hold")
    hid = db.insert("RG_LEGAL_HOLD", {"source_id": source_id, "root_table": root_table, "key_value": key, "reason": reason[:290],
                                      "matter_ref": (matter_ref or "").strip()[:60] or None, "entity_label": label[:120],
                                      "customer_ref": cust, "created_by": username}, "hold_id")
    invalidate(source_id)
    audit(username, "legal_hold", hid, "HOLD", f"{label}: {reason}"[:490])
    return db.query_one("SELECT * FROM RG_LEGAL_HOLD WHERE hold_id = :i", {"i": hid})


def release_hold(hold_id: int, username: str, reason: str = "") -> dict:
    h = db.query_one("SELECT * FROM RG_LEGAL_HOLD WHERE hold_id = :i", {"i": hold_id})
    if not h:
        raise NotFound(f"Legal hold {hold_id} not found")
    if h["status"] != "ACTIVE":
        raise ValidationError("That legal hold has already been released")
    reason = (reason or "").strip()
    if len(reason) < 3:
        raise ValidationError("Give a reason for releasing the legal hold")
    db.execute("UPDATE RG_LEGAL_HOLD SET status='RELEASED', released_at=now(), released_by=:u, release_reason=:r "
               "WHERE hold_id=:i", {"u": username, "r": reason[:290], "i": hold_id})
    invalidate(h["source_id"])
    audit(username, "legal_hold", hold_id, "RELEASE", f"{h.get('entity_label') or h['root_table'] + ' ' + h['key_value']}: {reason}"[:490])
    return db.query_one("SELECT * FROM RG_LEGAL_HOLD WHERE hold_id = :i", {"i": hold_id})


def set_flag(source_id: int, root_table: str, key_value, flag: str, reason: str, username: str, matter_ref: str = "") -> dict:
    """The Y / N switch: Y places a hold on the record, N releases the active hold on it."""
    flag = (flag or "").upper()
    if flag == "Y":
        return create_hold(source_id, root_table, key_value, reason, username, matter_ref)
    if flag == "N":
        # scoped by source_id too, not just root_table/key_value - two sources can share both a table
        # name ("CUSTOMER") and, coincidentally, a numeric key, and releasing must not cross that streams
        h = db.query_one("SELECT hold_id FROM RG_LEGAL_HOLD WHERE source_id = :s AND root_table = :t "
                         "AND key_value = :k AND status = 'ACTIVE'",
                         {"s": source_id, "t": (root_table or "").strip(), "k": _norm(key_value)})
        if not h:
            raise ValidationError("That record is not on legal hold")
        return release_hold(h["hold_id"], username, reason)
    raise ValidationError("The legal hold flag must be Y or N")


# --------------------------------------------------------------------------- the screen: find a customer, see their records
def _state(idx: HeldIndex, table: str, key) -> str:
    """Y = this record itself is held, COVERED = held because of a related record, N = free."""
    rels = idx.keys(table).get(_norm(key), {})
    if any(r == "SELF" for r in rels.values()):
        return "Y"
    return "COVERED" if rels else "N"


def search_customers(q: str, limit: int = 25) -> list[dict]:
    q = " ".join((q or "").split())
    if len(q) < 2:
        raise ValidationError("Type at least 2 characters of a customer number, policy number, claim number or name")
    like = f"%{q.upper()}%"
    out: list[dict] = []
    for source_id, model in SUBJECT_MODEL.items():
        try:
            graph = catalog.Graph(source_id)
            _require(graph)
        except ValidationError:
            continue   # this source hasn't been discovered yet - skip it, not an error for the other source(s)
        engine = graph.engine
        root = model["root"]
        rc = model["root_columns"]
        root_cols = graph.columns.get(root, {})
        number_col, first_col, last_col = rc.get("number"), rc.get("first_name"), rc.get("last_name")
        conds = []
        if number_col and number_col in root_cols:
            conds.append(f"UPPER({engine.ident(number_col)}) LIKE :q")
        if first_col in root_cols and last_col in root_cols:
            full = engine.concat(engine.ident(first_col), "' '", engine.ident(last_col))
            conds.append(f"UPPER({full}) LIKE :q")
        for sub in model.get("search_tables", ()):
            edge = next((e for e in graph.edges if e["child_table"] == sub and e["parent_table"] == root), None)
            sub_number = model["label_column"].get(sub)
            if edge and sub_number and sub_number in graph.columns.get(sub, {}):
                conds.append(f"{engine.ident(graph.pk[root])} IN (SELECT {engine.ident(edge['child_column'])} "
                             f"FROM {engine.ident(sub)} WHERE UPPER({engine.ident(sub_number)}) LIKE :q)")
        if not conds:
            continue

        paths = graph.paths_from(root)
        root_alias_pk = f"c.{engine.ident(graph.pk[root])}"
        policy_cnt = (f"(SELECT COUNT(*) FROM {engine.ident(model['policy_table'])} WHERE "
                      f"{graph.subject_predicate(model['policy_table'], paths[model['policy_table']], root, key_bind=root_alias_pk)})"
                      if model.get("policy_table") in paths else "0")
        claim_cnt = (f"(SELECT COUNT(*) FROM {engine.ident(model['claim_table'])} WHERE "
                     f"{graph.subject_predicate(model['claim_table'], paths[model['claim_table']], root, key_bind=root_alias_pk)})"
                     if model.get("claim_table") in paths else "0")
        select = [f"{engine.ident(graph.pk[root])} AS pk_"]
        for alias, col in (("number_", number_col), ("first_", first_col), ("last_", last_col),
                          ("email_", rc.get("email")), ("country_", rc.get("country")), ("city_", rc.get("city"))):
            select.append(f"{engine.ident(col)} AS {alias}" if col and col in root_cols else f"NULL AS {alias}")
        select.append(f"{policy_cnt} AS policies_")
        select.append(f"{claim_cnt} AS claims_")
        sql = (f"SELECT {', '.join(select)} FROM {engine.ident(root)} c WHERE " + " OR ".join(conds) +
              f" ORDER BY {engine.ident(graph.pk[root])}")
        rows = engine.query(sql, {"q": like})[: int(limit)]
        idx = index(source_id)
        source_name = db.scalar("SELECT name FROM RG_DATA_SOURCE WHERE source_id = :s", {"s": source_id})
        for r in rows:
            # email is shown in clear (not masked): whoever is placing a hold needs to be sure they have the right person
            out.append({"customer_id": r["pk_"], "customer_no": r.get("number_"),
                        "name": sample_mask(f"{r.get('first_') or ''} {r.get('last_') or ''}".strip()), "email": r.get("email_"),
                        "country": r.get("country_"), "city": r.get("city_"), "policies": r.get("policies_") or 0,
                        "claims": r.get("claims_") or 0, "hold": _state(idx, root, r["pk_"]),
                        "source_id": source_id, "source_name": source_name})
    return out[: int(limit)]


def customer_tree(source_id: int, customer_id) -> dict:
    """One customer with their policies and claims, and the hold flag of each."""
    graph = catalog.Graph(source_id)
    model = _require(graph)
    engine = graph.engine
    root = model["root"]
    rc = model["root_columns"]
    pk = graph.pk[root]
    kv = _kv(graph, root, customer_id)
    root_cols = graph.columns.get(root, {})
    wanted = {"number": rc.get("number"), "first": rc.get("first_name"), "last": rc.get("last_name"),
             "email": rc.get("email"), "country": rc.get("country"), "city": rc.get("city"), "status": rc.get("status")}
    select = [f"{engine.ident(pk)} AS pk_"] + [f"{engine.ident(v)} AS {k}_" if v and v in root_cols else f"NULL AS {k}_" for k, v in wanted.items()]
    c = engine.query_one(f"SELECT {', '.join(select)} FROM {engine.ident(root)} WHERE {engine.ident(pk)} = :k", {"k": kv})
    if not c:
        raise NotFound(f"Customer {customer_id} not found")
    idx = index(source_id, fresh=True)
    active = {(h["root_table"], h["key_value"]): h for h in idx.holds}

    def rec(table: str, key, label, extra: dict) -> dict:
        k = _norm(key)
        h = active.get((table, k))
        covered = []
        if not h:
            for hid, rel in idx.keys(table).get(k, {}).items():
                src = next((x for x in idx.holds if x["hold_id"] == hid), None)
                if src:
                    covered.append({"hold_id": hid, "relation": rel, "entity": src.get("entity_label") or f"{src['root_table']} {src['key_value']}"})
        return {"table": table, "kind_label": model["nice"].get(table, table), "key": k, "label": label,
                "hold": _state(idx, table, k), "hold_id": h["hold_id"] if h else None,
                "reason": h["reason"] if h else None, "matter_ref": h.get("matter_ref") if h else None,
                "held_by": h["created_by"] if h else None, "held_at": h["created_at"] if h else None, "covered_by": covered, **extra}

    paths = graph.paths_from(root)
    claim_table, policy_table = model.get("claim_table"), model.get("policy_table")
    # the FK column on claim_table that points at policy_table (if claim is a direct child of policy) -
    # used to group claims under their policy in the tree
    claim_policy_edge = next((e for e in graph.edges if e["child_table"] == claim_table and e["parent_table"] == policy_table), None)

    def sub_rows(table: str | None) -> list[dict]:
        if not table or table not in paths:
            return []
        pred = graph.subject_predicate(table, paths[table], root)
        sc = model["sub_columns"].get(table, {})
        cols = graph.columns.get(table, {})
        number_col = model["label_column"].get(table)
        select = [f"{engine.ident(graph.pk[table])} AS pk_",
                 f"{engine.ident(number_col)} AS number_" if number_col and number_col in cols else "NULL AS number_",
                 f"{engine.ident(sc['status'])} AS status_" if sc.get("status") in cols else "NULL AS status_",
                 f"{engine.ident(sc['date'])} AS date_" if sc.get("date") in cols else "NULL AS date_",
                 f"{engine.ident(sc['kind'])} AS kind_" if sc.get("kind") in cols else "NULL AS kind_"]
        if table == claim_table and claim_policy_edge:
            select.append(f"{engine.ident(claim_policy_edge['child_column'])} AS policy_fk_")
        return engine.query(f"SELECT {', '.join(select)} FROM {engine.ident(table)} WHERE {pred} ORDER BY {engine.ident(graph.pk[table])}", {"k": kv})

    policies = sub_rows(policy_table)
    claims = sub_rows(claim_table)

    return {
        "customer": rec(root, c["pk_"], c.get("number_") or str(c["pk_"]),
                        {"name": sample_mask(f"{c.get('first_') or ''} {c.get('last_') or ''}".strip()), "email": c.get("email_"),
                         "country": c.get("country_"), "city": c.get("city_"), "status": c.get("status_")}),
        "policies": [rec(policy_table, p["pk_"], p.get("number_") or str(p["pk_"]), {"status": p.get("status_"), "date": p.get("date_")}) for p in policies],
        "claims": [rec(claim_table, x["pk_"], x.get("number_") or str(x["pk_"]),
                       {"policy_id": str(x["policy_fk_"]) if x.get("policy_fk_") is not None else None,
                        "status": x.get("status_"), "kind": x.get("kind_"), "date": x.get("date_")}) for x in claims],
        "history": db.query("SELECT hold_id, root_table, key_value, entity_label, reason, matter_ref, status, created_by, created_at, "
                            "released_by, released_at, release_reason FROM RG_LEGAL_HOLD WHERE customer_ref = :c AND source_id = :s ORDER BY hold_id DESC",
                            {"c": c.get("number_") or str(c["pk_"]), "s": source_id}),
    }
