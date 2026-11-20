"""Discovery: read a data source's own dictionary into the RG_CATALOG_* and RG_LINEAGE tables, via Unity
Catalog's ANSI information_schema over the one Databricks SQL Warehouse this app uses. Column type names
are normalised down to the vocabulary scanner.READ_TYPES expects (VARCHAR2/CHAR/NVARCHAR2/NCHAR/NUMBER/
DATE/TIMESTAMP) - a holdover naming convention from this app's original relational-engine lineage, kept
because scanner.py and every classifier still key off it; not evidence of another engine underneath.

RetentionGuard calls this the metadata scan / data-source catalog. Two kinds of lineage are recorded:
  FK        declared foreign keys
  INFERRED  a column with the same name as another table's primary key whose values all exist there
            (finds derived copies such as MKT_CUSTOMER_360 that have no declared foreign key)
"""
from __future__ import annotations

from . import config, db, engines
from .common import audit


def _norm_databricks_type(t: str) -> str:
    """Spark SQL's information_schema.columns.data_type is the full type string (e.g. 'decimal(10,2)',
    'varchar(50)') - strip any (...) precision/scale/length suffix before mapping the base type name."""
    base = t.split("(", 1)[0].strip().lower()
    if base in ("string", "varchar", "char"):
        return "VARCHAR2" if base != "char" else "CHAR"
    if base in ("int", "bigint", "smallint", "tinyint", "decimal", "double", "float"):
        return "NUMBER"
    if base == "boolean":
        return "NUMBER"   # scanner.READ_TYPES has no boolean concept; treated as a small numeric
    if base == "date":
        return "DATE"
    if base in ("timestamp", "timestamp_ntz"):
        return "TIMESTAMP"
    return t.upper()      # array/map/struct/binary etc. fall outside scanner.READ_TYPES - metadata-only is fine


def discover(source_id: int, username: str | None = None) -> dict:
    src = db.query_one("SELECT * FROM RG_DATA_SOURCE WHERE source_id = :s", {"s": source_id})
    if not src:
        raise ValueError(f"Data source {source_id} not found")
    return _discover_databricks(source_id, username)


def _persist_catalog(source_id: int, tables: list[str], cols: list[dict], counts: dict[str, int],
                     fks: list[dict], inferred: list[dict], username: str | None) -> dict:
    """Wipe this source's catalog/lineage rows and reinsert what was just read.
    `cols` items: table_name, column_name, data_type (already normalised), data_length, nullable(bool), is_pk(bool), ordinal,
    and optionally uc_classification (a 'pii_classification' tag value read from Unity Catalog's own tagging system).
    `fks`/`inferred` items: child_table, child_column, parent_table, parent_column, (inferred also: confidence)."""
    with db.transaction() as conn:
        db.execute("DELETE FROM RG_CATALOG_TABLE WHERE source_id = :s", {"s": source_id}, conn)
        db.execute("DELETE FROM RG_CATALOG_COLUMN WHERE source_id = :s", {"s": source_id}, conn)
        db.execute("DELETE FROM RG_LINEAGE WHERE source_id = :s", {"s": source_id}, conn)
        for t in tables:
            tcols = [c for c in cols if c["table_name"] == t]
            db.insert("RG_CATALOG_TABLE", {"source_id": source_id, "table_name": t, "row_count": counts[t],
                                           "column_count": len(tcols)}, "catalog_table_id", conn)
            for c in tcols:
                db.insert("RG_CATALOG_COLUMN", {
                    "source_id": source_id, "table_name": t, "column_name": c["column_name"],
                    "data_type": c["data_type"], "data_length": c["data_length"],
                    "is_nullable": 1 if c["nullable"] else 0, "is_pk": 1 if c["is_pk"] else 0,
                    "ordinal": c["ordinal"], "uc_classification": c.get("uc_classification")},
                    "catalog_column_id", conn)
        for f in fks:
            db.insert("RG_LINEAGE", {"source_id": source_id, "child_table": f["child_table"],
                                     "child_column": f["child_column"], "parent_table": f["parent_table"],
                                     "parent_column": f["parent_column"], "kind": "FK", "confidence": 1},
                      "lineage_id", conn)
        for f in inferred:
            db.insert("RG_LINEAGE", {"source_id": source_id, "child_table": f["child_table"],
                                     "child_column": f["child_column"], "parent_table": f["parent_table"],
                                     "parent_column": f["parent_column"], "kind": "INFERRED",
                                     "confidence": f["confidence"]}, "lineage_id", conn)
        db.execute("UPDATE RG_DATA_SOURCE SET last_discovered_at = now() WHERE source_id = :s",
                   {"s": source_id}, conn)
        audit(username, "source", source_id, "DISCOVER",
              f"{len(tables)} tables, {len(cols)} columns, {len(fks)} FK + {len(inferred)} inferred links", conn)
    return {"tables": len(tables), "columns": len(cols), "fk_links": len(fks), "inferred_links": len(inferred)}


def _discover_databricks(source_id: int, username: str | None = None) -> dict:
    """A Databricks source is scoped to one catalog.schema (DatabricksEngine.catalog/.schema, set when
    the source was added - see rg/engines/databricks.py), so table names are stored bare."""
    engine = engines.for_source(source_id)
    cat, sch = engine.catalog, engine.schema

    # Unity Catalog reconciliation: a column tagged `pii_classification` (value = one of this app's own
    # classifier codes, e.g. EMAIL, PHONE, FIRST_NAME ...) via Catalog Explorer or ALTER TABLE ... ALTER
    # COLUMN ... SET TAGS is treated as that column's governing classification - see scanner._run. Column
    # tags are a newer Unity Catalog feature and not every metastore has information_schema.column_tags,
    # so a missing/erroring view just means "no UC classifications yet", not a failed discovery.
    uc_tags: dict[tuple[str, str], str] = {}
    try:
        tag_rows = engine.query(
            f"SELECT table_name, column_name, tag_value FROM {engine.ident(cat)}.information_schema.column_tags "
            f"WHERE schema_name = :s AND lower(tag_name) = 'pii_classification'", {"s": sch})
        uc_tags = {(r["table_name"], r["column_name"]): r["tag_value"] for r in tag_rows if r["tag_value"]}
    except Exception:
        uc_tags = {}

    raw_cols = engine.query(
        f"SELECT table_name, column_name, data_type, is_nullable, ordinal_position "
        f"FROM {engine.ident(cat)}.information_schema.columns "
        f"WHERE table_schema = :s ORDER BY table_name, ordinal_position", {"s": sch})
    tables = sorted({c["table_name"] for c in raw_cols})
    tables = [t for t in tables if not any(t.upper().startswith(p) for p in config.EXCLUDED_TABLE_PREFIXES)]
    table_set = set(tables)

    pk_rows = engine.query(
        f"SELECT kcu.table_name, kcu.column_name "
        f"FROM {engine.ident(cat)}.information_schema.table_constraints tc "
        f"JOIN {engine.ident(cat)}.information_schema.key_column_usage kcu "
        f"  ON kcu.constraint_name = tc.constraint_name AND kcu.table_schema = tc.table_schema "
        f"WHERE tc.table_schema = :s AND tc.constraint_type = 'PRIMARY KEY'", {"s": sch})
    pk_cols: dict[str, list[str]] = {}
    for p in pk_rows:
        if p["table_name"] in table_set:
            pk_cols.setdefault(p["table_name"], []).append(p["column_name"])

    fk_rows = engine.query(
        f"SELECT rc.constraint_name, kcu.table_name child_table, kcu.column_name child_column, "
        f"       rc.unique_constraint_name "
        f"FROM {engine.ident(cat)}.information_schema.referential_constraints rc "
        f"JOIN {engine.ident(cat)}.information_schema.key_column_usage kcu "
        f"  ON kcu.constraint_name = rc.constraint_name AND kcu.table_schema = rc.constraint_schema "
        f"WHERE rc.constraint_schema = :s", {"s": sch})
    parent_rows = engine.query(
        f"SELECT constraint_name, table_name parent_table, column_name parent_column "
        f"FROM {engine.ident(cat)}.information_schema.key_column_usage WHERE table_schema = :s", {"s": sch})
    parent_by_uc = {r["constraint_name"]: r for r in parent_rows}
    fks = []
    for f in fk_rows:
        parent = parent_by_uc.get(f["unique_constraint_name"])
        if parent:
            fks.append({"child_table": f["child_table"], "child_column": f["child_column"],
                       "parent_table": parent["parent_table"], "parent_column": parent["parent_column"]})

    norm_cols = [{"table_name": c["table_name"], "column_name": c["column_name"],
                 "data_type": _norm_databricks_type(c["data_type"]), "data_length": None,
                 "nullable": c["is_nullable"] == "YES",
                 "is_pk": c["column_name"] in pk_cols.get(c["table_name"], []),
                 "ordinal": c["ordinal_position"],
                 "uc_classification": uc_tags.get((c["table_name"], c["column_name"]))}
                for c in raw_cols if c["table_name"] in table_set]
    counts = {t: engine.scalar(f"SELECT COUNT(*) FROM {engine.ident(t)}") for t in tables}

    fks = [f for f in fks if f["child_table"] in table_set and f["parent_table"] in table_set]
    fk_keys = {(f["child_table"], f["child_column"]) for f in fks}
    fk_parents = {f["parent_table"] for f in fks}
    inferred = []
    single_pk = {t: cs[0] for t, cs in pk_cols.items() if len(cs) == 1}
    for t in tables:
        if t in fk_parents:
            continue
        for c in [c for c in norm_cols if c["table_name"] == t]:
            if (t, c["column_name"]) in fk_keys:
                continue
            for parent, pk in single_pk.items():
                if parent == t or pk != c["column_name"]:
                    continue
                nonnull = engine.scalar(f"SELECT COUNT({engine.ident(c['column_name'])}) FROM {engine.ident(t)}")
                if not nonnull:
                    continue
                hit = engine.scalar(
                    f"SELECT COUNT(*) FROM {engine.ident(t)} c WHERE c.{engine.ident(pk)} IS NOT NULL AND EXISTS "
                    f"(SELECT 1 FROM {engine.ident(parent)} p WHERE p.{engine.ident(pk)} = c.{engine.ident(pk)})")
                ratio = hit / nonnull
                if ratio >= 0.95:
                    inferred.append({"child_table": t, "child_column": c["column_name"], "parent_table": parent,
                                     "parent_column": pk, "confidence": round(ratio, 3)})
    return _persist_catalog(source_id, tables, norm_cols, counts, fks, inferred, username)


def get_catalog(source_id: int) -> dict:
    tables = db.query("SELECT table_name, row_count, column_count, discovered_at FROM RG_CATALOG_TABLE "
                      "WHERE source_id = :s ORDER BY table_name", {"s": source_id})
    cols = db.query("SELECT table_name, column_name, data_type, data_length, is_nullable, is_pk, ordinal, "
                    "null_ratio, distinct_ratio FROM RG_CATALOG_COLUMN WHERE source_id = :s "
                    "ORDER BY table_name, ordinal", {"s": source_id})
    findings = db.query("SELECT finding_id, table_name, column_name, data_element, category, confidence, status, protection "
                        "FROM RG_FINDING WHERE source_id = :s AND status NOT IN ('RESOLVED', 'REJECTED') "
                        "ORDER BY confidence DESC", {"s": source_id})
    by_col: dict[tuple, list[dict]] = {}
    for f in findings:
        by_col.setdefault((f["table_name"], f["column_name"]), []).append(f)
    by_table: dict[str, list[dict]] = {}
    for c in cols:
        c["findings"] = by_col.get((c["table_name"], c["column_name"]), [])
        by_table.setdefault(c["table_name"], []).append(c)
    for t in tables:
        t["columns"] = by_table.get(t["table_name"], [])
        t["pii_columns"] = sum(1 for c in t["columns"] if any(f["category"] == "PII" and f["status"] in ("AUTO", "CONFIRMED", "NEEDS_REVIEW") for f in c["findings"]))
    lineage = db.query("SELECT child_table, child_column, parent_table, parent_column, kind, confidence "
                       "FROM RG_LINEAGE WHERE source_id = :s ORDER BY parent_table, child_table", {"s": source_id})
    return {"tables": tables, "lineage": lineage}


# --------------------------------------------------------------------------- lineage graph helpers
class Graph:
    """Parent -> child edges of the source schema, with path enumeration used by erasure and retention.

    Holds the Engine for this source_id (rg/engines) so its own SQL-fragment builders (subject_predicate,
    exists_from_row, jurisdiction_expr) quote identifiers correctly for Spark SQL."""

    COUNTRY_COLUMNS = ("COUNTRY_CODE", "COUNTRY", "COUNTRY_ISO", "COUNTRY_ISO2", "CNTRY_CD")

    def __init__(self, source_id: int):
        self.source_id = source_id
        self.engine = engines.for_source(source_id)
        self.edges = db.query("SELECT child_table, child_column, parent_table, parent_column, kind FROM RG_LINEAGE "
                              "WHERE source_id = :s", {"s": source_id})
        cols = db.query("SELECT table_name, column_name, data_type, data_length, is_pk FROM RG_CATALOG_COLUMN WHERE source_id = :s",
                        {"s": source_id})
        self.columns: dict[str, dict[str, dict]] = {}
        self.pk: dict[str, str] = {}
        pks: dict[str, list[str]] = {}
        for c in cols:
            self.columns.setdefault(c["table_name"], {})[c["column_name"]] = c
            if c["is_pk"]:
                pks.setdefault(c["table_name"], []).append(c["column_name"])
        for t, cs in pks.items():
            if len(cs) == 1:
                self.pk[t] = cs[0]
        # tables about people: they hold a direct identifier
        self.people = {r["table_name"] for r in db.query(
            "SELECT DISTINCT table_name FROM RG_FINDING WHERE source_id = :s AND category = 'PII' "
            "AND pii_class IN ('DIRECT', 'IDENTIFIER') AND status IN ('AUTO', 'CONFIRMED')", {"s": source_id})}

    def children(self, table: str) -> list[dict]:
        return [e for e in self.edges if e["parent_table"] == table and e["child_table"] != table]

    def paths_from(self, root: str, max_depth: int = 5) -> dict[str, list[list[dict]]]:
        """All simple edge-paths from root to each descendant table."""
        out: dict[str, list[list[dict]]] = {}

        def walk(table: str, path: list[dict], seen: set[str]):
            if len(path) >= max_depth:
                return
            for e in self.children(table):
                if e["child_table"] in seen:
                    continue
                p = path + [e]
                out.setdefault(e["child_table"], []).append(p)
                walk(e["child_table"], p, seen | {e["child_table"]})

        walk(root, [], {root})
        return out

    def subject_predicate(self, table: str, paths: list[list[dict]], root: str, key_bind: str = ":k") -> str:
        """SQL WHERE fragment selecting `table` rows that belong to the root row identified by key_bind."""
        root_pk = self.pk.get(root)
        preds = []
        for path in paths:
            if path[0]["parent_column"] != root_pk:
                continue
            preds.append(self._path_pred(path, key_bind))
        return "(" + " OR ".join(dict.fromkeys(preds)) + ")" if preds else "1 = 0"

    def _path_pred(self, path: list[dict], key_bind: str) -> str:
        ident = self.engine.ident
        last = path[-1]
        if len(path) == 1:
            return f"{ident(last['child_column'])} = {key_bind}"
        inner = self._path_pred(path[:-1], key_bind)
        prev = path[-2]
        return (f"{ident(last['child_column'])} IN (SELECT {ident(last['parent_column'])} "
                f"FROM {ident(prev['child_table'])} WHERE {inner})")

    def exists_from_row(self, path: list[dict], root_alias: str, final_cond: str) -> str:
        """Correlated EXISTS from a root row down `path`, with final_cond (using alias 'aN') on the last table."""
        ident = self.engine.ident

        def build(i: int, outer_alias: str) -> str:
            e = path[i]
            a = f"a{i + 1}"
            cond = f"{a}.{ident(e['child_column'])} = {outer_alias}.{ident(e['parent_column'])}"
            if i == len(path) - 1:
                return f"EXISTS (SELECT 1 FROM {ident(e['child_table'])} {a} WHERE {cond} AND {final_cond.replace('{a}', a)})"
            return f"EXISTS (SELECT 1 FROM {ident(e['child_table'])} {a} WHERE {cond} AND {build(i + 1, a)})"
        return build(0, root_alias)


    # ---- jurisdiction: which country does a row belong to?
    def _country_col(self, table: str) -> str | None:
        """Name-based heuristic, compared case-insensitively since column casing can vary by how the
        table was created in Unity Catalog."""
        cols = self.columns.get(table, {})
        by_upper = {name.upper(): name for name in cols}
        for name in self.COUNTRY_COLUMNS:
            actual = by_upper.get(name)
            c = cols.get(actual) if actual else None
            if c and c["data_type"] in ("CHAR", "VARCHAR2", "NCHAR", "NVARCHAR2") and (c["data_length"] or 0) <= 3:
                return actual
        return None

    def jurisdiction_path(self, table: str, max_depth: int = 4):
        """The nearest table (following child -> parent links) that holds a country column.
        Returns (edges, country_table, country_column) or None. Parents that hold people are preferred."""
        col = self._country_col(table)
        if col:
            return ([], table, col)
        level, seen = [(table, [])], {table}
        for _ in range(max_depth):
            found, nxt = [], []
            for t, path in level:
                for e in self.edges:
                    if e["child_table"] != t or e["parent_table"] in seen:
                        continue
                    p = path + [e]
                    c = self._country_col(e["parent_table"])
                    if c:
                        found.append((p, e["parent_table"], c))
                    nxt.append((e["parent_table"], p))
            if found:
                found.sort(key=lambda f: (0 if f[1] in self.people else 1, f[1]))
                return found[0]
            seen |= {t for t, _ in nxt}
            level = nxt
        return None

    def jurisdiction_expr(self, table: str, alias: str) -> str | None:
        """SQL expression giving the upper-case country code of a row of `table` (alias `alias`), or None."""
        path = self.jurisdiction_path(table)
        if not path:
            return None
        edges, _, col = path
        ident = self.engine.ident

        def build(i: int, outer: str) -> str:
            if i == len(edges):
                return f"{outer}.{ident(col)}"
            e = edges[i]
            a = f"j{i + 1}"
            # MAX(...) is a no-op here (parent_column is a PK, so at most one row matches), but it's what
            # tells Spark SQL this correlated subquery is a scalar aggregate - without it Databricks
            # rejects the bare `SELECT ... FROM ... WHERE corr = outer` form with "correlated scalar
            # subqueries must be aggregated" for any path more than one hop long.
            return (f"(SELECT MAX({build(i + 1, a)}) FROM {ident(e['parent_table'])} {a} "
                    f"WHERE {a}.{ident(e['parent_column'])} = {outer}.{ident(e['child_column'])})")
        return f"UPPER(TRIM({build(0, alias)}))"

    def jurisdiction_info(self, table: str) -> dict:
        path = self.jurisdiction_path(table)
        if not path:
            return {"table": table, "source": "NONE", "via": [], "country_table": None, "country_column": None}
        edges, ctable, ccol = path
        return {"table": table, "source": "DIRECT" if not edges else "INHERITED",
                "via": [f"{e['child_table']}.{e['child_column']} -> {e['parent_table']}.{e['parent_column']}" for e in edges],
                "country_table": ctable, "country_column": ccol}


# --------------------------------------------------------------------------- UC governed-tag write-back
# Mirrors the reconciliation pass's read side (uc_tags, read at discovery time in _discover_databricks)
# with the other direction: once a steward AUTHORIZES a finding the classifier itself produced (not one
# the platform's own tag already confirmed/overrode - see scanner.py's pass 1.6), write that
# classification back as the column's `pii_classification` tag, so the native platform and this app's
# own findings converge over time instead of staying two parallel, ever-diverging sources of truth.
# Off by default (uc_tagging.enabled) - this writes real Unity Catalog governance metadata, a bigger
# blast radius than any other setting in this app, which is why it needs an explicit opt-in.
UC_TAGGING_DEFAULTS = {"uc_tagging.enabled": "0"}


def uc_tagging_enabled() -> bool:
    v = db.scalar("SELECT setting_value FROM RG_SETTING WHERE setting_key = 'uc_tagging.enabled'")
    return (v if v is not None else UC_TAGGING_DEFAULTS["uc_tagging.enabled"]) == "1"


def save_uc_tagging_setting(enabled: bool, username: str) -> dict:
    value = "1" if enabled else "0"
    n = db.execute("UPDATE RG_SETTING SET setting_value = :v, updated_by = :u, updated_at = now() "
                   "WHERE setting_key = 'uc_tagging.enabled'", {"v": value, "u": username})
    if not n:
        db.execute("INSERT INTO RG_SETTING (setting_key, setting_value, updated_by) VALUES "
                   "('uc_tagging.enabled', :v, :u)", {"v": value, "u": username})
    audit(username, "uc_tagging", None, "SETTING", f"enabled={value}")
    return {"enabled": enabled}


def uc_tagging_stats(source_id: int | None = None) -> dict:
    """Dashboard figure: how many confirmed findings have had their classification written back to
    Unity Catalog as a real column tag, vs. how many are still eligible (confirmed, classifier-sourced,
    not yet synced) - the latter is non-zero only when the feature is off, or was off when that finding
    was confirmed."""
    where = "WHERE source_id = :s" if source_id else ""
    p = {"s": source_id} if source_id else {}
    return db.query_one(
        f"SELECT COUNT(*) FILTER (WHERE is_uc_tag_applied = 1) AS tagged, "
        f"COUNT(*) FILTER (WHERE is_uc_tag_applied = 0 AND status = 'CONFIRMED' "
        f"AND classification_source = 'CLASSIFIER') AS eligible_untagged "
        f"FROM RG_FINDING {where}", p)


def _apply_tag(f: dict, username: str) -> bool:
    """Writes f's classification to Unity Catalog and marks it synced. No gating here - callers
    (sync_uc_tag for the per-decide path, commit_uc_tags for the manual button) decide when this is
    appropriate to call; this function just does the write."""
    engine = engines.for_source(f["source_id"])
    if engine.name != "DATABRICKS":
        return False
    code = f["data_element"].replace("'", "''")
    engine.execute(
        f"ALTER TABLE {engine.ident(f['table_name'])} ALTER COLUMN {engine.ident(f['column_name'])} "
        f"SET TAGS ('pii_classification' = '{code}')")
    db.execute("UPDATE RG_FINDING SET is_uc_tag_applied = 1 WHERE finding_id = :i", {"i": f["finding_id"]})
    audit(username, "uc_tag", f["finding_id"], "SYNC",
          f"{f['table_name']}.{f['column_name']} tagged pii_classification={f['data_element']}")
    return True


def _remove_tag(f: dict, username: str, reason: str) -> bool:
    engine = engines.for_source(f["source_id"])
    if engine.name == "DATABRICKS":
        engine.execute(
            f"ALTER TABLE {engine.ident(f['table_name'])} ALTER COLUMN {engine.ident(f['column_name'])} "
            f"UNSET TAGS ('pii_classification')")
    db.execute("UPDATE RG_FINDING SET is_uc_tag_applied = 0 WHERE finding_id = :i", {"i": f["finding_id"]})
    audit(username, "uc_tag", f["finding_id"], "UNSYNC", f"{f['table_name']}.{f['column_name']} untagged pii_classification - {reason}")
    return True


def sync_uc_tag(finding_id: int, username: str) -> dict:
    """Writes finding_id's classification back to Unity Catalog, but ONLY when: the feature is on, the
    column has no native tag already (classification_source == 'CLASSIFIER' - a NATIVE_CONFIRMED/
    NATIVE_OVERRIDE finding means a tag is already there, which is exactly why it got that label), and
    it hasn't been synced before. Never overwrites an existing tag, whoever or whatever set it. Called
    automatically from scanner.decide() on CONFIRMED - gated by uc_tagging_enabled() because that path
    is implicit, unlike the explicit commit_uc_tags() button below."""
    if not uc_tagging_enabled():
        return {"synced": False, "reason": "UC auto-tagging is switched off"}
    f = db.query_one("SELECT * FROM RG_FINDING WHERE finding_id = :i", {"i": finding_id})
    if not f:
        raise ValueError(f"Finding {finding_id} not found")
    if f["is_uc_tag_applied"]:
        return {"synced": False, "reason": "Already synced"}
    if f["classification_source"] != "CLASSIFIER":
        return {"synced": False, "reason": "Column already has a native UC tag"}
    if not _apply_tag(f, username):
        return {"synced": False, "reason": f"UC tagging is not available for this source"}
    return {"synced": True}


def unsync_uc_tag(finding_id: int, username: str) -> dict:
    """The reverse of sync_uc_tag(): called automatically from scanner.decide() when a finding that WAS
    confirmed (and so had a tag written) is later REJECTED - a steward reversing their own decision must
    reverse the UC write too, or the tag silently keeps asserting a classification the steward just said
    is wrong. No-op if this finding never had an app-written tag (nothing to undo)."""
    f = db.query_one("SELECT * FROM RG_FINDING WHERE finding_id = :i", {"i": finding_id})
    if not f or not f["is_uc_tag_applied"]:
        return {"removed": False}
    _remove_tag(f, username, "finding rejected")
    return {"removed": True}


def commit_uc_tags(username: str, source_id: int | None = None) -> dict:
    """The 'UC Commit' button: reconciles Unity Catalog tags against EVERY finding's CURRENT status
    right now, in one pass - not gated by uc_tagging_enabled(), since pressing this button is itself
    the explicit authorization (unlike the automatic per-decide sync/unsync, which only fires when that
    setting is on). For each finding: CONFIRMED + classifier-sourced + not yet tagged -> apply the tag;
    tagged but no longer CONFIRMED (rejected, or reopened back to review) -> remove it. A finding that's
    already consistent with its own status is left untouched either way."""
    where = "WHERE source_id = :s" if source_id else ""
    p = {"s": source_id} if source_id else {}
    findings = db.query(f"SELECT * FROM RG_FINDING {where}", p)
    tagged = untagged = 0
    for f in findings:
        if f["status"] == "CONFIRMED" and f["classification_source"] == "CLASSIFIER" and not f["is_uc_tag_applied"]:
            if _apply_tag(f, username):
                tagged += 1
        elif f["is_uc_tag_applied"] and f["status"] != "CONFIRMED":
            if _remove_tag(f, username, "no longer confirmed as of this commit"):
                untagged += 1
    audit(username, "uc_tag", None, "COMMIT", f"{tagged} tagged, {untagged} untagged")
    return {"tagged": tagged, "untagged": untagged}


def unset_uc_tags_for_source(source_id: int) -> int:
    """Removes every UC tag THIS APP applied for the given source - never one that was already there
    independently. Used by snapshot.clear_all()/restore() so a demo reset doesn't leave stale
    app-written tags behind for the next scan to read back as 'native' and treat as authoritative."""
    rows = db.query(
        "SELECT table_name, column_name FROM RG_FINDING WHERE source_id = :s AND is_uc_tag_applied = 1",
        {"s": source_id})
    if not rows:
        return 0
    engine = engines.for_source(source_id)
    if engine.name != "DATABRICKS":
        return 0
    for r in rows:
        engine.execute(
            f"ALTER TABLE {engine.ident(r['table_name'])} ALTER COLUMN {engine.ident(r['column_name'])} "
            f"UNSET TAGS ('pii_classification')")
    return len(rows)
