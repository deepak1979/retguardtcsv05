"""Policies and rules, and how rules attach to classification output.

A rule has a TRIGGER (when), an ACTION (then) and a SCOPE (what data it applies to):

  trigger ALWAYS + MASK                   scope = classifier output (policy category, elements, min confidence, tables)
  trigger GDPR_ERASURE_REQUEST + DELETE   scope = the subject found via classified PII columns
  trigger RETENTION_EXPIRY + DELETE/ANONYMIZE/ARCHIVE  scope = target table + anchor date column + retention days
  ALWAYS + RETAIN                         scope = target table + anchor date column + retention days (protects rows)

ARCHIVE exports the matching rows to a JSON file (rg/archive.py, indexed in RG_ARCHIVE) and only then deletes them -
a middle ground between DELETE (gone for good) and ANONYMIZE (kept, identity removed).

Precedence when rules conflict:  legal hold  >  RETAIN  >  erasure / expiry actions.
"""
from __future__ import annotations

import fnmatch

from . import db, scope
from .common import ANON_LEVEL_HELP, ANON_LEVELS, MASKING_METHODS, audit

CATEGORIES = ["PII", "SPECIAL_CATEGORY", "PHI", "FINANCIAL", "CLAIMS", "MARKETING", "LEGAL", "GENERAL"]
TRIGGERS = ["ALWAYS", "GDPR_ERASURE_REQUEST", "RETENTION_EXPIRY"]
ACTIONS = ["MASK", "DELETE", "ANONYMIZE", "ARCHIVE", "RETAIN"]
ENFORCEMENT = ["VIEW", "IN_PLACE"]
CASCADE = ["NONE", "SUBJECT_TREE"]
STATUSES = ["DRAFT", "ACTIVE", "RETIRED"]
REGULATIONS = ["GDPR", "UK_GDPR", "CCPA", "HIPAA", "GLBA", "LGPD", "PDPA", "PIPL", "APPI", "DPDP", "POPIA", "PCI_DSS", "SOLVENCY_II", "EPRIVACY", "CAN_SPAM", "TCPA", "INTERNAL"]


class ValidationError(ValueError):
    pass


class NotFound(LookupError):
    pass


def _scope_lookups() -> dict:
    ix = scope.ScopeIndex()
    return {"regions": [{"region_id": r["region_id"], "code": r["code"], "name": r["name"], "is_active": r["is_active"]} for r in ix.regions.values()],
            "countries": [{"country_id": c["country_id"], "iso2": c["iso2"], "name": c["name"], "region_id": c["region_id"], "is_active": c["is_active"]}
                          for c in ix.countries.values()]}


def lookups() -> dict:
    return {
        "data_categories": CATEGORIES, "trigger_events": TRIGGERS, "rule_actions": ACTIONS,
        "masking_methods": MASKING_METHODS, "enforcement_modes": ENFORCEMENT, "cascade_scopes": CASCADE,
        "policy_statuses": STATUSES, "regulations": REGULATIONS, "roles": ["admin", "steward", "viewer"],
        "anonymization_levels": [{"code": c, "help": ANON_LEVEL_HELP[c]} for c in ANON_LEVELS],
        "scope_levels": list(scope.LEVELS), **_scope_lookups(),
        "data_elements": db.query("SELECT code, name, category, pii_class FROM RG_CLASSIFIER WHERE is_active = 1 ORDER BY code"),
    }


# --------------------------------------------------------------------------- matching rules to findings
def _table_matches(patterns: str | None, table: str) -> bool:
    if not patterns:
        return True
    return any(fnmatch.fnmatch(table.upper(), p.strip().upper().replace("%", "*")) for p in patterns.split(",") if p.strip())


def rule_findings(category: str, rule: dict, statuses: tuple = ("AUTO", "CONFIRMED")) -> list[dict]:
    """Findings a rule applies to: same category, confident enough, inside the rule's element/table filters - from
    every data source. MASK rules are inherently multi-source this way (remediation.evaluate() groups the result
    by (source_id, table) and dispatches each group to the right engine); RETENTION_EXPIRY/RETAIN rules instead
    name one explicit target_table, resolved to its source via RG_RULE.source_id (see policy._resolve_table)."""
    marks = ", ".join(f"'{s}'" for s in statuses)
    rows = db.query(f"SELECT * FROM RG_FINDING WHERE category = :c AND status IN ({marks}) AND confidence >= :mc "
                    f"ORDER BY table_name, column_name", {"c": category, "mc": rule.get("min_confidence") or 0})
    elements = {e.strip().upper() for e in (rule.get("element_filter") or "").split(",") if e.strip()}
    return [f for f in rows if (not elements or f["data_element"] in elements) and _table_matches(rule.get("table_filter"), f["table_name"])]


# --------------------------------------------------------------------------- validation
def _resolve_table(source_id: int, table: str) -> str:
    """Canonical catalog casing for `table` in `source_id`, resolved once at rule save time so every
    later exact-match lookup (table_cols, row_count, ...) just works."""
    row = db.query_one("SELECT table_name FROM RG_CATALOG_TABLE WHERE source_id = :s AND UPPER(table_name) = UPPER(:t)",
                       {"s": source_id, "t": table})
    return row["table_name"] if row else table.upper()


def _resolve_column(source_id: int, table: str, column: str) -> str:
    row = db.query_one("SELECT column_name FROM RG_CATALOG_COLUMN WHERE source_id = :s AND UPPER(table_name) = UPPER(:t) "
                       "AND UPPER(column_name) = UPPER(:c)", {"s": source_id, "t": table, "c": column})
    return row["column_name"] if row else column.upper()


def _catalog_column(source_id: int, table: str, column: str) -> dict | None:
    return db.query_one("SELECT data_type FROM RG_CATALOG_COLUMN WHERE source_id = :s AND UPPER(table_name) = UPPER(:t) "
                        "AND UPPER(column_name) = UPPER(:c)", {"s": source_id, "t": table, "c": column})


def normalise_scope(d: dict) -> None:
    """Make scope_level / region_id / country_id consistent (and inside the active organisation)."""
    level = d.get("scope_level") or "GLOBAL"
    if level not in scope.LEVELS:
        raise ValidationError(f"Unknown scope '{level}'")
    ix = scope.ScopeIndex()
    if level == "GLOBAL":
        d["region_id"] = d["country_id"] = None
    elif level == "REGION":
        if d.get("region_id") not in ix.regions:
            raise ValidationError("Choose a region of the active organisation")
        d["country_id"] = None
    else:
        c = ix.countries.get(d.get("country_id"))
        if not c:
            raise ValidationError("Choose a country of the active organisation")
        d["region_id"] = c["region_id"]
    d["scope_level"] = level
    d["override_parent"] = 1 if d.get("override_parent") and level != "GLOBAL" else 0


def validate_policy(d: dict, policy_id: int | None = None) -> None:
    if d.get("data_category") not in CATEGORIES:
        raise ValidationError(f"Unknown data category '{d.get('data_category')}'")
    if d.get("status") not in STATUSES:
        raise ValidationError(f"Unknown status '{d.get('status')}'")
    if d.get("regulation") and d["regulation"] not in REGULATIONS:
        raise ValidationError(f"Unknown regulation '{d['regulation']}'")
    if db.scalar("SELECT COUNT(*) FROM RG_POLICY WHERE policy_code = :c AND policy_id <> COALESCE(:i, -1)",
                 {"c": d["policy_code"], "i": policy_id}):
        raise ValidationError(f"Policy code '{d['policy_code']}' already exists")


def validate_rule(d: dict) -> None:
    trig, action = d["trigger_event"], d["action"]
    if trig not in TRIGGERS:
        raise ValidationError(f"Unknown trigger '{trig}'")
    if action not in ACTIONS:
        raise ValidationError(f"Unknown action '{action}'")
    mc = d.get("min_confidence")
    if mc is not None and not 0.3 <= float(mc) <= 1:
        raise ValidationError("Minimum confidence must be between 0.30 and 1.00")
    if action == "MASK":
        if trig != "ALWAYS":
            raise ValidationError("MASK rules use the trigger ALWAYS")
        if d.get("masking_method") not in MASKING_METHODS:
            raise ValidationError("A MASK rule needs a masking method")
        if (d.get("enforcement_mode") or "VIEW") not in ENFORCEMENT:
            raise ValidationError("Enforcement must be VIEW or IN_PLACE")
    if action == "RETAIN" and trig != "ALWAYS":
        raise ValidationError("RETAIN rules use the trigger ALWAYS")
    if action == "ARCHIVE" and trig != "RETENTION_EXPIRY":
        raise ValidationError("ARCHIVE rules use the trigger Retention expiry")
    if trig == "GDPR_ERASURE_REQUEST" and action not in ("DELETE", "ANONYMIZE"):
        raise ValidationError("An erasure-request rule must DELETE or ANONYMIZE")
    if trig == "RETENTION_EXPIRY" and action not in ("DELETE", "ANONYMIZE", "ARCHIVE"):
        raise ValidationError("A retention-expiry rule must DELETE, ANONYMIZE or ARCHIVE")
    if d.get("cascade_scope") not in (None, *CASCADE):
        raise ValidationError("Unknown cascade scope")
    if d.get("anonymization_level") not in (None, *ANON_LEVELS):
        raise ValidationError("Unknown anonymisation level")
    needs_target = action == "RETAIN" or trig == "RETENTION_EXPIRY"
    if needs_target:
        if not (d.get("target_table") and d.get("anchor_column")):
            raise ValidationError("This rule needs a target table and an anchor date column")
        col = _catalog_column(d.get("source_id") or 1, d["target_table"], d["anchor_column"])
        if not col:
            raise ValidationError(f"{d['target_table']}.{d['anchor_column']} is not in that data source's catalog (run discovery)")
        if col["data_type"] not in ("DATE", "TIMESTAMP"):
            raise ValidationError("The anchor column must be a DATE or TIMESTAMP column")
        if not d.get("retention_days") or int(d["retention_days"]) <= 0:
            raise ValidationError("Retention period must be a positive number of days")


# --------------------------------------------------------------------------- policies
def _owner(uid) -> str | None:
    return db.scalar("SELECT username FROM RG_USER WHERE user_id = :u", {"u": uid}) if uid else None


def list_policies(q: str | None = None, status: str | None = None, category: str | None = None) -> list[dict]:
    sql = ["SELECT p.*, (SELECT COUNT(*) FROM RG_RULE r WHERE r.policy_id = p.policy_id) AS rule_count, "
           "(SELECT username FROM RG_USER u WHERE u.user_id = p.owner_user_id) AS owner FROM RG_POLICY p WHERE 1=1"]
    p: dict = {}
    if status:
        sql.append("AND p.status = :st")
        p["st"] = status
    if category:
        sql.append("AND p.data_category = :cat")
        p["cat"] = category
    if q:
        sql.append("AND (LOWER(p.name) LIKE :q OR LOWER(p.policy_code) LIKE :q OR LOWER(p.description) LIKE :q)")
        p["q"] = f"%{q.lower()}%"
    sql.append("ORDER BY p.policy_id")
    rows = db.query(" ".join(sql), p)
    ix = scope.index()
    for r in rows:
        r["scope_label"] = ix.label(r)
        r["scope_valid"] = ix.valid(r)
    return rows


def get_policy(policy_id: int) -> dict:
    p = db.query_one("SELECT * FROM RG_POLICY WHERE policy_id = :i", {"i": policy_id})
    if not p:
        raise NotFound(f"Policy {policy_id} not found")
    p["owner"] = _owner(p["owner_user_id"])
    ix = scope.index()
    p["scope_label"], p["scope_valid"] = ix.label(p), ix.valid(p)
    cs = ix.countries_of(p) if p["scope_valid"] else set()
    p["covered_countries"] = sorted(ix.active_iso) if cs is None else sorted(cs)
    p["rules"] = db.query("SELECT * FROM RG_RULE WHERE policy_id = :i ORDER BY rule_order, rule_id", {"i": policy_id})
    p["rule_count"] = len(p["rules"])
    # classification output this policy applies to (union across its classification-scoped rules)
    seen, matched = set(), []
    for r in p["rules"]:
        if r["action"] == "RETAIN" or r["trigger_event"] == "RETENTION_EXPIRY":
            continue
        for f in rule_findings(p["data_category"], r, ("AUTO", "CONFIRMED", "NEEDS_REVIEW")):
            k = f["finding_id"]
            if k not in seen:
                seen.add(k)
                matched.append({"finding_id": k, "table_name": f["table_name"], "column_name": f["column_name"],
                                "data_element": f["data_element"], "confidence": f["confidence"],
                                "status": f["status"], "protection": f["protection"], "rule": r["name"]})
    p["matched_findings"] = matched
    return p


def create_policy(d: dict, username: str) -> dict:
    d = {"description": "", "status": "DRAFT", "regulation": "INTERNAL", "effective_from": None, "scope_level": "GLOBAL",
         "region_id": None, "country_id": None, "override_parent": 0, **d}
    normalise_scope(d)
    if not d.get("policy_code"):
        n = (db.scalar("SELECT COALESCE(MAX(policy_id), 0) FROM RG_POLICY") or 0) + 1
        d["policy_code"] = f"POL-{d['data_category'][:3]}-{n:03d}"
    validate_policy(d)
    owner = db.scalar("SELECT user_id FROM RG_USER WHERE username = :u", {"u": username})
    pid = db.insert("RG_POLICY", {"policy_code": d["policy_code"], "name": d["name"], "description": d["description"],
                                  "data_category": d["data_category"], "regulation": d["regulation"],
                                  "status": d["status"], "owner_user_id": owner,
                                  "effective_from": _date(d["effective_from"]), "scope_level": d["scope_level"],
                                  "region_id": d["region_id"], "country_id": d["country_id"],
                                  "override_parent": d["override_parent"]}, "policy_id")
    audit(username, "policy", pid, "CREATE", d["name"])
    return get_policy(pid)


def update_policy(policy_id: int, d: dict, username: str) -> dict:
    cur = get_policy(policy_id)
    merged = {**{k: cur[k] for k in ("policy_code", "name", "description", "data_category", "regulation", "status",
                                     "scope_level", "region_id", "country_id", "override_parent")},
              **{k: v for k, v in d.items() if v is not None or k in ("region_id", "country_id")}}
    normalise_scope(merged)
    validate_policy(merged, policy_id)
    db.update("RG_POLICY", "policy_id", policy_id, {
        "policy_code": merged["policy_code"], "name": merged["name"], "description": merged["description"],
        "data_category": merged["data_category"], "regulation": merged["regulation"], "status": merged["status"],
        "scope_level": merged["scope_level"], "region_id": merged["region_id"], "country_id": merged["country_id"],
        "override_parent": merged["override_parent"],
        "effective_from": _date(d["effective_from"]) if d.get("effective_from") else cur["effective_from"]})
    db.execute("UPDATE RG_POLICY SET version = version + 1, updated_at = now() WHERE policy_id = :i", {"i": policy_id})
    audit(username, "policy", policy_id, "UPDATE", merged["name"])
    return get_policy(policy_id)


def delete_policy(policy_id: int, username: str) -> None:
    name = get_policy(policy_id)["name"]
    db.execute("DELETE FROM RG_POLICY WHERE policy_id = :i", {"i": policy_id})
    audit(username, "policy", policy_id, "DELETE", name)


def _date(v):
    import datetime as dt
    if not v:
        return None
    return v if isinstance(v, (dt.date, dt.datetime)) else dt.datetime.strptime(str(v)[:10], "%Y-%m-%d")


# --------------------------------------------------------------------------- rules
_RULE_FIELDS = ("name", "description", "trigger_event", "action", "masking_method", "enforcement_mode", "min_confidence",
                "element_filter", "table_filter", "source_id", "target_table", "anchor_column", "retention_days",
                "cascade_scope", "anonymization_level", "is_active")


def _norm_rule(d: dict) -> dict:
    out = {k: d.get(k) for k in _RULE_FIELDS}
    # source_id only means anything for a rule with an explicit target_table (RETAIN / RETENTION_EXPIRY) - a MASK
    # rule matches classifier output from every source, see rule_findings(). Defaults to source 1, same
    # fallback every other source_id-less piece of app logic uses.
    out["source_id"] = int(out["source_id"]) if out.get("source_id") else 1
    if out.get("target_table"):
        out["target_table"] = _resolve_table(out["source_id"], out["target_table"])
    if out.get("anchor_column") and out.get("target_table"):
        out["anchor_column"] = _resolve_column(out["source_id"], out["target_table"], out["anchor_column"])
    out["element_filter"] = ",".join(x.strip().upper() for x in (out["element_filter"] or "").split(",") if x.strip()) or None
    out["table_filter"] = ",".join(x.strip().upper() for x in (out["table_filter"] or "").split(",") if x.strip()) or None
    out["min_confidence"] = float(out["min_confidence"]) if out["min_confidence"] is not None else 0.8
    out["cascade_scope"] = out["cascade_scope"] or "NONE"
    out["is_active"] = 1 if out["is_active"] is None or out["is_active"] else 0
    if out["action"] != "MASK":
        out["masking_method"] = out["enforcement_mode"] = None
    elif not out["enforcement_mode"]:
        out["enforcement_mode"] = "VIEW"
    if out["action"] == "RETAIN" or out["trigger_event"] == "RETENTION_EXPIRY":
        out["retention_days"] = int(out["retention_days"]) if out["retention_days"] else None
    else:
        out["target_table"] = out["anchor_column"] = out["retention_days"] = None
        out["source_id"] = 1
    if out["trigger_event"] != "GDPR_ERASURE_REQUEST":
        out["cascade_scope"] = "NONE"
    # how much an anonymisation removes: erasure requests, and retention rules whose action is ANONYMIZE
    anonymises = out["trigger_event"] == "GDPR_ERASURE_REQUEST" or (out["trigger_event"] == "RETENTION_EXPIRY" and out["action"] == "ANONYMIZE")
    out["anonymization_level"] = (out["anonymization_level"] or "FULL") if anonymises else None
    out["description"] = out["description"] or ""
    return out


def create_rule(policy_id: int, d: dict, username: str) -> dict:
    get_policy(policy_id)
    r = _norm_rule(d)
    validate_rule(r)
    order = (db.scalar("SELECT COALESCE(MAX(rule_order), 0) FROM RG_RULE WHERE policy_id = :i", {"i": policy_id}) or 0) + 1
    rid = db.insert("RG_RULE", {"policy_id": policy_id, "rule_order": order, **r}, "rule_id")
    audit(username, "rule", rid, "CREATE", f"policy {policy_id}: {r['name']}")
    return get_policy(policy_id)


def update_rule(rule_id: int, d: dict, username: str) -> dict:
    cur = db.query_one("SELECT * FROM RG_RULE WHERE rule_id = :i", {"i": rule_id})
    if not cur:
        raise NotFound(f"Rule {rule_id} not found")
    r = _norm_rule({**cur, **d})
    validate_rule(r)
    db.update("RG_RULE", "rule_id", rule_id, r)
    db.execute("UPDATE RG_RULE SET updated_at = now() WHERE rule_id = :i", {"i": rule_id})
    audit(username, "rule", rule_id, "UPDATE", r["name"])
    return get_policy(cur["policy_id"])


def delete_rule(rule_id: int, username: str) -> dict:
    cur = db.query_one("SELECT * FROM RG_RULE WHERE rule_id = :i", {"i": rule_id})
    if not cur:
        raise NotFound(f"Rule {rule_id} not found")
    db.execute("DELETE FROM RG_RULE WHERE rule_id = :i", {"i": rule_id})
    audit(username, "rule", rule_id, "DELETE", cur["name"])
    return get_policy(cur["policy_id"])


def active_rules(trigger: str | None = None, action: str | None = None) -> list[dict]:
    """Active rules of ACTIVE policies, with their policy attached."""
    sql = ["SELECT r.*, p.data_category, p.policy_code, p.name AS policy_name, p.scope_level, p.region_id, p.country_id, "
           "p.override_parent FROM RG_RULE r "
           "JOIN RG_POLICY p ON p.policy_id = r.policy_id WHERE p.status = 'ACTIVE' AND r.is_active = 1"]
    params: dict = {}
    if trigger:
        sql.append("AND r.trigger_event = :t")
        params["t"] = trigger
    if action:
        sql.append("AND r.action = :a")
        params["a"] = action
    sql.append("ORDER BY r.policy_id, r.rule_order")
    ix = scope.index()
    return [r for r in db.query(" ".join(sql), params) if ix.valid(r)]   # rules scoped outside the active organisation are ignored
