"""Organisation, branding and the region / country hierarchy (the top of the scope model).

    Organisation (the company this deployment is configured for)
      +-- Region   (APAC, Europe, North America ...)
            +-- Country (ISO-2 code, the privacy law that governs it)

Only one organisation is active at a time. Several can be stored, and activating another re-brands the app and
switches the hierarchy. Policies and classifiers are scoped to a region or country of the active organisation.
"""
from __future__ import annotations

import base64
import re

from . import catalog, db, policy, remediation, scope
from .common import audit
from .policy import NotFound, ValidationError

_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
_CODE = re.compile(r"^[A-Z][A-Z0-9_]{1,19}$")
_ISO = re.compile(r"^[A-Z]{2}$")
MAX_LOGO_CHARS = 700_000

# Reference data: a starting point for the legal team to confirm, not legal advice.
REGION_SEED = [
    ("APAC", "Asia Pacific", "Asia, Australia and the Pacific"),
    ("EUROPE", "Europe", "European Union, United Kingdom and Switzerland"),
    ("NORTH_AMERICA", "North America", "United States and Canada"),
    ("LATAM", "Latin America", "Central and South America"),
    ("MEA", "Middle East & Africa", "Gulf states, Turkey and Africa"),
]
# region, iso2, name, governing privacy law, regulator (only where well established)
COUNTRY_SEED = [
    ("APAC", "SG", "Singapore", "PDPA", "PDPC"), ("APAC", "IN", "India", "DPDP Act 2023", "Data Protection Board of India"),
    ("APAC", "AU", "Australia", "Privacy Act 1988", "OAIC"), ("APAC", "JP", "Japan", "APPI", "PPC"),
    ("APAC", "CN", "China", "PIPL", "CAC"), ("APAC", "HK", "Hong Kong", "PDPO", "PCPD"),
    ("APAC", "KR", "South Korea", "PIPA", "PIPC"), ("APAC", "TH", "Thailand", "PDPA (2019)", "PDPC Thailand"),
    ("EUROPE", "DE", "Germany", "GDPR + BDSG", "Federal and state data protection authorities"),
    ("EUROPE", "FR", "France", "GDPR", "CNIL"), ("EUROPE", "GB", "United Kingdom", "UK GDPR + DPA 2018", "ICO"),
    ("EUROPE", "ES", "Spain", "GDPR", "AEPD"), ("EUROPE", "IT", "Italy", "GDPR", "Garante"),
    ("EUROPE", "IE", "Ireland", "GDPR", "DPC"), ("EUROPE", "NL", "Netherlands", "GDPR", "Autoriteit Persoonsgegevens"),
    ("EUROPE", "CH", "Switzerland", "revised FADP", "FDPIC"),
    ("NORTH_AMERICA", "US", "United States", "State privacy laws (e.g. CCPA/CPRA), GLBA", "FTC and state attorneys general"),
    ("NORTH_AMERICA", "CA", "Canada", "PIPEDA", "OPC"),
    ("LATAM", "BR", "Brazil", "LGPD", "ANPD"), ("LATAM", "MX", "Mexico", "LFPDPPP", None),
    ("LATAM", "AR", "Argentina", "Law 25.326", None), ("LATAM", "CO", "Colombia", "Law 1581", None),
    ("LATAM", "CL", "Chile", "Law 19.628", None),
    ("MEA", "AE", "United Arab Emirates", "PDPL", None), ("MEA", "ZA", "South Africa", "POPIA", "Information Regulator"),
    ("MEA", "SA", "Saudi Arabia", "PDPL", "SDAIA"), ("MEA", "TR", "Turkiye", "KVKK", None),
]


# --------------------------------------------------------------------------- seed
def seed_organization() -> None:
    if not db.scalar("SELECT COUNT(*) FROM RG_ORGANIZATION"):
        db.insert("RG_ORGANIZATION", {"code": "CHUBB", "name": "Chubb", "tagline": "Insurance",
                                      "logo_url": "/logos/chubb.svg", "banner_color": "#ffffff",
                                      "primary_color": "#000080", "is_active": 1}, "org_id")
    org = db.query_one("SELECT org_id FROM RG_ORGANIZATION WHERE is_active = 1") or \
        db.query_one("SELECT org_id FROM RG_ORGANIZATION ORDER BY org_id FETCH FIRST 1 ROWS ONLY")
    db.execute("UPDATE RG_ORGANIZATION SET is_active = CASE WHEN org_id = :o THEN 1 ELSE 0 END", {"o": org["org_id"]})
    if not db.scalar("SELECT COUNT(*) FROM RG_REGION WHERE org_id = :o", {"o": org["org_id"]}):
        seed_hierarchy(org["org_id"])
    scope.invalidate()


# Additional companies the Organisation tab can switch to, beyond the default active Chubb - same
# "Add a company" mechanism (create_org(), below), just pre-seeded so they're available on any
# deployment (including a fresh one in a new environment) without manual setup. Each starts inactive;
# Chubb stays the default active org until someone explicitly activates a different one. Logo SVGs
# already exist as static assets (backend-databricks/static/logos/, mirrored from the Angular app's
# public/logos/ at build time) - brand colours are reasonable visual approximations for a demo, not
# verified against each company's actual brand guidelines, same spirit as REGION_SEED/COUNTRY_SEED
# above ("a starting point ... not legal advice").
EXTRA_ORGANIZATION_SEED = [
    {"code": "ZURICH", "name": "Zurich", "tagline": "Insurance", "logo_url": "/logos/zurich.svg",
     "banner_color": "#ffffff", "primary_color": "#0014a8"},
    {"code": "ALLIANZ", "name": "Allianz", "tagline": "Insurance", "logo_url": "/logos/allianz.svg",
     "banner_color": "#ffffff", "primary_color": "#003781"},
    {"code": "ERGO", "name": "ERGO", "tagline": "Insurance", "logo_url": "/logos/ergo.svg",
     "banner_color": "#ffffff", "primary_color": "#4c9c2e"},
    {"code": "MUNICHRE", "name": "Munich Re", "tagline": "Reinsurance", "logo_url": "/logos/munichre.svg",
     "banner_color": "#ffffff", "primary_color": "#8f1b24"},
]


def seed_extra_organizations(username: str = "system") -> int:
    """Ensures every EXTRA_ORGANIZATION_SEED company exists - idempotent per company (checked by code),
    unlike seed_organization()'s whole-table-empty gate, so it's safe to call on every startup,
    including against an already-seeded deployment that only has Chubb. Returns how many were newly
    created. Never changes which org is active."""
    created = 0
    for spec in EXTRA_ORGANIZATION_SEED:
        if db.scalar("SELECT COUNT(*) FROM RG_ORGANIZATION WHERE code = :c", {"c": spec["code"]}):
            continue
        create_org(spec, username)
        created += 1
    return created


def seed_hierarchy(org_id: int) -> None:
    """Give an organisation the standard region and country list (a starting point it can edit freely)."""
    ids = {}
    for i, (code, name, desc) in enumerate(REGION_SEED):
        ids[code] = db.insert("RG_REGION", {"org_id": org_id, "code": code, "name": name,
                                            "description": desc, "sort_order": i}, "region_id")
    for region, iso, name, law, regulator in COUNTRY_SEED:
        db.insert("RG_COUNTRY", {"region_id": ids[region], "iso2": iso, "name": name, "regulation": law,
                                 "regulator": regulator}, "country_id")


def scope_ids(level: str, code: str | None) -> dict:
    """{'scope_level','region_id','country_id'} for a region code or ISO country code of the active organisation."""
    if level == "GLOBAL" or not code:
        return {"scope_level": "GLOBAL", "region_id": None, "country_id": None}
    ix = scope.index()
    if level == "REGION":
        r = next((r for r in ix.regions.values() if r["code"] == code), None)
        return {"scope_level": "REGION", "region_id": r["region_id"], "country_id": None} if r else {}
    c = next((c for c in ix.countries.values() if c["iso2"] == code), None)
    return {"scope_level": "COUNTRY", "region_id": c["region_id"], "country_id": c["country_id"]} if c else {}


# --------------------------------------------------------------------------- branding & organisations
def _logo(o: dict) -> str | None:
    return o.get("logo_data") or o.get("logo_url")


def branding() -> dict:
    o = db.query_one("SELECT * FROM RG_ORGANIZATION WHERE is_active = 1")
    if not o:
        return {"org_id": None, "name": "RetentionGuard", "tagline": "", "logo": None, "banner_color": "#0f2a43",
                "primary_color": "#0f766e"}
    return {"org_id": o["org_id"], "code": o["code"], "name": o["name"], "tagline": o["tagline"] or "", "logo": _logo(o),
            "banner_color": o["banner_color"], "primary_color": o["primary_color"]}


def _validate_org(d: dict) -> dict:
    name = (d.get("name") or "").strip()
    if len(name) < 2:
        raise ValidationError("Enter the company name")
    for k in ("banner_color", "primary_color"):
        if not _COLOR.match(d.get(k) or ""):
            raise ValidationError("Colours must look like #1a2b3c")
    url = (d.get("logo_url") or "").strip() or None
    if url and not (url.startswith("/") or url.lower().startswith(("http://", "https://"))):
        raise ValidationError("The logo address must start with http://, https:// or /")
    data = d.get("logo_data") or None
    if data:
        if len(data) > MAX_LOGO_CHARS:
            raise ValidationError("The logo file is too large (limit about 500 KB)")
        m = re.match(r"^data:image/(png|jpeg|jpg|gif|webp|svg\+xml);base64,([A-Za-z0-9+/=]+)$", data)
        if not m:
            raise ValidationError("The logo must be a PNG, JPEG, GIF, WebP or SVG image")
        if m.group(1) == "svg+xml":
            try:
                svg = base64.b64decode(m.group(2)).decode("utf-8", "ignore").lower()
            except Exception:  # noqa: BLE001
                raise ValidationError("The SVG could not be read")
            if re.search(r"<script|<foreignobject|javascript:|\son\w+\s*=|<iframe|@import", svg):
                raise ValidationError("The SVG contains scripts or external content and was rejected")
    return {"name": name, "tagline": (d.get("tagline") or "").strip()[:200] or None, "logo_url": url, "logo_data": data,
            "banner_color": d["banner_color"].lower(), "primary_color": d["primary_color"].lower()}


def list_orgs() -> list[dict]:
    rows = db.query("SELECT org_id, code, name, tagline, logo_url, logo_data, banner_color, primary_color, is_active, "
                    "(SELECT COUNT(*) FROM RG_REGION r WHERE r.org_id = o.org_id) regions FROM RG_ORGANIZATION o ORDER BY org_id")
    for r in rows:
        r["logo"] = _logo(r)
        r.pop("logo_data")
    return rows


def get_org(org_id: int) -> dict:
    o = db.query_one("SELECT * FROM RG_ORGANIZATION WHERE org_id = :i", {"i": org_id})
    if not o:
        raise NotFound(f"Organisation {org_id} not found")
    o["logo"] = _logo(o)
    return o


def create_org(d: dict, username: str) -> dict:
    v = _validate_org(d)
    code = re.sub(r"[^A-Z0-9_]", "_", (d.get("code") or v["name"]).upper())[:30]
    if db.scalar("SELECT COUNT(*) FROM RG_ORGANIZATION WHERE code = :c", {"c": code}):
        raise ValidationError(f"An organisation with code {code} already exists")
    oid = db.insert("RG_ORGANIZATION", {"code": code, **v, "is_active": 0}, "org_id")
    if d.get("seed_hierarchy", True):
        seed_hierarchy(oid)
    audit(username, "organization", oid, "CREATE", v["name"])
    return get_org(oid)


def update_org(org_id: int, d: dict, username: str) -> dict:
    cur = get_org(org_id)
    merged = {**cur, **{k: d.get(k) for k in ("name", "tagline", "logo_url", "logo_data", "banner_color", "primary_color") if k in d}}
    if d.get("clear_logo"):
        merged["logo_url"] = merged["logo_data"] = None
    v = _validate_org(merged)
    db.update("RG_ORGANIZATION", "org_id", org_id, v)
    db.execute("UPDATE RG_ORGANIZATION SET updated_at = now() WHERE org_id = :i", {"i": org_id})
    audit(username, "organization", org_id, "UPDATE", v["name"])
    return get_org(org_id)


def activate_org(org_id: int, username: str) -> dict:
    o = get_org(org_id)
    db.execute("UPDATE RG_ORGANIZATION SET is_active = CASE WHEN org_id = :o THEN 1 ELSE 0 END", {"o": org_id})
    scope.invalidate()
    audit(username, "organization", org_id, "ACTIVATE", o["name"])
    return get_org(org_id)


def delete_org(org_id: int, username: str) -> None:
    o = get_org(org_id)
    if o["is_active"]:
        raise ValidationError("Activate another organisation before deleting this one")
    refs = db.scalar("SELECT COUNT(*) FROM RG_POLICY WHERE region_id IN (SELECT region_id FROM RG_REGION WHERE org_id = :o)", {"o": org_id})
    if refs:
        raise ValidationError(f"{refs} policy(ies) are scoped to this organisation's regions or countries")
    db.execute("DELETE FROM RG_ORGANIZATION WHERE org_id = :o", {"o": org_id})
    audit(username, "organization", org_id, "DELETE", o["name"])


# --------------------------------------------------------------------------- hierarchy
def _active_org_id() -> int:
    o = db.scalar("SELECT org_id FROM RG_ORGANIZATION WHERE is_active = 1")
    if not o:
        raise ValidationError("No organisation is active")
    return o


def hierarchy() -> dict:
    ix = scope.index()
    pol = {(r["scope_level"], r["region_id"], r["country_id"]): r["n"] for r in db.query(
        "SELECT scope_level, region_id, country_id, COUNT(*) n FROM RG_POLICY GROUP BY scope_level, region_id, country_id")}
    clf = {(r["scope_level"], r["region_id"], r["country_id"]): r["n"] for r in db.query(
        "SELECT scope_level, region_id, country_id, COUNT(*) n FROM RG_CLASSIFIER GROUP BY scope_level, region_id, country_id")}
    out = {"org": branding(), "global": {"policies": pol.get(("GLOBAL", None, None), 0), "classifiers": clf.get(("GLOBAL", None, None), 0)}, "regions": []}
    for r in ix.regions.values():
        cs = []
        for c in ix.countries.values():
            if c["region_id"] == r["region_id"]:
                cs.append({**c, "policies": pol.get(("COUNTRY", r["region_id"], c["country_id"]), 0),
                           "classifiers": clf.get(("COUNTRY", r["region_id"], c["country_id"]), 0)})
        out["regions"].append({**r, "policies": pol.get(("REGION", r["region_id"], None), 0),
                               "classifiers": clf.get(("REGION", r["region_id"], None), 0), "countries": cs})
    return out


def _region_in_org(region_id: int) -> dict:
    r = db.query_one("SELECT * FROM RG_REGION WHERE region_id = :i AND org_id = :o", {"i": region_id, "o": _active_org_id()})
    if not r:
        raise NotFound(f"Region {region_id} not found in the active organisation")
    return r


def _in_use(level: str, region_id: int | None, country_id: int | None) -> str | None:
    col = "region_id" if level == "REGION" else "country_id"
    val = region_id if level == "REGION" else country_id
    p = db.scalar(f"SELECT COUNT(*) FROM RG_POLICY WHERE scope_level = :l AND {col} = :v", {"l": level, "v": val})
    c = db.scalar(f"SELECT COUNT(*) FROM RG_CLASSIFIER WHERE scope_level = :l AND {col} = :v", {"l": level, "v": val})
    if p or c:
        return f"{p} policy(ies) and {c} classifier(s) are scoped to it. Move or delete them first, or deactivate it instead"
    return None


def create_region(d: dict, username: str) -> dict:
    code = re.sub(r"[^A-Z0-9_]", "_", (d.get("code") or d.get("name") or "").upper())
    if not _CODE.match(code) or len((d.get("name") or "").strip()) < 2:
        raise ValidationError("A region needs a code (letters, digits, underscore) and a name")
    oid = _active_org_id()
    if db.scalar("SELECT COUNT(*) FROM RG_REGION WHERE org_id = :o AND code = :c", {"o": oid, "c": code}):
        raise ValidationError(f"Region {code} already exists")
    order = (db.scalar("SELECT COALESCE(MAX(sort_order), 0) FROM RG_REGION WHERE org_id = :o", {"o": oid}) or 0) + 1
    rid = db.insert("RG_REGION", {"org_id": oid, "code": code, "name": d["name"].strip(), "description": (d.get("description") or "")[:300] or None,
                                  "sort_order": order}, "region_id")
    scope.invalidate()
    audit(username, "region", rid, "CREATE", code)
    return _region_in_org(rid)


def update_region(region_id: int, d: dict, username: str) -> dict:
    r = _region_in_org(region_id)
    name = (d.get("name") or r["name"]).strip()
    if len(name) < 2:
        raise ValidationError("Enter a region name")
    db.update("RG_REGION", "region_id", region_id, {"name": name, "description": (d.get("description") if "description" in d else r["description"]),
                                                   "is_active": 1 if d.get("is_active", r["is_active"]) else 0})
    scope.invalidate()
    audit(username, "region", region_id, "UPDATE", name)
    return _region_in_org(region_id)


def delete_region(region_id: int, username: str) -> None:
    r = _region_in_org(region_id)
    if db.scalar("SELECT COUNT(*) FROM RG_COUNTRY WHERE region_id = :r", {"r": region_id}):
        raise ValidationError("Remove or move the region's countries first")
    msg = _in_use("REGION", region_id, None)
    if msg:
        raise ValidationError(msg)
    db.execute("DELETE FROM RG_REGION WHERE region_id = :r", {"r": region_id})
    scope.invalidate()
    audit(username, "region", region_id, "DELETE", r["code"])


def _country_row(country_id: int) -> dict:
    c = db.query_one("SELECT c.* FROM RG_COUNTRY c JOIN RG_REGION r ON r.region_id = c.region_id "
                     "WHERE c.country_id = :i AND r.org_id = :o", {"i": country_id, "o": _active_org_id()})
    if not c:
        raise NotFound(f"Country {country_id} not found in the active organisation")
    return c


def create_country(d: dict, username: str) -> dict:
    iso = (d.get("iso2") or "").strip().upper()
    if not _ISO.match(iso) or len((d.get("name") or "").strip()) < 2:
        raise ValidationError("A country needs a 2-letter ISO code and a name")
    _region_in_org(int(d["region_id"]))
    if db.scalar("SELECT COUNT(*) FROM RG_COUNTRY c JOIN RG_REGION r ON r.region_id = c.region_id WHERE r.org_id = :o AND c.iso2 = :i",
                 {"o": _active_org_id(), "i": iso}):
        raise ValidationError(f"{iso} is already in the hierarchy")
    cid = db.insert("RG_COUNTRY", {"region_id": int(d["region_id"]), "iso2": iso, "name": d["name"].strip(),
                                   "regulation": (d.get("regulation") or "")[:120] or None,
                                   "regulator": (d.get("regulator") or "")[:160] or None,
                                   "notes": (d.get("notes") or "")[:300] or None}, "country_id")
    scope.invalidate()
    audit(username, "country", cid, "CREATE", f"{iso} {d['name']}")
    return _country_row(cid)


def update_country(country_id: int, d: dict, username: str) -> dict:
    c = _country_row(country_id)
    new_region = int(d.get("region_id") or c["region_id"])
    _region_in_org(new_region)
    name = (d.get("name") or c["name"]).strip()
    db.update("RG_COUNTRY", "country_id", country_id, {
        "region_id": new_region, "name": name,
        "regulation": (d["regulation"] if "regulation" in d else c["regulation"]),
        "regulator": (d["regulator"] if "regulator" in d else c["regulator"]),
        "notes": (d["notes"] if "notes" in d else c["notes"]),
        "is_active": 1 if d.get("is_active", c["is_active"]) else 0})
    if new_region != c["region_id"]:      # keep country-scoped policies and classifiers pointing at the right region
        db.execute("UPDATE RG_POLICY SET region_id = :r WHERE country_id = :c", {"r": new_region, "c": country_id})
        db.execute("UPDATE RG_CLASSIFIER SET region_id = :r WHERE country_id = :c", {"r": new_region, "c": country_id})
    scope.invalidate()
    audit(username, "country", country_id, "UPDATE", f"{c['iso2']} {name}")
    return _country_row(country_id)


def delete_country(country_id: int, username: str) -> None:
    c = _country_row(country_id)
    msg = _in_use("COUNTRY", c["region_id"], country_id)
    if msg:
        raise ValidationError(msg)
    db.execute("DELETE FROM RG_COUNTRY WHERE country_id = :c", {"c": country_id})
    scope.invalidate()
    audit(username, "country", country_id, "DELETE", c["iso2"])


# --------------------------------------------------------------------------- what applies where
def _rule_detail(r: dict) -> str:
    if r["action"] == "RETAIN":
        return f"keep {r['target_table']} until {r['anchor_column']} + {r['retention_days']} days"
    if r["trigger_event"] == "RETENTION_EXPIRY":
        return f"{r['action'].lower()} {r['target_table']} {r['retention_days']} days after {r['anchor_column']}"
    if r["action"] == "MASK":
        return f"mask {r['data_category']} data ({(r['masking_method'] or '').lower()}, {'masked view' if (r['enforcement_mode'] or 'VIEW') == 'VIEW' else 'in place'})"
    return f"{r['action'].lower()} on an erasure request" + (f" ({(r['anonymization_level'] or '').lower()} level)" if r.get("anonymization_level") else "")


def coverage(iso2: str | None) -> dict:
    """What applies to one country: inherited policies, the effective rules after overrides, and its classifiers."""
    ix = scope.index()
    iso2 = (iso2 or "").upper() or None
    country = ix.active_iso.get(iso2) if iso2 else None
    if iso2 and not country:
        raise NotFound(f"{iso2} is not an active country of the active organisation")
    region = ix.regions.get(country["region_id"]) if country else None

    pols = [p for p in policy.list_policies() if ix.applies(p, iso2)]
    groups = []
    for level, title in (("GLOBAL", "Global"), ("REGION", region["name"] if region else "Region"), ("COUNTRY", country["name"] if country else "Country")):
        items = [{"policy_id": p["policy_id"], "policy_code": p["policy_code"], "name": p["name"], "status": p["status"],
                  "data_category": p["data_category"], "rule_count": p["rule_count"], "override_parent": bool(p["override_parent"])}
                 for p in pols if p["scope_level"] == level]
        if items or level == "GLOBAL":
            groups.append({"level": level, "title": title, "policies": items})

    rules = policy.active_rules()
    by_kind: dict[tuple, list[dict]] = {}
    for r in rules:
        by_kind.setdefault(scope.retention_kind(r) if (r["action"] == "RETAIN" or r["trigger_event"] == "RETENTION_EXPIRY")
                           else scope.category_kind(r), []).append(r)
    resolved = []
    for kind, rs in by_kind.items():
        fn = scope.retention_kind if (rs[0]["action"] == "RETAIN" or rs[0]["trigger_event"] == "RETENTION_EXPIRY") else scope.category_kind
        applicable = [r for r in rs if ix.applies(r, iso2)]
        effective = ix.effective(rs, iso2, fn)
        for r in applicable:
            resolved.append({"rule_id": r["rule_id"], "rule": r["name"], "policy_code": r["policy_code"], "scope": ix.label(r),
                             "scope_level": r["scope_level"], "action": r["action"], "trigger": r["trigger_event"],
                             "detail": _rule_detail(r), "effective": r in effective,
                             "overridden_by": None if r in effective else next(
                                 (o["policy_code"] for o in applicable if o.get("override_parent") and ix.spec(o) > ix.spec(r) and fn(o) == fn(r)), None)})
    resolved.sort(key=lambda x: (x["trigger"], x["action"], -{"COUNTRY": 2, "REGION": 1, "GLOBAL": 0}[x["scope_level"]]))

    clfs = [c for c in db.query("SELECT classifier_id, code, name, category, pii_class, scope_level, region_id, country_id, is_active "
                                "FROM RG_CLASSIFIER ORDER BY code") if c["is_active"] and ix.applies(c, iso2)]
    for c in clfs:
        c["scope"] = ix.label(c)
    return {"country": country, "region": region, "groups": groups, "rules": resolved, "classifiers": clfs}


def jurisdiction_report() -> dict:
    """How each source table learns a row's country, and how the data is distributed across countries.

    FIX (was a real bug): `expr` is built by Graph.jurisdiction_expr() using the DATA-PLANE engine's own
    identifier quoting (graph.engine.ident - backticks, for Databricks/Spark SQL), since `t` is a source
    table that only exists in Unity Catalog. This used to run that expression through `db` (rg/db.py,
    the Lakebase CONTROL-plane/Postgres connection) instead, which doesn't understand backtick-quoted
    identifiers at all and raised psycopg.errors.SyntaxError on every call - GET /api/jurisdiction always
    500'd past the point this function is reached. Fixed by running the query through graph.engine (the
    same engine jurisdiction_expr()'s own identifiers were quoted for) instead of db."""
    ix = scope.index()
    graph = catalog.Graph(remediation.source_id())
    tables, seen_codes = [], {}
    for t in sorted(graph.columns):
        info = graph.jurisdiction_info(t)
        expr = graph.jurisdiction_expr(t, "t")
        dist = []
        if expr:
            dist = [{"country": r["c"], "rows": r["n"]} for r in graph.engine.query(
                f'SELECT c, COUNT(*) n FROM (SELECT {expr} c FROM {graph.engine.ident(t)} t) GROUP BY c ORDER BY n DESC')]
            for d in dist:
                seen_codes[d["country"]] = seen_codes.get(d["country"], 0) + d["rows"]
        tables.append({**info, "distribution": dist})
    unmapped = sorted(c for c in seen_codes if c and c not in ix.active_iso)
    return {"tables": tables, "unmapped_countries": unmapped}
