"""First-run seed: users, the Databricks data source, the classifier library and starter policies."""
from __future__ import annotations

import hashlib
import secrets

from . import config, db, org, scope
from .classifiers import BUILTIN_CLASSIFIERS

ROLES = ["admin", "steward", "viewer"]


def hash_pw(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()


def seed() -> None:
    if not db.scalar("SELECT COUNT(*) FROM RG_USER"):
        for username, pw, name, role in [("admin", "admin123", "Alex Admin", "admin"),
                                         ("steward", "steward123", "Sam Steward", "steward"),
                                         ("viewer", "viewer123", "Vera Viewer", "viewer")]:
            salt = secrets.token_hex(8)
            db.insert("RG_USER", {"username": username, "password_hash": hash_pw(pw, salt), "salt": salt,
                                  "full_name": name, "role": role}, "user_id")

    if not db.scalar("SELECT COUNT(*) FROM RG_DATA_SOURCE"):
        db.insert("RG_DATA_SOURCE", {"name": f"Insurance Databricks ({config.DBX_CATALOG}.{config.DBX_SCHEMA})",
                                     "source_type": "DATABRICKS", "host": config.DATABRICKS_HOST,
                                     "service_name": config.DBX_HTTP_PATH,
                                     "username": f"{config.DBX_CATALOG}.{config.DBX_SCHEMA}",
                                     "password": config.DATABRICKS_TOKEN,
                                     "schema_name": config.SOURCE_SCHEMA, "domain": "Insurance"},
                  "source_id")

    org.seed_organization()
    org.seed_extra_organizations()
    sync_classifiers()
    if not db.scalar("SELECT COUNT(*) FROM RG_POLICY"):
        _seed_policies()
    ensure_policy_packs()


def sync_classifiers() -> None:
    """Insert missing built-in classifiers and bring existing ones up to date (including their region / country pack).
    A user's enable/disable choice is kept. A country pack whose country is not in the hierarchy is skipped."""
    scope.invalidate()
    ix = scope.ScopeIndex()
    countries = {c["iso2"]: c for c in ix.countries.values()}
    regions = {r["code"]: r for r in ix.regions.values()}
    have = {r["code"]: r for r in db.query("SELECT code, classifier_id FROM RG_CLASSIFIER")}
    for c in BUILTIN_CLASSIFIERS:
        d = {k: v for k, v in c.items() if k not in ("code", "scope_country", "scope_region")}
        if c.get("scope_country"):
            ctry = countries.get(c["scope_country"])
            if not ctry:
                continue
            d.update(scope_level="COUNTRY", region_id=ctry["region_id"], country_id=ctry["country_id"])
        elif c.get("scope_region"):
            reg = regions.get(c["scope_region"])
            if not reg:
                continue
            d.update(scope_level="REGION", region_id=reg["region_id"], country_id=None)
        else:
            d.update(scope_level="GLOBAL", region_id=None, country_id=None)
        if c["code"] in have:
            db.update("RG_CLASSIFIER", "classifier_id", have[c["code"]]["classifier_id"], d)
        else:
            db.insert("RG_CLASSIFIER", {**d, "code": c["code"], "is_builtin": 1, "is_active": 1}, "classifier_id")


def _pack(code: str, name: str, desc: str, category: str, regulation: str, level: str, scope_code: str | None,
          override: bool, rules: list[dict], status: str = "ACTIVE") -> None:
    """Create a scoped policy once (identified by its code). Skipped when its region / country is not configured."""
    if db.scalar("SELECT COUNT(*) FROM RG_POLICY WHERE policy_code = :c", {"c": code}):
        return
    sc = org.scope_ids(level, scope_code)
    if not sc:
        return
    admin = db.scalar("SELECT user_id FROM RG_USER WHERE username = 'admin'")
    pid = db.insert("RG_POLICY", {"policy_code": code, "name": name, "description": desc, "data_category": category,
                                  "regulation": regulation, "status": status, "owner_user_id": admin,
                                  "override_parent": 1 if override else 0, **sc}, "policy_id")
    for i, r in enumerate(rules, 1):
        _rule(pid, i, **r)


def ensure_policy_packs() -> None:
    """Policies added after the first release. Each is created once, identified by its policy code."""
    admin = db.scalar("SELECT user_id FROM RG_USER WHERE username = 'admin'")
    if not db.scalar("SELECT COUNT(*) FROM RG_POLICY WHERE policy_code = 'POL-PHI-001'"):
        p = db.insert("RG_POLICY", {"policy_code": "POL-PHI-001", "name": "Health data protection",
                                    "description": "Special-category data (GDPR Art. 9): medical and health information in claims. "
                                                   "Tokenised in a masked view, so analysts can still group and join on it.",
                                    "data_category": "PHI", "regulation": "GDPR", "status": "ACTIVE",
                                    "owner_user_id": admin}, "policy_id")
        _rule(p, 1, name="Tokenise health information", trigger_event="ALWAYS", action="MASK", masking_method="TOKENIZE",
              enforcement_mode="VIEW", min_confidence=0.8,
              description="Health information is replaced by a consistent token (TOK-...) in a masked view. "
                          "The same medical term always gives the same token, so counts and joins still work.")

    # ---- examples of region / country policies. The values are illustrations for the legal team to replace.
    _pack("POL-EU-001", "Europe: GDPR / UK GDPR data protection",
          "Applies to every European country. Personal data is tokenised (stronger than the global partial mask), "
          "so European data subjects are never shown even partly.", "PII", "GDPR", "REGION", "EUROPE", False,
          [dict(name="Tokenise PII of European data subjects", trigger_event="ALWAYS", action="MASK", masking_method="TOKENIZE",
                enforcement_mode="VIEW", description="Overrides nothing: it adds a stronger mask for rows in Europe. Where both apply, "
                                                      "the strongest method wins.")])
    _pack("POL-DE-001", "Germany: extended claim retention",
          "Example only: a longer retention period than the global 7 years. Confirm the statutory period with local counsel.",
          "GENERAL", "INTERNAL", "COUNTRY", "DE", False,
          [dict(name="Retain claims for 10 years (Germany)", trigger_event="ALWAYS", action="RETAIN", target_table="CLAIM",
                anchor_column="SETTLED_DATE", retention_days=3650, description="Rows of German customers are protected for 10 years."),
           dict(name="Retain claim payments for 10 years (Germany)", trigger_event="ALWAYS", action="RETAIN", target_table="CLAIM_PAYMENT",
                anchor_column="PAYMENT_DATE", retention_days=3650)])
    _pack("POL-GB-001", "United Kingdom: shorter operational retention",
          "Example only: replaces the global 3-year clean-up of policy operations with 2 years for UK customers.",
          "GENERAL", "UK_GDPR", "COUNTRY", "GB", True,
          [dict(name="Delete policy operations after 2 years (UK)", trigger_event="RETENTION_EXPIRY", action="DELETE",
                target_table="POLICY_OPERATION", anchor_column="OPERATION_DATE", retention_days=730,
                description="Because this policy overrides its parent, the global 3-year rule no longer applies to UK rows.")])
    _pack("POL-US-001", "United States: deletion requests (de-identify)",
          "Example only: US privacy laws generally accept de-identification, so a deletion request generalises instead of "
          "removing every attribute.", "PII", "CCPA", "COUNTRY", "US", False,
          [dict(name="Deletion request: de-identify (US)", trigger_event="GDPR_ERASURE_REQUEST", action="ANONYMIZE",
                cascade_scope="SUBJECT_TREE", anonymization_level="GENERALISE",
                description="The most specific erasure rule applies, so US subjects are generalised while European ones are fully anonymised.")])
    _pack("POL-APAC-001", "Asia Pacific: strict masking",
          "Example only: full masking for Asia Pacific data subjects (PDPA, PIPL, APPI ...). Nothing is raised until "
          "the data holds rows for those countries.", "PII", "PDPA", "REGION", "APAC", False,
          [dict(name="Fully mask PII of Asia Pacific data subjects", trigger_event="ALWAYS", action="MASK", masking_method="FULL",
                enforcement_mode="VIEW")])

    # ---- examples for the marketing and legal domains. DRAFT: nothing is enforced until someone reviews and activates them.
    _pack("POL-MKT-001", "Marketing profile protection",
          "Example only (draft): profiling output such as segment, next-best product and cross-sell candidates is tokenised "
          "in a masked view, and profiles of customers who have gone quiet are deleted.",
          "MARKETING", "GDPR", "GLOBAL", None, False,
          [dict(name="Tokenise marketing profile data", trigger_event="ALWAYS", action="MASK", masking_method="TOKENIZE",
                enforcement_mode="VIEW", description="Analysts can still group and count by segment, but see a consistent token, "
                                                     "not the segment itself.")],
          # v04 note: v03's second rule here (DELETE on MKT_CUSTOMER_360, a derived marketing table) is
          # dropped - that table belongs to a separate, unrelated actuarial/commission exploration that
          # happened to share v03's deepak.insurance schema, and was never part of RetentionGuard's own
          # core insurance data model, which v04's deepak.insurance_v04 clone deliberately excludes.
          status="DRAFT")
    _pack("POL-MKT-DE-001", "Germany: strict marketing profiling",
          "Example only (draft): German rules on marketing and profiling are stricter, so segments of German data subjects "
          "are fully masked, which is stronger than the global token. Confirm with local counsel.",
          "MARKETING", "EPRIVACY", "COUNTRY", "DE", False,
          [dict(name="Fully mask marketing profile data (Germany)", trigger_event="ALWAYS", action="MASK", masking_method="FULL",
                enforcement_mode="VIEW", description="Where both this rule and the global one cover a row, the strongest method wins.")],
          status="DRAFT")
    _pack("POL-LEG-001", "Litigation material handling",
          "Example only (draft): litigation and legal-matter references are kept out of general view, and claim files are "
          "retained long enough to cover limitation periods.",
          "LEGAL", "INTERNAL", "GLOBAL", None, False,
          [dict(name="Fully mask litigation and legal-matter columns", trigger_event="ALWAYS", action="MASK", masking_method="FULL",
                enforcement_mode="VIEW", description="Restricts privileged or litigation-related information to those who need it."),
           dict(name="Retain claims for 10 years (limitation periods)", trigger_event="ALWAYS", action="RETAIN", target_table="CLAIM",
                anchor_column="SETTLED_DATE", retention_days=3650,
                description="Stacks with the 7-year insurance retention rule: the longer period protects the row, and it outranks erasure.")],
          status="DRAFT")

    # v04 note: v03's POL-GEN-024 (AGENT_COMMISSION_SUMMARY) and POL-GEN-025 (PROC_RUN_LOG) demo
    # policies are dropped here - both tables belong to the same unrelated actuarial/commission
    # exploration noted above, not v04's deepak.insurance_v04 clone. See
    # RETENTIONGUARD_V4_STATUS.md for the full list of tables v04 actually governs.

    # v04: a replacement ARCHIVE-action demo (so the selective-evaluation picker and the UC-Volumes
    # archive export path - rg/archive.py - both have a real rule to exercise), on an in-scope table.
    _pack("POL-GEN-024", "Settled claim payment archival",
          "Demo policy: archives claim payments older than 5 years (well past the claim's own "
          "settlement), then deletes them from the live table. The exported JSON lands in the "
          "deepak.rg_v04_app.archive UC Volume - GET /api/archive lists every export.",
          "GENERAL", "INTERNAL", "GLOBAL", None, False,
          [dict(name="Archive settled claim payments after 5 years", trigger_event="RETENTION_EXPIRY",
                action="ARCHIVE", target_table="CLAIM_PAYMENT", anchor_column="PAYMENT_DATE", retention_days=1825)])


def _rule(policy_id: int, order: int, **kw) -> None:
    base = {"policy_id": policy_id, "rule_order": order, "description": "", "min_confidence": 0.8,
            "cascade_scope": "NONE", "is_active": 1}
    db.insert("RG_RULE", {**base, **kw}, "rule_id")


def _seed_policies() -> None:
    admin = db.scalar("SELECT user_id FROM RG_USER WHERE username = 'admin'")

    def policy(code, name, desc, cat, reg, status):
        return db.insert("RG_POLICY", {"policy_code": code, "name": name, "description": desc, "data_category": cat,
                                       "regulation": reg, "status": status, "owner_user_id": admin}, "policy_id")

    p1 = policy("POL-PII-001", "Personal data protection",
                "Governs personally identifiable information found by the scanner.", "PII", "GDPR", "ACTIVE")
    _rule(p1, 1, name="Always mask PII", trigger_event="ALWAYS", action="MASK", masking_method="PARTIAL",
          enforcement_mode="VIEW", description="PII must be masked whenever it is read or shared. "
                                               "Applied through masked views over the source tables.")
    _rule(p1, 2, name="GDPR erasure incl. all linked data", trigger_event="GDPR_ERASURE_REQUEST", action="DELETE",
          cascade_scope="SUBJECT_TREE", anonymization_level="FULL", description="On a GDPR erasure request the person's PII is deleted, together "
                                                    "with every table that depends on it - unless retention rules "
                                                    "require the row to stay, in which case it is anonymised.")
    _rule(p1, 3, name="Anonymise dormant customers", trigger_event="RETENTION_EXPIRY", action="ANONYMIZE",
          target_table="CUSTOMER", anchor_column="UPDATED_AT", retention_days=2555, anonymization_level="GENERALISE",
          description="Customers untouched for 7 years and without retained records are anonymised. Year of birth, postcode "
                      "prefix and income band are kept for analytics; everything else that identifies is removed.")

    p2 = policy("POL-INS-001", "Insurance record retention",
                "Statutory retention of contract, claim and payment records. Takes precedence over erasure.",
                "GENERAL", "SOLVENCY_II", "ACTIVE")
    for i, (t, anchor, nm) in enumerate([("POLICY", "EXPIRY_DATE", "policy records after expiry"),
                                         ("CLAIM", "SETTLED_DATE", "claims after settlement"),
                                         ("CLAIM_PAYMENT", "PAYMENT_DATE", "claim payments"),
                                         ("PREMIUM_PAYMENT", "DUE_DATE", "premium payments")], 1):
        _rule(p2, i, name=f"Retain {nm} for 7 years", trigger_event="ALWAYS", action="RETAIN", target_table=t,
              anchor_column=anchor, retention_days=2555,
              description=f"Rows of {t} are protected from deletion until {anchor} + 7 years "
                          f"(rows with an empty {anchor} are still open and stay protected).")

    p3 = policy("POL-OPS-001", "Operational data minimisation",
                "Removes stale operational records that no regulation requires us to keep.", "GENERAL", "INTERNAL", "ACTIVE")
    _rule(p3, 1, name="Delete policy operations after 3 years", trigger_event="RETENTION_EXPIRY", action="DELETE",
          target_table="POLICY_OPERATION", anchor_column="OPERATION_DATE", retention_days=1095,
          description="Redundant, outdated and trivial data (ROT) clean-up.")

    p4 = policy("POL-FIN-001", "Financial data protection",
                "Draft: masks financial identifiers and personal income found by the scanner.", "FINANCIAL", "PCI_DSS", "DRAFT")
    _rule(p4, 1, name="Always mask financial data", trigger_event="ALWAYS", action="MASK", masking_method="FULL",
          enforcement_mode="VIEW")
