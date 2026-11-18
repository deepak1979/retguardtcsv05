"""Small shared helpers: audit log, masking / anonymisation SQL expression builders.

The masking/anonymisation builders take an `engine` (rg/engines/base.py:Engine) and build their SQL through its
dialect primitives instead of hardcoding one database's syntax, so the same element-by-element logic (EMAIL, PHONE,
names, address...) works unchanged if a second engine is ever added. `db` is still used directly for RG_AUDIT_LOG -
that control table always lives in Lakebase, regardless of which source is being remediated.
"""
from __future__ import annotations

from . import db
from .engines.base import Engine

MASKING_METHODS = ["FULL", "PARTIAL", "HASH", "TOKENIZE"]
ANON_MARKER = "ERASED"  # value written into anonymised name columns; also used to spot already-anonymised rows


def audit(username: str | None, entity: str, entity_id: int | None, action: str, details: str = "", conn=None) -> None:
    db.insert("RG_AUDIT_LOG", {"username": username, "entity_type": entity, "entity_id": entity_id or 0,
                               "action": action, "details": details[:500]}, "audit_id", conn)


def is_date(dtype: str) -> bool:
    return dtype in ("DATE", "TIMESTAMP")


def _mask_expr_raw(engine: Engine, col: str, element: str | None, method: str, dtype: str, nullable: bool, length: int) -> str:
    """SQL expression that returns a masked version of column `col` (used in views and in-place updates)."""
    q = engine.ident(col)
    length = int(length or 100)
    if is_date(dtype):
        if method == "PARTIAL":
            return engine.year_trunc(q)          # keep only the year
        return "NULL" if nullable else engine.date_literal("1900-01-01")
    if dtype == "NUMBER":
        if method == "PARTIAL":
            return engine.round_num(q, -3)        # round to thousands
        return "NULL" if nullable else "0"
    # strings
    if method == "FULL":
        return engine.rpad_star(q, length)
    if method == "HASH":
        return engine.substr(engine.hash_hex(q), 1, min(length, 64))
    if method == "TOKENIZE":
        return engine.substr(engine.concat("'TOK-'", engine.hash_hex(q)), 1, min(length, 20))
    # PARTIAL, tailored to the element
    stars = "'***'"
    if element == "EMAIL":
        at = engine.instr(q, "'@'")
        return (f"CASE WHEN {at} > 0 THEN {engine.concat(engine.substr(q, 1, 2), stars, engine.substr(q, at))} "
                f"ELSE {engine.stars_like(q)} END")
    if element == "PHONE":
        return engine.concat("'***'", engine.right(q, 4))
    if element in ("FIRST_NAME", "LAST_NAME", "FULL_NAME"):
        return engine.concat(engine.substr(q, 1, 1), "'***'")
    if element == "STREET_ADDRESS":
        sp = engine.instr(q, "' '")
        return engine.concat("'*** '", engine.substr(q, f"{sp} + 1"))
    if element == "POSTAL_CODE":
        return engine.concat(engine.substr(q, 1, 2), "'***'")
    if element == "CUSTOMER_NUMBER":
        return engine.concat(engine.substr(q, 1, 2), "'***'", engine.right(q, 2))
    rest = engine.concat(engine.substr(q, 1, 1), engine.stars_like(engine.substr(q, 2)))
    return f"CASE WHEN {engine.length_of(q)} <= 2 THEN {engine.stars_like(q)} ELSE {rest} END"


# --------------------------------------------------------------------------- anonymisation levels
ANON_LEVELS = ["BASIC", "GENERALISE", "FULL"]
ANON_LEVEL_HELP = {
    "BASIC": "Direct identifiers only (names, email, phone, address, IDs). Quasi-identifiers such as city, occupation "
             "or income stay as they are.",
    "GENERALISE": "Direct identifiers removed. Quasi-identifiers are coarsened (year of birth, postcode prefix, rounded "
                  "income) or removed when they cannot be coarsened. Keeps some analytic value.",
    "FULL": "Direct identifiers and every quasi-identifier removed. The safest choice for an erasure request.",
}
GENERALISABLE = {"POSTAL_CODE", "DATE_OF_BIRTH", "ANNUAL_INCOME"}   # can be coarsened
COARSE_KEEP = {"GENDER", "REGION", "MARITAL_STATUS"}                 # already coarse: kept when generalising


def anon_treatment(element: str | None, pii_class: str | None, level: str) -> str:
    """REMOVE | GENERALISE | PSEUDONYM | KEEP for one classified column at the given level."""
    if pii_class in ("DIRECT", "SENSITIVE"):
        return "REMOVE"
    if pii_class == "IDENTIFIER":
        return "PSEUDONYM"                     # a business id: replaced by ERASED-<key>, so links and uniqueness survive
    if level == "BASIC":
        return "KEEP"
    if level == "FULL":
        return "REMOVE"
    if element in GENERALISABLE:
        return "GENERALISE"
    return "KEEP" if element in COARSE_KEEP else "REMOVE"


def describe_treatment(element: str | None, treatment: str) -> str:
    if treatment == "GENERALISE":
        return {"POSTAL_CODE": "postcode prefix only", "DATE_OF_BIRTH": "year of birth only",
                "ANNUAL_INCOME": "rounded to 10,000"}.get(element or "", "generalised")
    return {"REMOVE": "removed", "PSEUDONYM": "replaced by ERASED-<key>", "KEEP": "kept (not identifying alone)"}[treatment]


def mask_expr(engine: Engine, col: str, element: str | None, method: str, dtype: str, nullable: bool, length: int) -> str:
    """Masked value for a column. An empty value stays empty (string concatenation would otherwise turn NULL
    into a non-null '***')."""
    raw = _mask_expr_raw(engine, col, element, method, dtype, nullable, length)
    if is_date(dtype) or dtype == "NUMBER":
        return raw
    return f"CASE WHEN {engine.ident(col)} IS NULL THEN NULL ELSE {raw} END"


def anonymize_expr(engine: Engine, col: str, element: str | None, dtype: str, nullable: bool, length: int,
                   treatment: str = "REMOVE", pk_col: str | None = None) -> str | None:
    """SQL expression that irreversibly replaces a value (GDPR anonymisation, not reversible masking).
    Returns None when the column is kept as it is."""
    length = int(length or 100)
    q = engine.ident(col)
    if treatment == "KEEP":
        return None
    if treatment == "GENERALISE":
        if is_date(dtype):
            return engine.year_trunc(q)
        if dtype == "NUMBER":
            return engine.round_num(q, -4)
        if element == "POSTAL_CODE":
            masked = engine.concat(engine.substr(q, 1, 2), "'***'")
            return f"CASE WHEN {q} IS NULL THEN NULL ELSE {masked} END"
    if treatment == "PSEUDONYM" and pk_col and dtype in ("VARCHAR2", "CHAR", "NVARCHAR2", "NCHAR"):
        return engine.substr(engine.concat(f"'{ANON_MARKER}-'", engine.to_char(engine.ident(pk_col))), 1, length)
    if is_date(dtype):
        return engine.date_literal("1900-01-01") if (element == "DATE_OF_BIRTH" or not nullable) else "NULL"
    if dtype == "NUMBER":
        return "NULL" if nullable else "0"
    if element in ("FIRST_NAME", "LAST_NAME", "FULL_NAME"):
        return f"'{ANON_MARKER[:length]}'"
    if nullable:
        return "NULL"
    return f"'{ANON_MARKER[:length]}'"


def sample_mask(value: str) -> str:
    """Mask a sampled value for display in the UI (never store raw PII in the metadata tables)."""
    v = str(value)
    if "@" in v:
        return v[:2] + "***" + v[v.index("@"):]
    if len(v) <= 3:
        return "*" * len(v)
    return v[:1] + "*" * min(len(v) - 2, 8) + v[-1:]
