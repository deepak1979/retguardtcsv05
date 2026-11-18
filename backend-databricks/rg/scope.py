"""Organisation scope: which policies, rules and classifiers apply where.

The hierarchy is   Organisation  >  Region  >  Country.   A policy (and a classifier) has a scope:

    GLOBAL    applies everywhere
    REGION    applies to every active country in that region
    COUNTRY   applies to that one country

How rules combine for a row that belongs to country C:

  * every ACTIVE rule whose scope contains C applies (broader rules are inherited by narrower scopes);
  * a policy flagged `override_parent` REPLACES the broader rules of the same kind, so a country can shorten a
    retention period as well as extend it. Kinds: retention = (trigger, action, table); others = (trigger, action, category);
  * masking: when several rules mask the same column, the strongest method wins for that row;
  * erasure: the most specific applicable rule is used.

A row's country comes from a country column on its table, or is inherited through the foreign-key / lineage graph
(see catalog.Graph.jurisdiction_expr). A row with no known country is treated as global-only.
"""
from __future__ import annotations

import re
import threading
import time

from . import db

LEVELS = ("GLOBAL", "REGION", "COUNTRY")
SPECIFICITY = {"GLOBAL": 0, "REGION": 1, "COUNTRY": 2}
METHOD_STRENGTH = {"PARTIAL": 1, "HASH": 2, "TOKENIZE": 3, "FULL": 4}
_ISO = re.compile(r"^[A-Z]{2}$")


def sql_list(codes) -> str:
    """'DE','FR' - validated so it is safe to interpolate."""
    out = sorted(c for c in codes)
    for c in out:
        if not _ISO.match(c):
            raise ValueError(f"Invalid country code {c!r}")
    return ", ".join(f"'{c}'" for c in out)


class ScopeIndex:
    def __init__(self) -> None:
        self.org = db.query_one("SELECT * FROM RG_ORGANIZATION WHERE is_active = 1")
        self.regions: dict[int, dict] = {}
        self.countries: dict[int, dict] = {}
        if self.org:
            for r in db.query("SELECT * FROM RG_REGION WHERE org_id = :o ORDER BY sort_order, name", {"o": self.org["org_id"]}):
                self.regions[r["region_id"]] = r
            if self.regions:
                for c in db.query("SELECT * FROM RG_COUNTRY ORDER BY name"):
                    if c["region_id"] in self.regions:
                        self.countries[c["country_id"]] = c
        self.active_iso = {c["iso2"]: c for c in self.countries.values()
                           if c["is_active"] and self.regions[c["region_id"]]["is_active"]}

    # ---- scope of an object (policy, rule joined with its policy, classifier, mask entry)
    @staticmethod
    def scope_of(o: dict) -> tuple[str, int | None, int | None]:
        return (o.get("scope_level") or "GLOBAL", o.get("region_id"), o.get("country_id"))

    def valid(self, o: dict) -> bool:
        level, rid, cid = self.scope_of(o)
        if level == "GLOBAL":
            return True
        if level == "REGION":
            r = self.regions.get(rid)
            return bool(r and r["is_active"])
        c = self.countries.get(cid)
        return bool(c and c["is_active"] and self.regions[c["region_id"]]["is_active"])

    def countries_of(self, o: dict) -> set[str] | None:
        """ISO codes an object covers. None means everywhere (global)."""
        level, rid, cid = self.scope_of(o)
        if level == "GLOBAL":
            return None
        if level == "REGION":
            return {c["iso2"] for c in self.active_iso.values() if c["region_id"] == rid}
        c = self.countries.get(cid)
        return {c["iso2"]} if c else set()

    def spec(self, o: dict) -> int:
        return SPECIFICITY[self.scope_of(o)[0]]

    def label(self, o: dict) -> str:
        level, rid, cid = self.scope_of(o)
        if level == "GLOBAL":
            return "Global"
        if level == "REGION":
            r = self.regions.get(rid)
            return r["name"] if r else "Unknown region"
        c = self.countries.get(cid)
        return f"{c['name']} ({c['iso2']})" if c else "Unknown country"

    def applies(self, o: dict, iso2: str | None) -> bool:
        if not self.valid(o):
            return False
        cs = self.countries_of(o)
        return cs is None or (iso2 is not None and iso2 in cs)

    # ---- combining rules
    def effective(self, rules: list[dict], iso2: str | None, kind) -> list[dict]:
        """Rules that govern a row of country `iso2` (None = unknown), after `override_parent` is applied."""
        app = [r for r in rules if self.applies(r, iso2)]
        return [r for r in app
                if not any(o.get("override_parent") and self.spec(o) > self.spec(r) and kind(o) == kind(r) for o in app)]

    def branches(self, rules: list[dict], kind) -> tuple[list[tuple[set[str], list[dict]]], list[dict]]:
        """Split countries into groups that share the same effective rules.
        Returns ([(countries, rules) for countries that differ from the default], default_rules)."""
        default = self.effective(rules, None, kind)
        dkey = tuple(sorted(id(x) for x in default))
        specific: set[str] = set()
        for r in rules:
            if self.valid(r):
                cs = self.countries_of(r)
                if cs:
                    specific |= cs
        groups: dict[tuple, tuple[set[str], list[dict]]] = {}
        for c in sorted(specific):
            eff = self.effective(rules, c, kind)
            key = tuple(sorted(id(x) for x in eff))
            if key == dkey:
                continue
            groups.setdefault(key, (set(), eff))[0].add(c)
        return list(groups.values()), default

    def rule_countries(self, rule: dict, rules: list[dict], kind):
        """Where does `rule` actually act?  None = everywhere; else ('IN' | 'NOT_IN', set of ISO codes)."""
        overridden: set[str] = set()
        for o in rules:
            if o is not rule and self.valid(o) and o.get("override_parent") and self.spec(o) > self.spec(rule) and kind(o) == kind(rule):
                overridden |= self.countries_of(o) or set()
        cs = self.countries_of(rule)
        if cs is None:
            return ("NOT_IN", overridden) if overridden else None
        return ("IN", cs - overridden)


def country_predicate(jur: str, spec) -> str | None:
    """SQL condition on a jurisdiction expression for the output of ScopeIndex.rule_countries()."""
    if spec is None:
        return None
    mode, codes = spec
    if mode == "IN":
        return f"{jur} IN ({sql_list(codes)})" if codes else "1 = 0"
    return f"({jur} IS NULL OR {jur} NOT IN ({sql_list(codes)}))" if codes else None


# ---- kinds: what makes two rules "the same kind of rule" for override purposes
def retention_kind(r: dict):
    return (r["trigger_event"], r["action"], r.get("target_table") or "")


def category_kind(r: dict):
    return (r["trigger_event"], r["action"], r.get("data_category") or "")


# ---- a short-lived cache: one request builds many conditions
_lock = threading.Lock()
_cache: dict = {"t": 0.0, "ix": None}


def index() -> ScopeIndex:
    with _lock:
        if _cache["ix"] is None or time.time() - _cache["t"] > 2.0:
            _cache["ix"], _cache["t"] = ScopeIndex(), time.time()
        return _cache["ix"]


def invalidate() -> None:
    with _lock:
        _cache["ix"] = None
