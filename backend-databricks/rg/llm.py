"""Optional LLM second opinion on the scanner's findings.

The rule-based scanner (regex, dictionaries, checksums) stays the engine. This module can be switched on to ask a language
model whether ONE finding looks right. It never changes a finding: a steward still confirms or rejects.

The model classifies the column BLIND: it is not shown the scanner's label (a small model shown the answer just agrees with it).
The app compares the model's own answer with the scanner's and derives the verdict.

The switch is a hard guarantee. While llm.enabled is off, `ensure_enabled()` stops every entry point before any client is
created, so nothing is sent anywhere and no model is needed.

What is sent depends on the sample level (Configure > "How much detail to send"), always in addition to the
metadata (table/column name, data type, null / distinct ratios, neighbouring column names, the classifier catalogue):
  NONE    (default) metadata only - never a database value.
  MASKED  up to 3 already-masked values (j***@x.com) from RG_FINDING_SAMPLE.
  REAL    up to 3 REAL, unmasked values read live from the column for this one request. Never stored anywhere -
          not in RG_FINDING_SAMPLE, not in RG_LLM_OPINION, only in the prompt sent to the model. Local provider only
          (refused for a cloud provider, both when saving the setting and again at request time).

Providers
  OLLAMA      a model running on this machine (http://localhost:11434). Nothing leaves the laptop.
  ANTHROPIC   the Anthropic API. Needs ANTHROPIC_API_KEY in backend-databricks/.env (the key is never stored in the database).
  DATABRICKS  this workspace's own Model Serving (Foundation Model API) - queried via this app's own
              service principal, same auth pattern as rg/engines/databricks.py and rg/vectorsearch.py.
              No API key to manage; "model" is the serving endpoint name (e.g. databricks-claude-sonnet-5),
              discovered via `databricks serving-endpoints list`, never hardcoded to one that might be
              retired later.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from urllib.parse import urlparse

import httpx

from . import db, engines
from .common import audit
from .policy import NotFound, ValidationError

PROMPT_VERSION = "v6"
PROVIDERS = {
    "OLLAMA": {"label": "Local model (Ollama)", "default_model": "qwen2.5:3b", "default_url": "http://localhost:11434",
               "needs_key": False, "local": True},
    "ANTHROPIC": {"label": "Anthropic API (cloud)", "default_model": "claude-haiku-4-5-20251001",
                  "default_url": "https://api.anthropic.com", "needs_key": True, "local": False},
    "DATABRICKS": {"label": "Databricks Model Serving", "default_model": "databricks-claude-sonnet-5",
                   "default_url": "", "needs_key": False, "local": False},
}
DEFAULTS = {"llm.enabled": "0", "llm.provider": "OLLAMA", "llm.model": PROVIDERS["OLLAMA"]["default_model"],
            "llm.base_url": PROVIDERS["OLLAMA"]["default_url"], "llm.sample_level": "NONE", "llm.timeout": "300"}
SAMPLE_LEVELS = ("NONE", "MASKED", "REAL")     # NONE = metadata only. REAL is refused for a non-local provider.
VERDICTS = ("AGREE", "DISAGREE", "UNSURE")
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class LlmOff(ValidationError):
    """The switch is off. Nothing was called."""


class LlmError(RuntimeError):
    """The model could not be reached or did not answer usably."""


# --------------------------------------------------------------------------- settings
def _get_all() -> dict[str, str]:
    have = {r["setting_key"]: r["setting_value"] for r in db.query("SELECT setting_key, setting_value FROM RG_SETTING WHERE setting_key LIKE 'llm.%'")}
    if "llm.sample_level" not in have and have.get("llm.send_samples") == "1":   # migrate the old on/off toggle once
        have["llm.sample_level"] = "MASKED"
    return {**DEFAULTS, **have}


def _put(key: str, value: str, username: str) -> None:
    n = db.execute("UPDATE RG_SETTING SET setting_value = :v, updated_by = :u, updated_at = now() WHERE setting_key = :k",
                   {"v": value, "u": username, "k": key})
    if not n:
        db.execute("INSERT INTO RG_SETTING (setting_key, setting_value, updated_by) VALUES (:k, :v, :u)", {"k": key, "v": value, "u": username})


def key_present(provider: str) -> bool:
    return bool(PROVIDERS.get(provider, {}).get("needs_key") is False or os.environ.get("ANTHROPIC_API_KEY", "").strip())


def get_settings() -> dict:
    s = _get_all()
    prov = s["llm.provider"] if s["llm.provider"] in PROVIDERS else "OLLAMA"
    level = s["llm.sample_level"] if s["llm.sample_level"] in SAMPLE_LEVELS else "NONE"
    if level == "REAL" and not PROVIDERS[prov]["local"]:      # a provider switch elsewhere must not silently keep REAL live
        level = "NONE"
    return {"enabled": s["llm.enabled"] == "1", "provider": prov, "model": s["llm.model"], "base_url": s["llm.base_url"],
            "sample_level": level, "send_samples": level != "NONE", "timeout": int(s["llm.timeout"]), "local": PROVIDERS[prov]["local"],
            "key_present": key_present(prov), "prompt_version": PROMPT_VERSION, "sample_levels": list(SAMPLE_LEVELS),
            "providers": [{"code": c, **{k: v for k, v in p.items()}} for c, p in PROVIDERS.items()]}


def enabled() -> bool:
    return _get_all()["llm.enabled"] == "1"


def ensure_enabled() -> dict:
    st = get_settings()
    if not st["enabled"]:
        raise LlmOff("LLM assistance is switched off. Everything runs locally with rules and dictionaries.")
    return st


def save_settings(d: dict, username: str) -> dict:
    cur = get_settings()
    new = {**{k: cur[k] for k in ("enabled", "provider", "model", "base_url", "sample_level", "timeout")},
           **{k: v for k, v in d.items() if v is not None}}
    if new["provider"] not in PROVIDERS:
        raise ValidationError(f"Provider must be one of {', '.join(PROVIDERS)}")
    if new["sample_level"] not in SAMPLE_LEVELS:
        raise ValidationError(f"Sample level must be one of {', '.join(SAMPLE_LEVELS)}")
    if new["sample_level"] == "REAL" and not PROVIDERS[new["provider"]]["local"]:
        raise ValidationError("Real sample values can only be sent to a local model. Set the sample level to "
                              "Masked samples or Metadata only before switching to a cloud provider.")
    if new["provider"] != cur["provider"]:                       # switching provider: start from that provider's defaults
        for k, dk in (("model", "default_model"), ("base_url", "default_url")):
            if k not in d or d[k] is None:
                new[k] = PROVIDERS[new["provider"]][dk]
    model = str(new["model"]).strip()
    if not model or len(model) > 100:
        raise ValidationError("Enter the model name")
    if new["provider"] == "DATABRICKS":
        # No base_url to validate - the SDK resolves this workspace's own host automatically, and
        # "model" is a serving endpoint name, not a URL.
        url = ""
    else:
        url = str(new["base_url"]).strip().rstrip("/")
        u = urlparse(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValidationError("The address must start with http:// or https://")
        if PROVIDERS[new["provider"]]["local"] and u.hostname not in _LOOPBACK:
            raise ValidationError("The local model must run on this machine (localhost), otherwise your data would leave the laptop")
        if not PROVIDERS[new["provider"]]["local"] and u.scheme != "https":
            raise ValidationError("A cloud provider must be reached over https")
    timeout = int(new["timeout"])
    if not 5 <= timeout <= 900:
        raise ValidationError("The timeout must be between 5 and 900 seconds")
    changes = []
    for key, val in (("enabled", "1" if new["enabled"] else "0"), ("provider", new["provider"]), ("model", model), ("base_url", url),
                     ("sample_level", new["sample_level"]), ("timeout", str(timeout))):
        if _get_all()[f"llm.{key}"] != val:
            _put(f"llm.{key}", val, username)
            changes.append(f"{key}={val}")
    if changes:
        state = "LLM_ON" if (new["enabled"] and not cur["enabled"]) else "LLM_OFF" if (cur["enabled"] and not new["enabled"]) else "SETTING"
        audit(username, "llm", None, state, ", ".join(changes)[:490])
    return get_settings()


# --------------------------------------------------------------------------- what is sent
def _catalogue() -> list[dict]:
    return [{"code": c["code"], "name": c["name"], "category": c["category"]}
            for c in db.query("SELECT code, name, category FROM RG_CLASSIFIER WHERE is_active = 1 ORDER BY code")]


def _display(v) -> str:
    return v.strftime("%Y-%m-%d") if hasattr(v, "strftime") else str(v)


def _real_samples(source_id: int, table: str, column: str, n: int = 3) -> list[str]:
    """Up to `n` REAL, unmasked, distinct values read live from the column, from whichever engine this source
    actually lives on. Never persisted anywhere - the caller puts them straight into the one prompt they are for."""
    engine = engines.for_source(source_id)
    col, tbl = engine.ident(column), engine.ident(table)
    sql = f"SELECT DISTINCT {col} v FROM {tbl} WHERE {col} IS NOT NULL FETCH FIRST {int(n)} ROWS ONLY"
    rows = engine.query(sql)
    return [_display(r["v"]) for r in rows]


def _context(f: dict, sample_level: str) -> dict:
    col = db.query_one("SELECT data_type, data_length, is_nullable, is_pk, null_ratio, distinct_ratio FROM RG_CATALOG_COLUMN "
                       "WHERE source_id = :s AND table_name = :t AND column_name = :c",
                       {"s": f["source_id"], "t": f["table_name"], "c": f["column_name"]}) or {}
    siblings = db.query("SELECT column_name, data_type FROM RG_CATALOG_COLUMN WHERE source_id = :s AND table_name = :t "
                        "AND column_name <> :c ORDER BY ordinal FETCH FIRST 40 ROWS ONLY",
                        {"s": f["source_id"], "t": f["table_name"], "c": f["column_name"]})
    others = db.query("SELECT column_name, data_element FROM RG_FINDING WHERE source_id = :s AND table_name = :t AND column_name <> :c "
                      "AND status IN ('AUTO', 'CONFIRMED', 'NEEDS_REVIEW') ORDER BY column_name",
                      {"s": f["source_id"], "t": f["table_name"], "c": f["column_name"]})
    # kept short on purpose: a laptop model reads about 50 tokens a second, so every extra line costs real time
    ctx = {
        "table": f["table_name"], "column": f["column_name"],
        "data_type": f"{col.get('data_type')}({col.get('data_length')})" + (" primary key" if col.get("is_pk") else ""),
        "null_ratio": col.get("null_ratio"), "distinct_ratio": col.get("distinct_ratio"),
        "other_columns_in_table": ", ".join(s["column_name"] for s in siblings[:30]),
        "scanner_found_in_other_columns": {o["column_name"]: o["data_element"] for o in others[:10]},
    }
    ctx = {k: v for k, v in ctx.items() if v not in (None, "", {})}
    if sample_level == "REAL":
        vals = _real_samples(f["source_id"], f["table_name"], f["column_name"])
        if vals:
            ctx["real_sample_values"] = vals
    elif sample_level == "MASKED":                                # already masked when they were stored (j***@x.com)
        vals = [r["masked_value"] for r in db.query(
            "SELECT masked_value FROM RG_FINDING_SAMPLE WHERE finding_id = :i ORDER BY sample_id FETCH FIRST 3 ROWS ONLY", {"i": f["finding_id"]})]
        if vals:
            ctx["masked_sample_values"] = vals
    return ctx


SYSTEM = (
    "You classify ONE column of an insurance company's database using only its metadata. "
    "Choose the single code from the catalogue that best describes the data the column stores. "
    "Answer with the exact code (for example EMAIL or FULL_NAME). Category names such as PII, PHI or FINANCIAL are not valid answers. "
    "Answer NONE when the column does not hold data about people, their contracts, money, health, marketing or legal matters: "
    "for example names of branches, products, procedures or steps, technical fields, keys, dates of processing, and reference or lookup data. "
    "A person's name is not the same as the name of a branch, product or procedure. "
    "If real_sample_values or masked_sample_values are given, they are genuine examples from that column - use them "
    "as your main evidence, over the column name, whenever they disagree. "
    'Reply with one JSON object and nothing else, for example '
    '{"code": "IBAN", "confidence": 0.9, "reason": "stores bank account numbers"} or '
    '{"code": "NONE", "confidence": 0.8, "reason": "an internal status flag with no personal data"}. '
    "Base the reason on this column, not on the examples."
)


def _system_prompt(cat: list[dict]) -> str:
    """Instructions plus the catalogue of codes by category. Identical for every finding, so Ollama can cache it."""
    by: dict[str, list[str]] = {}
    for c in cat:
        by.setdefault(c["category"], []).append(f"{c['code']} ({c['name']})")
    return SYSTEM + "\nCatalogue of codes by category:\n" + "\n".join(f"[{k}] {'; '.join(v)}" for k, v in sorted(by.items()))


def _fingerprint(ctx: dict, st: dict, codes: list[str]) -> str:
    key = {"ctx": {k: v for k, v in ctx.items()}, "provider": st["provider"], "model": st["model"], "v": PROMPT_VERSION, "codes": codes}
    return hashlib.sha256(json.dumps(key, sort_keys=True, default=str).encode()).hexdigest()


# --------------------------------------------------------------------------- talking to the model
def _chat(st: dict, system: str, user: str) -> str:
    provider, timeout = st["provider"], st["timeout"]
    if provider == "DATABRICKS":
        from databricks.sdk import WorkspaceClient
        from databricks.sdk.errors import DatabricksError
        from databricks.sdk.service.serving import ChatMessage, ChatMessageRole
        messages = [ChatMessage(role=ChatMessageRole.SYSTEM, content=system),
                    ChatMessage(role=ChatMessageRole.USER, content=user)]
        # This workspace's one usable chat endpoint scales to zero and can take ~60-90s to cold-start,
        # which both the SDK's own request timeout and the Databricks Apps reverse proxy's hard
        # (non-configurable) 120s request cap can land right on top of - a bare retry right after a
        # failed first attempt almost always hits an already-warm model and returns quickly (confirmed
        # empirically: a timed-out CLI call followed immediately by a retry succeeded in seconds).
        last_err: DatabricksError | None = None
        for attempt in range(2):
            try:
                r = WorkspaceClient().serving_endpoints.query(name=st["model"], messages=messages, max_tokens=400)
                return r.choices[0].message.content
            except DatabricksError as e:
                last_err = e
        raise LlmError(f"Model Serving endpoint '{st['model']}' error: {last_err}")
    try:
        with httpx.Client(timeout=timeout) as c:
            if provider == "OLLAMA":
                r = c.post(f"{st['base_url']}/api/chat", json={
                    "model": st["model"], "stream": False, "format": "json",
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                    "keep_alive": "15m", "options": {"temperature": 0, "num_predict": 160, "num_ctx": 2048}})
                if r.status_code == 404:
                    raise LlmError(f"The model '{st['model']}' is not installed in Ollama. Run: ollama pull {st['model']}")
                r.raise_for_status()
                return r.json()["message"]["content"]
            key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
            if not key:
                raise LlmError("ANTHROPIC_API_KEY is not set. Add it to backend-databricks/.env and restart the API")
            r = c.post(f"{st['base_url']}/v1/messages", headers={"x-api-key": key, "anthropic-version": "2023-06-01"}, json={
                "model": st["model"], "max_tokens": 400, "temperature": 0, "system": system,
                "messages": [{"role": "user", "content": user}]})
            if r.status_code in (401, 403):
                raise LlmError("The Anthropic API rejected the key")
            r.raise_for_status()
            return "".join(b.get("text", "") for b in r.json()["content"] if b.get("type") == "text")
    except LlmError:
        raise
    except httpx.ConnectError:
        raise LlmError(f"Cannot reach the model at {st['base_url']}. " + ("Is Ollama running?" if provider == "OLLAMA" else "Check the network."))
    except httpx.TimeoutException:
        raise LlmError(f"The model did not answer within {timeout} seconds. Try a smaller model or a longer timeout")
    except httpx.HTTPStatusError as e:
        raise LlmError(f"The model returned HTTP {e.response.status_code}")
    except (KeyError, ValueError):
        raise LlmError("The model returned a response in an unexpected format")


def _parse(text: str, codes: set[str], current: str) -> dict:
    """The model's own classification, compared with the scanner's label to give AGREE / DISAGREE / UNSURE."""
    m = re.search(r"\{.*\}", text or "", re.S)
    if not m:
        raise LlmError("The model did not return a JSON answer")
    try:
        d = json.loads(m.group(0))
    except ValueError:
        raise LlmError("The model's answer was not valid JSON")
    code = str(d.get("code") or d.get("suggested") or "").strip().upper()
    try:
        conf = max(0.0, min(1.0, float(d.get("confidence"))))
    except (TypeError, ValueError):
        conf = 0.0
    reason = str(d.get("reason") or "")
    if code != "NONE" and code not in codes:                      # an invented or missing code is not accepted
        reason = f"The model answered '{code[:30]}', which is not a catalogue code. {reason}"
        code, verdict = "UNKNOWN", "UNSURE"
    elif conf < 0.4:
        verdict = "UNSURE"
    else:
        verdict = "AGREE" if code == current else "DISAGREE"
    return {"verdict": verdict, "suggested": code, "confidence": round(conf, 3), "reason": reason[:480]}


# --------------------------------------------------------------------------- the opinion
def second_opinion(finding_id: int, username: str, refresh: bool = False) -> dict:
    st = ensure_enabled()
    f = db.query_one("SELECT * FROM RG_FINDING WHERE finding_id = :i", {"i": finding_id})
    if not f:
        raise NotFound(f"Finding {finding_id} not found")
    cat = _catalogue()
    codes = [c["code"] for c in cat]
    level = st["sample_level"]
    if level == "REAL" and not st["local"]:                       # belt and braces: save_settings() already refuses this combination
        raise ValidationError("Real sample values can only be sent to a local model.")
    ctx = _context(f, level)
    fp = _fingerprint(ctx, st, codes)
    if not refresh:
        hit = db.query_one("SELECT * FROM RG_LLM_OPINION WHERE finding_id = :i AND fingerprint = :f ORDER BY opinion_id DESC FETCH FIRST 1 ROWS ONLY",
                           {"i": finding_id, "f": fp})
        if hit:
            return {**hit, "cached": True}
    user = json.dumps({"finding": ctx}, default=str)
    res = _parse(_chat(st, _system_prompt(cat), user), set(codes), f["data_element"])
    oid = db.insert("RG_LLM_OPINION", {
        "finding_id": finding_id, "table_name": f["table_name"], "column_name": f["column_name"], "current_element": f["data_element"],
        "verdict": res["verdict"], "suggested": res["suggested"], "confidence": res["confidence"], "reason": res["reason"],
        "provider": st["provider"], "model": st["model"], "prompt_version": PROMPT_VERSION,
        "samples_sent": 0 if level == "NONE" else 1, "sample_level": level, "fingerprint": fp, "created_by": username}, "opinion_id")
    audit(username, "llm", oid, "OPINION", (f"{f['table_name']}.{f['column_name']} ({f['data_element']}): {res['verdict']} -> {res['suggested']} "
                                            f"[{st['provider']}/{st['model']}, samples={level.lower()}]")[:490])
    return {**db.query_one("SELECT * FROM RG_LLM_OPINION WHERE opinion_id = :i", {"i": oid}), "cached": False}


def opinions() -> list[dict]:
    """Latest opinion per finding. Empty while the switch is off: switched off means not used at all."""
    if not enabled():
        return []
    return db.query("SELECT * FROM RG_LLM_OPINION WHERE opinion_id IN (SELECT MAX(opinion_id) FROM RG_LLM_OPINION GROUP BY finding_id)")


def test_connection(username: str) -> dict:
    """A round trip that carries no data from the database: the model is asked to answer with a fixed word."""
    st = ensure_enabled()
    text = _chat(st, "Answer with the single word OK.", "Say OK.")
    audit(username, "llm", None, "TEST", f"{st['provider']}/{st['model']}")
    return {"ok": True, "reply": text.strip()[:60], "provider": st["provider"], "model": st["model"]}
