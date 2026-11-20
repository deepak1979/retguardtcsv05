"""LLM-assisted name detection for the document body-text sweep (docscan.py).

The existing FULL_NAME classifier only catches a name if BOTH its first and last token are in the
FIRST_NAMES/LAST_NAMES dictionaries (classifiers.py) - a real limitation: "Anna Kowalski" is missed
whenever the surname (or, for some nationalities, the given name too) isn't in those lists. This module
adds a second, complementary source of FULL_NAME candidates: a model reads the document's own text and
names the people it recognises from context, the way a person would, rather than checking a fixed list.

v04: queries this workspace's own Databricks Model Serving (same mechanism as llm.py's DATABRICKS
provider and rg/vectorsearch.py's embeddings), not v03's local-only Ollama - Ollama cannot run inside a
deployed Databricks App at all (no local model server possible there), so porting this was required for
the feature to work once deployed, not an optional enhancement. v03's "never leaves the laptop"
guarantee for this specific feature no longer applies in v04: document text already reaches this same
workspace's Model Serving via rg/vectorsearch.py's embeddings (see its own module docstring) - the trust
boundary for document text in v04 is "stays in this Databricks workspace", consistently, not "stays on
this one feature's laptop while every other document-text path already left it".

Design choices, deliberately:
  - Gated by BOTH switches. find_names() first checks llm.enabled() (the app-wide "nothing is sent
    anywhere" guarantee llm.py documents) and only then this module's OWN docscan_llm.enabled toggle - so
    turning the master LLM switch off silences this feature too, exactly like every other LLM entry point.
  - Never raises into the scan. A scan that touches many documents must not fail because the model was
    slow, unreachable, or answered oddly on one document - find_names() swallows every failure internally
    and returns whatever it already found (often nothing), the same resilience _extract_text() already
    has for a corrupt PDF. Only ensure_enabled()/save_settings() (settings-API-facing) raise.
  - No caching. _raw_matches() (docscan.py) already recomputes its dictionary/regex passes from scratch
    every time it's called - once when a document is scanned, again if redact.py later needs the same
    spans to black out - and this feature follows that same precedent rather than adding a new cache table
    for one method.
  - Names must appear verbatim. redact.py's execute() needs the literal matched substring to find and
    black out on the PDF page, so a name the model returns is only kept if it is found, case-insensitively,
    as an actual substring of the text that was sent to it - never trusted as-is. A model that paraphrases
    or invents a name contributes nothing (silently dropped), never a bad redaction target.
"""
from __future__ import annotations

import json
import re

from . import db, llm
from .policy import ValidationError

MODEL_DEFAULT = "databricks-claude-sonnet-5"   # a Foundation Model API endpoint - see llm.py's own note
DEFAULTS = {"docscan_llm.enabled": "0", "docscan_llm.model": MODEL_DEFAULT, "docscan_llm.timeout": "120"}

CHUNK_CHARS = 3_000       # ~500-700 words: comfortably inside even a 2048-token context with room to spare
CHUNK_OVERLAP = 150       # so a name split across a chunk boundary still lands whole in at least one chunk
MAX_CHARS_PER_DOC = 15_000  # safety cap - a huge PDF must not turn one scan into a multi-minute LLM run
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}

def _is_name_token(t: str) -> bool:
    """True for a capitalised word - Unicode-aware (str.isupper()/islower() handle accented letters
    correctly, e.g. 'S' vs 's' vs 's'-with-acute, unlike an ASCII-only [A-Za-z] regex class, which would
    silently reject a real name like "Wisniewska" for containing a non-ASCII letter)."""
    return len(t) >= 2 and t[0].isupper() and all(c.islower() or c in "'-" for c in t[1:])

SYSTEM_PROMPT = (
    "You find the full names of real people mentioned in a piece of text - claimants, customers, "
    "policyholders, agents, witnesses, or anyone else named as an individual. "
    "Only count a FULL name: a given name followed by a family name, written together. Do not count a "
    "single name alone, a company, a product, a place, or a job title. "
    "Copy each name EXACTLY as it is spelled in the text, with its original capitalisation and spacing - "
    "never translate, correct, or reformat it. "
    'Reply with one JSON object and nothing else: {"names": ["Anna Kowalski", "John Smith"]}. '
    'If there are no person names, reply {"names": []}.'
)


# --------------------------------------------------------------------------- settings (RG_SETTING, docscan_llm.*)
def _get_all() -> dict[str, str]:
    have = {r["setting_key"]: r["setting_value"]
            for r in db.query("SELECT setting_key, setting_value FROM RG_SETTING WHERE setting_key LIKE 'docscan_llm.%'")}
    return {**DEFAULTS, **have}


def _put(key: str, value: str, username: str) -> None:
    n = db.execute("UPDATE RG_SETTING SET setting_value = :v, updated_by = :u, updated_at = now() WHERE setting_key = :k",
                   {"v": value, "u": username, "k": key})
    if not n:
        db.execute("INSERT INTO RG_SETTING (setting_key, setting_value, updated_by) VALUES (:k, :v, :u)", {"k": key, "v": value, "u": username})


def get_settings() -> dict:
    s = _get_all()
    master = llm.enabled()
    return {"enabled": s["docscan_llm.enabled"] == "1", "master_llm_enabled": master,
            "active": master and s["docscan_llm.enabled"] == "1",
            "model": s["docscan_llm.model"], "timeout": int(s["docscan_llm.timeout"])}


def enabled() -> bool:
    return llm.enabled() and _get_all()["docscan_llm.enabled"] == "1"


def ensure_enabled() -> dict:
    if not llm.enabled():
        raise llm.LlmOff("LLM assistance is switched off (Findings > LLM second opinion). Everything runs locally with rules and dictionaries.")
    st = get_settings()
    if not st["enabled"]:
        raise llm.LlmOff("LLM-assisted name detection is switched off for documents. Document scans use the name dictionaries only.")
    return st


def save_settings(d: dict, username: str) -> dict:
    cur = get_settings()
    new = {**{k: cur[k] for k in ("enabled", "model", "timeout")}, **{k: v for k, v in d.items() if v is not None}}
    model = str(new["model"]).strip()
    if not model or len(model) > 100:
        raise ValidationError("Enter the model name")
    timeout = int(new["timeout"])
    if not 5 <= timeout <= 600:
        raise ValidationError("The timeout must be between 5 and 600 seconds")
    changes = []
    for key, val in (("enabled", "1" if new["enabled"] else "0"), ("model", model), ("timeout", str(timeout))):
        if _get_all()[f"docscan_llm.{key}"] != val:
            _put(f"docscan_llm.{key}", val, username)
            changes.append(f"{key}={val}")
    if changes:
        from .common import audit
        audit(username, "docscan_llm", None, "SETTING", ", ".join(changes)[:490])
    return get_settings()


def test_connection(username: str) -> dict:
    st = ensure_enabled()
    reply = _chat(st, "Answer with the single word OK.", "Say OK.")
    from .common import audit
    audit(username, "docscan_llm", None, "TEST", st["model"])
    return {"ok": True, "reply": reply.strip()[:60], "model": st["model"]}


# --------------------------------------------------------------------------- talking to Databricks Model Serving
class _SoftError(Exception):
    """Raised internally and always caught - find_names() never lets a chunk-level failure escape."""


def _chat(st: dict, system: str, user: str) -> str:
    from databricks.sdk import WorkspaceClient
    from databricks.sdk.errors import DatabricksError
    from databricks.sdk.service.serving import ChatMessage, ChatMessageRole
    messages = [ChatMessage(role=ChatMessageRole.SYSTEM, content=system),
                ChatMessage(role=ChatMessageRole.USER, content=user)]
    # Same cold-start retry as llm.py's _chat() - this workspace's one usable chat endpoint scales to
    # zero, and a bare retry right after a failed first attempt almost always hits an already-warm model.
    last_err: DatabricksError | None = None
    for attempt in range(2):
        try:
            r = WorkspaceClient().serving_endpoints.query(name=st["model"], messages=messages, max_tokens=300)
            return r.choices[0].message.content
        except DatabricksError as e:
            last_err = e
    raise _SoftError(f"Model Serving endpoint '{st['model']}' error: {last_err}")


def _parse_names(reply: str) -> list[str]:
    m = re.search(r"\{.*\}", reply or "", re.S)
    if not m:
        return []
    try:
        d = json.loads(m.group(0))
    except ValueError:
        return []
    names = d.get("names")
    if not isinstance(names, list):
        return []
    return [n for n in names if isinstance(n, str) and n.strip()]


def _chunks(text: str) -> list[str]:
    text = text[:MAX_CHARS_PER_DOC]
    if len(text) <= CHUNK_CHARS:
        return [text]
    out, i = [], 0
    while i < len(text):
        out.append(text[i:i + CHUNK_CHARS])
        i += CHUNK_CHARS - CHUNK_OVERLAP
    return out


def _verbatim(name: str, text: str) -> str | None:
    """Only accept a name the model returned if it is truly present in the text (case-insensitively) and
    looks like a name (every token capitalised) - returns the EXACT substring from `text`, not the model's
    copy of it, so it matches byte-for-byte for redaction span-finding later."""
    name = name.strip()
    if not name or len(name) > 80:
        return None
    tokens = name.split()
    if len(tokens) < 2 or not all(_is_name_token(t) for t in tokens):
        return None
    m = re.search(re.escape(name), text, re.I)
    return text[m.start():m.end()] if m else None


def find_names(text: str) -> list[str]:
    """Every distinct person-name substring the local model found and that genuinely appears in `text`.
    Returns [] immediately (no settings read even) when the feature isn't active, and [] on any failure -
    never raises. Called from docscan.py's _raw_matches(), which is itself reused by both the scanner and
    redact.py (see this module's docstring for why there's no cache)."""
    if not text or not enabled():
        return []
    try:
        st = get_settings()
    except Exception:  # noqa: BLE001 - settings read itself must not be able to break a scan
        return []
    found: list[str] = []
    seen_lower: set[str] = set()
    for chunk in _chunks(text):
        try:
            names = _parse_names(_chat(st, SYSTEM_PROMPT, chunk))
        except Exception as e:  # noqa: BLE001 - one bad chunk (timeout, model hiccup) must not drop the rest
            print(f"[name_llm] chunk skipped: {e}")
            continue
        for n in names:
            real = _verbatim(n, chunk)
            if real and real.lower() not in seen_lower:
                seen_lower.add(real.lower())
                found.append(real)
    return found
