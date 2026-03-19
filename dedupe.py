from __future__ import annotations
import json, re, hashlib, time
from pathlib import Path
from typing import Iterable, Dict, Any, Tuple, List

CACHE_PATH = Path("output/sent_cache.json")
CACHE_TTL_DAYS = 30  # verwijder verouderde entries

def _now_ts() -> int:
    return int(time.time())

def load_cache() -> dict:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"advisory_ids": {}, "last_message_hash": None, "version": 1}

def save_cache(cache: dict) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    cutoff = _now_ts() - CACHE_TTL_DAYS * 86400
    cache["advisory_ids"] = {
        k: v for k, v in cache.get("advisory_ids", {}).items() if v >= cutoff
    }
    CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")

# Herken een stabiele sleutel per advisory
ID_RE = re.compile(r"(NCSC-\d{4}-\d{4})", re.IGNORECASE)

def advisory_key(row: Dict[str, Any]) -> str | None:
    advisory_id = None
    for field in ("AdvisoryID", "TrackingID", "ID", "CsafID", "Tracking.Id", "tracking.id"):
        if field in row and row[field]:
            advisory_id = str(row[field]).strip().upper()
            break

    release_date = str(row.get("ReleaseDate", "")).strip()
    if advisory_id:
        return f"{advisory_id}|{release_date}" if release_date else advisory_id
    # 2) regex uit Title/Description
    for field in ("Description", "Title", "Naam", "Name"):
        if field in row and row[field]:
            m = ID_RE.search(str(row[field]))
            if m:
                return m.group(1).upper()
    # 3) fallback-signatuur
    sig = "|".join(str(row.get(k, "")).strip() for k in ("Title", "Description", "Vendor", "Product", "CVE", "URL"))
    if not sig:
        return None
    return "HASH:" + hashlib.sha256(sig.encode("utf-8")).hexdigest()[:16]

def filter_new_advisories(rows: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    cache = load_cache()
    seen = cache.get("advisory_ids", {})
    new_rows, used_ids = [], []
    for r in rows:
        key = advisory_key(r)
        if not key:
            new_rows.append(r)
            continue
        used_ids.append(key)
        if key not in seen:
            new_rows.append(r)
    return new_rows, used_ids

def mark_sent(used_ids: List[str], message_text: str) -> None:
    cache = load_cache()
    ts = _now_ts()
    for k in used_ids:
        if k:
            cache.setdefault("advisory_ids", {})[k] = ts
    cache["last_message_hash"] = hashlib.sha256(message_text.encode("utf-8")).hexdigest()
    save_cache(cache)

def is_same_message(message_text: str) -> bool:
    cache = load_cache()
    h = hashlib.sha256(message_text.encode("utf-8")).hexdigest()
    return cache.get("last_message_hash") == h
