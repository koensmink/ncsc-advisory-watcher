# notify_ncsc.py
import os
import sys
import csv
import re
from pathlib import Path
from typing import List, Dict, Tuple
import requests
from dedupe import filter_new_advisories, mark_sent, is_same_message

# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------
OUTPUT_DIR = Path("output/daily")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID")

DEBUG     = os.getenv("DEBUG", "0") == "1"
NO_DEDUPE = os.getenv("NO_DEDUPE", "0") == "1"

SEV_RE = re.compile(r"(\[?(H/H|M/H|H/M)\]?|High/High|Med/High|High/Med)", re.IGNORECASE)

# ---------------------------------------------------------------------
def log(msg: str) -> None:
    print(msg, flush=True)

def latest_csv() -> Path | None:
    files = sorted(OUTPUT_DIR.glob("*.csv"))
    return files[-1] if files else None

def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def filter_high_risk(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    return [r for r in rows if SEV_RE.search((r.get("Severity") or "").strip())]

def send_to_telegram(text: str) -> Tuple[bool, str]:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log("⚠️  Telegram niet geconfigureerd; skipping.")
        return (False, "Telegram not configured")

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": False,
    }
    r = requests.post(url, json=payload, timeout=20)
    if r.status_code != 200:
        return (False, f"Telegram error {r.status_code}: {r.text}")
    return (True, "ok")

def build_urgent_message(rows: List[Dict[str, str]]) -> str:
    header = "🚨<b>URGENT</b>\n\nDetails:\n"
    lines = []
    for r in rows:
        sev = r.get("Severity") or "?"
        desc = r.get("Description") or "Onbekende melding"
        url  = r.get("Link") or r.get("AdvisoryURL") or r.get("URL") or ""
        if len(desc) > 300:
            desc = desc[:300].rstrip() + "…"
        line = f"• <b>[{sev}]</b> — {desc}"
        if url:
            line += f"\n  🔗 <a href='{url}'>Bekijk advisory</a>"
        lines.append(line)
    return (header + "\n".join(lines))[:3900]

# ---------------------------------------------------------------------
def main() -> int:
    csv_path = latest_csv()
    if not csv_path:
        log("Geen CSV-input gevonden.")
        return 0

    rows = read_csv_rows(csv_path)
    log(f"Totaal rijen in CSV ({csv_path.name}): {len(rows)}")

    high_risk = filter_high_risk(rows)
    log(f"Na severity-filter (H/H, M/H, H/M, High/High, Med/High, High/Med): {len(high_risk)} rijen")

    if not high_risk:
        log("Geen high-risk meldingen gevonden.")
        return 0

    if NO_DEDUPE:
        rows_to_send, used_ids = high_risk, []
        log("⚠️ NO_DEDUPE=1 gezet: dedupe tijdelijk uitgeschakeld.")
    else:
        rows_to_send, used_ids = filter_new_advisories(high_risk)
        log(f"Na advisory-dedupe: {len(rows_to_send)} te versturen items")

    if not rows_to_send:
        log("Geen nieuwe high-risk advisories na dedupe; niets te sturen.")
        return 0

    message_text = build_urgent_message(rows_to_send)

    if not NO_DEDUPE and is_same_message(message_text):
        log("Bericht is identiek aan vorige push; overslaan.")
        return 0

    ok, info = send_to_telegram(message_text)
    if ok:
        log("✅ Telegram-bericht verzonden.")
        mark_sent(used_ids, message_text)
    else:
        log(info)

    return 0

if __name__ == "__main__":
    sys.exit(main())
