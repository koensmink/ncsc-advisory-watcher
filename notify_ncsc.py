import csv
import datetime
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import requests

from dedupe import filter_new_advisories, is_same_message, mark_sent

OUTPUT_DIR = Path("output/daily")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
WEBHOOK_TYPE = os.getenv("WEBHOOK_TYPE", "generic")

DEBUG = os.getenv("DEBUG", "0") == "1"
NO_DEDUPE = os.getenv("NO_DEDUPE", "0") == "1"

SEV_RE = re.compile(r"(\[?(H/H|M/H|H/M)\]?|High/High|Med/High|High/Med)", re.IGNORECASE)


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


def build_urgent_message(rows: List[Dict[str, str]]) -> str:
    header = "🚨<b>NCSC CVE ALERT</b>🚨\n\nDetails:\n"
    lines = []
    for r in rows:
        sev = r.get("Severity") or "?"
        desc = (r.get("Description") or "Onbekende melding")[:300]
        url = r.get("Link") or ""
        line = f"• <b>[{sev}]</b> — {desc}"
        if url:
            line += f"\n  🔗 <a href='{url}'>Bekijk advisory</a>"
        lines.append(line)
    return (header + "\n".join(lines))[:3900]


def send_to_telegram(text: str) -> Tuple[bool, str]:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False, "Telegram not configured"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": False}
    r = requests.post(url, json=payload, timeout=20)
    return (r.status_code == 200, f"Telegram status {r.status_code}")


def send_to_teams(text: str) -> Tuple[bool, str]:
    if not TEAMS_WEBHOOK_URL:
        return False, "Teams not configured"
    r = requests.post(TEAMS_WEBHOOK_URL, json={"text": text}, timeout=20)
    return (200 <= r.status_code < 300, f"Teams status {r.status_code}")


def send_to_webhook(payload: dict) -> Tuple[bool, str]:
    if not WEBHOOK_URL:
        return False, "Webhook not configured"
    r = requests.post(WEBHOOK_URL, json=payload, timeout=20)
    return (200 <= r.status_code < 300, f"Webhook status {r.status_code} type={WEBHOOK_TYPE}")


def send_notifications(rows: List[Dict[str, str]], message_text: str) -> Tuple[bool, List[str]]:
    advisories = [
        {
            "advisory_id": r.get("AdvisoryID", ""),
            "version": r.get("Version", ""),
            "severity": r.get("Severity", ""),
            "description": r.get("Description", ""),
            "link": r.get("Link", ""),
            "release_date": r.get("ReleaseDate", ""),
        }
        for r in rows
    ]
    payload = {
        "event_type": "ncsc_advisory_alert",
        "source": "NCSC-NL",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "count": len(advisories),
        "advisories": advisories,
    }

    results = []
    successes = 0
    any_configured = any([TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, TEAMS_WEBHOOK_URL, WEBHOOK_URL])

    for sender in (lambda: send_to_telegram(message_text), lambda: send_to_teams(message_text), lambda: send_to_webhook(payload)):
        ok, info = sender()
        results.append(info)
        if ok:
            successes += 1

    if not any_configured:
        log("⚠️ Geen notificatie-target geconfigureerd; exit 0.")
        return False, results
    return successes > 0, results


def main() -> int:
    csv_path = latest_csv()
    if not csv_path:
        log("Geen CSV-input gevonden.")
        return 0

    rows = read_csv_rows(csv_path)
    high_risk = filter_high_risk(rows)
    if not high_risk:
        log("Geen high-risk meldingen gevonden.")
        return 0

    if NO_DEDUPE:
        rows_to_send, used_ids = high_risk, []
    else:
        rows_to_send, used_ids = filter_new_advisories(high_risk)

    if not rows_to_send:
        return 0

    message_text = build_urgent_message(rows_to_send)
    if not NO_DEDUPE and is_same_message(message_text):
        return 0

    sent_ok, infos = send_notifications(rows_to_send, message_text)
    for info in infos:
        log(info)

    if sent_ok:
        if not NO_DEDUPE:
            mark_sent(used_ids, message_text)
        return 0

    configured = any([TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, TEAMS_WEBHOOK_URL, WEBHOOK_URL])
    return 1 if configured else 0


if __name__ == "__main__":
    sys.exit(main())
