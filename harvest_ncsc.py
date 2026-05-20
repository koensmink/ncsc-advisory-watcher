#!/usr/bin/env python3
import argparse
import csv
import datetime
import json
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from dateutil import parser as dtparser
from zoneinfo import ZoneInfo

BASE_ROOT = "https://advisories.ncsc.nl/"
LOCAL_TZ = ZoneInfo("Europe/Amsterdam")
OUTPUT_DAILY_DIR = Path("output/daily")
OUTPUT_JSONL_DIR = Path("output/jsonl")
LAST_RUN_PATH = Path("output/last_run.json")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Harvest NCSC advisories to CSV and JSONL")
    parser.add_argument("--days", type=int, default=1, help="Lookback window in days (>=1)")
    args = parser.parse_args()
    if args.days < 1:
        parser.error("--days must be >= 1")
    return args


def get_years_for_window(start_date: datetime.date, end_date: datetime.date) -> list[int]:
    return sorted({start_date.year, end_date.year}, reverse=True)


def fetch_directory_listing(year: int) -> list[str]:
    base_dir = f"{BASE_ROOT}csaf/v2/{year}/"
    r = requests.get(base_dir, timeout=20)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    return [a.get("href") for a in soup.find_all("a") if (a.get("href") or "").lower().endswith(".json")]


def _extract_note_text(notes: list[dict], title: str) -> str:
    for n in notes or []:
        if (n.get("title") or "").strip().lower() == title.lower():
            return (n.get("text") or "").strip().lower()
    return ""


def _severity_from_kans_schade(kans: str, schade: str) -> str:
    map_short = {"low": "L", "medium": "M", "high": "H", "critical": "H"}
    k = map_short.get(kans, "")
    s = map_short.get(schade, "")
    return f"[{k}/{s}]" if k and s else ""


def _format_version(v: str) -> str:
    if not v:
        return ""
    parts = v.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        return f"[{major}.{minor:02d}]"
    except Exception:
        return f"[{v}]"


def _get_release_dt(json_data: dict) -> datetime.datetime | None:
    tracking = json_data.get("document", {}).get("tracking", {})
    date_str = tracking.get("current_release_date") or tracking.get("initial_release_date")
    if not date_str:
        return None
    try:
        dt = dtparser.isoparse(date_str)
        return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        return None


def normalize_advisory(json_data: dict) -> dict:
    doc = json_data.get("document", {})
    tracking = doc.get("tracking", {})
    notes = doc.get("notes", [])
    advisory_id = tracking.get("id", "")
    return {
        "AdvisoryID": advisory_id,
        "Version": _format_version(str(tracking.get("version", ""))),
        "Severity": _severity_from_kans_schade(_extract_note_text(notes, "Kans"), _extract_note_text(notes, "Schade")),
        "Description": (doc.get("title") or "").strip(),
        "Link": f"{BASE_ROOT}advisory?id={advisory_id}" if advisory_id else "",
        "ReleaseDate": "",
    }


def _build_advisory_url(year: int, href: str) -> str:
    if href.startswith(("http://", "https://")):
        return href
    if href.startswith("csaf/"):
        return urljoin(BASE_ROOT, href.lstrip("/"))
    return urljoin(f"{BASE_ROOT}csaf/v2/{year}/", href)


def harvest_advisories(days: int) -> tuple[list[dict], datetime.date, datetime.date]:
    end_date = datetime.datetime.now(LOCAL_TZ).date()
    start_date = end_date - datetime.timedelta(days=days - 1)
    seen_ids = set()
    rows = []

    for year in get_years_for_window(start_date, end_date):
        for href in fetch_directory_listing(year):
            url = _build_advisory_url(year, href)
            try:
                r = requests.get(url, timeout=20)
                if r.status_code != 200:
                    continue
                data = r.json()
                release_dt = _get_release_dt(data)
                if not release_dt:
                    continue
                release_local_date = release_dt.astimezone(LOCAL_TZ).date()
                if not (start_date <= release_local_date <= end_date):
                    continue
                normalized = normalize_advisory(data)
                normalized["ReleaseDate"] = release_local_date.isoformat()
                advisory_id = normalized.get("AdvisoryID")
                dedupe_key = advisory_id or f"{normalized.get('Description')}|{normalized.get('ReleaseDate')}"
                if dedupe_key in seen_ids:
                    continue
                seen_ids.add(dedupe_key)
                if advisory_id or normalized.get("Description"):
                    rows.append(normalized)
            except Exception:
                continue

    return rows, start_date, end_date


def write_csv(rows: list[dict], out_csv: Path) -> None:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["AdvisoryID", "Version", "Severity", "Description", "Link", "ReleaseDate"]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(rows: list[dict], out_jsonl: Path) -> None:
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    ingested_at = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    with out_jsonl.open("w", encoding="utf-8") as f:
        for row in rows:
            event = {
                "event_type": "ncsc_advisory",
                "source": "NCSC-NL",
                "advisory_id": row.get("AdvisoryID", ""),
                "version": row.get("Version", ""),
                "severity": row.get("Severity", ""),
                "description": row.get("Description", ""),
                "link": row.get("Link", ""),
                "release_date": row.get("ReleaseDate", ""),
                "ingested_at": ingested_at,
            }
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


def save_last_run(csv_path: str, count: int, days: int, start_date: datetime.date, end_date: datetime.date) -> None:
    LAST_RUN_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "last_run_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "count": count,
        "lookback_days": days,
        "window_start": start_date.isoformat(),
        "window_end": end_date.isoformat(),
        "csv_path": csv_path,
    }
    LAST_RUN_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def main() -> int:
    args = parse_args()
    rows, start_date, end_date = harvest_advisories(args.days)
    out_csv = OUTPUT_DAILY_DIR / f"{end_date.isoformat()}.csv"
    out_jsonl = OUTPUT_JSONL_DIR / f"{end_date.isoformat()}.jsonl"
    write_csv(rows, out_csv)
    write_jsonl(rows, out_jsonl)
    save_last_run(str(out_csv), len(rows), args.days, start_date, end_date)
    print(f"✅ {len(rows)} advisories geschreven naar {out_csv} en {out_jsonl}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
