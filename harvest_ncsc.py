#!/usr/bin/env python3
import csv
import json
import datetime
import requests
from pathlib import Path
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from zoneinfo import ZoneInfo
from dateutil import parser as dtparser  # python-dateutil staat al in requirements

# ------------------------------------------------------------
# Config
# ------------------------------------------------------------
YEAR = datetime.datetime.utcnow().year
BASE_ROOT = "https://advisories.ncsc.nl/"
BASE_DIR = f"{BASE_ROOT}csaf/v2/{YEAR}/"

OUTPUT_DIR = Path("output/daily")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

LAST_RUN_PATH = Path("output/last_run.json")

LOCAL_TZ = ZoneInfo("Europe/Amsterdam")


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def save_last_run(csv_path: str, count: int) -> None:
    data = {
        "last_run_at": datetime.datetime.utcnow().isoformat(),
        "todays_count": count,
        "csv_path": csv_path,
    }
    LAST_RUN_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def fetch_directory_listing() -> list[str]:
    """Return list of JSON filenames from index HTML."""
    print(f"🔎 Gebruik directory listing: {BASE_DIR}")

    r = requests.get(BASE_DIR, timeout=20)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "html.parser")
    links = soup.find_all("a")

    json_files = []
    for a in links:
        href = a.get("href")
        if not href:
            continue
        if href.lower().endswith(".json"):
            json_files.append(href)

    return json_files


def _extract_note_text(notes: list[dict], title: str) -> str:
    """Find note by title and return its text."""
    for n in notes or []:
        if (n.get("title") or "").strip().lower() == title.lower():
            return (n.get("text") or "").strip().lower()
    return ""


def _severity_from_kans_schade(kans: str, schade: str) -> str:
    """Map kans/schade to [H/H], [M/H], etc."""
    map_short = {
        "low": "L",
        "medium": "M",
        "high": "H",
        "critical": "H",
    }
    k = map_short.get(kans, "")
    s = map_short.get(schade, "")
    if k and s:
        return f"[{k}/{s}]"
    return ""


def _format_version(v: str) -> str:
    """
    Convert tracking.version like '1.0.0' to '[1.00]'.
    If format is unexpected, just wrap raw.
    """
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
    """
    Returns current_release_date or initial_release_date as aware datetime.
    CSAF gebruikt RFC3339/ISO8601; dateutil kan dit robuust parsen.
    """
    doc = json_data.get("document", {})
    tracking = doc.get("tracking", {})
    date_str = tracking.get("current_release_date") or tracking.get("initial_release_date")
    if not date_str:
        return None

    try:
        dt = dtparser.isoparse(date_str)
        if dt.tzinfo is None:
            # als er geen tz in staat, interpreteer als UTC
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        return None


def normalize_advisory(json_data: dict) -> dict:
    """Extract normalized advisory fields from CSAF JSON."""
    doc = json_data.get("document", {})
    tracking = doc.get("tracking", {})
    notes = doc.get("notes", [])

    advisory_id = tracking.get("id", "")
    version_raw = str(tracking.get("version", ""))

    kans = _extract_note_text(notes, "Kans")
    schade = _extract_note_text(notes, "Schade")
    severity = _severity_from_kans_schade(kans, schade)

    title = (doc.get("title") or "").strip()

    return {
        "AdvisoryID": advisory_id,
        "Version": _format_version(version_raw),
        "Severity": severity,
        "Description": title,
        "Link": f"{BASE_ROOT}advisory?id={advisory_id}" if advisory_id else "",
        "ReleaseDate": "",
    }


# ------------------------------------------------------------
# Main harvest logic
# ------------------------------------------------------------
def main():
    # "vandaag" in Europe/Amsterdam
    today_local = datetime.datetime.now(LOCAL_TZ).date()
    out_csv = OUTPUT_DIR / f"{today_local.isoformat()}.csv"

    json_files = fetch_directory_listing()
    print(f"📄 {len(json_files)} JSON-bestanden gevonden.")

    rows = []
    skipped_not_today = 0

    for href in json_files:
        # URL opbouw
        if href.startswith("http://") or href.startswith("https://"):
            advisory_url = href
        elif href.startswith("csaf/"):
            advisory_url = urljoin(BASE_ROOT, href.lstrip("/"))
        else:
            advisory_url = urljoin(BASE_DIR, href)

        try:
            r = requests.get(advisory_url, timeout=20)
            if r.status_code != 200:
                print(f"⚠️ Skip {advisory_url}: {r.status_code}")
                continue

            data = r.json()

            release_dt = _get_release_dt(data)
            if release_dt is None:
                # als release-datum ontbreekt: overslaan (of kies hier ander gedrag)
                skipped_not_today += 1
                continue

            release_local_date = release_dt.astimezone(LOCAL_TZ).date()
            if release_local_date != today_local:
                skipped_not_today += 1
                continue

            normalized = normalize_advisory(data)
            normalized["ReleaseDate"] = release_local_date.isoformat()
            if normalized["AdvisoryID"] or normalized["Description"]:
                rows.append(normalized)

        except Exception as e:
            print(f"⚠️ Error tijdens ophalen {advisory_url}: {e}")
            continue

    # CSV schrijven
    fieldnames = ["AdvisoryID", "Version", "Severity", "Description", "Link", "ReleaseDate"]

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    save_last_run(str(out_csv), len(rows))

    print(f"✅ {len(rows)} advisories van vandaag geschreven naar {out_csv}")
    print(f"ℹ️ Overgeslagen (niet van vandaag / geen datum): {skipped_not_today}")
    return 0


if __name__ == "__main__":
    main()
