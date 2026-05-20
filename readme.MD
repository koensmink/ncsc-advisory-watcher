# NCSC Advisory Watcher

Python-based watcher for Dutch NCSC security advisories.

This project collects NCSC CSAF advisories, normalizes relevant metadata, stores daily CSV output, filters high-risk advisories, deduplicates previously sent alerts, and optionally sends Telegram notifications.

> Primary use case: lightweight security advisory monitoring for homelab, SOC-support, MSP workflows, or personal security intelligence pipelines.

---

## What it does

NCSC Advisory Watcher performs the following steps:

1. Fetch NCSC CSAF advisory JSON files.
2. Parse and normalize advisory metadata.
3. Write daily CSV output to `output/daily/`.
4. Filter advisories based on risk level.
5. Deduplicate already processed or already notified advisories.
6. Send high-risk notifications to Telegram.
7. Persist runtime state for future runs.

---

## Features

| Feature | Description |
|---|---|
| CSAF harvesting | Reads NCSC CSAF advisories from the public advisory feed |
| Daily CSV export | Stores normalized advisory data per day |
| Severity filtering | Sends alerts only for high-risk combinations |
| Telegram notifications | Sends formatted advisory alerts via Telegram Bot API |
| Deduplication | Prevents repeated alerts for the same advisory |
| Message hash check | Avoids sending identical notification payloads repeatedly |
| GitHub Actions support | Runs automatically through a scheduled workflow |
| Self-hosted runner support | Designed to run from a self-hosted GitHub Actions runner |
| Output persistence | Commits generated output/state back to the repository |

---

## Data source

The harvester reads advisory data from:

```text
https://advisories.ncsc.nl/csaf/v2/<YEAR>/
```

Each CSAF JSON file is parsed and normalized into a smaller operational format.

---

## Architecture

```text
NCSC CSAF feed
      |
      v
harvest_ncsc.py
      |
      |-- output/daily/YYYY-MM-DD.csv
      |-- output/last_run.json
      |
      v
notify_ncsc.py
      |
      |-- high-risk severity filter
      |-- advisory dedupe
      |-- message hash dedupe
      |
      v
Telegram Bot API
      |
      v
output/sent_cache.json
```

---

## Repository structure

```text
.
├── .github/
│   └── workflows/
│       └── ncsc.yaml
├── output/
│   ├── daily/
│   │   └── YYYY-MM-DD.csv
│   ├── last_run.json
│   └── sent_cache.json
├── dedupe.py
├── harvest_ncsc.py
├── notify_ncsc.py
├── scraper.py
├── requirements.txt
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
└── readme.md
```
---

## Requirements

- Python 3.11+
- GitHub Actions, optional
- Telegram bot, optional
- Self-hosted runner, optional but currently used by the workflow

Install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Main dependencies:

```text
requests
beautifulsoup4
python-dateutil
feedparser
pandas
tqdm
black
```

---

## Configuration

### Environment variables

| Variable | Required | Description |
|---|---:|---|
| `TELEGRAM_BOT_TOKEN` | No | Telegram bot token used for sending alerts |
| `TELEGRAM_CHAT_ID` | No | Target Telegram chat ID |
| `DEBUG` | No | Enables extra debug behavior when set to `1` |
| `NO_DEDUPE` | No | Disables dedupe temporarily when set to `1` |

When Telegram variables are not configured, the scripts still run but skip notification delivery.

---

## Usage

### Run the harvester

```bash
python harvest_ncsc.py
```

This creates or updates:

```text
output/daily/<YYYY-MM-DD>.csv
output/last_run.json
```
---

## Output files

### Daily CSV

```text
output/daily/<YYYY-MM-DD>.csv
```

Example schema:

```csv
AdvisoryID,Version,Severity,Description,Link,ReleaseDate
NCSC-2026-0001,[1.00],[H/H],Example advisory,https://advisories.ncsc.nl/advisory?id=NCSC-2026-0001,2026-05-08
```
---

## Telegram notification format

Notifications are sent as HTML-formatted Telegram messages.

Example format:

```text
🚨 NCSC CVE ALERT 🚨

Details:
• [[H/H]] — Example advisory title
  Bekijk advisory
```

Telegram delivery is skipped safely when `TELEGRAM_BOT_TOKEN` or `TELEGRAM_CHAT_ID` is missing.

---

## Roadmap ideas

Potential improvements:

- Add configurable lookback window, for example `--days 7`.
- Add CLI arguments for severity thresholds.
- Add JSONL output for SIEM/SOAR ingestion.
- Add Microsoft Teams or webhook notifications.
- Add unit tests for CSAF parsing and dedupe behavior.
- Add Dockerfile for reproducible local execution.
- Add structured logging.
- Add optional NCSC advisory diffing between versions.
- Add GitHub release artifacts instead of committing output to the repository.

## New options

- `python harvest_ncsc.py --days 7` harvests a 7-day Amsterdam-local window.
- JSONL output is written to `output/jsonl/YYYY-MM-DD.jsonl`.
- `notify_ncsc.py` now supports Telegram, Microsoft Teams (`TEAMS_WEBHOOK_URL`) and generic webhooks (`WEBHOOK_URL`, `WEBHOOK_TYPE`).

Workflow env additions:
- `LOOKBACK_DAYS`
- `TEAMS_WEBHOOK_URL`
- `WEBHOOK_URL`
