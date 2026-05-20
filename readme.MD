# NCSC Advisory Watcher

Python-based watcher for Dutch NCSC security advisories.

This project collects NCSC CSAF advisories, normalizes relevant metadata, stores daily CSV and JSONL output, filters high-risk advisories, deduplicates previously sent alerts, and optionally sends Telegram, Microsoft Teams, and generic webhook notifications.

> Primary use case: lightweight security advisory monitoring for homelab, SOC-support, MSP workflows, or personal security intelligence pipelines.

---

## What it does

NCSC Advisory Watcher performs the following steps:

1. Fetch NCSC CSAF advisory JSON files.
2. Parse and normalize advisory metadata.
3. Write daily CSV output to `output/daily/`.
4. Filter advisories based on risk level.
5. Deduplicate already processed or already notified advisories.
6. Send high-risk notifications to Telegram / Teams / generic webhooks.
7. Persist runtime state for future runs.

---

## Features

| Feature | Description |
|---|---|
| CSAF harvesting | Reads NCSC CSAF advisories from the public advisory feed |
| Daily CSV export | Stores normalized advisory data per day |
| JSONL export | Stores SIEM/SOAR-friendly newline-delimited events per day |
| Severity filtering | Sends alerts only for high-risk combinations |
| Multi-channel notifications | Sends alerts via Telegram, Microsoft Teams, and generic webhooks |
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
      |-- output/jsonl/YYYY-MM-DD.jsonl
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
| `TEAMS_WEBHOOK_URL` | No | Teams incoming webhook URL |
| `WEBHOOK_URL` | No | Generic webhook target URL |
| `WEBHOOK_TYPE` | No | Generic webhook payload style selector (default: `generic`) |
| `LOOKBACK_DAYS` | No | Lookback window in days for harvesting (default: `1`) |
| `DEBUG` | No | Enables extra debug behavior when set to `1` |
| `NO_DEDUPE` | No | Disables dedupe temporarily when set to `1` |

When no notification variables are configured, the notifier logs a warning and exits successfully without sending alerts.

---

## Usage

### Run the harvester

```bash
python harvest_ncsc.py
python harvest_ncsc.py --days 7
```

This creates or updates:

```text
output/daily/<YYYY-MM-DD>.csv
output/jsonl/<YYYY-MM-DD>.jsonl
output/last_run.json
```

### Run notifications

```bash
python notify_ncsc.py
```

### Run with Docker

Build image:

```bash
docker build -t ncsc-advisory-watcher .
```

Harvest (1-day default):

```bash
docker run --rm \
  -v "$(pwd)/output:/app/output" \
  ncsc-advisory-watcher
```

Harvest with lookback window:

```bash
docker run --rm \
  -v "$(pwd)/output:/app/output" \
  ncsc-advisory-watcher \
  python harvest_ncsc.py --days 7
```

Send notifications from container:

```bash
docker run --rm \
  -v "$(pwd)/output:/app/output" \
  -e TELEGRAM_BOT_TOKEN \
  -e TELEGRAM_CHAT_ID \
  -e TEAMS_WEBHOOK_URL \
  -e WEBHOOK_URL \
  -e WEBHOOK_TYPE=generic \
  ncsc-advisory-watcher \
  python notify_ncsc.py
```
---

## Output files

```text
output/daily/<YYYY-MM-DD>.csv
output/jsonl/<YYYY-MM-DD>.jsonl
output/last_run.json
output/sent_cache.json
```

### Daily CSV

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

## Workflow notes

For GitHub Actions, set these variables/secrets if needed:

- `LOOKBACK_DAYS` (example: `1` or `7`)
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- `TEAMS_WEBHOOK_URL`
- `WEBHOOK_URL`
- `WEBHOOK_TYPE`

