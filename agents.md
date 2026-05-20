This repository contains a Python-based NCSC advisory watcher.
Current functional flow:
`harvest_ncsc.py`
Fetches NCSC CSAF JSON advisories from `https://advisories.ncsc.nl/`.
Normalizes advisory fields into CSV rows.
Writes daily CSV output under `output/daily/`.
Writes run metadata to `output/last_run.json`.
`notify_ncsc.py`
Reads the latest CSV from `output/daily/`.
Filters high-risk advisories.
Deduplicates already-sent advisories through `dedupe.py`.
Sends notifications through Telegram.
`dedupe.py`
Maintains sent-state in `output/sent_cache.json`.
Uses advisory IDs, release dates, and message hashes to suppress duplicate notifications.
`.github/workflows/ncsc.yaml`
Runs the harvester and notifier on a scheduled GitHub Actions workflow.
Commits generated output/state back to the repository.
The project is intentionally lightweight. Keep dependencies minimal and avoid introducing frameworks unless strictly required.
---
Desired feature additions
Implement the following features:
Configurable lookback window, for example:
```bash
   python harvest_ncsc.py --days 7
   ```
JSONL output for SIEM/SOAR ingestion.
Microsoft Teams or generic webhook notifications.
---
General implementation rules
Preserve the current CLI behavior when no arguments are supplied.
Default lookback behavior must remain compatible with the current daily workflow.
Keep the code Python 3.11 compatible.
Prefer standard-library modules where possible.
Do not introduce breaking changes to existing CSV columns unless explicitly required.
Keep output files deterministic and stable enough for Git diffs.
Ensure all network calls use explicit timeouts.
Do not log secrets, webhook URLs, tokens, or full authorization headers.
Keep generated state/output under `output/`.
Do not commit local virtual environments, caches, or temporary files.
---
Feature 1: Configurable lookback window
Goal
Allow the harvester to collect advisories from a configurable number of past days instead of only advisories released on the current local day.
Example:
```bash
python harvest_ncsc.py --days 7
```
This should collect advisories whose release date falls between today and `today - 6 days`, based on `Europe/Amsterdam`.
Implementation requirements
Add argument parsing to `harvest_ncsc.py` using `argparse`.
Add `--days` as an integer argument.
Default value: `1`.
Validate that `--days >= 1`.
The date comparison must remain timezone-aware.
Use `Europe/Amsterdam` as the local reporting timezone, matching the existing code.
Replace the current strict `release_local_date == today_local` logic with an inclusive date window:
```text
  start_date <= release_local_date <= end_date
  ```
where:
```text
  end_date = today in Europe/Amsterdam
  start_date = end_date - (days - 1)
  ```
Keep the existing yearly CSAF source logic, but account for year-boundary edge cases:
If the lookback window crosses into the previous year, fetch both the current year and previous year CSAF directory.
Avoid duplicate advisories if the same item appears across source sets.
Recommended structure
Refactor the harvester into smaller functions:
```python
def parse_args() -> argparse.Namespace:
    ...

def get_years_for_window(start_date: date, end_date: date) -> list[int]:
    ...

def fetch_directory_listing(year: int) -> list[str]:
    ...

def harvest_advisories(days: int) -> list[dict]:
    ...
```
Acceptance criteria
`python harvest_ncsc.py` behaves like the current daily run.
`python harvest_ncsc.py --days 7` writes advisories from the last 7 local calendar days.
Invalid values such as `--days 0` fail fast with a clear error.
`output/last_run.json` includes the lookback configuration, for example:
```json
  {
    "last_run_at": "2026-05-20T10:00:00Z",
    "count": 12,
    "lookback_days": 7,
    "window_start": "2026-05-14",
    "window_end": "2026-05-20",
    "csv_path": "output/daily/2026-05-20.csv"
  }
  ```
---
Feature 2: JSONL output for SIEM/SOAR ingestion
Goal
Add newline-delimited JSON output so downstream SIEM/SOAR platforms can ingest advisories without CSV parsing.
Example output path:
```text
output/jsonl/YYYY-MM-DD.jsonl
```
Implementation requirements
Add `output/jsonl/` as a generated output directory.
For every harvested advisory written to CSV, write one JSON object per line to JSONL.
Use UTF-8 encoding.
Do not pretty-print JSONL.
Ensure each JSONL line is independently parseable.
Keep field names stable and SIEM-friendly.
Minimum JSONL schema
Each JSONL object should include at least:
```json
{
  "event_type": "ncsc_advisory",
  "source": "NCSC-NL",
  "advisory_id": "NCSC-2026-0001",
  "version": "[1.00]",
  "severity": "[H/H]",
  "description": "Example advisory title",
  "link": "https://advisories.ncsc.nl/advisory?id=NCSC-2026-0001",
  "release_date": "2026-05-20",
  "ingested_at": "2026-05-20T10:00:00Z"
}
```
Field mapping
JSONL field	Source field
`event_type`	Constant: `ncsc_advisory`
`source`	Constant: `NCSC-NL`
`advisory_id`	`AdvisoryID`
`version`	`Version`
`severity`	`Severity`
`description`	`Description`
`link`	`Link`
`release_date`	`ReleaseDate`
`ingested_at`	Current UTC timestamp
Optional useful fields
Add these only if they can be derived reliably:
```json
{
  "severity_probability": "H",
  "severity_impact": "H",
  "risk_bucket": "high",
  "dedupe_key": "NCSC-2026-0001|2026-05-20"
}
```
Acceptance criteria
Running the harvester creates both CSV and JSONL output.
JSONL contains the same advisory count as the CSV, excluding the CSV header.
Each line can be parsed with `json.loads(line)`.
JSONL output is suitable for filebeat, vector, fluent-bit, Sentinel custom ingestion, or SOAR workflows.
---
Feature 3: Microsoft Teams or generic webhook notifications
Goal
Add notification support beyond Telegram.
Support at least one of the following:
Microsoft Teams webhook.
Generic JSON webhook.
Prefer implementing both if the change remains small and maintainable.
Environment variables
Add support for these variables:
```bash
TEAMS_WEBHOOK_URL=
WEBHOOK_URL=
WEBHOOK_TYPE=generic
```
Recommended behavior:
Variable	Purpose
`TEAMS_WEBHOOK_URL`	Sends a Microsoft Teams-compatible notification
`WEBHOOK_URL`	Sends a generic JSON webhook notification
`WEBHOOK_TYPE`	Optional selector for future webhook formatting
Keep existing Telegram variables unchanged:
```bash
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```
Notification behavior
Preserve Telegram support.
Do not make Telegram mandatory.
If multiple notification targets are configured, send to all configured targets.
If no notification target is configured, log a warning and exit successfully.
Deduplication must remain notification-channel agnostic:
Do not mark an advisory as sent unless at least one notification target succeeds.
If all targets fail, do not update the sent cache.
Partial success is acceptable:
If Telegram succeeds but Teams fails, mark as sent and log the Teams failure.
If all configured destinations fail, return non-zero or log a clear failure depending on current workflow expectations.
Teams payload
For Microsoft Teams, start with a simple payload compatible with incoming webhook style connectors:
```json
{
  "text": "**NCSC CVE ALERT**\n\n- [H/H] Example advisory\nhttps://advisories.ncsc.nl/advisory?id=NCSC-2026-0001"
}
```
If using Adaptive Cards, keep the implementation isolated and documented.
Generic webhook payload
For generic webhook notifications, send structured JSON:
```json
{
  "event_type": "ncsc_advisory_alert",
  "source": "NCSC-NL",
  "generated_at": "2026-05-20T10:00:00Z",
  "count": 1,
  "advisories": [
    {
      "advisory_id": "NCSC-2026-0001",
      "version": "[1.00]",
      "severity": "[H/H]",
      "description": "Example advisory title",
      "link": "https://advisories.ncsc.nl/advisory?id=NCSC-2026-0001",
      "release_date": "2026-05-20"
    }
  ]
}
```
Recommended code structure
Refactor notification logic into channel-specific functions:
```python
def send_to_telegram(text: str) -> tuple[bool, str]:
    ...

def send_to_teams(text: str) -> tuple[bool, str]:
    ...

def send_to_webhook(payload: dict) -> tuple[bool, str]:
    ...

def send_notifications(rows: list[dict], message_text: str) -> tuple[bool, list[str]]:
    ...
```
Acceptance criteria
Telegram behavior remains intact.
Teams notification works when `TEAMS_WEBHOOK_URL` is configured.
Generic webhook notification works when `WEBHOOK_URL` is configured.
Webhook URLs are never printed in logs.
Dedupe cache is updated only after at least one configured target succeeds.
---
Workflow updates
Update `.github/workflows/ncsc.yaml` to support the new configuration.
Suggested environment variables
```yaml
env:
  TELEGRAM_BOT_TOKEN: ${{ secrets.TELEGRAM_BOT_TOKEN }}
  TELEGRAM_CHAT_ID: ${{ secrets.TELEGRAM_CHAT_ID }}
  TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
  WEBHOOK_URL: ${{ secrets.WEBHOOK_URL }}
  LOOKBACK_DAYS: "1"
  DEBUG: "1"
```
Suggested run command
```yaml
- name: Harvest CSAF -> CSV + JSONL
  run: python harvest_ncsc.py --days "${LOOKBACK_DAYS:-1}"

- name: Notify high-risk advisories
  run: python notify_ncsc.py
```
Optional manual workflow input
Add `workflow_dispatch` input support:
```yaml
workflow_dispatch:
  inputs:
    days:
      description: "Lookback window in days"
      required: false
      default: "1"
```
Then map it safely:
```yaml
env:
  LOOKBACK_DAYS: ${{ github.event.inputs.days || '1' }}
```
---
README updates
Update `readme.MD` with:
`--days` usage examples.
JSONL output path and schema.
Teams/webhook secrets.
Updated workflow configuration.
Clear distinction between:
harvesting,
deduplication,
notification delivery,
generated SIEM/SOAR output.
Suggested examples:
```bash
python harvest_ncsc.py
python harvest_ncsc.py --days 7
python notify_ncsc.py
```
Document outputs:
```text
output/daily/YYYY-MM-DD.csv
output/jsonl/YYYY-MM-DD.jsonl
output/last_run.json
output/sent_cache.json
```
---
Test requirements
Add lightweight tests if possible. If no test framework exists, add a minimal `tests/` folder using `pytest`.
Recommended tests:
`--days` parsing:
Default is `1`.
`--days 7` is accepted.
`--days 0` fails.
Date window filtering:
Advisories inside the lookback window are included.
Advisories outside the lookback window are excluded.
Year-boundary lookback is handled.
JSONL output:
File is created.
Line count equals harvested advisory count.
Every line is valid JSON.
Required fields exist.
Webhook notification:
Missing webhook URL does not crash.
Configured webhook sends expected payload.
Secret URL is not logged.
Deduplication:
Cache is updated only after at least one notification channel succeeds.
---
Security requirements
Treat all webhook URLs and tokens as secrets.
Never print secret values.
Avoid sending full stack traces that may contain environment variables.
Use `requests.post(..., timeout=20)` or stricter.
Fail closed on malformed command-line input.
Keep output JSON safe for ingestion:
no control characters,
UTF-8 only,
one event per line.
Avoid shelling out from Python.
Do not add dependencies for notification handling unless necessary.
---
Definition of done
The feature set is complete when:
`python harvest_ncsc.py` still performs a one-day harvest.
`python harvest_ncsc.py --days 7` harvests the last seven local calendar days.
CSV output remains available.
JSONL output is created under `output/jsonl/`.
`notify_ncsc.py` supports Telegram plus Teams and/or generic webhooks.
Existing dedupe behavior remains intact.
Notification success/failure is logged without leaking secrets.
GitHub Actions workflow can pass `LOOKBACK_DAYS`.
README documents the new behavior.
Tests or validation commands are included.
