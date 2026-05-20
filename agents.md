# AGENTS.md

## Repository context

This repository contains a Python-based NCSC advisory watcher.

Current functional flow:

1. `harvest_ncsc.py`
   - Fetches NCSC CSAF JSON advisories from `https://advisories.ncsc.nl/`.
   - Normalizes advisory fields into CSV rows.
   - Writes daily CSV output under `output/daily/`.
   - Writes JSONL output under `output/jsonl/` if implemented.
   - Writes run metadata to `output/last_run.json`.

2. `notify_ncsc.py`
   - Reads the latest CSV from `output/daily/`.
   - Filters high-risk advisories.
   - Deduplicates already-sent advisories through `dedupe.py`.
   - Sends notifications through configured channels.

3. `dedupe.py`
   - Maintains sent-state in `output/sent_cache.json`.
   - Uses advisory IDs, release dates, and message hashes to suppress duplicate notifications.

4. `.github/workflows/ncsc.yaml`
   - Runs the harvester and notifier on a scheduled GitHub Actions workflow.
   - Commits generated output/state back to the repository.

The project is intentionally lightweight. Keep dependencies minimal and avoid introducing frameworks unless strictly required.

---

## Non-breaking principle

Do **not** remove or replace the existing file-based workflow.

The application must continue writing generated files to disk. The database must be an additional cache/persistence layer, not a replacement for existing CSV/JSONL output.

The following file outputs must remain supported:

```text
output/daily/YYYY-MM-DD.csv
output/jsonl/YYYY-MM-DD.jsonl
output/last_run.json
output/sent_cache.json
```

`notify_ncsc.py` must remain compatible with the existing flow by reading the latest CSV from `output/daily/`.

---

## Desired feature additions

Implement the following features:

1. Configurable lookback window, for example:

   ```bash
   python harvest_ncsc.py --days 7
   ```

2. JSONL output for SIEM/SOAR ingestion.

3. Microsoft Teams or generic webhook notifications.

4. SQLite advisory cache while preserving all current file-based outputs.

---

## General implementation rules

- Preserve the current CLI behavior when no arguments are supplied.
- Default lookback behavior must remain compatible with the current daily workflow.
- Keep the code Python 3.11 compatible.
- Prefer standard-library modules where possible.
- Do not introduce breaking changes to existing CSV columns unless explicitly required.
- Keep output files deterministic and stable enough for Git diffs.
- Ensure all network calls use explicit timeouts.
- Do not log secrets, webhook URLs, tokens, or full authorization headers.
- Keep generated state/output under `output/`.
- Do not commit local virtual environments, caches, or temporary files.
- Treat SQLite as an additional persistence layer only.
- Do not make downstream notification behavior depend exclusively on SQLite.

---

## Feature 1: Configurable lookback window

### Goal

Allow the harvester to collect advisories from a configurable number of past days instead of only advisories released on the current local day.

Example:

```bash
python harvest_ncsc.py --days 7
```

This should collect advisories whose release date falls between today and `today - 6 days`, based on `Europe/Amsterdam`.

### Implementation requirements

- Add argument parsing to `harvest_ncsc.py` using `argparse`.
- Add `--days` as an integer argument.
- Default value: `1`.
- Validate that `--days >= 1`.
- The date comparison must remain timezone-aware.
- Use `Europe/Amsterdam` as the local reporting timezone, matching the existing code.
- Replace strict `release_local_date == today_local` logic with an inclusive date window:

```text
start_date <= release_local_date <= end_date
```

where:

```text
end_date = today in Europe/Amsterdam
start_date = end_date - (days - 1)
```

- Keep the existing yearly CSAF source logic, but account for year-boundary edge cases:
  - If the lookback window crosses into the previous year, fetch both the current year and previous year CSAF directory.
  - Avoid duplicate advisories if the same item appears across source sets.

### Acceptance criteria

- `python harvest_ncsc.py` behaves like the current daily run.
- `python harvest_ncsc.py --days 7` writes advisories from the last 7 local calendar days.
- Invalid values such as `--days 0` fail fast with a clear error.
- `output/last_run.json` includes the lookback configuration.

---

## Feature 2: JSONL output for SIEM/SOAR ingestion

### Goal

Add newline-delimited JSON output so downstream SIEM/SOAR platforms can ingest advisories without CSV parsing.

Example output path:

```text
output/jsonl/YYYY-MM-DD.jsonl
```

### Implementation requirements

- Add `output/jsonl/` as a generated output directory.
- For every harvested advisory written to CSV, write one JSON object per line to JSONL.
- Use UTF-8 encoding.
- Do not pretty-print JSONL.
- Ensure each JSONL line is independently parseable.
- Keep field names stable and SIEM-friendly.
- JSONL output must remain file-based even when SQLite is enabled.

### Minimum JSONL schema

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

### Acceptance criteria

- Running the harvester creates both CSV and JSONL output.
- JSONL contains the same advisory count as the CSV, excluding the CSV header.
- Each line can be parsed with `json.loads(line)`.
- JSONL output is suitable for filebeat, vector, fluent-bit, Sentinel custom ingestion, or SOAR workflows.

---

## Feature 3: Microsoft Teams or generic webhook notifications

### Goal

Add notification support beyond Telegram.

Support at least one of the following:

1. Microsoft Teams webhook.
2. Generic JSON webhook.

Prefer implementing both if the change remains small and maintainable.

### Environment variables

Add support for these variables:

```bash
TEAMS_WEBHOOK_URL=
WEBHOOK_URL=
WEBHOOK_TYPE=generic
```

Keep existing Telegram variables unchanged:

```bash
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

### Notification behavior

- Preserve Telegram support.
- Do not make Telegram mandatory.
- If multiple notification targets are configured, send to all configured targets.
- If no notification target is configured, log a warning and exit successfully.
- Deduplication must remain notification-channel agnostic:
  - Do not mark an advisory as sent unless at least one notification target succeeds.
  - If all targets fail, do not update the sent cache.
- Partial success is acceptable:
  - If Telegram succeeds but Teams fails, mark as sent and log the Teams failure.
  - If all configured destinations fail, return non-zero or log a clear failure depending on current workflow expectations.
- Webhook URLs and tokens must never be printed.

### Teams payload

For Microsoft Teams, start with a simple payload compatible with incoming webhook-style handlers or Teams Workflows:

```json
{
  "text": "**NCSC CVE ALERT**\n\n- [H/H] Example advisory\nhttps://advisories.ncsc.nl/advisory?id=NCSC-2026-0001"
}
```

Avoid HTML formatting for Teams-specific messages. Use Markdown-compatible text.

### Generic webhook payload

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

### Acceptance criteria

- Telegram behavior remains intact.
- Teams notification works when `TEAMS_WEBHOOK_URL` is configured.
- Generic webhook notification works when `WEBHOOK_URL` is configured.
- Webhook URLs are never printed in logs.
- Dedupe cache is updated only after at least one configured target succeeds.

---

## Feature 4: SQLite advisory cache while preserving file-based output

### Goal

Add SQLite-backed advisory persistence to reduce repeated full harvesting, while preserving the existing file-based output and notification flow.

SQLite must help with persistence, deduplication, faster lookups, and stable exports. It must not replace CSV/JSONL generation.

### Required behavior

The harvester must follow this flow:

1. Fetch and normalize NCSC CSAF advisories.
2. Upsert normalized advisories into SQLite.
3. Query the requested lookback window from SQLite.
4. Write the selected rows to CSV.
5. Write the selected rows to JSONL.
6. Write/update `output/last_run.json`.
7. Leave `notify_ncsc.py` working from the generated CSV file.

### Database storage

Add SQLite database:

```text
output/ncsc.sqlite3
```

Use SQLite from the Python standard library. Do not introduce external database dependencies.

Create table:

```sql
CREATE TABLE IF NOT EXISTS advisories (
    advisory_id TEXT NOT NULL,
    version TEXT NOT NULL,
    severity TEXT,
    description TEXT,
    link TEXT,
    release_date TEXT,
    source_url TEXT,
    content_hash TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (advisory_id, version)
);
```

Recommended indexes:

```sql
CREATE INDEX IF NOT EXISTS idx_advisories_release_date
ON advisories (release_date);

CREATE INDEX IF NOT EXISTS idx_advisories_severity
ON advisories (severity);
```

### File output must remain authoritative for downstream steps

Even when SQLite is enabled, the following outputs must still be written every run:

#### CSV

```text
output/daily/YYYY-MM-DD.csv
```

Required columns must remain compatible with the current notifier:

```text
AdvisoryID, Version, Severity, Description, Link, ReleaseDate
```

#### JSONL

```text
output/jsonl/YYYY-MM-DD.jsonl
```

Each advisory must be written as one JSON object per line.

#### Last run metadata

```text
output/last_run.json
```

Should include at least:

```json
{
  "last_run_at": "2026-05-20T10:00:00Z",
  "count": 12,
  "lookback_days": 7,
  "window_start": "2026-05-14",
  "window_end": "2026-05-20",
  "csv_path": "output/daily/2026-05-20.csv",
  "jsonl_path": "output/jsonl/2026-05-20.jsonl",
  "db_path": "output/ncsc.sqlite3"
}
```

### Database upsert behavior

Use `(advisory_id, version)` as the primary key.

On insert:

- Set `first_seen_at`.
- Set `last_seen_at`.
- Store normalized fields.
- Store `source_url`.
- Store `content_hash`.

On repeated sighting:

- Update `last_seen_at`.
- Update advisory fields only when `content_hash` changed.
- Do not create duplicate rows for the same advisory/version.

### Content hash

Add a deterministic content hash based on the original CSAF JSON or normalized advisory payload.

Recommended:

```python
import hashlib
import json

def content_hash(data: dict) -> str:
    canonical = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
```

### Compatibility requirements

- `python harvest_ncsc.py` must still work.
- `python harvest_ncsc.py --days 7` must still write CSV and JSONL files.
- `python notify_ncsc.py` must not need database access.
- Existing Telegram/Teams/webhook notification behavior must remain unchanged.
- Existing dedupe behavior using `output/sent_cache.json` must remain unchanged unless explicitly refactored later.
- No downstream behavior should depend exclusively on SQLite.

### GitHub Actions requirements

The workflow must continue committing generated file output.

Recommended commit list:

```bash
git add output/daily output/jsonl output/sent_cache.json output/ncsc.sqlite3 2>/dev/null || true
```

Do not remove file-based exports from the workflow.

`output/last_run.json` may be excluded from Git commits if it causes frequent conflicts, but it should still be written locally during each run.

### Acceptance criteria

- CSV output is still created.
- JSONL output is still created.
- SQLite database is created or updated.
- The row count in CSV matches the selected lookback window.
- The JSONL line count matches the CSV row count.
- `notify_ncsc.py` can still send alerts using the latest CSV.
- No downstream behavior depends exclusively on SQLite.
- Existing GitHub Actions flow still produces file artifacts in `output/`.

---

## Workflow updates

Update `.github/workflows/ncsc.yaml` to support the new configuration.

### Suggested environment variables

```yaml
env:
  TELEGRAM_BOT_TOKEN: ${{ secrets.TELEGRAM_BOT_TOKEN }}
  TELEGRAM_CHAT_ID: ${{ secrets.TELEGRAM_CHAT_ID }}
  TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
  WEBHOOK_URL: ${{ secrets.WEBHOOK_URL }}
  LOOKBACK_DAYS: ${{ github.event.inputs.days || '1' }}
  DEBUG: "1"
```

### Suggested run command

```yaml
- name: Harvest CSAF -> CSV + JSONL
  run: python harvest_ncsc.py --days "${LOOKBACK_DAYS}"

- name: Notify high-risk advisories
  run: python notify_ncsc.py
```

### Recommended commit step

Avoid rebasing generated runtime state after the notification step. Sync before harvesting, then commit output.

```yaml
- name: Sync latest main
  run: |
    git fetch origin main
    git reset --hard origin/main

- name: Commit & push outputs/state
  run: |
    set -euo pipefail

    git config user.name "github-actions[bot]"
    git config user.email "github-actions[bot]@users.noreply.github.com"

    git add output/daily output/jsonl output/sent_cache.json output/ncsc.sqlite3 2>/dev/null || true

    if git diff --staged --quiet; then
      echo "No changes to commit."
      exit 0
    fi

    git commit -m "Automated NCSC advisories update"
    git push origin HEAD:main
```

---

## README updates

Update `readme.MD` with:

- `--days` usage examples.
- JSONL output path and schema.
- SQLite cache behavior.
- Teams/webhook secrets.
- Updated workflow configuration.
- Clear distinction between:
  - harvesting,
  - database persistence/cache,
  - file export,
  - deduplication,
  - notification delivery.

Document outputs:

```text
output/daily/YYYY-MM-DD.csv
output/jsonl/YYYY-MM-DD.jsonl
output/last_run.json
output/sent_cache.json
output/ncsc.sqlite3
```

---

## Test requirements

Add lightweight tests if possible. If no test framework exists, add a minimal `tests/` folder using `pytest`.

Recommended tests:

1. `--days` parsing.
2. Date window filtering.
3. JSONL output.
4. SQLite cache.
5. Webhook notification.
6. Deduplication.

---

## Security requirements

- Treat all webhook URLs and tokens as secrets.
- Never print secret values.
- Avoid sending full stack traces that may contain environment variables.
- Use `requests.post(..., timeout=20)` or stricter.
- Fail closed on malformed command-line input.
- Keep output JSON safe for ingestion.
- Avoid shelling out from Python.
- Do not add dependencies for notification handling unless necessary.
- SQLite database must stay under `output/`.
- Do not store API tokens, webhook URLs, or secrets inside SQLite.

---

## Definition of done

The feature set is complete when:

- `python harvest_ncsc.py` still performs a one-day harvest.
- `python harvest_ncsc.py --days 7` harvests or exports the last seven local calendar days.
- CSV output remains available.
- JSONL output is created under `output/jsonl/`.
- SQLite database is created or updated under `output/ncsc.sqlite3`.
- SQLite is used as an additional persistence/cache layer.
- File-based CSV/JSONL output remains the integration contract for downstream steps.
- `notify_ncsc.py` still works from the latest generated CSV.
- `notify_ncsc.py` supports Telegram plus Teams and/or generic webhooks.
- Existing dedupe behavior remains intact.
- Notification success/failure is logged without leaking secrets.
- GitHub Actions workflow can pass `LOOKBACK_DAYS`.
- README documents the new behavior.
- Tests or validation commands are included.
