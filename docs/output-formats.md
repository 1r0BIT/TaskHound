# Output Formats

TaskHound defaults to plain text on stdout because that's what you need 90% of the time. For the other 10%, there are options.

## Available Formats

| Format | Flag | What you get |
|--------|------|-------------|
| `plain` | `-o plain` | Text tables to stdout and file. The default. |
| `json` | `-o json` | Machine-readable JSON. For when humans aren't the audience. |
| `csv` | `-o csv` | Spreadsheet-friendly. Management loves spreadsheets. |
| `html` | `-o html` | Self-contained HTML report with severity scoring. The fancy one. |

## Usage

```bash
# Single format
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local -o json

# Multiple formats at once (comma-separated)
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local -o plain,json,html

# Custom output directory
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local -o json,html --output-dir ./engagement-results
```

## Directory Structure

All output goes under `--output-dir` (default: `./output`), organized by format:

```
./output/
├── plain/
│   ├── summary.txt
│   └── <host>/
│       └── tasks.txt
├── json/
│   └── taskhound_results.json
├── csv/
│   ├── taskhound_tasks.csv
│   └── taskhound_services.csv      # Only when --services is used
├── html/
│   └── taskhound_report.html
└── raw_backups/                     # Unless --no-backup
    └── <host>/
        ├── tasks/*.xml
        └── dpapi_loot/              # With --loot
            ├── masterkeys/
            └── credentials/
```

## JSON Structure

The JSON output is a single file with all results. When you use `--services` to also enumerate Windows services, the JSON includes both:

```json
{
  "tasks": [ ... ],
  "services": [ ... ]
}
```

Without `--services`, you just get the tasks array. Each task object includes host, task path, RunAs account, classification, triggers, credential validation status, and everything else TaskHound found.

## CSV Notes

CSV writes separate files for tasks and services: `taskhound_tasks.csv` and `taskhound_services.csv`. This is because they have different column schemas and cramming them into one file would be a mess. (I tried. It was a mess.)

## HTML Report

The HTML report is a self-contained single file — no external dependencies, no CSS CDN links, works offline. It includes:

- Severity-scored task listing with color coding
- Per-host breakdown with expandable sections
- Summary statistics
- Credential validation results where available

It's not going to win any design awards, but it's functional and you can hand it to a client without explaining how to parse JSON.

## Raw Backups

By default (unless you pass `--no-backup`), TaskHound saves the raw XML files it pulled from each host. This is useful for:

- Offline re-analysis later without touching the network again
- Evidence preservation for reports
- Feeding into `taskhound --offline-disk` on a different machine

If you used `--loot` for DPAPI credential extraction, the raw DPAPI blobs (masterkeys and credential files) are saved alongside the XMLs.

The backup collection happens regardless of which output formats you chose. It's a separate thing. Disable it with `--no-backup` if you don't want raw files cluttering your output directory.
