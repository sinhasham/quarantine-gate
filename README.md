
Options:

| Flag | Meaning |
| --- | --- |
| `--path` | Folder to scan (default `.`) |
| `--min-age-days` | Cooldown in days (default 7) |
| `--allowlist` | File with `name` or `name==version` lines exempt from the age check (default `gate-allow.txt`) |
| `--out` | Report folder (default `gate-report`) |
| `--fail-on-warn` | Treat warnings as failures |
| `--require-network` | Fail if the OSV lookup could not complete (recommended in CI) |
| `--offline` | Parse files only, skip network checks |

Exit codes: `0` pass, `1` gate failed, `2` nothing to check.

The allowlist never bypasses the malicious-package check.

Only the Python standard library is used.

## Jenkins pipeline

The `Jenkinsfile` runs two gate stages:

1. **Dependency Quarantine Gate**: scans the repo root (`requirements.txt`)
2. **Node Quarantine Gate**: scans `node-sample/` (`package-lock.json`, 69 packages)

Both use `--min-age-days 7 --require-network`, and the reports are archived as build artifacts.

Setup notes (Windows): Jenkins runs as a service and does not see the user PATH, so the Jenkinsfile uses the full path to `python.exe` and `bat` steps.

## Demo

| Build | Setting | Result |
| --- | --- | --- |
| #1 | cooldown 7 days | PASSED (2 WARN: known vulnerabilities in flask/requests, unpinned numpy) |
| #2 | cooldown 3650 days | **FAILED** (flask and requests blocked as too new) |
| #3 | cooldown 7 days | PASSED |
| #4 | Python + Node stages | PASSED (Node: 61 OK, 8 WARN) |

Build #2 shows that the gate really blocks, not just passes.

## Notes

- Jenkins shows the archived `report.html` unstyled because of its Content Security Policy. Download it to view it with styling.
- Known limitation: the gate checks package metadata and advisories; it does not scan package contents.

## Future work

- Install stage in Docker with `--ignore-scripts`
- Match Jenkins' own plugins against security advisories
