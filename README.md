# Dependency Quarantine Gate

A CI gate that checks a project's dependencies before they are installed.

It reads `requirements*.txt` and `package-lock.json` and:

- **FAIL** if a package is a known malicious package (OSV.dev `MAL-` advisory)
- **FAIL** if a version was published less than N days ago (cooldown, default 7)
- **WARN** for npm packages that run install scripts
- **WARN** for known (non-malicious) vulnerabilities
- **WARN** for unpinned Python dependencies

A report is written to `gate-report/report.html` and `gate-report/report.json`.

## Run

```
python gate.py --path . --min-age-days 7 --require-network
```

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
