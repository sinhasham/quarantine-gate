#!/usr/bin/env python3
"""
Dependency Quarantine Gate
--------------------------
Checks a project's dependencies BEFORE they are installed in CI.

What it checks (for requirements.txt and package-lock.json):
  1. Malicious packages   -> OSV.dev advisories with a "MAL-" id      -> FAIL
  2. Release-age cooldown -> version published < N days ago           -> FAIL
  3. Install scripts      -> npm packages with hasInstallScript       -> WARN
  4. Known vulnerabilities (non-malicious OSV advisories)             -> WARN
  5. Unpinned python deps (no ==version)                              -> WARN

Why: in 2026 most malicious package versions were caught and removed within
hours/days of publishing, so refusing very fresh versions blocks most attacks.

Only the Python standard library is used (no pip install needed).

Exit codes: 0 = pass, 1 = gate failed, 2 = nothing to check / usage error.
"""

import argparse
import html
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
PYPI_URL = "https://pypi.org/pypi/{name}/{version}/json"
NPM_URL = "https://registry.npmjs.org/{name}"
TIMEOUT = 20
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}


# ----------------------------------------------------------------- helpers --
def http_json(url, data=None):
    """GET (or POST when data is given) and return parsed JSON."""
    headers = {
        "User-Agent": "dependency-quarantine-gate/1.0",
        "Accept": "application/json",
    }
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.load(resp)


def pkg_key(p):
    return (p["eco"], p["name"], p["version"])


def parse_ts(value):
    """Parse an ISO-8601 timestamp (PyPI / npm style) into an aware datetime."""
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ----------------------------------------------------------------- parsers --
def parse_requirements(path):
    """Return (pinned_packages, unpinned_names) from a requirements file."""
    pinned, unpinned = [], []
    pin_re = re.compile(
        r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9._!+-]+)$"
    )
    name_re = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split(" #")[0].strip()
            if not line or line.startswith(("#", "-")):
                continue
            line = line.split(";")[0]          # drop environment markers
            line = line.split(" --")[0]        # drop inline --hash=... options
            line = line.rstrip("\\").strip()   # drop line-continuation slash
            m = pin_re.match(line)
            if m:
                name = re.sub(r"[-_.]+", "-", m.group(1)).lower()
                pinned.append(
                    {"eco": "pypi", "name": name, "version": m.group(3),
                     "install_script": False, "source": path}
                )
            else:
                m2 = name_re.match(line)
                if m2:
                    unpinned.append({"name": m2.group(1), "source": path})
    return pinned, unpinned


def parse_package_lock(path):
    """Return packages from package-lock.json (lockfile v1, v2 and v3)."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    found = {}

    def add(name, meta):
        version = meta.get("version")
        if not name or not version or meta.get("link"):
            return
        p = {"eco": "npm", "name": name, "version": version,
             "install_script": bool(meta.get("hasInstallScript")), "source": path}
        found[pkg_key(p)] = p

    if "packages" in data:                       # lockfile v2 / v3
        for key, meta in data["packages"].items():
            if key and "node_modules/" in key:
                add(key.split("node_modules/")[-1], meta)
    else:                                        # lockfile v1 (nested)
        def walk(deps):
            for name, meta in deps.items():
                add(name, meta)
                walk(meta.get("dependencies", {}))
        walk(data.get("dependencies", {}))
    return list(found.values())


def collect(root):
    """Walk the repo and gather all dependencies we know how to read."""
    pkgs, unpinned = {}, []
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            full = os.path.join(folder, fname)
            if re.match(r"^requirements.*\.txt$", fname):
                pinned, loose = parse_requirements(full)
                for p in pinned:
                    pkgs[pkg_key(p)] = p
                unpinned.extend(loose)
            elif fname == "package-lock.json":
                for p in parse_package_lock(full):
                    pkgs[pkg_key(p)] = p
    return list(pkgs.values()), unpinned


def load_allowlist(path):
    allow = set()
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#")[0].strip().lower()
                if line:
                    allow.add(line)
    return allow


# ------------------------------------------------------------ network checks --
def osv_check(pkgs):
    """Ask OSV.dev about every package. Returns ({key: [advisory ids]}, ok)."""
    result = {pkg_key(p): [] for p in pkgs}
    try:
        for i in range(0, len(pkgs), 500):
            chunk = pkgs[i:i + 500]
            queries = [
                {"package": {"name": p["name"],
                             "ecosystem": "PyPI" if p["eco"] == "pypi" else "npm"},
                 "version": p["version"]}
                for p in chunk
            ]
            resp = http_json(OSV_BATCH_URL, {"queries": queries})
            for p, r in zip(chunk, resp.get("results", [])):
                result[pkg_key(p)] = [v["id"] for v in r.get("vulns", [])]
        return result, True
    except Exception as exc:  # network down, API change, ...
        print("WARNING: OSV lookup failed: %s" % exc)
        return result, False


def fetch_release_time(p):
    """Return the publish time (datetime) of one package version, or None."""
    try:
        if p["eco"] == "pypi":
            url = PYPI_URL.format(name=urllib.parse.quote(p["name"]),
                                  version=urllib.parse.quote(p["version"]))
            data = http_json(url)
            times = [parse_ts(u.get("upload_time_iso_8601"))
                     for u in data.get("urls", [])]
            times = [t for t in times if t]
            return min(times) if times else None
        url = NPM_URL.format(name=urllib.parse.quote(p["name"], safe="@"))
        data = http_json(url)
        return parse_ts(data.get("time", {}).get(p["version"]))
    except Exception:
        return None


# -------------------------------------------------------------- evaluation --
def is_allowed(p, allow):
    name = p["name"].lower()
    return name in allow or ("%s==%s" % (name, p["version"])).lower() in allow


def evaluate(p, osv_ids, released, osv_ok, allow, min_age, now):
    flags = []
    mal = [i for i in osv_ids if i.startswith("MAL-")]
    vulns = [i for i in osv_ids if not i.startswith("MAL-")]
    age = (now - released).total_seconds() / 86400 if released else None

    if mal:
        flags.append(("FAIL", "Known MALICIOUS package (%s)" % ", ".join(mal)))
    if age is None:
        flags.append(("WARN", "Release date unknown"))
    elif age < min_age:
        if is_allowed(p, allow):
            flags.append(("WARN", "Released %.1f days ago, allowlisted" % age))
        else:
            flags.append(("FAIL", "Released %.1f days ago (cooldown is %g days)"
                          % (age, min_age)))
    if p.get("install_script"):
        flags.append(("WARN", "Runs install scripts"))
    if vulns:
        flags.append(("WARN", "%d known vulnerabilities (%s)"
                      % (len(vulns), ", ".join(vulns[:3]))))
    if not osv_ok:
        flags.append(("WARN", "OSV lookup failed"))

    status = "OK"
    if any(level == "WARN" for level, _ in flags):
        status = "WARN"
    if any(level == "FAIL" for level, _ in flags):
        status = "FAIL"
    return {
        "ecosystem": p["eco"], "name": p["name"], "version": p["version"],
        "age_days": None if age is None else round(age, 1),
        "status": status, "flags": [text for _, text in flags],
        "source": p["source"],
    }


# ------------------------------------------------------------------ report --
def write_reports(out_dir, rows, unpinned, meta):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "packages": rows, "unpinned": unpinned}, fh, indent=2)

    esc = html.escape
    colors = {"FAIL": "#fde2e2", "WARN": "#fff4d6", "OK": "#e6f6e6"}
    body = []
    for r in rows:
        age = "?" if r["age_days"] is None else r["age_days"]
        body.append(
            '<tr style="background:%s"><td>%s</td><td>%s</td><td>%s</td>'
            "<td>%s</td><td>%s</td><td>%s</td></tr>"
            % (colors[r["status"]], r["status"], esc(r["ecosystem"]), esc(r["name"]),
               esc(r["version"]), age, esc("; ".join(r["flags"]) or "-"))
        )
    loose = "".join("<li>%s <small>(%s)</small></li>"
                    % (esc(u["name"]), esc(u["source"])) for u in unpinned)
    page = """<!doctype html><html><head><meta charset="utf-8">
<title>Dependency Quarantine Gate</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px}
table{border-collapse:collapse;width:100%%}td,th{border:1px solid #ccc;padding:6px 8px;text-align:left}
th{background:#222;color:#fff}.verdict{font-size:22px;font-weight:bold}</style></head><body>
<h1>Dependency Quarantine Gate</h1>
<p class="verdict">Verdict: %(verdict)s</p>
<p>Checked %(total)d packages | FAIL: %(fail)d | WARN: %(warn)d | OK: %(ok)d |
cooldown: %(min_age)g days | generated: %(time)s</p>
<table><tr><th>Status</th><th>Eco</th><th>Package</th><th>Version</th><th>Age (days)</th><th>Findings</th></tr>
%(rows)s</table>
<h3>Unpinned python dependencies (cannot be checked)</h3><ul>%(loose)s</ul>
</body></html>""" % {
        "verdict": meta["verdict"], "total": meta["total"], "fail": meta["fail"],
        "warn": meta["warn"], "ok": meta["ok"], "min_age": meta["min_age_days"],
        "time": meta["generated"], "rows": "".join(body), "loose": loose or "<li>none</li>",
    }
    with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(page)


# -------------------------------------------------------------------- main --
def main():
    ap = argparse.ArgumentParser(description="Dependency Quarantine Gate")
    ap.add_argument("--path", default=".", help="repo folder to scan")
    ap.add_argument("--min-age-days", type=float, default=7,
                    help="fail if a version is newer than this (default 7)")
    ap.add_argument("--allowlist", default="gate-allow.txt",
                    help="file with 'name' or 'name==version' lines exempt from the age check")
    ap.add_argument("--out", default="gate-report", help="report output folder")
    ap.add_argument("--fail-on-warn", action="store_true", help="treat warnings as failures")
    ap.add_argument("--offline", action="store_true", help="skip network checks (parsing only)")
    ap.add_argument("--require-network", action="store_true",
                    help="fail the gate if the OSV lookup could not be completed (recommended in CI)")
    args = ap.parse_args()

    root = os.path.abspath(args.path)
    pkgs, unpinned = collect(root)
    if not pkgs and not unpinned:
        print("No requirements*.txt or package-lock.json found in %s" % root)
        return 2

    now = datetime.now(timezone.utc)
    allow = load_allowlist(args.allowlist)
    print("Scanning %d packages in %s (cooldown: %g days)" % (len(pkgs), root, args.min_age_days))

    if args.offline:
        osv, osv_ok, times = {pkg_key(p): [] for p in pkgs}, True, [None] * len(pkgs)
    else:
        osv, osv_ok = osv_check(pkgs)
        with ThreadPoolExecutor(max_workers=8) as pool:
            times = list(pool.map(fetch_release_time, pkgs))

    rows = [evaluate(p, osv.get(pkg_key(p), []), t, osv_ok, allow, args.min_age_days, now)
            for p, t in zip(pkgs, times)]
    rows.sort(key=lambda r: ({"FAIL": 0, "WARN": 1, "OK": 2}[r["status"]], r["name"]))

    fail = sum(r["status"] == "FAIL" for r in rows)
    warn = sum(r["status"] == "WARN" for r in rows)
    ok = sum(r["status"] == "OK" for r in rows)
    failed = (fail > 0
              or (args.fail_on_warn and (warn > 0 or unpinned))
              or (args.require_network and not osv_ok))
    meta = {"verdict": "FAILED" if failed else "PASSED", "total": len(rows),
            "fail": fail, "warn": warn, "ok": ok, "min_age_days": args.min_age_days,
            "generated": now.strftime("%Y-%m-%d %H:%M UTC")}
    write_reports(args.out, rows, unpinned, meta)

    for r in rows:
        if r["status"] != "OK":
            print("[%s] %s %s==%s : %s" % (r["status"], r["ecosystem"], r["name"],
                                          r["version"], "; ".join(r["flags"])))
    for u in unpinned:
        print("[WARN] unpinned python dependency: %s" % u["name"])
    print("\nResult: %s  (FAIL=%d WARN=%d OK=%d)" % (meta["verdict"], fail, warn, ok))
    print("Report: %s" % os.path.join(args.out, "report.html"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
