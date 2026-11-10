#!/usr/bin/env python3
"""
Evidence folder validator and manifest generator.
Verifies file naming conventions, SHA-256 hashes, provenance records,
and immutability against SHA256SUMS.

Usage:
  python tools/evidence_manifest.py
  python tools/evidence_manifest.py --dropped E-18,E-22,E-35,E-37,E-38
  python tools/evidence_manifest.py --record <file> --script <path> --cmd <command>
"""

import argparse
import csv
import datetime
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

NAME = re.compile(
    r"^E-(?P<id>\d{2})_(?P<slug>[a-z0-9]+(?:-[a-z0-9]+)*)"
    r"(?:_(?P<variant>[a-z0-9]+(?:-[a-z0-9]+)*))?"
    r"_(?P<date>\d{8})_(?P<commit>[0-9a-f]{7}|na)\.(?P<ext>[a-z0-9]+)$")
FOLDER = re.compile(r"^E-(?P<id>\d{2})_(?P<slug>[a-z0-9]+(?:-[a-z0-9]+)*)$")
SECRET = re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
TEXT = {"txt", "log", "json", "csv", "md", "py", "yaml", "yml"}
IGNORE = {".ds_store", "thumbs.db", "desktop.ini"}

SLUGS = {
    1: "title-approval", 2: "render-region", 3: "backend-payload",
    4: "request-body-logging", 5: "placeholder-benchmark", 6: "full-pipeline-rerun",
    7: "ablation", 8: "phishing-corpus-metrics", 9: "flower-shop-probe",
    10: "scoring-formula-code", 11: "auth-inference-code", 12: "manuscript-figure-audit",
    13: "two-tier-xai-panel", 14: "spf-dkim-drawer-states", 15: "virustotal-reasons-panel",
    16: "threshold-presets", 17: "post-defense-ui-commits", 18: "multitab-memory",
    19: "scan-trigger-ratelimit", 20: "test-set-composition", 21: "model-provenance",
    22: "taglish-test", 23: "uat-data", 24: "threshold-sweep", 25: "citation-check",
    26: "primary-reports", 27: "gmail-use-confirmation", 28: "in-memory-dict-check",
    29: "fr01-fr08-wording", 30: "revised-page-numbers", 31: "repro-package",
    32: "nfr04-sample-size", 33: "inter-rater", 34: "transactional-fpr",
    35: "ph-brand-test", 36: "string-audit", 37: "shortener-unit-tests",
    38: "shortener-test-log",
}
EXPECTED = sorted(SLUGS)

REPORT_IDS = {6, 8}
REPORT_EXEMPT_VARIANTS = {"failed", "raw", "refs"}
REPORT_FIELDS = ("commit", "script", "model_id", "model_loaded", "dataset_sha256", "seed")
TIMESTAMP_KEYS = ("timestamp", "timestamp_utc", "run_at_utc")

SCRIPT_REQUIRED_IDS = {6, 7, 8, 22, 24, 34, 35, 37, 38}
PROV_FIELDS = ["file", "produced_by", "script", "command", "script_sha256", "note"]
KINDS = {"script", "manual", "copy"}


def sha256(p):
    """Computes SHA-256 digest of file at path p."""
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def norm_hash(data):
    """Computes SHA-256 with CRLF normalized to LF for cross-platform consistency."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def git(*args):
    """Executes a git command with timeout handling."""
    try:
        return subprocess.run(["git", *args], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None


def git_available():
    """Checks if git binary is available in the current work tree."""
    r = git("rev-parse", "--is-inside-work-tree")
    return bool(r and r.returncode == 0)


def parse_ids(text):
    """Parses a comma-separated list of evidence IDs."""
    out = set()
    for tok in re.split(r"[,\s]+", text.strip()):
        if not tok:
            continue
        m = re.fullmatch(r"(?i)E-?(\d{1,2})", tok)
        if not m:
            sys.exit(f"ERROR: bad ID in --dropped: {tok!r} (use E-18,E-22)")
        out.add(int(m.group(1)))
    return out


def load_baseline(path):
    """Loads baseline SHA256SUMS file into dictionary."""
    base = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = re.fullmatch(r"([0-9a-f]{64})  (.+)", line.rstrip("\r"))
            if m:
                base[m.group(2)] = m.group(1)
    return base


def load_old_index(path):
    """Reads existing EVIDENCE_INDEX.csv to track provenance changes."""
    old = {}
    if path.is_file():
        with open(path, newline="", encoding="utf-8-sig") as fh:
            rd = csv.DictReader(fh)
            if rd.fieldnames and "produced_by" in rd.fieldnames:
                for r in rd:
                    if (r.get("produced_by") or "").strip():
                        old[r["file"]] = (r["produced_by"], r.get("script", ""), r.get("command", ""), r.get("script_sha256", ""))
    return old


def load_prov(path, errors):
    """Reads PROVENANCE.csv into a dictionary."""
    prov = {}
    if not path.is_file():
        return prov
    with open(path, newline="", encoding="utf-8-sig") as fh:
        rd = csv.DictReader(fh)
        if [(c or "").strip() for c in (rd.fieldnames or [])] != PROV_FIELDS:
            errors.append(f"{path}: header must be {','.join(PROV_FIELDS)} (got {rd.fieldnames})")
            return prov
        for n, r in enumerate(rd, start=2):
            key = (r["file"] or "").strip().replace("\\", "/")
            if not key:
                continue
            if key in prov:
                errors.append(f"{path} line {n}: duplicate provenance row for {key}")
                continue
            prov[key] = {k: (r.get(k) or "").strip() for k in PROV_FIELDS}
    return prov


def load_drive_links(path, errors, warns):
    """Parses optional external drive links mapping."""
    folder_links, file_links = {}, {}
    with open(path, newline="", encoding="utf-8-sig") as fh:
        rd = csv.DictReader(fh)
        need = {"e_id", "folder_link", "file", "file_link"}
        cols = {(c or "").strip() for c in (rd.fieldnames or [])}
        if not need <= cols:
            errors.append(f"{path}: header must be e_id,folder_link,file,file_link (got {rd.fieldnames})")
            return folder_links, file_links
        for n, r in enumerate(rd, start=2):
            eid = (r.get("e_id") or "").strip()
            fl = (r.get("folder_link") or "").strip()
            fn = (r.get("file") or "").strip()
            fk = (r.get("file_link") or "").strip()
            for link in (fl, fk):
                if link and not link.startswith("https://"):
                    warns.append(f"{path} line {n}: link is not https: {link[:60]}")
            if eid and fl:
                if not re.fullmatch(r"E-\d{2}", eid):
                    warns.append(f"{path} line {n}: bad e_id {eid!r}")
                folder_links[eid] = fl
            if fn and fk:
                file_links[fn] = fk
    return folder_links, file_links


def check_report(f, m, errors):
    """Validates structure and model loading status of JSON benchmark reports."""
    rel = str(f)
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except Exception as e:
        errors.append(f"{rel}: not valid JSON ({e})")
        return None
    if not isinstance(data, dict):
        errors.append(f"{rel}: JSON report must be an object")
        return None
    for k in REPORT_FIELDS:
        if k not in data or data[k] in (None, ""):
            errors.append(f"{rel}: report is missing '{k}'")
    if not any(data.get(k) for k in TIMESTAMP_KEYS):
        errors.append(f"{rel}: report is missing a UTC timestamp")
    if "model_loaded" in data and data["model_loaded"] is not True:
        errors.append(f"{rel}: model_loaded is {data['model_loaded']!r}; unloaded runs are invalid")
    c = str(data.get("commit") or "")
    if c and m["commit"] == "na":
        errors.append(f"{rel}: code evidence must name its commit, not 'na'")
    elif c and not c.lower().startswith(m["commit"]):
        errors.append(f"{rel}: 'commit' field ({c[:12]}) does not match filename ({m['commit']})")
    return data


def check_script_row(rel, m, p, errors, warns, git_ok, warned):
    """Verifies that script-produced evidence matches its git history and recorded hash."""
    sp = p["script"]
    if not sp:
        errors.append(f"{rel}: provenance says script but 'script' is empty")
        return
    if Path(sp).is_absolute() or ".." in Path(sp).parts or "\\" in sp:
        errors.append(f"{rel}: script must be a repo-relative path with forward slashes: {sp}")
        return
    if not p["command"]:
        errors.append(f"{rel}: provenance row needs the exact 'command' that was run")
    if not re.fullmatch(r"[0-9a-f]{64}", p["script_sha256"] or ""):
        errors.append(f"{rel}: provenance row needs a 64-hex script_sha256")
        return
    sf = Path(sp)
    if not sf.is_file():
        errors.append(f"{rel}: script not found: {sp}")
        return
    commit = m["commit"]
    if commit == "na":
        if norm_hash(sf.read_bytes()) != p["script_sha256"]:
            warns.append(f"{rel}: script {sp} has changed since this evidence was recorded")
        return
    if not git_ok:
        if not warned.get("git"):
            warns.append("git not available: script hashes were not verified against commits")
            warned["git"] = True
        return
    exists = git("cat-file", "-e", f"{commit}^{{commit}}")
    if exists is None or exists.returncode != 0:
        warns.append(f"{rel}: commit {commit} not found in this repo; script hash not verified")
        return
    blob = git("show", f"{commit}:{sp}")
    if blob is None or blob.returncode != 0:
        errors.append(f"{rel}: {sp} does not exist at commit {commit}")
    elif norm_hash(blob.stdout) != p["script_sha256"]:
        errors.append(f"{rel}: recorded script hash does not match {sp} at commit {commit}")


def record(a):
    """Appends provenance metadata to PROVENANCE.csv."""
    root = Path(a.root)
    path = root / "PROVENANCE.csv"
    kinds = [bool(a.script), bool(a.manual), bool(a.copy_of)]
    if sum(kinds) != 1:
        sys.exit("ERROR: --record needs exactly one of --script (with --cmd), --manual NOTE, --copy-of ORIGINAL")
    row_common = {"script": "", "command": "", "script_sha256": "", "note": ""}
    if a.script:
        sp = Path(a.script)
        if sp.is_absolute() or ".." in sp.parts:
            sys.exit("ERROR: --script must be a repo-relative path")
        if not sp.is_file():
            sys.exit(f"ERROR: script not found: {a.script}")
        if not a.cmd:
            sys.exit("ERROR: --script needs --cmd with the exact command that was run")
        kind = "script"
        row_common.update(script=sp.as_posix(), command=a.cmd, script_sha256=norm_hash(sp.read_bytes()),
                          note=a.note or "")
    elif a.manual:
        kind = "manual"
        row_common["note"] = a.manual
    else:
        kind = "copy"
        row_common["note"] = f"source={a.copy_of}"
    errs = []
    existing = load_prov(path, errs)
    if errs:
        sys.exit("ERROR: " + "; ".join(errs))
    new_rows = []
    for fname in a.record:
        f = Path(fname)
        try:
            key = f.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            sys.exit(f"ERROR: {fname} is not inside {root}/")
        if not f.is_file() or not NAME.match(f.name):
            sys.exit(f"ERROR: {fname} is not an existing, correctly named evidence file")
        if key in existing:
            sys.exit(f"ERROR: {key} already has a provenance row")
        new_rows.append({"file": key, "produced_by": kind, **row_common})
    fresh = not path.is_file()
    with open(path, "a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=PROV_FIELDS, lineterminator="\n")
        if fresh:
            w.writeheader()
        w.writerows(new_rows)
    for r in new_rows:
        print(f"recorded {r['file']}: {kind}" + (f" <- {r['script']} ({r['script_sha256'][:12]})" if kind == "script" else ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="evidence")
    ap.add_argument("--base-url", default="")
    ap.add_argument("--drive-links", default="")
    ap.add_argument("--dropped", default="", help="comma list of dropped IDs, e.g. E-18,E-37")
    ap.add_argument("--require-complete", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--allow-changes", action="store_true")
    ap.add_argument("--allow-missing-provenance", action="store_true")
    rec = ap.add_argument_group("record provenance")
    rec.add_argument("--record", nargs="+", metavar="FILE")
    rec.add_argument("--script", default="")
    rec.add_argument("--cmd", default="")
    rec.add_argument("--manual", default="", metavar="NOTE")
    rec.add_argument("--copy-of", default="", metavar="ORIGINAL")
    rec.add_argument("--note", default="")
    a = ap.parse_args()

    if a.record:
        record(a)
        return

    root = Path(a.root)
    errors, warns, rows, seen = [], [], [], set()
    dropped = parse_ids(a.dropped) if a.dropped else set()
    base = a.base_url.rstrip("/") + "/" if a.base_url else ""
    if not root.is_dir():
        sys.exit(f"ERROR: {root}/ not found. Run from repo root.")

    folder_links, file_links = ({}, {})
    if a.drive_links:
        folder_links, file_links = load_drive_links(a.drive_links, errors, warns)

    sums_path = root / "SHA256SUMS"
    baseline = load_baseline(sums_path)
    old_index = load_old_index(root / "EVIDENCE_INDEX.csv")
    prov = load_prov(root / "PROVENANCE.csv", errors)
    git_ok = git_available()
    warned = {}
    today = datetime.datetime.now(datetime.timezone.utc).date()
    folders_seen, files_seen = set(), set()
    miss_prov = warns if a.allow_missing_provenance else errors

    for folder in sorted(p for p in root.iterdir() if p.is_dir()):
        fm = FOLDER.match(folder.name)
        if not fm:
            errors.append(f"folder name invalid: {folder.name} (expected E-NN_slug)")
            continue
        fid = int(fm["id"])
        folders_seen.add(f"E-{fm['id']}")
        if fid in SLUGS and fm["slug"] != SLUGS[fid]:
            errors.append(f"folder slug wrong: {folder.name}")
        if fid > 38:
            warns.append(f"{folder.name}: ID above E-38")
        files = sorted(p for p in folder.rglob("*")
                       if p.is_file() and p.name.lower() not in IGNORE)
        if not files:
            warns.append(f"empty evidence folder: {folder.name}")
        for f in files:
            rel_root = f.relative_to(root).as_posix()
            m = NAME.match(f.name)
            if not m:
                errors.append(f"file name invalid: {rel_root}")
                continue
            if m["id"] != fm["id"] or m["slug"] != fm["slug"]:
                errors.append(f"file/folder mismatch: {rel_root}")
                continue
            try:
                d = datetime.datetime.strptime(m["date"], "%Y%m%d").date()
                if d > today + datetime.timedelta(days=1):
                    warns.append(f"{rel_root}: date {m['date']} is in the future")
            except ValueError:
                errors.append(f"{rel_root}: {m['date']} is not a real calendar date")
                continue
            if f.stat().st_size == 0:
                errors.append(f"{rel_root}: file is empty")
                continue
            seen.add(fid)
            files_seen.add(rel_root)

            if m["ext"] in TEXT:
                txt = f.read_text(encoding="utf-8", errors="ignore")
                if SECRET.search(txt):
                    warns.append(f"possible secret in {rel_root}")
                if fid == 23 and EMAIL.search(txt):
                    warns.append(f"possible email address in UAT data {rel_root}")
            report = None
            if (fid in REPORT_IDS and m["ext"] == "json"
                    and (m["variant"] or "") not in REPORT_EXEMPT_VARIANTS):
                report = check_report(f, m, errors)

            p = prov.get(rel_root)
            if p is None:
                miss_prov.append(f"{rel_root}: no provenance row")
                p = {"produced_by": "", "script": "", "command": "", "script_sha256": "", "note": ""}
            else:
                kind = p["produced_by"]
                if kind not in KINDS:
                    errors.append(f"{rel_root}: produced_by must be one of {sorted(KINDS)}")
                elif kind == "script":
                    check_script_row(rel_root, m, p, errors, warns, git_ok, warned)
                elif kind == "manual" and not p["note"]:
                    errors.append(f"{rel_root}: manual provenance needs a note")
                elif kind == "copy" and "source=" not in p["note"]:
                    errors.append(f"{rel_root}: copy provenance needs note 'source=<original path>'")
                if kind != "script" and fid in SCRIPT_REQUIRED_IDS and (m["variant"] or "") != "failed":
                    errors.append(f"{rel_root}: E-{fm['id']} must name producing script")
                if report is not None and kind == "script" and str(report.get("script") or "") != p["script"]:
                    errors.append(f"{rel_root}: report 'script' differs from provenance script")

            h = sha256(f)
            rel = f.as_posix()
            rows.append({
                "e_id": f"E-{m['id']}", "slug": m["slug"], "file": rel,
                "variant": m["variant"] or "", "date_utc": m["date"],
                "commit": m["commit"], "bytes": f.stat().st_size, "sha256": h,
                "file_link": file_links.get(f.name) or (base + rel if base else ""),
                "folder_link": folder_links.get(f"E-{m['id']}") or (
                    base.replace("/blob/", "/tree/") + folder.as_posix() + "/" if base else ""),
                "produced_by": p["produced_by"], "script": p["script"],
                "command": p["command"], "script_sha256": p["script_sha256"]})

    for key in sorted(set(prov) - files_seen):
        warns.append(f"PROVENANCE.csv has a row for {key} but no such evidence file")

    cur = {Path(r["file"]).relative_to(root).as_posix(): r["sha256"] for r in rows}
    imm = warns if a.allow_changes else errors
    for path, old in sorted(baseline.items()):
        if path not in cur:
            imm.append(f"IMMUTABLE: {path} was in SHA256SUMS but is now missing")
        elif cur[path] != old:
            imm.append(f"IMMUTABLE: {path} changed since SHA256SUMS was written")
    for r in rows:
        old = old_index.get(r["file"])
        if old and old != (r["produced_by"], r["script"], r["command"], r["script_sha256"]):
            imm.append(f"IMMUTABLE: provenance of {r['file']} changed since last index")

    for eid in sorted(dropped):
        if eid in seen:
            warns.append(f"E-{eid:02d} is marked dropped but has files")
    missing = [f"E-{i:02d}" for i in EXPECTED if i not in seen and i not in dropped]
    dropped_missing = [f"E-{i:02d}" for i in EXPECTED if i not in seen and i in dropped]

    if a.drive_links:
        index_ids = {r["e_id"] for r in rows}
        for eid in sorted(index_ids):
            if not folder_links.get(eid):
                warns.append(f"{eid} has files but no folder link")

    print(f"{len(rows)} files indexed across {len(seen)} evidence IDs.")
    print("No files yet for: " + (", ".join(missing) or "none"))
    if dropped_missing:
        print("Dropped (no files expected): " + ", ".join(dropped_missing))
    for w_ in warns:
        print("WARN:", w_)
    for e in errors:
        print("ERROR:", e)

    if errors:
        print("Nothing written. Resolve errors and re-run.")
        sys.exit(1)

    with open(root / "EVIDENCE_INDEX.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else ["e_id"], lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    with open(sums_path, "w", newline="\n", encoding="utf-8") as fh:
        for r in rows:
            fh.write(f"{r['sha256']}  {Path(r['file']).relative_to(root).as_posix()}\n")
    print(f"Wrote {root}/EVIDENCE_INDEX.csv and {root}/SHA256SUMS.")

    if a.require_complete and missing:
        print(f"ERROR: --require-complete: missing {', '.join(missing)}")
        sys.exit(1)
    if a.strict and warns:
        print(f"ERROR: --strict: {len(warns)} warnings")
        sys.exit(1)


if __name__ == "__main__":
    main()
