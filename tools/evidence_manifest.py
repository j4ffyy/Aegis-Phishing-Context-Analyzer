#!/usr/bin/env python3
"""Validate the evidence folder, then write EVIDENCE_INDEX.csv and SHA256SUMS.

Usage (run from the repo root):
  python tools/evidence_manifest.py                       # validate + index
  python tools/evidence_manifest.py --drive-links drive_links.csv
  python tools/evidence_manifest.py --base-url https://github.com/ORG/REPO/blob/<FULL_SHA>/
  python tools/evidence_manifest.py --dropped E-18,E-22,E-35,E-37,E-38 --require-complete --strict

Record where each evidence file came from (do this right after producing it):
  python tools/evidence_manifest.py --record evidence/E-07_ablation/E-07_ablation_summary_20261110_a1b2c3d.csv \\
      --script tools/run_ablation.py --cmd "python tools/run_ablation.py --seed 42"
  python tools/evidence_manifest.py --record evidence/E-14_.../E-14_..._state-fail_20261109_na.png \\
      --manual "screenshot by human, Gmail test account, state: auth fail"
  python tools/evidence_manifest.py --record evidence/E-05_.../E-05_..._20261106_na.json \\
      --copy-of "backend/tests/evaluation_report.json"

What it checks (plan sections 1, 4.2, 4.3, 4.6, 8):
  * folder name E-NN_slug; file name matches the pattern; file and folder agree
  * slug equals the canonical slug for that ID (plan 4.2); IDs above 38 only need slug == folder
  * the date in the file name is a real calendar date; zero-byte files; possible secrets;
    email addresses in UAT data (E-23)
  * JSON reports for E-06 and E-08 carry commit, script, model_id, model_loaded (must be true),
    dataset_sha256, seed and a UTC timestamp; `commit` matches the file name; `script` matches
    the provenance row
  * PROVENANCE: every evidence file has a row in evidence/PROVENANCE.csv saying whether it came
    from a script (path, command, script hash), by hand (manual) or as a copy of an existing
    file. A script row is verified: the script must exist and its hash must equal the script as
    committed at the file's commit. Run-output IDs (E-06, 07, 08, 22, 24, 34, 35, 37, 38) must
    come from a script
  * IMMUTABILITY: a file in the previous SHA256SUMS must still exist with the same hash, and a
    provenance entry in the previous index must not change (never rename or replace; add v2)
  * drive_links.csv: BOM tolerated, https only, unknown IDs/files reported

Nothing is written if there is any ERROR, so a bad run cannot destroy the baseline.
Exit codes: 0 clean, 1 any ERROR (also --strict with WARN, --require-complete with gaps).
SHA256SUMS paths are relative to evidence/ and use LF line endings, so on any OS:
  cd <copy of evidence/> && sha256sum -c SHA256SUMS
"""
import argparse, csv, datetime, hashlib, json, re, subprocess, sys
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

# Canonical slugs, plan section 4.2.
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

# JSON reports that must be produced by the I-02 guard (plan 4.3). E-05 and E-09 are existing
# evidence and exempt. Variants that mark an invalid run are exempt too.
REPORT_IDS = {6, 8}
REPORT_EXEMPT_VARIANTS = {"failed", "raw", "refs"}
REPORT_FIELDS = ("commit", "script", "model_id", "model_loaded", "dataset_sha256", "seed")
TIMESTAMP_KEYS = ("timestamp", "timestamp_utc", "run_at_utc")

# Evidence that is the output of a run must name the script that produced it.
SCRIPT_REQUIRED_IDS = {6, 7, 8, 22, 24, 34, 35, 37, 38}
PROV_FIELDS = ["file", "produced_by", "script", "command", "script_sha256", "note"]
KINDS = {"script", "manual", "copy"}


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def norm_hash(data):
    """Hash with CRLF folded to LF so Windows checkouts (autocrlf) compare equal to git blobs."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def git(*args):
    try:
        return subprocess.run(["git", *args], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None


def git_available():
    r = git("rev-parse", "--is-inside-work-tree")
    return bool(r and r.returncode == 0)


def parse_ids(text):
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
    base = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = re.fullmatch(r"([0-9a-f]{64})  (.+)", line.rstrip("\r"))
            if m:
                base[m.group(2)] = m.group(1)
    return base


def load_old_index(path):
    """file -> (produced_by, script, command, script_sha256) from the previous EVIDENCE_INDEX.csv."""
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
    folder_links, file_links = {}, {}
    # utf-8-sig drops the BOM that Excel adds, which would otherwise rename e_id to ﻿e_id
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
    """Validate an I-02 style JSON report. Returns the parsed dict (or None)."""
    rel = str(f)
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        errors.append(f"{rel}: not valid JSON ({e})")
        return None
    if not isinstance(data, dict):
        errors.append(f"{rel}: JSON report must be an object")
        return None
    for k in REPORT_FIELDS:
        if k not in data or data[k] in (None, ""):
            errors.append(f"{rel}: report is missing '{k}' (plan 4.3)")
    if not any(data.get(k) for k in TIMESTAMP_KEYS):
        errors.append(f"{rel}: report is missing a UTC timestamp (one of {', '.join(TIMESTAMP_KEYS)})")
    if "model_loaded" in data and data["model_loaded"] is not True:
        errors.append(f"{rel}: model_loaded is {data['model_loaded']!r}; a non-loaded run is "
                      f"invalid evidence, rename it with variant 'failed'")
    c = str(data.get("commit") or "")
    if c and m["commit"] == "na":
        errors.append(f"{rel}: code evidence must name its commit, not 'na'")
    elif c and not c.lower().startswith(m["commit"]):
        errors.append(f"{rel}: 'commit' field ({c[:12]}) does not match the file name ({m['commit']})")
    return data


def check_script_row(rel, m, p, errors, warns, git_ok, warned):
    """Verify a produced_by=script provenance row."""
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
        errors.append(f"{rel}: provenance row needs a 64-hex script_sha256 (use --record)")
        return
    sf = Path(sp)
    if not sf.is_file():
        errors.append(f"{rel}: script not found: {sp}")
        return
    commit = m["commit"]
    if commit == "na":
        if norm_hash(sf.read_bytes()) != p["script_sha256"]:
            warns.append(f"{rel}: script {sp} has changed since this evidence was recorded (commit is 'na', "
                         f"cannot verify against a commit)")
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
        errors.append(f"{rel}: {sp} does not exist at commit {commit}; the script that produced "
                      f"this evidence was not committed (commit it, then re-run)")
    elif norm_hash(blob.stdout) != p["script_sha256"]:
        errors.append(f"{rel}: recorded script hash does not match {sp} at commit {commit}; "
                      f"the evidence was produced with a different (uncommitted?) version of the script")


def record(a):
    """Append provenance rows (never edits existing rows)."""
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
            sys.exit(f"ERROR: {key} already has a provenance row (rows are never edited; add a v2 file)")
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
    ap.add_argument("--require-complete", action="store_true",
                    help="exit 1 if any non-dropped ID in E-01..E-38 has no files")
    ap.add_argument("--strict", action="store_true", help="exit 1 on any WARN")
    ap.add_argument("--allow-changes", action="store_true",
                    help="human only: accept changed/removed files and changed provenance against "
                         "the previous SHA256SUMS/index (downgrades the immutability ERROR to a WARN)")
    ap.add_argument("--allow-missing-provenance", action="store_true",
                    help="human only: downgrade 'no provenance row' to a WARN (transition use)")
    rec = ap.add_argument_group("record provenance")
    rec.add_argument("--record", nargs="+", metavar="FILE", help="evidence file(s) to add a provenance row for")
    rec.add_argument("--script", default="", help="repo-relative script that produced the file(s)")
    rec.add_argument("--cmd", default="", help="exact command line that was run")
    rec.add_argument("--manual", default="", metavar="NOTE", help="file made by hand (screenshot, approval, ...)")
    rec.add_argument("--copy-of", default="", metavar="ORIGINAL", help="copy of an existing file (original path)")
    rec.add_argument("--note", default="", help="optional note for a script row")
    a = ap.parse_args()

    if a.record:
        record(a)
        return

    root = Path(a.root)
    errors, warns, rows, seen = [], [], [], set()
    dropped = parse_ids(a.dropped) if a.dropped else set()
    base = a.base_url.rstrip("/") + "/" if a.base_url else ""
    if not root.is_dir():
        sys.exit(f"ERROR: {root}/ not found. Run from the repo root.")

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
            errors.append(f"folder slug wrong: {folder.name} (plan 4.2 says E-{fm['id']}_{SLUGS[fid]})")
        if fid > 38:
            warns.append(f"{folder.name}: ID above E-38; make sure it is in the Annex A table and plan 4.2 first")
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
                    warns.append(f"{rel_root}: date {m['date']} is in the future (UTC)")
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
                    warns.append(f"possible secret in {rel_root}: remove before commit")
                if fid == 23 and EMAIL.search(txt):
                    warns.append(f"possible email address in UAT data {rel_root}: anonymize")
            report = None
            if (fid in REPORT_IDS and m["ext"] == "json"
                    and (m["variant"] or "") not in REPORT_EXEMPT_VARIANTS):
                report = check_report(f, m, errors)

            # ---- provenance
            p = prov.get(rel_root)
            if p is None:
                miss_prov.append(f"{rel_root}: no provenance row (run --record with --script/--manual/--copy-of)")
                p = {"produced_by": "", "script": "", "command": "", "script_sha256": "", "note": ""}
            else:
                kind = p["produced_by"]
                if kind not in KINDS:
                    errors.append(f"{rel_root}: produced_by must be one of {sorted(KINDS)} (got {kind!r})")
                elif kind == "script":
                    check_script_row(rel_root, m, p, errors, warns, git_ok, warned)
                elif kind == "manual" and not p["note"]:
                    errors.append(f"{rel_root}: manual provenance needs a note (who made it, how)")
                elif kind == "copy" and "source=" not in p["note"]:
                    errors.append(f"{rel_root}: copy provenance needs note 'source=<original path>' (plan 4.1)")
                if kind != "script" and fid in SCRIPT_REQUIRED_IDS and (m["variant"] or "") != "failed":
                    errors.append(f"{rel_root}: E-{fm['id']} is run output and must name the script that "
                                  f"produced it (produced_by=script)")
                if report is not None and kind == "script" and str(report.get("script") or "") != p["script"]:
                    errors.append(f"{rel_root}: report 'script' ({report.get('script')}) differs from "
                                  f"provenance script ({p['script']})")

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

    # Immutability against the previous SHA256SUMS and index.
    cur = {Path(r["file"]).relative_to(root).as_posix(): r["sha256"] for r in rows}
    imm = warns if a.allow_changes else errors
    for path, old in sorted(baseline.items()):
        if path not in cur:
            imm.append(f"IMMUTABLE: {path} was in SHA256SUMS but is now missing or renamed "
                       f"(never rename or delete; supersede with a v2 variant)")
        elif cur[path] != old:
            imm.append(f"IMMUTABLE: {path} changed since SHA256SUMS was written "
                       f"(never overwrite; add a v2 variant and keep the old file)")
    for r in rows:
        old = old_index.get(r["file"])
        if old and old != (r["produced_by"], r["script"], r["command"], r["script_sha256"]):
            imm.append(f"IMMUTABLE: provenance of {r['file']} changed since the last index "
                       f"(was {old[0]} {old[1]} {old[3][:12]}); add a v2 file instead of editing the row")

    for eid in sorted(dropped):
        if eid in seen:
            warns.append(f"E-{eid:02d} is marked dropped but has files; remove it from --dropped or from the matrix")
    missing = [f"E-{i:02d}" for i in EXPECTED if i not in seen and i not in dropped]
    dropped_missing = [f"E-{i:02d}" for i in EXPECTED if i not in seen and i in dropped]

    if a.drive_links:
        index_ids = {r["e_id"] for r in rows}
        for eid in sorted(index_ids):
            if not folder_links.get(eid):
                warns.append(f"{eid} has files but no folder link in {a.drive_links}")
        for eid in sorted(set(folder_links) - folders_seen):
            warns.append(f"{a.drive_links}: folder link for {eid} but no such evidence folder")
        for fn in sorted(set(file_links) - {Path(r['file']).name for r in rows}):
            warns.append(f"{a.drive_links}: file link for {fn} but no such evidence file")

    print(f"{len(rows)} files indexed across {len(seen)} evidence IDs.")
    print("No files yet for: " + (", ".join(missing) or "none"))
    if dropped_missing:
        print("Dropped (no files expected): " + ", ".join(dropped_missing))
    for w_ in warns:
        print("WARN:", w_)
    for e in errors:
        print("ERROR:", e)

    if errors:
        print("Nothing written (index and SHA256SUMS left as they were). Fix the ERRORs and re-run.")
        sys.exit(1)

    with open(root / "EVIDENCE_INDEX.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else ["e_id"], lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    # newline="\n": CRLF would make `sha256sum -c` on Linux report every file as missing.
    with open(sums_path, "w", newline="\n", encoding="utf-8") as fh:
        for r in rows:
            fh.write(f"{r['sha256']}  {Path(r['file']).relative_to(root).as_posix()}\n")
    print(f"Wrote {root}/EVIDENCE_INDEX.csv and {root}/SHA256SUMS.")

    if a.require_complete and missing:
        print(f"ERROR: --require-complete: no files for {', '.join(missing)}")
        sys.exit(1)
    if a.strict and warns:
        print(f"ERROR: --strict: {len(warns)} WARN(s) must be cleared")
        sys.exit(1)


if __name__ == "__main__":
    main()
