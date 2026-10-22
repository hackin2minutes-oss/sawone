#!/usr/bin/env python3
"""
Merge the reports of several scanner runs (one per pipeline job) into one report set,
then write the combined summary, JUnit and PDF.

  merge_reports.py --out merged reports-secrets reports-sast ... [--jobs needs.json] [--release release.json]

--jobs     JSON of the workflow's job results (GitHub: toJSON(needs)). A job that FAILED or was
           CANCELLED without producing a summary becomes an explicit scanner error, so a crashed
           job can never look like a clean scan.
--expect   comma list of report part names (directory names) that must exist; a missing one is an error.
--release  JSON with supply-chain and release facts (image, digest, signed, attested, provenance, deploy).
Exit code follows render_outputs: 0 passed / report-only, 1 gate failed, 2 scanner error.
"""
import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sawone_scan import STAGES, load_json, render_outputs  # noqa: E402

PRE_EXISTING = "all {n} blocking finding(s) already exist on the base branch (not introduced by this change)"


def apply_new_only(stages, findings, base_fps):
    """Pull-request gating: a failed gate whose every blocking finding already exists on the base
    branch passes, with a note. Gates that cannot list their findings (exit-code tools) are untouched."""
    changed = 0
    for row in stages:
        if row["status"] != "failed" or not row.get("gate", True):
            continue
        mine = [f for f in findings if f.get("stage") == row["stage"] and f.get("tool") == row["tool"] and f.get("gating")]
        if not mine:
            continue
        new = [f for f in mine if f["fingerprint"] not in base_fps]
        if new:
            row["findings"] = f"{row.get('findings', '')} · {len(new)} new in this change".lstrip(" ·")
        else:
            row["status"] = "passed"
            row["pr_preexisting"] = True   # still a gap for compliance evidence, just not this PR's fault
            row["findings"] = f"{row.get('findings', '')} · " + PRE_EXISTING.format(n=len(mine))
            changed += 1
    return changed


def merge(out: Path, sources, jobs=None, release=None, job_stage=None, expect=None, base_findings=None, pr_gate="all",
          previous_findings=None, unchanged=None, languages=None):
    out.mkdir(parents=True, exist_ok=True)
    for d in ["sarif", "raw", "logs"]:
        (out / d).mkdir(exist_ok=True)
    merged = {"stages": [], "inventory": {}, "tools": {}, "enforce": True, "severity": None, "repository": None}
    seen_sources = set()
    blocking, findings = [], []
    for src in sources:
        src = Path(src)
        summ = load_json(src / "summary.json")
        if not summ:
            continue
        tag = src.name
        seen_sources.add(tag)
        merged["stages"] += summ.get("stages", [])
        if not merged["inventory"] and summ.get("inventory"):
            merged["inventory"] = summ["inventory"]
        merged["tools"].update({k: v for k, v in (summ.get("tools") or {}).items() if v})
        merged["enforce"] = merged["enforce"] and summ.get("enforce", True)
        merged["severity"] = merged["severity"] or summ.get("severity")
        merged["repository"] = merged["repository"] or summ.get("repository")
        if summ.get("options") and not merged.get("options"):
            merged["options"] = summ["options"]
        for f in (src / "sarif").glob("*.sarif"):
            dest = out / "sarif" / f.name
            if dest.exists():
                dest = out / "sarif" / f"{tag}-{f.name}"
            shutil.copy(f, dest)
        if (src / "raw").is_dir():
            shutil.copytree(src / "raw", out / "raw" / tag, dirs_exist_ok=True)
        if (src / "logs").is_dir():
            shutil.copytree(src / "logs", out / "logs" / tag, dirs_exist_ok=True)
        for name in ["zap.json", "zap-full.json", "zap-api.json", "waf-results.txt", "tools.json", "inventory.json"]:
            if (src / name).exists() and not (out / name).exists():
                shutil.copy(src / name, out / name)
        findings += load_json(src / "findings.json") or []
        if (src / "trivy-image-blocking.txt").exists():
            blocking.append((src / "trivy-image-blocking.txt").read_text())
    (out / "trivy-image-blocking.txt").write_text("".join(blocking))
    # job-level results: a failed/cancelled job with no summary is an error, never silence
    job_rows = []
    for job, res in (jobs or {}).items():
        result = (res or {}).get("result", "unknown")
        job_rows.append({"job": job, "result": result})
        # job_stage says what each job is accountable for: a report part name (a failure is an error only
        # if that part is missing — a failed gate still leaves its report), None (the job produces no
        # report, e.g. publishing: any failure is an error). Jobs not listed are shown but not judged;
        # matrix jobs are judged through --expect instead.
        if job_stage is None:
            judged, produced = True, False
        elif job in job_stage:
            judged, produced = True, job_stage[job] is not None and job_stage[job] in seen_sources
        else:
            judged, produced = False, True
        if judged and result in ("failure", "cancelled") and not produced:
            merged["stages"].append({"stage": "pipeline", "tool": f"job {job}", "status": "error", "gate": True,
                                     "reason": f"job {result} before producing a report", "findings": ""})
    # every report part the pipeline planned must be present: a matrix leg that died early
    # leaves no artifact, and that must read as an error, not as a stage that never existed
    for name in expect or []:
        if name not in seen_sources:
            merged["stages"].append({"stage": "pipeline", "tool": f"part {name}", "status": "error", "gate": True,
                                     "reason": "expected report part is missing (job crashed, was cancelled or "
                                               "uploaded nothing)", "findings": ""})
    # pull requests: stages the change cannot affect were not run (incremental scan)
    for st in unchanged or []:
        merged["stages"].append({"stage": st, "tool": "—", "status": "skipped", "gate": False, "findings": "",
                                 "reason": "not affected by this change (no relevant files changed); the base "
                                           "branch's results apply"})
    # every part loads the same baseline and risk feeds: keep one policy row per tool (an error wins)
    pol, rows = {}, []
    for row in merged["stages"]:
        if row["stage"] != "policy":
            rows.append(row)
        elif row["tool"] not in pol or row["status"] == "error":
            pol[row["tool"]] = row
    merged["stages"] = rows + list(pol.values())
    (out / "findings.json").write_text(json.dumps(findings, indent=1))
    if base_findings is not None:
        base_fps = {f["fingerprint"] for f in base_findings if f.get("fingerprint")}
        merged["pr"] = {"base_fingerprints": sorted(base_fps), "gate": pr_gate}
        if pr_gate == "new":
            n = apply_new_only(merged["stages"], findings, base_fps)
            merged["pr"]["note"] = (f"PR gate: only findings new in this change block; {n} gate(s) passed because "
                                    "their findings already exist on the base branch (tracked there, not here).")
    elif pr_gate == "new":
        merged["pr"] = {"gate": pr_gate, "note": "PR gate 'new' requested, but no base-branch report was available, "
                                                 "so every finding is treated as new."}
    order = {s: i for i, s in enumerate(["pipeline", "scanner", "policy"] + STAGES)}
    merged["stages"].sort(key=lambda s: order.get(s["stage"], 99))
    merged["jobs"] = job_rows
    if release:
        merged["release"] = release
    merged["severity"] = merged["severity"] or ["HIGH", "CRITICAL"]
    merged["generated"] = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
    if previous_findings:
        merged["previous_findings"] = str(previous_findings)
    if languages:
        merged.setdefault("options", {})["languages"] = languages
    if merged["tools"]:
        (out / "tools.json").write_text(json.dumps(merged["tools"], indent=2))
    return render_outputs(out, merged)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--jobs", help="JSON file of job results (toJSON(needs))")
    ap.add_argument("--job-stage", help="JSON map: job id -> report part it uploads, or null for jobs that produce none")
    ap.add_argument("--release", help="JSON file of release/supply-chain facts")
    ap.add_argument("--expect", default="", help="comma list of report part names that must be present")
    ap.add_argument("--base-findings", help="findings.json of the base branch (pull requests)")
    ap.add_argument("--pr-gate", choices=["new", "all"], default="all")
    ap.add_argument("--previous-findings", help="findings-consolidated.json of the previous report (first-seen, trend, SLA)")
    ap.add_argument("--unchanged", default="", help="comma list of stages skipped because the change cannot affect them")
    ap.add_argument("--languages", default="", help="report languages, e.g. en,ar (overrides the scan config)")
    ap.add_argument("sources", nargs="*")
    a = ap.parse_args()
    jobs = load_json(a.jobs) if a.jobs else None
    job_stage = load_json(a.job_stage) if a.job_stage else None
    release = load_json(a.release) if a.release else None
    expect = [x.strip() for x in a.expect.split(",") if x.strip()]
    base = load_json(a.base_findings) if a.base_findings else None
    langs = [x.strip() for x in a.languages.split(",") if x.strip() in ("en", "ar")]
    sys.exit(merge(Path(a.out), a.sources, jobs, release, job_stage, expect, base, a.pr_gate,
                   a.previous_findings if a.previous_findings and Path(a.previous_findings).exists() else None,
                   [x.strip() for x in a.unchanged.split(",") if x.strip()], langs or None))


if __name__ == "__main__":
    main()
