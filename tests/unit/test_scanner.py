"""Unit tests for the scanner's detection, gating, version policy, outputs and report merging.
External tools are never executed: Scan.run is replaced by a fake that returns scripted results."""
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scanner"))
import sawone_scan as ds  # noqa: E402
import merge_reports  # noqa: E402

FIX = ROOT / "tests" / "fixtures"


def make_scan(tmp_path, ws, cfg=None, docker=True):
    work = tmp_path / "ws"
    shutil.copytree(ws, work)
    reports = work / "sawone-reports"
    reports.mkdir()
    s = ds.Scan.__new__(ds.Scan)
    # replicate __init__ without probing a real Docker daemon
    s.ws, s.reports, s.cfg, s.plan_only = work, reports, ds.deep_merge(ds.DEFAULTS, cfg or {}), False
    s.stages, s.pinned, s.tool_versions = [], {}, {}
    s.docker_ok = docker
    s.sev = [x.strip().upper() for x in s.cfg["severity"].split(",")]
    s.network = "devsecops-test"
    s.only = set(s.cfg.get("only") or [])
    s.prebuilt = s.cfg.get("image")
    s.lock = s.cfg.get("tools_lock")
    s.images, s.target, s.iast_attached = [], None, False
    s.findings, s.policy, s.cache_dir, s.baseline_state = [], ds.F.Policy(), None, None
    s.base_sha = s.cfg.get("base_sha")
    for d in ["sarif", "raw", "logs"]:
        (reports / d).mkdir(exist_ok=True)
    s.detect()
    return s


class FakeRun:
    """Scripted replacement for Scan.run: rules are (predicate(cmd) -> (code, out, side_effect))."""
    def __init__(self, scan, rules):
        self.scan, self.rules, self.calls = scan, rules, []

    def __call__(self, cmd, log_name=None, timeout=3600, quiet=False, stdout_file=None, env=None):
        self.calls.append(cmd)
        for match, code, out, effect in self.rules:
            if match(cmd):
                if effect:
                    effect(cmd)
                if log_name:  # same layout as the real Scan.run log: command, output, exit code
                    (self.scan.reports / "logs" / f"{log_name}.log").write_text(
                        " ".join(map(str, cmd)) + "\n\n" + out + f"\n\n[exit code: {code}]\n")
                return code, out
        if log_name:
            (self.scan.reports / "logs" / f"{log_name}.log").write_text(" ".join(map(str, cmd)) + "\n\n\n[exit code: 0]\n")
        return 0, ""


def status(scan, stage, tool_prefix=""):
    return [s["status"] for s in scan.stages if s["stage"] == stage and s["tool"].startswith(tool_prefix)]


# ------------------------------------------------------------------ detection
def test_detects_python_flask_fixture(tmp_path):
    s = make_scan(tmp_path, FIX / "python-flask")
    inv = s.inv
    assert "python" in inv["languages"]
    assert "flask" in inv["frameworks"]
    assert inv["dockerfiles"] == ["Dockerfile"]
    assert inv["openapi"] == "openapi.yaml"
    assert "p/flask" in s.semgrep_configs() and "p/python" in s.semgrep_configs()


def test_helm_templates_not_treated_as_plain_manifests(tmp_path):
    s = make_scan(tmp_path, FIX / "k8s-helm")
    assert s.inv["helm_charts"] == ["chart"]
    assert s.inv["kubernetes"] == ["manifests/deployment.yaml"]


def test_terraform_only_needs_no_sca_tools(tmp_path):
    s = make_scan(tmp_path, FIX / "terraform-aws")
    tools = s.needed_tools()
    assert "osv" not in tools and "zap" not in tools
    assert "trivy" in tools and "checkov" in tools


def test_only_filter_limits_tools(tmp_path):
    s = make_scan(tmp_path, FIX / "python-flask", {"only": ["secrets"]})
    assert s.needed_tools() == ["gitleaks", "trufflehog"]


def test_prebuilt_image_enables_runtime_stages_without_dockerfile(tmp_path):
    s = make_scan(tmp_path, FIX / "terraform-aws", {"only": ["dast", "runtime"], "image": "ghcr.io/x/app@sha256:" + "a" * 64})
    assert set(s.needed_tools()) >= {"zap", "curl", "waf"}


def test_missing_lockfile_is_reported(tmp_path):
    work = tmp_path / "src"
    shutil.copytree(FIX / "node-express", work)
    (work / "package-lock.json").unlink()
    s = make_scan(tmp_path, work)
    assert s.lockfile_gaps() == ["package.json"]
    s2 = make_scan(tmp_path / "b", FIX / "node-express")
    assert s2.lockfile_gaps() == []


# ------------------------------------------------------------------ version policy
def test_unresolvable_tool_is_an_error_not_a_tag_fallback(tmp_path):
    s = make_scan(tmp_path, FIX / "terraform-aws")
    def digest_for(cmd):
        return cmd[:3] == ["docker", "image", "inspect"]
    s.run = FakeRun(s, [
        (lambda c: c[:2] == ["docker", "pull"] and "trivy" in c[-1], 1, "toomanyrequests: rate limit", None),
        (lambda c: digest_for(c) and "gitleaks" in c[-1], 0, "zricethezav/gitleaks@sha256:" + "3" * 64, None),
        (lambda c: digest_for(c), 0, "", None),   # every other image: no digest available
    ])
    assert s.update_tools() is False
    errs = {x["tool"]: x["reason"] for x in s.stages if x["status"] == "error"}
    assert "rate limit" in errs["resolve trivy"]
    assert "no immutable digest" in errs["resolve checkov"]   # never silently falls back to the :latest tag
    assert s.pinned == {"gitleaks": "zricethezav/gitleaks@sha256:" + "3" * 64}


def test_lock_missing_tool_is_an_error(tmp_path):
    s = make_scan(tmp_path, FIX / "terraform-aws", {"tools_lock": {"images": {"gitleaks": "g@sha256:" + "1" * 64}, "pip": {}}})
    s.run = FakeRun(s, [])
    assert s.update_tools() is False
    assert any("missing from the tool lock" in x["reason"] for x in s.stages)


def test_lock_digest_is_used_verbatim(tmp_path):
    lock = {"images": {t: f"{t}@sha256:{'2' * 64}" for t in ds.IMAGES}, "pip": {}}
    s = make_scan(tmp_path, FIX / "terraform-aws", {"tools_lock": lock, "self_update": False})
    s.run = FakeRun(s, [])
    assert s.update_tools() is True
    assert s.pinned["trivy"] == f"trivy@sha256:{'2' * 64}"


# ------------------------------------------------------------------ gates vs errors
def test_semgrep_clean_exit_without_output_passes(tmp_path):
    s = make_scan(tmp_path, FIX / "terraform-aws")
    s.run = FakeRun(s, [(lambda c: c[0] == "semgrep", 0, "", None)])
    s.scan_sast()
    assert status(s, "sast") == ["passed"]


def test_semgrep_crash_is_an_error(tmp_path):
    s = make_scan(tmp_path, FIX / "python-flask")
    s.run = FakeRun(s, [(lambda c: c[0] == "semgrep", 2, "Fatal error: invalid rule", None)])
    s.scan_sast()
    assert status(s, "sast") == ["error"]


def test_semgrep_error_findings_fail_the_gate(tmp_path):
    s = make_scan(tmp_path, FIX / "python-flask")

    def write(cmd):
        out = [a.split("=", 1)[1] for a in cmd if a.startswith("--json-output=")][0]
        Path(out).write_text(json.dumps({"results": [{"extra": {"severity": "ERROR"}}, {"extra": {"severity": "WARNING"}}]}))
    s.run = FakeRun(s, [(lambda c: c[0] == "semgrep", 0, "", write)])
    s.scan_sast()
    assert status(s, "sast") == ["failed"]
    assert "1 ERROR / 2 total" in s.stages[-1]["findings"]


def test_checkov_without_report_is_an_error(tmp_path):
    s = make_scan(tmp_path, FIX / "terraform-aws", {"skip": ["trivy"]})
    s.run = FakeRun(s, [(lambda c: "checkov" in " ".join(c), 0, "unexpected crash", None)])
    s.scan_iac()
    assert status(s, "iac", "Checkov") == ["error"]


def test_osv_unexpected_exit_is_an_error(tmp_path):
    s = make_scan(tmp_path, FIX / "node-express", {"skip": ["trivy"]})
    s.run = FakeRun(s, [(lambda c: "osv" in " ".join(c), 127, "exec format error", None)])
    s.scan_sca()
    assert status(s, "sca", "OSV") == ["error"]


def test_defectdojo_requires_https_and_both_values(tmp_path, monkeypatch):
    s = make_scan(tmp_path, FIX / "terraform-aws")
    monkeypatch.setenv("DEFECTDOJO_URL", "http://dojo.example")
    monkeypatch.setenv("DEFECTDOJO_TOKEN", "x")
    s.defectdojo()
    assert status(s, "tracking") == ["error"]
    monkeypatch.delenv("DEFECTDOJO_TOKEN")
    s.defectdojo()
    assert status(s, "tracking")[-1] == "error"
    monkeypatch.delenv("DEFECTDOJO_URL")
    s.defectdojo()
    assert status(s, "tracking")[-1] == "skipped"


def test_defectdojo_auth_failure_is_reported(tmp_path):
    reports = tmp_path / "r"
    (reports / "sarif").mkdir(parents=True)
    (reports / "sarif" / "a.sarif").write_text("{}")
    calls = []

    def runner(cmd, **kw):
        calls.append(cmd)
        return 22, '{"detail":"Invalid token."} 401'
    ok, total, err = ds.import_reports(reports, "https://dojo", "t", "p", "e", runner)
    assert err and "401" in err and ok == 0


# ------------------------------------------------------------------ outputs
def _summary(stages, enforce=True):
    return {"repository": "r", "enforce": enforce, "severity": ["HIGH"], "stages": stages, "inventory": {}, "tools": {}}


def test_exit_codes(tmp_path):
    passed = [{"stage": "sast", "tool": "Semgrep", "status": "passed", "gate": True}]
    failed = [{"stage": "sast", "tool": "Semgrep", "status": "failed", "gate": True}]
    errored = failed + [{"stage": "sca", "tool": "Trivy", "status": "error", "gate": True, "reason": "boom"}]
    report_only = [{"stage": "sca", "tool": "OSV", "status": "report", "gate": False}]
    for i, (stages, enforce, want) in enumerate([(passed, True, 0), (failed, True, 1), (errored, True, 2),
                                                 (failed, False, 0), (report_only, True, 0)]):
        d = tmp_path / f"case{i}"
        d.mkdir()
        assert ds.render_outputs(d, _summary(stages, enforce)) == want, f"case {i}"


def test_junit_marks_failures_errors_and_skips(tmp_path):
    stages = [{"stage": "sast", "tool": "Semgrep", "status": "failed", "gate": True, "findings": "3 ERROR"},
              {"stage": "sca", "tool": "Trivy", "status": "error", "gate": True, "reason": "db"},
              {"stage": "dast", "tool": "—", "status": "skipped", "gate": False, "reason": "no image"}]
    ds.render_outputs(tmp_path, _summary(stages))
    junit = (tmp_path / "junit.xml").read_text()
    assert 'failures="1"' in junit and 'errors="1"' in junit
    assert "<failure" in junit and "<error" in junit and "<skipped" in junit


def test_pdf_is_generated_even_with_missing_inputs(tmp_path):
    pytest.importorskip("weasyprint")
    ds.render_outputs(tmp_path, _summary([{"stage": "secrets", "tool": "Gitleaks", "status": "passed", "gate": True}]))
    assert (tmp_path / "security-report.pdf").stat().st_size > 1000


# ------------------------------------------------------------------ merging
def _job_report(base, name, stages):
    d = base / name
    (d / "sarif").mkdir(parents=True)
    (d / "sarif" / "tool.sarif").write_text('{"runs": []}')
    (d / "summary.json").write_text(json.dumps(_summary(stages)))
    return d


def test_merge_combines_jobs_and_flags_crashed_job(tmp_path):
    a = _job_report(tmp_path, "reports-secrets", [{"stage": "secrets", "tool": "Gitleaks", "status": "passed", "gate": True}])
    b = _job_report(tmp_path, "reports-sast", [{"stage": "sast", "tool": "Semgrep", "status": "failed", "gate": True}])
    jobs = {"secrets": {"result": "success"}, "sast": {"result": "failure"}, "iac": {"result": "failure"}}
    job_stage = {"secrets": "reports-secrets", "sast": "reports-sast", "iac": "reports-iac"}
    code = merge_reports.merge(tmp_path / "merged", [a, b, tmp_path / "missing"], jobs, {"signed": "yes"}, job_stage)
    merged = json.loads((tmp_path / "merged" / "summary.json").read_text())
    tools = [(s["stage"], s["status"]) for s in merged["stages"]]
    assert ("secrets", "passed") in tools and ("sast", "failed") in tools
    # iac job failed without a report: must surface as an error, not vanish
    assert ("pipeline", "error") in tools
    assert code == 2
    assert merged["release"] == {"signed": "yes"}
    # same-named SARIF files from different jobs must not overwrite each other
    assert len(list((tmp_path / "merged" / "sarif").glob("*.sarif"))) == 2


def test_merge_flags_missing_expected_part(tmp_path):
    a = _job_report(tmp_path, "devsecops-part-secrets",
                    [{"stage": "secrets", "tool": "Gitleaks", "status": "passed", "gate": True}])
    code = merge_reports.merge(tmp_path / "merged", [a], expect=["devsecops-part-secrets", "devsecops-part-sast"])
    merged = json.loads((tmp_path / "merged" / "summary.json").read_text())
    errs = [s for s in merged["stages"] if s["status"] == "error"]
    assert len(errs) == 1 and "devsecops-part-sast" in errs[0]["tool"]
    assert code == 2


def test_merge_all_parts_present_passes(tmp_path):
    a = _job_report(tmp_path, "devsecops-part-secrets",
                    [{"stage": "secrets", "tool": "Gitleaks", "status": "passed", "gate": True}])
    assert merge_reports.merge(tmp_path / "merged", [a], expect=["devsecops-part-secrets"]) == 0


def test_merge_job_stage_judges_only_listed_jobs(tmp_path):
    a = _job_report(tmp_path, "p-part-sast", [{"stage": "sast", "tool": "Semgrep", "status": "failed", "gate": True}])
    jobs = {"gates": {"result": "failure"}, "publish": {"result": "failure"}, "provenance": {"result": "skipped"}}
    code = merge_reports.merge(tmp_path / "m", [a], jobs, None, {"publish": None, "provenance": None},
                               expect=["p-part-sast"])
    merged = json.loads((tmp_path / "m" / "summary.json").read_text())
    errs = [s["tool"] for s in merged["stages"] if s["status"] == "error"]
    # the gates matrix failed because a gate failed (its report exists) -> not an error;
    # publishing failed and produces no report -> an error
    assert errs == ["job publish"]
    assert code == 2
