"""DevSecOps phases: selection, per-phase status, merge, report, summary, dashboard, workflow plan step."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scanner"))
sys.path.insert(0, str(ROOT / "tests" / "unit"))
import dashboard  # noqa: E402
import merge_reports  # noqa: E402
import phases as PH  # noqa: E402
import report  # noqa: E402
import sawone_scan as ds  # noqa: E402
from test_scanner import FIX, FakeRun, make_scan  # noqa: E402


def test_every_stage_has_a_phase_and_parse_validates():
    assert set(ds.STAGES) <= set(PH.STAGE_PHASE)
    assert PH.parse("") == PH.PHASES and PH.parse("all") == PH.PHASES
    assert PH.parse("Build, plan") == ["plan", "build"]                     # case, spaces, lifecycle order
    with pytest.raises(ValueError, match="unknown phase"):
        PH.parse("plan,coding")


def test_phase_status_reflects_the_run():
    st = [{"stage": "threat-model", "status": "passed", "gate": True},
          {"stage": "secrets", "status": "failed", "gate": True},
          {"stage": "sca", "status": "error", "gate": True},
          {"stage": "runtime", "status": "skipped", "gate": False}]
    s = PH.status(st, ["plan", "code", "build"])
    assert s == {"plan": "passed", "code": "failed", "build": "error", "test": "notsel", "release": "error",
                 "deploy": "elsewhere", "operate": "notsel", "monitor": "elsewhere"}
    ok = PH.status([{"stage": "sast", "status": "passed", "gate": True}])
    assert ok["release"] == "passed" and ok["test"] == "skipped"


def test_the_scanner_skips_unselected_phases_and_says_why(tmp_path):
    s = make_scan(tmp_path, FIX / "python-flask", {"phases": ["code"]})
    s.run = FakeRun(s, [(lambda c: True, 0, "leaks found: 0", None)])
    s.update_tools = lambda: True
    s.prepare_policy = lambda: None
    s.cleanup = lambda: None
    s.write_outputs = lambda: 0
    s.docker_ok = True
    s.main()
    rows = {r["stage"]: r for r in s.stages}
    assert rows["threat-model"]["status"] == "skipped" and "Plan phase not selected" in rows["threat-model"]["reason"]
    assert rows["sca"]["status"] == "skipped" and "Build phase not selected" in rows["sca"]["reason"]
    assert rows["secrets"]["status"] != "skipped"


def test_scan_phases_env_is_validated(tmp_path):
    env = dict(os.environ, SCAN_PHASES="plan,nonsense")
    p = subprocess.run([sys.executable, str(ROOT / "scanner" / "sawone_scan.py"), "--path", str(tmp_path), "--plan"],
                       env=env, capture_output=True, text=True)
    assert p.returncode != 0 and "SCAN_PHASES: unknown phase(s): nonsense" in (p.stdout + p.stderr)


def test_merge_marks_unselected_phases(tmp_path):
    part = tmp_path / "p"
    part.mkdir()
    (part / "summary.json").write_text(json.dumps({"stages": [{"stage": "sast", "tool": "Semgrep CE",
                                                               "status": "passed", "gate": True}]}))
    os.environ.pop("SCAN_ONLY", None)
    merge_reports.merge(tmp_path / "m", [part], languages=["en"], phases="code,build")
    s = json.loads((tmp_path / "m" / "summary.json").read_text())
    rows = {r["stage"]: r for r in s["stages"]}
    assert s["phases"] == ["code", "build"]
    assert rows["dast"]["status"] == "skipped" and "Test phase not selected" in rows["dast"]["reason"]
    assert rows["threat-model"]["reason"].startswith("Plan phase not selected")
    md = (tmp_path / "m" / "summary.md").read_text()
    assert "**DevSecOps lifecycle:** ⏸️ Plan → ✅ Code" in md and "| Phase | Stage |" in md and "| Code | sast |" in md


def _report_dir(tmp_path, stages, phases=None):
    r = tmp_path / "r"
    r.mkdir()
    (r / "findings.json").write_text("[]")
    (r / "findings-consolidated.json").write_text("[]")
    (r / "summary.json").write_text(json.dumps({"repository": "acme/shop", "stages": stages, "enforce": False,
                                                **({"phases": phases} if phases else {})}))
    return r


def test_report_has_the_lifecycle_strip_phase_column_and_bands(tmp_path):
    stages = [{"stage": "threat-model", "tool": "OWASP pytm", "status": "passed", "gate": True, "findings": ""},
              {"stage": "secrets", "tool": "Gitleaks", "status": "failed", "gate": True, "findings": "2 leaks"},
              {"stage": "dast", "tool": "ZAP baseline", "status": "passed", "gate": True, "findings": ""}]
    en = report.build(_report_dir(tmp_path, stages, ["plan", "code", "test"]), "en")
    assert 'class="lifecycle"' in en and "DevSecOps lifecycle" in en
    assert "ph-code ph-failed" not in en and 'class="ph ph-failed"' in en          # code failed
    assert "Not selected" in en and "Separate workflow" in en and "would block release" in en
    assert 'class="phase-band"><b>Plan</b>' in en and "Code · Secrets detection" in en
    assert '<span class="phase-tag">Code</span>' in en


def test_arabic_report_translates_the_phases(tmp_path):
    stages = [{"stage": "sast", "tool": "Semgrep CE", "status": "passed", "gate": True, "findings": ""}]
    ar = report.build(_report_dir(tmp_path, stages), "ar")
    assert "دورة حياة DevSecOps" in ar and "البرمجة" in ar and "سير عمل مستقل" in ar


def test_dashboard_shows_lifecycle_chips(tmp_path):
    d = tmp_path / "in" / "acme__api"
    d.mkdir(parents=True)
    (d / "summary.json").write_text(json.dumps({"repository": "acme/api", "passed": False, "stages": [
        {"stage": "secrets", "status": "failed", "gate": True}], "phases": ["code"]}))
    (d / "findings-consolidated.json").write_text("[]")
    snap = dashboard.snapshot("acme__api", d)
    assert snap["phases"]["code"] == "failed" and snap["phases"]["plan"] == "notsel"
    assert 'title="Code: failed"' in dashboard.lifecycle(snap["phases"])


# ---------------------------------------------------------------- the workflow's plan step, run as GitHub runs it
def _plan(tmp_path, phases):
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "sawone-scan.yml").read_text())
    step = next(s for s in wf["jobs"]["validate"]["steps"] if s.get("id") == "plan")
    script = tmp_path / "plan.sh"
    script.write_text(step["run"])
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    (ws / "Dockerfile").write_text("FROM scratch\n")
    out = tmp_path / "out"
    out.write_text("")
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "GITHUB_WORKSPACE": str(ws), "GITHUB_OUTPUT": str(out),
           "GITHUB_STEP_SUMMARY": str(tmp_path / "sum"), "EVENT": "push", "PR_BASE_SHA": "", "IN_PATH": ".",
           "IN_PHASES": phases, "IN_INCREMENTAL": "auto", "IN_LANGS": "en", "IN_DEPTH": "auto", "IN_PR_GATE": "new",
           "IN_EPSS": "0", "IN_BASELINE": "", "IN_PORT": "0", "IN_TIMEOUT": "60", "IN_PREFIX": "sawone",
           "IN_POLICY": "latest", "IN_SARIF": "never", "IN_SEVERITY": "HIGH,CRITICAL", "IN_DD": "false",
           "IN_IAST": "false", "HAS_DD_TOKEN": "false", "IN_FULL": "true", "IN_DOCKERFILE": "", "IN_CONTEXT": "",
           "IN_LOCK": "", "IN_SCANNER_SRC": "", "IN_HEALTH": "", "IN_DD_URL": "", "IN_DONGTAI_URL": "",
           "IN_IAST_ARGS": "",
           **{k: "true" for k in ["EN_THREAT", "EN_SECRETS", "EN_SAST", "EN_SCA", "EN_IAC", "EN_K8S", "EN_CICD",
                                  "EN_CONTAINER", "EN_DAST", "EN_RUNTIME"]}}
    p = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)], cwd=ws, env=env,
                       capture_output=True, text=True)
    outputs = dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)
    return p, outputs


def test_workflow_plan_step_filters_by_phase(tmp_path):
    p, o = _plan(tmp_path, "plan,code")
    assert p.returncode == 0, p.stdout + p.stderr
    assert json.loads(o["gate-stages"]) == ["threat-model", "secrets", "sast"]
    assert o["has-image"] == "false" and json.loads(o["attack-stages"]) == [] and o["phases"] == "plan,code"
    p, o = _plan(tmp_path, "all")
    assert json.loads(o["gate-stages"]) == ["threat-model", "secrets", "sast", "sca", "iac", "kubernetes", "cicd"]
    assert o["has-image"] == "true" and "runtime" in json.loads(o["attack-stages"])
    p, o = _plan(tmp_path, "plan,coding")
    assert p.returncode != 0 and "unknown phase 'coding'" in p.stdout
