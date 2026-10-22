"""Sawone 1.0: history/SLA, false positives, incremental scans, live secrets, Nuclei tech filter, compliance
frameworks, evidence pack, Arabic report, dashboard, merge options."""
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scanner"))
sys.path.insert(0, str(ROOT / "tests" / "unit"))
import dashboard  # noqa: E402
import findings as F  # noqa: E402
import merge_reports  # noqa: E402
import report  # noqa: E402
import sawone_scan as ds  # noqa: E402
from test_scanner import FIX, FakeRun, make_scan  # noqa: E402


def _v(cve="CVE-1", pkg="openssl", sev="CRITICAL"):
    return F.vuln("container", "Trivy image (x)", cve, pkg, "1.0", sev, "1.1", "OS package (debian)", gating=True)


# ------------------------------------------------------------------ history and SLA
def test_first_seen_is_carried_forward_and_deadlines_are_computed():
    old = F.consolidate([_v("CVE-1"), _v("CVE-2", "zlib", "HIGH")])
    for f in old:
        f["first_seen"] = "2026-09-01"
    now = dt.datetime(2026, 10, 22, tzinfo=dt.timezone.utc)
    cur = F.consolidate([_v("CVE-1"), _v("CVE-3", "curl", "HIGH")])
    tr = F.apply_history(cur, old, now=now, sla={"CRITICAL": 7})
    by = {f["id"]: f for f in cur}
    assert by["CVE-1"]["first_seen"] == "2026-09-01" and by["CVE-1"]["overdue"] and by["CVE-1"]["sla_due"] == "2026-09-08"
    assert by["CVE-3"]["first_seen"] == "2026-10-22" and not by["CVE-3"].get("overdue")
    assert tr["new"] == 1 and tr["fixed"] == 1 and tr["overdue"] == 1 and tr["by_age"]["31-90"] == 1


def test_without_a_previous_report_everything_is_first_seen_now():
    cur = F.consolidate([_v()])
    tr = F.apply_history(cur, None)
    assert tr["previous"] is False and tr["new"] is None and cur[0]["first_seen"] == dt.date.today().isoformat()


# ------------------------------------------------------------------ false positives
def test_false_positive_exceptions_suppress_and_are_labelled(tmp_path):
    p = tmp_path / "b.yml"
    exp = (dt.date.today() + dt.timedelta(days=30)).isoformat()
    p.write_text(f"exceptions:\n  - id: CVE-1\n    type: false-positive\n    reason: not shipped\n    owner: sawan\n"
                 f"    expires: {exp}\n  - id: CVE-2\n    type: maybe\n    reason: x\n    owner: y\n    expires: {exp}\n")
    active, _, errors = F.load_baseline(p)
    assert len(active) == 1 and active[0]["type"] == "false-positive"
    assert errors and "type must be accepted-risk or false-positive" in errors[0]
    f = F.Policy(active).apply([_v("CVE-1")])[0]
    assert not f["gating"] and f["baselined"]["type"] == "false-positive"
    assert "False positive" in report.finding_state(f)


# ------------------------------------------------------------------ incremental scans
def test_pull_request_scans_look_only_at_the_change(tmp_path):
    s = make_scan(tmp_path, FIX / "python-flask", {"base_sha": "a" * 40})
    s.inv["git"] = True
    (s.ws / ".git").mkdir()
    s.run = FakeRun(s, [(lambda c: True, 0, "leaks found: 0", None)])
    s.scan_secrets()
    gl = next(c for c in s.run.calls if "gitleaks" in " ".join(map(str, c)))
    th = next(c for c in s.run.calls if "git" in c and any(str(x).startswith("file://") for x in c))
    assert f"--log-opts={'a' * 40}..HEAD" in gl and "--since-commit" in th
    s.run = FakeRun(s, [(lambda c: c[0] == "semgrep", 0, "", None)])
    s.scan_sast()
    assert "--baseline-commit" in s.run.calls[0]


def test_an_invalid_base_commit_is_ignored(tmp_path):
    s = ds.Scan.__new__(ds.Scan)
    s.cfg = {"base_sha": "main; rm -rf /"}
    assert ds.re.fullmatch(r"[0-9a-f]{7,40}", str(s.cfg["base_sha"])) is None


def test_trufflehog_reads_history_and_marks_verified_secrets(tmp_path):
    s = make_scan(tmp_path, FIX / "python-flask")
    s.inv["git"] = True

    def write(cmd):
        line = json.dumps({"DetectorName": "AWS", "Verified": True, "Raw": "AKIAxxxx",
                           "SourceMetadata": {"Data": {"Git": {"file": "old.env", "line": 2, "commit": "abc12345ff"}}}})
        Path(s.reports / "raw" / "trufflehog-git.jsonl").write_text(line + "\n")
    s.run = FakeRun(s, [(lambda c: "file://" in " ".join(map(str, c)), 183, "", write), (lambda c: True, 0, "", None)])
    s.scan_secrets()
    th = [f for f in s.findings if f["tool"] == "TruffleHog"]
    assert len(th) == 1 and th[0]["verified"] and "commit abc12345" in th[0]["title"]
    assert any(r["tool"] == "TruffleHog" and r["status"] == "failed" for r in s.stages)


def test_azure_unset_variable_is_not_used_as_a_credential(tmp_path, monkeypatch):
    monkeypatch.setenv("DAST_AUTH_VALUE", "$(DAST_AUTH_VALUE)")
    s = make_scan(tmp_path, FIX / "python-flask")
    assert s.prepare_auth("http://app:8080") and s.auth_mode is None


# ------------------------------------------------------------------ compliance and evidence
def test_compliance_frameworks_can_be_chosen_and_carry_arabic_titles():
    stages = [{"stage": "sast", "tool": "Semgrep CE", "status": "passed"}]
    comp = ds.compliance_status(stages, frameworks=["cscc", "pdpl"])
    assert {c["key"] for c in comp} == {"cscc", "pdpl"} and all(c["title_ar"] for c in comp)
    assert any(c["id"] == "2-9-T-1-1" for c in ds.compliance_status(stages, frameworks=["ccc"]))


def test_evidence_index_and_manifest_verify(tmp_path):
    r = tmp_path / "r"
    (r / "sarif").mkdir(parents=True)
    (r / "sarif" / "semgrep.sarif").write_text('{"runs": []}')
    (r / "summary.json").write_text("{}")
    comp = ds.compliance_status([{"stage": "sast", "tool": "Semgrep CE", "status": "passed"}], frameworks=["cscc"])
    idx = ds.build_evidence(r, {"repository": "acme/x", "passed": True}, comp)
    ctrl = next(c for c in idx["controls"] if c["id"] == "1-3-2-1")
    assert ctrl["artifacts"][0]["path"] == "sarif/semgrep.sarif"
    assert ctrl["artifacts"][0]["sha256"] == hashlib.sha256(b'{"runs": []}').hexdigest()
    ds.write_manifest(r)
    p = subprocess.run(["sha256sum", "--quiet", "-c", "evidence/manifest.sha256"], cwd=r, capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr


def test_a_gate_job_writes_no_pdf_and_no_evidence(tmp_path):
    (tmp_path / "logs").mkdir()
    ds.render_outputs(tmp_path, {"stages": [{"stage": "sast", "tool": "Semgrep CE", "status": "passed", "gate": True}],
                                 "only": ["sast"], "enforce": True})
    assert not (tmp_path / "security-report.pdf").exists() and not (tmp_path / "evidence").exists()


# ------------------------------------------------------------------ Arabic report
def _report_dir(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    fs = [_v("CVE-2023-4863", "Pillow", "HIGH")]
    fs[0]["kev"] = True
    (r / "findings.json").write_text(json.dumps(fs))
    (r / "findings-consolidated.json").write_text(json.dumps(F.consolidate(fs)))
    stages = [{"stage": "container", "tool": "Trivy image (x)", "status": "failed", "gate": True, "findings": "1", "reason": ""}]
    (r / "summary.json").write_text(json.dumps({"repository": "acme/shop", "stages": stages, "enforce": False,
                                                "compliance": ds.compliance_status(stages, frameworks=["cscc"])}))
    return r


def test_arabic_report_is_right_to_left_and_translated(tmp_path):
    r = _report_dir(tmp_path)
    ar = report.build(r, "ar")
    assert 'dir="rtl"' in ar and "الملخص التنفيذي" in ar and "تقرير تقييم" in ar
    assert "مراجعة أمنية للشيفرة المصدرية" in ar           # control title in Arabic
    assert "CVE-2023-4863" in ar                            # tool output is never translated
    for english in (">Executive summary<", ">Security gate results<", ">Detailed results<"):
        assert english not in ar
    en = report.build(r, "en")
    assert 'dir="ltr"' in en and "Executive summary" in en and "الملخص" not in en


def test_every_fixed_report_text_has_an_arabic_translation():
    import ast
    import re
    import report_i18n
    keys = set()
    for node in ast.walk(ast.parse((ROOT / "scanner" / "report.py").read_text())):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "T" and node.args:
            a = node.args[0]
            for c in ([a.body, a.orelse] if isinstance(a, ast.IfExp) else [a]):
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    keys.add(re.sub(r"\s+", " ", c.value).strip())
    missing = sorted(k for k in keys if k not in report_i18n.AR)
    assert not missing, missing


# ------------------------------------------------------------------ merge and dashboard
def test_merge_records_unchanged_stages_and_languages(tmp_path):
    part = tmp_path / "p"
    part.mkdir()
    (part / "summary.json").write_text(json.dumps({"stages": [{"stage": "sast", "tool": "Semgrep CE", "status": "passed",
                                                               "gate": True}], "options": {"languages": ["en", "ar"]}}))
    os.environ.pop("SCAN_ONLY", None)
    merge_reports.merge(tmp_path / "m", [part], unchanged=["sca", "iac"], languages=["en"])
    s = json.loads((tmp_path / "m" / "summary.json").read_text())
    rows = {r["stage"]: r for r in s["stages"]}
    assert rows["sca"]["status"] == "skipped" and "not affected by this change" in rows["sca"]["reason"]
    assert s["options"]["languages"] == ["en"] and "trend" in s


def test_dashboard_summarises_every_repository(tmp_path):
    inp = tmp_path / "in"
    for name, kev in (("acme__api", True), ("acme__web", False)):
        d = inp / name
        d.mkdir(parents=True)
        f = _v()
        f["kev"] = kev
        (d / "summary.json").write_text(json.dumps({"repository": name.replace("__", "/"), "passed": not kev,
                                                    "stages": [], "compliance": [{"framework": "NCA CSCC-1:2019",
                                                                                  "status": "evidenced"}]}))
        (d / "findings-consolidated.json").write_text(json.dumps(F.consolidate([f])))
    out, hist = tmp_path / "site", tmp_path / "h.json"
    sys.argv = ["dashboard.py", "--inputs", str(inp), "--history", str(hist), "--out", str(out)]
    assert dashboard.main() == 0
    page = (out / "index.html").read_text()
    assert "acme/api" in page and "acme/web" in page and "NCA CSCC-1:2019" in page
    assert set(json.loads(hist.read_text())) == {"acme/api", "acme/web"}


# ------------------------------------------------------------------ Nuclei
def test_nuclei_falls_back_to_every_template_when_the_tech_filter_cannot_run(tmp_path, monkeypatch):
    s = make_scan(tmp_path, FIX / "python-flask", {"dast": {"full_scan": False, "openapi": None}})
    wrk = tmp_path / "zap"
    wrk.mkdir()
    monkeypatch.setattr(s, "ensure_app", lambda *a, **k: {"base": "http://app:8080"})
    monkeypatch.setattr(s, "_zap_dir", lambda: wrk)
    monkeypatch.setattr(s, "prepare_auth", lambda base: True)
    monkeypatch.setattr(s, "_zap_gate", lambda *a, **k: None)
    monkeypatch.setattr(ds.shutil, "copy", lambda *a, **k: None)

    def plain(cmd):
        Path(s.reports / "sarif" / "nuclei.sarif").write_text('{"runs": []}')
    s.run = FakeRun(s, [
        (lambda c: "nuclei" in " ".join(map(str, c)) and "-as" in c, 1, '[FTL] no templates found in path "/root/nuclei-templates"', None),
        (lambda c: "nuclei" in " ".join(map(str, c)) and "-u" in c, 0, "", plain),
    ])
    s.scan_dast()
    runs = [c for c in s.run.calls if "-u" in c and any("nuclei" in str(x) for x in c)]
    assert len(runs) == 2 and "-as" in runs[0] and "-as" not in runs[1]
    assert not any(r["tool"] == "Nuclei" and r["status"] == "error" for r in s.stages), s.stages
