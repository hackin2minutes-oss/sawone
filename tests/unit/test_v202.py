"""v2.0.2: cross-tool correlation, Semgrep framework filter, workspace-relative SARIF, endpoint WAF checks,
authenticated DAST, Dockle, Nuclei findings, job-summary grouping and report fixes."""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scanner"))
sys.path.insert(0, str(ROOT / "tests" / "unit"))
import findings as F  # noqa: E402
import sawone_scan as ds  # noqa: E402
from test_scanner import FIX, FakeRun, make_scan  # noqa: E402


# ------------------------------------------------------------------ correlation
def _code(rule, path, line, cwe, tool="Semgrep CE", sev="HIGH"):
    f = F.issue("sast", tool, "code", rule, path, line, sev, rule, key=f"{rule}{line}", gating=True)
    f["cwe"] = cwe
    return f


def test_semgrep_rules_on_one_line_with_a_shared_cwe_merge():
    a = _code("python.flask.security.injection.tainted-sql-string.tainted-sql-string", "app.py", 71, ["CWE-89"])
    b = _code("python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query", "app.py", 71, ["CWE-89"])
    c = _code("python.flask.security.injection.ssrf-requests.ssrf-requests", "app.py", 71, ["CWE-918"])
    merged = F.consolidate([a, b, c])
    assert len(merged) == 2
    sql = next(m for m in merged if "CWE-89" in m["cwe"])
    assert sql["related"] and len(sql["fingerprints"]) == 2


def test_one_private_key_from_three_tools_is_one_finding():
    g = F.issue("secrets", "Gitleaks", "secret", "private-key", "config/deploy_key.pem", 1, "HIGH", "key", key="c", gating=True)
    s = _code("generic.secrets.security.detected-private-key.detected-private-key", "config/deploy_key.pem", 1, ["CWE-798"])
    t = F.issue("container", "Trivy image (x)", "secret", "private-key", "/app/config/deploy_key.pem", 2, "HIGH",
                "Asymmetric Private Key", key="x", gating=True)
    other = F.issue("secrets", "Gitleaks", "secret", "generic-api-key", "app.py", 23, "HIGH", "api key", key="d", gating=True)
    merged = F.consolidate([g, s, t, other])
    assert len(merged) == 2
    key = next(m for m in merged if "deploy_key" in m["location"])
    assert set(key["tools"]) == {"Gitleaks", "Semgrep CE", "Trivy image (x)"}


def test_root_user_rules_from_different_tools_merge():
    a = F.issue("iac", "Trivy config", "config", "DS-0002", "Dockerfile", None, "HIGH", "Image user should not be root", gating=True)
    b = _code("dockerfile.security.missing-user.missing-user", "Dockerfile", 10, [])
    merged = F.consolidate([a, b])
    assert len(merged) == 1 and merged[0]["related"]


def test_baseline_written_from_a_merged_finding_covers_every_tool(tmp_path):
    g = F.issue("secrets", "Gitleaks", "secret", "private-key", "k.pem", 1, "HIGH", "key", key="c", gating=True)
    s = _code("generic.secrets.security.detected-private-key.detected-private-key", "k.pem", 1, [])
    n = F.write_baseline([g, s], tmp_path / "b.yml", owner="sawan")
    assert n == 2
    active, _, errors = F.load_baseline(tmp_path / "b.yml")
    assert not errors
    pol = F.Policy(active)
    items = pol.apply([dict(g), dict(s)])
    assert not any(i["gating"] for i in items)


# ------------------------------------------------------------------ scanner
def test_semgrep_drops_rules_for_frameworks_not_in_use(tmp_path):
    s = make_scan(tmp_path, FIX / "python-flask")
    js = s.reports / "raw" / "semgrep.json"

    def write(cmd):
        res = [{"check_id": cid, "path": str(s.ws / "app.py"), "start": {"line": 5},
                "extra": {"severity": "ERROR", "message": "m", "metadata": {"cwe": ["CWE-89: SQL"]}}}
               for cid in ["python.flask.security.x.x", "python.django.security.x.x", "python.lang.security.y.y"]]
        js.write_text(json.dumps({"results": res}))
        (s.reports / "sarif" / "semgrep.sarif").write_text(json.dumps({"runs": []}))
    s.run = FakeRun(s, [(lambda c: c[0] == "semgrep", 1, "", write)])
    s.scan_sast()
    row = next(r for r in s.stages if r["tool"] == "Semgrep CE")
    assert "1 results from rules for frameworks not in use dropped" in row["findings"]
    assert {f["id"] for f in s.findings} == {"python.flask.security.x.x", "python.lang.security.y.y"}
    assert s.findings[0]["cwe"] == ["CWE-89"]


def test_sarif_paths_become_workspace_relative(tmp_path):
    s = make_scan(tmp_path, FIX / "python-flask")
    p = s.reports / "sarif" / "osv.sarif"
    p.write_text(json.dumps({"runs": [{"results": [{"locations": [{"physicalLocation": {"artifactLocation": {
        "uri": f"file://{s.ws}/requirements.txt"}}}]}]}]}))
    s.sarif_tag(p, "osv")
    uri = json.loads(p.read_text())["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "requirements.txt"


def test_sarif_with_findings_is_not_reported_as_a_failed_run(tmp_path):
    """kube-linter writes executionSuccessful: false whenever it finds something; code scanning then says the
    tool 'exited with errors'. Only error notifications mean the run itself failed."""
    s = make_scan(tmp_path, FIX / "python-flask")
    p = s.reports / "sarif" / "kube-linter.sarif"
    found = {"tool": {"driver": {"name": "kube-linter"}}, "invocations": [{"executionSuccessful": False}],
             "results": [{"ruleId": "run-as-non-root"}]}
    broken = {"tool": {"driver": {"name": "x"}}, "invocations": [{"executionSuccessful": False,
              "toolExecutionNotifications": [{"level": "error", "message": {"text": "parse failure"}}]}]}
    p.write_text(json.dumps({"runs": [found, broken]}))
    s.sarif_tag(p, "kube-linter")
    runs = json.loads(p.read_text())["runs"]
    assert runs[0]["invocations"][0]["executionSuccessful"] is True
    assert runs[1]["invocations"][0]["executionSuccessful"] is False


def test_waf_attacks_each_real_endpoint_from_the_openapi_spec(tmp_path):
    s = make_scan(tmp_path, FIX / "python-flask")
    checks = s.waf_endpoint_checks()
    urls = {c[2].split("?")[0] for c in checks}
    assert "http://waf:8080/user" in urls and "http://waf:8080/ping" in urls
    assert any(c[4] == "info" and "template injection" in c[0] for c in checks)
    assert all(c[4] in ("block", "info") for c in checks)


def test_fixed_credential_reaches_zap_only_through_the_environment(tmp_path, monkeypatch):
    s = make_scan(tmp_path, FIX / "python-flask")
    monkeypatch.setenv("DAST_AUTH_VALUE", "Bearer s3cret")
    assert s.prepare_auth("http://app:8080")
    flags = s.zap_auth_env()
    assert flags == ["-e", "ZAP_AUTH_HEADER", "-e", "ZAP_AUTH_HEADER_VALUE", "-e", "ZAP_AUTH_HEADER_SITE"]
    assert "s3cret" not in " ".join(flags) and os.environ["ZAP_AUTH_HEADER_VALUE"] == "Bearer s3cret"
    for k in ("ZAP_AUTH_HEADER", "ZAP_AUTH_HEADER_VALUE", "ZAP_AUTH_HEADER_SITE"):
        monkeypatch.delenv(k, raising=False)


def test_login_without_credentials_is_an_error_not_an_anonymous_scan(tmp_path, monkeypatch):
    for k in ("DAST_AUTH_VALUE", "DAST_USERNAME", "DAST_PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    s = make_scan(tmp_path, FIX / "python-flask", {"dast": {"auth": {"login_url": "/api/login"}}})
    assert s.prepare_auth("http://app:8080") is False
    assert any(r["tool"] == "authentication" and r["status"] == "error" for r in s.stages)


def test_login_token_is_read_from_the_reply_and_not_logged(tmp_path, monkeypatch):
    monkeypatch.setenv("DAST_USERNAME", "alice")
    monkeypatch.setenv("DAST_PASSWORD", "pw")
    s = make_scan(tmp_path, FIX / "python-flask",
                  {"dast": {"auth": {"login_url": "/api/login", "token_field": "data.access_token"}}})
    s.run = FakeRun(s, [(lambda c: "SAWONE_LOGIN_BODY" in c, 0, '{"data": {"access_token": "tok123"}}', None)])
    assert s.prepare_auth("http://app:8080")
    assert os.environ["ZAP_AUTH_HEADER_VALUE"] == "Bearer tok123"
    assert not any("tok123" in p.read_text() for p in (s.reports / "logs").glob("*.log"))
    for k in ("ZAP_AUTH_HEADER", "ZAP_AUTH_HEADER_VALUE", "ZAP_AUTH_HEADER_SITE"):
        monkeypatch.delenv(k, raising=False)


def test_dockle_is_skipped_for_an_older_lock_file(tmp_path):
    lock = {"images": {t: f"x/{t}@sha256:{'a' * 64}" for t in ds.IMAGES if t != "dockle"}, "pip": {}}
    s = make_scan(tmp_path, FIX / "python-flask", {"only": ["container"], "tools_lock": lock})
    assert "dockle" not in s.needed_tools()
    s2 = make_scan(tmp_path / "b", FIX / "python-flask", {"only": ["container"]})
    assert "dockle" in s2.needed_tools()


def test_dockle_findings_are_report_only(tmp_path):
    s = make_scan(tmp_path, FIX / "python-flask")
    s.pinned["dockle"] = "goodwithtech/dockle@sha256:" + "b" * 64

    def write(cmd):
        out = Path(cmd[cmd.index("-o") + 1])
        out.write_text(json.dumps({"details": [
            {"code": "CIS-DI-0001", "title": "Create a user for the container", "level": "WARN", "alerts": ["Last user should not be root"]},
            {"code": "CIS-DI-0010", "title": "Do not store credential in environment variables/files", "level": "FATAL",
             "alerts": ["Suspicious filename found : app/config/deploy_key.pem"]}]}))
    s.run = FakeRun(s, [(lambda c: "dockle" in " ".join(c), 0, "", write)])
    s._dockle(s.reports / "raw" / "img0.tar", "app:1", "img0")
    row = next(r for r in s.stages if r["tool"] == "Dockle")
    assert row["status"] == "report" and "1 FATAL" in row["findings"]
    assert {f["severity"] for f in s.findings} == {"HIGH", "MEDIUM"}


def test_gate_job_summary_has_no_partial_compliance_and_groups_cves(tmp_path):
    r = tmp_path / "r"
    (r / "logs").mkdir(parents=True)
    fs = [F.vuln("container", "Trivy image (x)", "CVE-1", p, "3.5", "CRITICAL", "3.6", "OS package (debian)", gating=True)
          for p in ("openssl", "libssl3t64", "openssl-provider-legacy")]
    (r / "findings.json").write_text(json.dumps(fs))
    stages = [{"stage": "container", "tool": "Trivy image (x)", "status": "failed", "gate": True, "findings": "3", "reason": ""}]
    ds.render_outputs(r, {"stages": stages, "only": ["container"], "enforce": False})
    md = (r / "summary.md").read_text()
    assert "Compliance evidence" not in md
    assert md.count("`CVE-1`") == 1 and "libssl3t64 3.5" in md


# ------------------------------------------------------------------ report
def test_report_counts_unique_kev_and_states_the_run_policy(tmp_path):
    from test_report import _stage, _write
    a = F.vuln("container", "Trivy image (x)", "CVE-2023-4863", "Pillow", "8.1.0", "HIGH", "10.0.1", "py", gating=True)
    b = F.vuln("container", "Grype (x)", "CVE-2023-4863", "pillow", "8.1.0", "HIGH", "10.0.1", "python: x", gating=True)
    for f in (a, b):
        f["kev"] = True
    html = _write(tmp_path / "r", [_stage("container", "Trivy image (x)", "failed")], [a, b],
                  extra={"release": {"Image built": "x", "Tool versions": "latest (resolved 2026-10-22)"}})
    assert "Patch the 1 vulnerability listed" in html
    assert "latest (resolved 2026-10-22)" in html and "Version policy: <b>lock</b>" not in html


def test_report_marks_informational_waf_checks(tmp_path):
    from test_report import _stage, _write
    r = tmp_path / "r"
    r.mkdir()
    (r / "waf-results.txt").write_text("PASS  SQL injection → GET /user?name → 403\nINFO  template injection → GET /user?name → 200\n")
    html = _write(r, [_stage("runtime", "ModSecurity + OWASP CRS", "passed", "1/1")])
    assert "Not blocked (info)" in html and "GET /user?name" in html
