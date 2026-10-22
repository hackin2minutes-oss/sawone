"""Unit tests for the enterprise PDF report (HTML stage; WeasyPrint is not needed)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scanner"))
import findings as F  # noqa: E402
import report  # noqa: E402
import sawone_scan as ds  # noqa: E402

IMG = "app:abc123"


def _stage(stage, tool, status, txt="", gate=True):
    return {"stage": stage, "tool": tool, "status": status, "gate": gate, "findings": txt, "reason": ""}


def _write(reports, stages, findings=(), extra=None, monkeypatch=None):
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "sarif").mkdir(exist_ok=True)
    (reports / "findings.json").write_text(json.dumps(list(findings)))
    merged = F.consolidate([dict(f) for f in findings])
    (reports / "findings-consolidated.json").write_text(json.dumps(merged))
    summary = {"repository": "acme/shop", "enforce": False, "severity": ["HIGH", "CRITICAL"], "stages": stages,
               "release": {"Image built": IMG, "Image ID": "sha256:1"}, "jobs": [{"job": "gates", "result": "success"}],
               "tools": {"_policy": "lock", "trivy": "aquasec/trivy@sha256:aa"}}
    summary.update(extra or {})
    (reports / "summary.json").write_text(json.dumps(summary))
    (reports / "tools.json").write_text(json.dumps(summary["tools"]))
    if monkeypatch:
        for k, v in {"REPO": "acme/shop", "SHA": "abc123", "REF": "refs/heads/main",
                     "RUN_URL": "https://example.test/run/1"}.items():
            monkeypatch.setenv(k, v)
    return report.build(reports)


def test_run_metadata_and_image_are_shown(tmp_path, monkeypatch):
    html = _write(tmp_path / "r", [_stage("sast", "Semgrep CE", "passed")], monkeypatch=monkeypatch)
    assert "refs/heads/main" in html and "abc123" in html and "https://example.test/run/1" in html
    assert IMG in html
    assert "pull request, disabled, or failed build" not in html


def test_threat_model_found_inside_merged_part(tmp_path):
    r = tmp_path / "r"
    part = r / "raw" / "sawone-part-threat-model"
    part.mkdir(parents=True)
    (part / "threats.json").write_text(json.dumps({"findings": [
        {"threat_id": "AA01", "target": "Login", "severity": "Very High", "description": "Auth bypass",
         "mitigations": "<p>Use MFA</p>"}]}))
    f = F.issue("threat-model", "OWASP pytm", "threat", "AA01", "threatmodel/tm.py", None, "CRITICAL",
                "Auth bypass — Login", key="Login", gating=True)
    html = _write(r, [_stage("threat-model", "OWASP pytm", "failed", "1 threats, 1 open")], [f])
    assert "Threat model did not run" not in html
    assert "Use MFA" in html and "Open threats requiring a decision (1)" in html


def test_banner_counts_every_failed_gate(tmp_path):
    stages = [_stage("dast", f"tool{i}", "failed") for i in range(10)] + [_stage("sast", "Semgrep CE", "passed")]
    html = _write(tmp_path / "r", stages)
    assert "10 of 11 security gates failed" in html


def test_internal_tool_keys_are_hidden(tmp_path):
    html = _write(tmp_path / "r", [_stage("sast", "Semgrep CE", "passed")])
    assert ">_policy<" not in html
    assert "Version policy: <b>lock</b>" in html


def test_checkov_is_unrated_and_gitleaks_high(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    (r / "sarif").mkdir()
    res = {"ruleId": "CKV_AWS_1", "level": "error", "message": {"text": "bucket public"},
           "locations": [{"physicalLocation": {"artifactLocation": {"uri": "main.tf"}, "region": {"startLine": 3}}}]}
    (r / "sarif" / "checkov.sarif").write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "Checkov"}},
                                                                     "automationDetails": {"id": "sawone/checkov/0/"},
                                                                     "results": [res, res]}]}))
    g = F.issue("secrets", "Gitleaks", "secret", "generic-api-key", "app.py", 4, "HIGH", "key", key="c1", gating=True)
    html = _write(r, [_stage("iac", "Checkov", "report", "2 findings", gate=False),
                      _stage("secrets", "Gitleaks", "failed", "1 leaks")], [g])
    data = report.Data(r)
    assert {f["severity"] for f in data.sarif["checkov"]} == {"UNKNOWN"}
    assert "Unrated" in html
    # the same Checkov rule in two places is one row
    assert html.count("CKV_AWS_1</span>") == 1


def test_every_tool_gets_its_own_panel(tmp_path):
    stages = [_stage("sast", "Semgrep CE", "failed", "1 ERROR"), _stage("cicd", "actionlint", "passed"),
              _stage("cicd", "zizmor", "failed"), _stage("container", f"Trivy image ({IMG})", "failed"),
              _stage("container", f"Grype ({IMG})", "failed")]
    fs = [F.issue("sast", "Semgrep CE", "code", "python.sqli", "app.py", 3, "HIGH", "SQL built from input", key="a", gating=True),
          F.issue("cicd", "zizmor", "config", "template-injection", ".github/workflows/x.yml", 9, "HIGH", "injection", key="b", gating=True),
          F.vuln("container", f"Trivy image ({IMG})", "CVE-2026-1", "openssl", "3.0", "CRITICAL", "3.1", "OS package (debian)", gating=True),
          F.vuln("container", f"Grype ({IMG})", "CVE-2026-1", "openssl", "3.0", "CRITICAL", "3.1", "deb: /var/lib/dpkg/status", gating=True),
          F.vuln("container", f"Grype ({IMG})", "CVE-2026-2", "zlib", "1.2", "HIGH", "1.3", "deb: /var/lib/dpkg/status", gating=True)]
    html = _write(tmp_path / "r", stages, fs)
    for name in ("Semgrep CE", "actionlint", "zizmor", "Trivy image", "Grype"):
        assert f'<span class="name">{name}</span>' in html
    assert "template-injection" in html                       # zizmor findings reach the report
    assert "Operating-system packages" in html and "3.1" in html
    assert "Blocking advisories found only by Grype" in html and "CVE-2026-2" in html


def test_zap_alerts_show_evidence_and_remediation(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    (r / "zap-full.json").write_text(json.dumps({"site": [{"alerts": [{
        "pluginid": "40018", "alert": "SQL Injection", "riskcode": "3", "cweid": "89", "count": "1",
        "solution": "<p>Use parameterised queries.</p>",
        "instances": [{"uri": "http://app/search?q=1", "method": "GET", "param": "q", "attack": "1' OR '1'='1"}]}]}]}))
    f = F.issue("dast", "ZAP full scan", "dast", "40018", "/search", None, "HIGH", "SQL Injection (GET /search)",
                key="GET q", gating=True)
    html = _write(r, [_stage("dast", "ZAP full scan", "failed", "High 1")], [f])
    assert "CWE-89" in html and "Use parameterised queries." in html and "1&#x27; OR" in html


def test_scanner_location_and_sbom_helpers():
    assert ds.Scan.trivy_location({"Class": "os-pkgs", "Type": "debian", "Target": "/x/img0.tar"}, {}) == "OS package (debian)"
    assert ds.Scan.trivy_location({"Target": "/x/img0.tar", "Type": "python-pkg"}, {}) == "python-pkg"
    assert ds.Scan.trivy_location({}, {"PkgPath": "usr/lib/a.dist-info/METADATA"}) == "usr/lib/a.dist-info/METADATA"
    assert ds.sbom_packages({"components": [{"type": "library"}, {"type": "file"}, {"type": "operating-system"}]}) == 2
    assert ds.sarif_severity({"properties": {"security-severity": "9.1"}}, {}) == "CRITICAL"
    assert ds.sarif_severity({"level": "warning"}, {}) == "MEDIUM"


def test_same_cve_merges_across_package_name_spelling():
    a = F.vuln("container", "Trivy image (x)", "CVE-2023-4863", "Pillow", "8.1.0", "HIGH", "10.0.1")
    b = F.vuln("container", "Grype (x)", "CVE-2023-4863", "pillow", "8.1.0", "HIGH", "10.0.1")
    c = F.vuln("sca", "Trivy (dependencies)", "CVE-2024-1", "typing_extensions", "4.0", "HIGH", "4.1")
    d = F.vuln("container", "Grype (x)", "CVE-2024-1", "typing-extensions", "4.0", "HIGH", "4.1")
    merged = F.consolidate([a, b, c, d])
    assert len(merged) == 2
    assert merged[0]["package"] in ("Pillow", "typing_extensions")   # display name kept as reported


def test_summary_rows_name_the_finding_and_shorten_tools():
    f = F.issue("dast", "ZAP full scan", "dast", "40018", "/api/login", None, "HIGH",
                "SQL Injection (POST http://app/api/login · param user)", key="k", gating=True)
    f["tools"] = ["ZAP full scan", "ZAP API scan"]
    row = ds._f_row(f)
    assert "`40018` SQL Injection |" in row
    v = F.vuln("container", "Trivy image (app:abc)", "CVE-1", "openssl", "3", "HIGH", "4")
    v["tools"] = ["Trivy image (app:abc)", "Grype (app:abc)"]
    assert "Trivy image, Grype |" in ds._f_row(v)
