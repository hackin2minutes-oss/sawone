"""Unit tests for Sawone v2: normalised findings, baseline, KEV/EPSS policy, dedupe, PR gating, compliance."""
import datetime as dt
import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scanner"))
import findings as F  # noqa: E402
import merge_reports  # noqa: E402
import sawone_scan as ds  # noqa: E402

TODAY = dt.date(2026, 10, 22)


def write(p, text):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def intel(kev=(), epss=None):
    return F.Intel({c: {"date_added": "2025-01-01", "ransomware": False} for c in kev}, epss or {})


# ------------------------------------------------------------------ fingerprints and dedupe
def test_vuln_fingerprint_is_shared_across_tools():
    a = F.vuln("container", "Trivy image", "CVE-2024-1", "openssl", "3.0.1", "HIGH", "3.0.2")
    b = F.vuln("container", "Grype", "cve-2024-1", "openssl", "3.0.1", "High", "")
    assert a["fingerprint"] == b["fingerprint"]
    merged = F.consolidate([a, b])
    assert len(merged) == 1 and merged[0]["tools"] == ["Trivy image", "Grype"]
    assert merged[0]["fixed_version"] == "3.0.2"


def test_code_fingerprint_survives_line_moves(tmp_path):
    write(tmp_path / "app.py", "x = 1\nquery = 'SELECT ' + q\n")
    a = F.issue("sast", "Semgrep", "code", "sqli", "app.py", 2, "HIGH", "sqli", ws=tmp_path)
    write(tmp_path / "app.py", "# new header\n\nx = 1\nquery = 'SELECT ' + q\n")
    b = F.issue("sast", "Semgrep", "code", "sqli", "app.py", 4, "HIGH", "sqli", ws=tmp_path)
    assert a["fingerprint"] == b["fingerprint"]
    assert a["location"] != b["location"]


def test_severity_normalisation():
    assert F.norm_sev("Negligible") == "LOW"
    assert F.norm_sev("moderate") == "MEDIUM"
    assert F.norm_sev("bogus") == "UNKNOWN"


# ------------------------------------------------------------------ baseline
def test_baseline_validation(tmp_path):
    p = write(tmp_path / ".sawone-baseline.yml", """
exceptions:
  - id: CVE-2024-1
    reason: no fix yet
    owner: sawan
    expires: 2026-12-31
  - id: CVE-2024-2
    owner: sawan
    expires: 2026-12-31
  - id: CVE-2024-3
    reason: too long
    owner: sawan
    expires: 2030-01-01
  - id: CVE-2024-4
    reason: lapsed
    owner: sawan
    expires: 2026-01-01
  - id: CVE-2024-5
    reason: bad date
    owner: sawan
    expires: next week
""")
    active, expired, errors = F.load_baseline(p, today=TODAY, max_days=365)
    assert [e["id"] for e in active] == ["CVE-2024-1"]
    assert [e["id"] for e in expired] == ["CVE-2024-4"]
    assert len(errors) == 3
    assert any("missing reason" in e for e in errors)
    assert any("more than 365 days" in e for e in errors)
    assert any("YYYY-MM-DD" in e for e in errors)


def test_missing_baseline_file_is_fine(tmp_path):
    assert F.load_baseline(tmp_path / "nope.yml") == ([], [], [])


def test_baseline_suppresses_and_expired_blocks_again(tmp_path):
    p = write(tmp_path / "b.yml", """
exceptions:
  - {id: CVE-2024-1, package: urllib3, reason: r, owner: o, expires: 2026-12-31}
  - {id: CVE-2024-2, reason: r, owner: o, expires: 2026-01-01}
""")
    active, expired, _ = F.load_baseline(p, today=TODAY)
    pol = F.Policy(active, expired, intel())
    items = [F.vuln("sca", "Trivy", "CVE-2024-1", "urllib3", "1.26.4", "HIGH", "1.26.5", gating=True),
             F.vuln("sca", "Trivy", "CVE-2024-1", "requests", "2.0", "HIGH", "2.1", gating=True),
             F.vuln("sca", "Trivy", "CVE-2024-2", "pyyaml", "5.3", "CRITICAL", "5.4", gating=True)]
    pol.apply(items)
    assert items[0]["gating"] is False and items[0]["baselined"]["owner"] == "o"
    assert items[1]["gating"] is True                 # package narrowing: other package still blocks
    assert items[2]["gating"] is True and items[2]["exception_expired"] == "2026-01-01"
    assert active[0]["used"] == 1


def test_baseline_path_glob_and_fingerprint(tmp_path):
    f1 = F.issue("sast", "Semgrep", "code", "sqli", "src/legacy/a.py", 3, "HIGH", "x", key="k1", gating=True)
    f2 = F.issue("sast", "Semgrep", "code", "sqli", "src/new/b.py", 3, "HIGH", "x", key="k2", gating=True)
    f3 = F.issue("sast", "Semgrep", "code", "xss", "src/new/c.py", 3, "HIGH", "x", key="k3", gating=True)
    entries = [{"n": 1, "id": "sqli", "fingerprint": "", "package": "", "path": "src/legacy/*", "reason": "r",
                "owner": "o", "expires": "2026-12-31", "used": 0},
               {"n": 2, "id": "", "fingerprint": f3["fingerprint"], "package": "", "path": "", "reason": "r",
                "owner": "o", "expires": "2026-12-31", "used": 0}]
    F.Policy(entries, [], intel()).apply([f1, f2, f3])
    assert (f1["gating"], f2["gating"], f3["gating"]) == (False, True, False)


def test_write_baseline_round_trip(tmp_path):
    items = [F.vuln("sca", "Trivy", "CVE-2024-9", "lodash", "4.17.15", "HIGH", "4.17.21", gating=True),
             F.vuln("sca", "Grype", "CVE-2024-9", "lodash", "4.17.15", "HIGH", "", gating=True),
             F.vuln("sca", "Trivy", "CVE-2024-8", "lodash", "4.17.15", "LOW", "", gating=False)]
    n = F.write_baseline(items, tmp_path / "b.yml", "sawan", days=30, today=TODAY)
    assert n == 1                                      # deduplicated, non-blocking skipped
    active, expired, errors = F.load_baseline(tmp_path / "b.yml", today=TODAY)
    assert not errors and len(active) == 1 and active[0]["expires"] == "2026-11-21"
    fresh = [F.vuln("sca", "Trivy", "CVE-2024-9", "lodash", "4.17.15", "HIGH", "4.17.21", gating=True)]
    F.Policy(active, expired, intel()).apply(fresh)
    assert fresh[0]["gating"] is False


# ------------------------------------------------------------------ KEV / EPSS
def test_kev_escalates_any_severity_and_alias():
    items = [F.vuln("container", "Grype", "GHSA-xxxx", "lib", "1", "LOW", "", aliases=["CVE-2021-44228"]),
             F.vuln("container", "Grype", "CVE-2020-1", "lib", "1", "MEDIUM", "")]
    F.Policy([], [], intel(kev=["CVE-2021-44228"])).apply(items)
    assert items[0]["kev"] and items[0]["gating"] and "KEV" in items[0]["escalated"]
    assert not items[1]["gating"]


def test_kev_escalation_can_be_turned_off_and_epss_threshold():
    items = [F.vuln("sca", "Trivy", "CVE-2021-44228", "log4j", "2.14", "LOW", ""),
             F.vuln("sca", "Trivy", "CVE-2023-7", "x", "1", "MEDIUM", "")]
    pol = F.Policy([], [], intel(kev=["CVE-2021-44228"], epss={"CVE-2023-7": (0.62, 0.99)}),
                   block_kev=False, epss_threshold=0.5)
    pol.apply(items)
    assert items[0]["kev"] and not items[0]["gating"]
    assert items[1]["gating"] and items[1]["epss"] == 0.62


def test_kev_escalated_finding_can_still_be_baselined():
    entries = [{"n": 1, "id": "CVE-2021-44228", "fingerprint": "", "package": "", "path": "", "reason": "no fix",
                "owner": "o", "expires": "2026-12-31", "used": 0}]
    items = [F.vuln("sca", "Trivy", "CVE-2021-44228", "log4j", "2.14", "LOW", "")]
    F.Policy(entries, [], intel(kev=["CVE-2021-44228"])).apply(items)
    assert items[0]["kev"] and not items[0]["gating"] and items[0]["baselined"]


def test_epss_parser_and_intel_loader(tmp_path):
    csv_text = "#model_version:v2025,score_date:2026-10-21\ncve,epss,percentile\nCVE-2024-1,0.91,0.999\nCVE-2024-2,0.01,0.2\n"
    (tmp_path / "epss.csv.gz").write_bytes(gzip.compress(csv_text.encode()))
    (tmp_path / "kev.json").write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2024-1", "dateAdded": "2024-05-01", "knownRansomwareCampaignUse": "Known"}]}))
    i = F.Intel.load(tmp_path)
    assert i.epss["CVE-2024-1"] == (0.91, 0.999)
    assert i.kev_hit(["cve-2024-1"])["ransomware"] is True


def test_fetch_intel_reports_failures(tmp_path):
    def opener(url):
        if "cisa" in url:
            return json.dumps({"vulnerabilities": [{"cveID": "CVE-1"}]}).encode()
        raise OSError("blocked")
    errs = F.fetch_intel(tmp_path, opener=opener)
    assert len(errs) == 1 and errs[0].startswith("EPSS")
    assert (tmp_path / "kev.json").exists()


# ------------------------------------------------------------------ scanner integration
def _scan(tmp_path, cfg=None):
    from test_scanner import make_scan  # noqa: WPS433
    return make_scan(tmp_path, ROOT / "tests" / "fixtures" / "python-flask", cfg)


def test_gate_recomputes_from_items_after_baseline(tmp_path):
    s = _scan(tmp_path)
    entries = [{"n": 1, "id": "CVE-1", "fingerprint": "", "package": "", "path": "", "reason": "r", "owner": "o",
                "expires": "2099-01-01", "used": 0}]
    s.policy = F.Policy(entries, [], intel())
    items = [F.vuln("sca", "Trivy", "CVE-1", "a", "1", "HIGH", "2", gating=True)]
    s.gate("sca", "Trivy (dependencies)", 1, "1 fixable CVEs", items=items)
    row = s.stages[-1]
    assert row["status"] == "passed" and "1 accepted in baseline" in row["findings"]
    assert s.findings[0]["tool"] == "Trivy (dependencies)"


def test_invalid_baseline_is_a_visible_error(tmp_path, monkeypatch):
    s = _scan(tmp_path)
    write(s.ws / ".sawone-baseline.yml", "exceptions:\n  - id: CVE-1\n")
    d = tmp_path / "intel"
    d.mkdir()
    (d / "kev.json").write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-1"}]}))
    monkeypatch.setenv("SCAN_INTEL_DIR", str(d))
    s.prepare_policy()
    rows = {r["tool"]: r for r in s.stages}
    assert rows["Baseline (.sawone-baseline.yml)"]["status"] == "error"
    assert rows["Risk intelligence (KEV/EPSS)"]["status"] == "report"


def test_missing_kev_feed_is_an_error_when_blocking_on_kev(tmp_path, monkeypatch):
    s = _scan(tmp_path)
    empty = tmp_path / "empty-intel"
    empty.mkdir()
    monkeypatch.setenv("SCAN_INTEL_DIR", str(empty))
    s.prepare_policy()
    assert any(r["stage"] == "policy" and r["status"] == "error" for r in s.stages)
    s2 = _scan(tmp_path / "b", {"policy": {"block_kev": False}})
    s2.prepare_policy()
    assert not any(r["stage"] == "policy" for r in s2.stages)


def test_zap_alerts_become_baselinable_findings(tmp_path):
    s = _scan(tmp_path)
    wrk = tmp_path / "zap"
    write(wrk / "rules.tsv", "40018\tFAIL\t(SQL Injection)\n10038\tWARN\t(CSP)\n")
    write(wrk / "zap.json", json.dumps({"site": [{"alerts": [
        {"pluginid": "40018", "alert": "SQL Injection", "riskcode": "3",
         "instances": [{"uri": "http://app:8080/search?q=1", "method": "GET", "param": "q"}]},
        {"pluginid": "10038", "alert": "CSP header not set", "riskcode": "2", "instances": [{"uri": "http://app:8080/"}]}]}]}))
    s._zap_gate("dast", "ZAP baseline", 1, wrk, "zap")
    assert s.stages[-1]["status"] == "failed"
    gating = [f for f in s.findings if f["gating"]]
    assert len(gating) == 1 and gating[0]["id"] == "40018" and gating[0]["location"] == "/search"


# ------------------------------------------------------------------ merge: PR new-only gating
def _part(root, name, stages, findings):
    d = root / name
    (d / "sarif").mkdir(parents=True)
    (d / "summary.json").write_text(json.dumps({"stages": stages, "enforce": True, "severity": ["HIGH", "CRITICAL"]}))
    (d / "findings.json").write_text(json.dumps(findings))
    return d


def test_pr_gate_new_passes_preexisting_and_fails_new(tmp_path):
    old = F.vuln("sca", "Trivy (dependencies)", "CVE-OLD", "a", "1", "HIGH", "2", gating=True)
    new = F.issue("sast", "Semgrep CE", "code", "sqli", "app.py", 3, "HIGH", "x", key="k", gating=True)
    a = _part(tmp_path, "p-sca", [{"stage": "sca", "tool": "Trivy (dependencies)", "status": "failed", "gate": True,
                                   "findings": "1 fixable"}], [old])
    b = _part(tmp_path, "p-sast", [{"stage": "sast", "tool": "Semgrep CE", "status": "failed", "gate": True,
                                    "findings": "1 ERROR"}], [new])
    code = merge_reports.merge(tmp_path / "m", [a, b], base_findings=[old], pr_gate="new")
    summ = json.loads((tmp_path / "m" / "summary.json").read_text())
    rows = {r["stage"]: r for r in summ["stages"]}
    assert rows["sca"]["status"] == "passed" and "already exist on the base branch" in rows["sca"]["findings"]
    assert rows["sast"]["status"] == "failed" and "1 new in this change" in rows["sast"]["findings"]
    assert summ["findings"]["new"] == 1 and summ["findings"]["new_blocking"] == 1
    assert code == 1
    md = (tmp_path / "m" / "summary.md").read_text()
    assert "1 new in this PR" in md and "🆕" in md


def test_pr_gate_all_keeps_failures_and_policy_rows_deduplicated(tmp_path):
    old = F.vuln("sca", "Trivy (dependencies)", "CVE-OLD", "a", "1", "HIGH", "2", gating=True)
    pol = {"stage": "policy", "tool": "Risk intelligence (KEV/EPSS)", "status": "report", "gate": False, "findings": "x"}
    a = _part(tmp_path, "p-sca", [{"stage": "sca", "tool": "Trivy (dependencies)", "status": "failed", "gate": True,
                                   "findings": "1"}, pol], [old])
    b = _part(tmp_path, "p-iac", [{"stage": "iac", "tool": "Trivy config", "status": "passed", "gate": True,
                                   "findings": "0"}, pol], [])
    code = merge_reports.merge(tmp_path / "m", [a, b], base_findings=[old], pr_gate="all")
    summ = json.loads((tmp_path / "m" / "summary.json").read_text())
    assert code == 1
    assert sum(1 for r in summ["stages"] if r["stage"] == "policy") == 1


def test_duplicates_merged_in_summary(tmp_path):
    t = F.vuln("container", "Trivy image (x)", "CVE-1", "openssl", "3", "HIGH", "4", gating=True)
    g = F.vuln("container", "Grype (x)", "CVE-1", "openssl", "3", "HIGH", "4", gating=True)
    a = _part(tmp_path, "p", [{"stage": "container", "tool": "Grype (x)", "status": "failed", "gate": True,
                               "findings": "1"}], [t, g])
    merge_reports.merge(tmp_path / "m", [a])
    summ = json.loads((tmp_path / "m" / "summary.json").read_text())
    assert summ["findings"]["unique"] == 1 and summ["findings"]["duplicates_merged"] == 1


# ------------------------------------------------------------------ compliance
def test_compliance_status_from_stages():
    stages = [{"stage": "sast", "tool": "Semgrep", "status": "failed"},
              {"stage": "secrets", "tool": "Gitleaks", "status": "passed"},
              {"stage": "dast", "tool": "ZAP", "status": "error"},
              {"stage": "iac", "tool": "Trivy", "status": "skipped"}]
    by = {(c["framework"], c["id"]): c["status"] for c in ds.compliance_status(stages)}
    assert by[("OWASP ASVS 4.0.3", "V2.10.4")] == "evidenced"
    assert by[("OWASP ASVS 4.0.3", "V5.5")] == "gap"
    assert by[("OWASP ASVS 4.0.3", "V14.4")] == "unverified"
    assert by[("NCA ECC-2:2024", "1-6-2-2")] == "not assessed"
    assert by[("SAMA CSF", "3.3.6")] == "gap"


def test_compliance_map_is_well_formed():
    import yaml
    m = yaml.safe_load((ROOT / "scanner" / "defaults" / "compliance.yml").read_text())
    valid = set(ds.STAGES) | {"policy", "licences"}
    for c in m["controls"]:
        assert c["framework"] in m["frameworks"]
        assert c["stages"] and set(c["stages"]) <= valid, c


def test_baseline_wildcard_id_with_path():
    e = [{"n": 1, "id": "AVD-AWS-*", "fingerprint": "", "package": "", "path": "legacy/*.tf", "reason": "r",
          "owner": "o", "expires": "2026-12-31", "used": 0}]
    a = F.issue("iac", "Trivy config", "config", "AVD-AWS-0107", "legacy/main.tf", 3, "HIGH", "x", key="1", gating=True)
    b = F.issue("iac", "Trivy config", "config", "AVD-AWS-0107", "new/main.tf", 3, "HIGH", "x", key="2", gating=True)
    c = F.issue("iac", "Trivy config", "config", "AVD-DS-0002", "legacy/main.tf", 3, "HIGH", "x", key="3", gating=True)
    F.Policy(e, [], intel()).apply([a, b, c])
    assert (a["gating"], b["gating"], c["gating"]) == (False, True, True)
