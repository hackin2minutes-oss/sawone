"""Threat model analysis: STRIDE, evidence matching, ownership, decisions, gaps, diagrams, report."""
import datetime as dt
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scanner"))
sys.path.insert(0, str(ROOT / "tests" / "unit"))
import findings as F  # noqa: E402
import report  # noqa: E402
import sawone_scan as ds  # noqa: E402
import threatmodel as TM  # noqa: E402
from test_scanner import FIX, make_scan  # noqa: E402


def model():
    """Browser -> app (container) -> SQL store; app -> third-party site in the Internet boundary."""
    el = lambda name, cls, b, files=(): {"name": name, "__class__": cls, "inBoundary": b, "sourceFiles": list(files)}
    return {
        "name": "shop", "description": "test",
        "actors": [el("Browser", "Actor", "Internet")],
        "elements": [el("Web app", "Process", "Container", ["app.py"]), el("DB", "Datastore", "Container"),
                     el("Partner site", "Process", "Internet")],
        "boundaries": [{"name": "Internet"}, {"name": "Container"}],
        "flows": [
            {"name": "request", "source": "Browser", "sink": "Web app", "order": 1, "protocol": "HTTP",
             "dstPort": 8080, "controls": {"isEncrypted": False}},
            {"name": "query", "source": "Web app", "sink": "DB", "order": 2, "protocol": "SQL", "controls": {}},
            {"name": "fetch", "source": "Web app", "sink": "Partner site", "order": 3, "controls": {}},
        ],
        "findings": [
            {"threat_id": "INP31", "target": "Web app", "severity": "Very High", "description": "Command Injection"},
            {"threat_id": "INP31", "target": "Partner site", "severity": "Very High", "description": "Command Injection"},
            {"threat_id": "INP27", "target": "Web app", "severity": "High", "description": "XSS"},
            {"threat_id": "CR03", "target": "Web app", "severity": "High", "description": "Dictionary attack"},
            {"threat_id": "DO01", "target": "Web app", "severity": "Medium", "description": "Flooding"},
            {"threat_id": "AA01", "target": "Web app", "severity": "Very High", "description": "Auth bypass"},
            {"threat_id": "DE01", "target": "request", "severity": "High", "description": "Interception"},
        ],
    }


def sast(rule, path, cwe=None):
    f = F.issue("sast", "Semgrep CE", "code", rule, path, 3, "HIGH", rule)
    f["cwe"] = cwe or []
    return f


def zap(pid, title):
    f = F.issue("dast", "ZAP full scan", "dast", str(pid), None, None, "HIGH", title)
    f["location"] = "/ping"
    return f


# ---------------------------------------------------------------- STRIDE and classification
def test_every_pytm_library_threat_has_a_stride_category():
    pytm = pytest.importorskip("pytm")
    lib = json.loads((Path(pytm.__file__).parent / "threatlib" / "threats.json").read_text())
    assert all(TM.stride_of(t["SID"]) in TM.STRIDE for t in lib)
    assert TM.stride_of("INP31") == "E" and TM.stride_of("DE01") == "I" and TM.stride_of("DO01") == "D"
    assert TM.stride_of("AA01") == "S" and TM.stride_of("DE04") == "R" and TM.stride_of("INP27") == "T"


def test_findings_are_classified_by_zap_id_cwe_and_rule():
    assert TM.classify(zap(40018, "SQL Injection")) == {"sql-injection"}
    assert "command-injection" in TM.classify(sast("subprocess-shell-true", "app.py", ["CWE-78"]))
    k8s = F.issue("iac", "Trivy config", "misconfig", "AVD-KSV-0001", "k8s/d.yaml", 1, "HIGH",
                  "Process can elevate its own privileges")
    assert TM.classify(k8s) == {"privilege"}                 # not "authentication"
    cve = F.vuln("sca", "Trivy (dependencies)", "CVE-1", "flask", "1.0", "HIGH")
    assert TM.classify(cve) == set()                          # component risk is not a design threat


# ---------------------------------------------------------------- analysis
def test_evidence_makes_threats_confirmed_or_in_code_and_skips_external_elements():
    fs = [zap(90020, "Remote OS Command Injection"), sast("subprocess-shell-true", "app.py", ["CWE-78"]),
          sast("weak-hash.md5", "app.py", ["CWE-327"])]
    a = TM.analyse(model(), fs)
    by = {(t["sid"], t["target"]): t for t in a["threats"]}
    assert by[("INP31", "Web app")]["status"] == "confirmed"
    assert by[("INP31", "Web app")]["evidence_total"] == 2
    assert by[("CR03", "Web app")]["status"] == "in-code"
    assert by[("INP31", "Partner site")]["status"] == "theoretical"     # a third party never takes our evidence
    assert by[("INP31", "Partner site")]["external"] and a["external"] == ["Partner site"]
    assert by[("INP27", "Web app")]["status"] == "theoretical"
    assert by[("INP31", "Web app")]["stride"] == "E"


def test_static_evidence_must_sit_in_the_elements_source_files():
    a = TM.analyse(model(), [sast("subprocess-shell-true", "other/worker.py", ["CWE-78"])])
    t = next(t for t in a["threats"] if t["sid"] == "INP31" and t["target"] == "Web app")
    assert t["status"] == "theoretical"
    a = TM.analyse(model(), [sast("subprocess-shell-true", "svc/web/app.py", ["CWE-78"])])  # scanned from a parent dir
    t = next(t for t in a["threats"] if t["sid"] == "INP31" and t["target"] == "Web app")
    assert t["status"] == "in-code"


def test_dast_evidence_needs_an_exposed_element():
    m = model()
    m["flows"] = [f for f in m["flows"] if f["name"] != "request"]           # nothing reaches the app from outside
    a = TM.analyse(m, [zap(90020, "Remote OS Command Injection")])
    t = next(t for t in a["threats"] if t["sid"] == "INP31" and t["target"] == "Web app")
    assert t["status"] == "theoretical"


def test_decisions_mitigate_accept_and_a_contradicted_mitigation():
    fs = [zap(90020, "Remote OS Command Injection")]
    dec = [{"threat": "INP31", "element": "Web app", "decision": "mitigate", "control": "no shell", "owner": "a",
            "expires": "2027-01-01", "reason": ""},
           {"threat": "DO01", "element": "*", "decision": "accept", "control": "", "owner": "a",
            "expires": "2027-01-01", "reason": "rate limited upstream"},
           {"threat": "INP27", "element": "Web app", "decision": "mitigate", "control": "autoescaping", "owner": "a",
            "expires": "2027-01-01", "reason": ""}]
    a = TM.analyse(model(), fs, dec)
    by = {(t["sid"], t["target"]): t for t in a["threats"]}
    assert by[("INP31", "Web app")]["status"] == "contradicted" and by[("INP31", "Web app")]["gating"]
    assert by[("DO01", "Web app")]["status"] == "accepted" and not by[("DO01", "Web app")]["gating"]
    assert by[("INP27", "Web app")]["status"] == "mitigated"
    assert a["counts"]["contradicted"] == 1


def test_legacy_mitigated_dict_still_counts():
    a = TM.analyse(model(), [], mitigated={"AA01@Web app": "SSO in front"})
    t = next(t for t in a["threats"] if t["sid"] == "AA01")
    assert t["status"] == "mitigated" and not t["gating"]


def test_scanner_evidence_without_a_matching_threat_is_a_model_gap():
    f = zap(40046, "Server Side Request Forgery")
    a = TM.analyse(model(), [f])
    assert [g["class"] for g in a["gaps"]] == ["ssrf"] and a["gaps"][0]["confirmed"] == 1


def test_false_positives_are_not_evidence():
    f = zap(90020, "Remote OS Command Injection")
    f["baselined"] = {"type": "false-positive"}
    a = TM.analyse(model(), [f])
    assert next(t for t in a["threats"] if t["sid"] == "INP31" and t["target"] == "Web app")["status"] == "theoretical"


def test_stride_matrix_and_worst_status():
    a = TM.analyse(model(), [zap(90020, "Remote OS Command Injection")])
    assert a["matrix"]["Web app"]["cells"]["E"] == ["confirmed"]
    assert a["worst"]["Web app"] == "confirmed" and "Browser" not in a["matrix"]
    assert sum(a["by_stride"].values()) == a["total"] == 7


# ---------------------------------------------------------------- decisions file
def test_threat_decisions_are_validated(tmp_path):
    today = dt.date(2026, 10, 22)
    p = tmp_path / "b.yml"
    p.write_text("""threats:
  - {threat: INP31, element: Web app, decision: mitigate, control: no shell, owner: a, expires: 2027-01-01}
  - {threat: DO01, decision: accept, reason: upstream limit, owner: a, expires: 2026-01-01}
  - {threat: CR03, decision: mitigate, owner: a, expires: 2027-01-01}
  - {threat: AA01, decision: ignore, owner: a, expires: 2027-01-01, reason: x}
  - {threat: AC21, decision: accept, reason: x, owner: a, expires: 2030-01-01}
  - {threat: DE01, decision: transfer, owner: a, expires: 2027-01-01}
""")
    active, expired, errors = TM.load_decisions(p, today=today)
    assert [d["threat"] for d in active] == ["INP31"] and active[0]["element"] == "Web app"
    assert [d["threat"] for d in expired] == ["DO01"]
    assert len(errors) == 4
    assert any("needs the control" in e for e in errors) and any("mitigate, accept or transfer" in e for e in errors)
    assert any("more than 365 days" in e for e in errors) and any("transfer needs a reason" in e for e in errors)


def test_the_gate_respects_baseline_decisions(tmp_path):
    s = make_scan(tmp_path, FIX / "python-flask")
    if s.inv.get("threat_model") is None:
        pytest.skip("fixture has no threat model")
    pytest.importorskip("pytm")
    s.run = ds.Scan.run.__get__(s)          # run pytm for real
    s.scan_threat_model()
    row = next(r for r in s.stages if r["stage"] == "threat-model")
    dec = json.loads((s.reports / "raw" / "threat-decisions.json").read_text())
    assert dec["active"][0]["threat"] == "INP31" and "1 decision(s)" in row["findings"]
    inp31 = [f for f in s.findings if f["id"] == "INP31" and "Flask API" in f["title"]]
    assert inp31 and not inp31[0]["gating"]


# ---------------------------------------------------------------- diagrams and report
def test_dfd_source_and_sequence_svg():
    a = TM.analyse(model(), [zap(90020, "Remote OS Command Injection")])
    dot = TM.dfd_dot(model(), a)
    assert "subgraph cluster_" in dot and 'label="Container"' in dot and "shape=cylinder" in dot
    assert "1. request\\nHTTP:8080\\n(unencrypted)" in dot and 'color="#b91c1c"' in dot     # confirmed element in red
    svg = TM.sequence_svg(model())
    assert svg.startswith("<svg") and svg.count("<line") >= 3 + 4 and "1. request" in svg


@pytest.mark.skipif(not shutil.which("dot"), reason="Graphviz not installed")
def test_dfd_renders_with_graphviz(tmp_path):
    assert TM.render_dot(TM.dfd_dot(model()), tmp_path / "dfd.svg")
    assert (tmp_path / "dfd.svg").read_text().startswith("<svg")


def test_build_writes_analysis_and_report_chapter(tmp_path):
    r = tmp_path / "r"
    (r / "raw" / "p").mkdir(parents=True)
    m = model()
    (r / "raw" / "p" / "threats.json").write_text(json.dumps(m))
    fs = F.consolidate([zap(90020, "Remote OS Command Injection")])
    (r / "findings.json").write_text(json.dumps(fs))
    (r / "findings-consolidated.json").write_text(json.dumps(fs))
    a = ds.threat_analysis(r, fs)
    assert a and (r / "threat-model.json").exists() and (r / "threatmodel" / "sequence.svg").exists()
    stages = [{"stage": "threat-model", "tool": "OWASP pytm", "status": "failed", "gate": True, "findings": "7 threats",
               "reason": ""}]
    (r / "summary.json").write_text(json.dumps({"repository": "acme/shop", "stages": stages}))
    en = report.build(r, "en")
    assert "STRIDE per element" in en and "Threats with scanner evidence (1)" in en and "Gaps in the model" not in en
    assert "Confirmed" in en and "Partner site" in en
    ar = report.build(r, "ar")
    assert "STRIDE لكل عنصر" in ar and "قرارات المخاطر" not in ar and "تهديدات نظرية" in ar


def test_a_contradicted_mitigation_fails_the_gate_once_the_evidence_is_in(tmp_path):
    r = tmp_path / "r"
    (r / "raw" / "p").mkdir(parents=True)
    (r / "logs").mkdir()
    (r / "raw" / "p" / "threats.json").write_text(json.dumps(model()))
    (r / "raw" / "p" / "threat-decisions.json").write_text(json.dumps({"active": [
        {"threat": "INP31", "element": "Web app", "decision": "mitigate", "control": "no shell", "owner": "a",
         "expires": "2027-01-01", "reason": ""}], "min_severity": "Very High"}))
    threat = F.issue("threat-model", "OWASP pytm", "threat", "INP31", "threatmodel/tm.py", None, "CRITICAL",
                     "Command Injection — Web app", key="Web app", gating=False)    # decided in the gate job
    (r / "findings.json").write_text(json.dumps([threat, zap(90020, "Remote OS Command Injection")]))
    stages = [{"stage": "threat-model", "tool": "OWASP pytm", "status": "passed", "gate": True,
               "findings": "7 threats, 0 open at ≥ Very High · 1 decision(s)"},
              {"stage": "dast", "tool": "ZAP full scan", "status": "passed", "gate": True, "findings": ""}]
    summary = {"repository": "acme/shop", "stages": stages, "enforce": True, "options": {"languages": ["en"]}}
    code = ds.render_outputs(r, summary)
    row = next(s for s in summary["stages"] if s["stage"] == "threat-model")
    assert row["status"] == "failed" and "1 mitigation(s) contradicted" in row["findings"] and code == 1
    merged = json.loads((r / "findings-consolidated.json").read_text())
    assert any(f["id"] == "INP31" and f["gating"] for f in merged)
    assert summary["threat_model"]["counts"]["contradicted"] == 1
    assert "mitigation(s) contradicted by evidence" in (r / "summary.md").read_text()


def test_flows_take_attack_evidence_only_and_unscoped_processes_are_named():
    m = model()
    tls = F.issue("iac", "Trivy config", "misconfig", "AVD-AWS-0054", "infra/lb.tf", 3, "HIGH",
                  "Load balancer listener does not use HTTPS")
    a = TM.analyse(m, [tls])
    assert next(t for t in a["threats"] if t["sid"] == "DE01")["status"] == "theoretical"
    hsts = zap(10035, "Strict-Transport-Security Header Not Set")
    a = TM.analyse(m, [hsts])
    assert next(t for t in a["threats"] if t["sid"] == "DE01")["status"] == "confirmed"
    assert a["unscoped"] == []                                            # one owned process: nothing to say
    m["elements"].append({"name": "Worker", "__class__": "Process", "inBoundary": "Container", "sourceFiles": []})
    m["elements"][0]["sourceFiles"] = []
    assert TM.analyse(m, [])["unscoped"] == ["Web app", "Worker"]
