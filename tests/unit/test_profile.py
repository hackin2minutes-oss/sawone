"""Product profiles (SAWONE_PROFILE): another product adds stages, wording, rules, controls and its brand."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run(code, profile, tmp_path):
    env = dict(os.environ, SAWONE_PROFILE=str(profile), PYTHONPATH=str(ROOT / "scanner"))
    p = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, cwd=tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    return p.stdout


def test_a_profile_adds_stages_wording_controls_and_brand(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "x.yml").write_text("rules: []\n")
    controls = tmp_path / "masvs.yml"
    controls.write_text("frameworks: {masvs: OWASP MASVS 2}\ncontrols:\n"
                        "  - {framework: masvs, id: MASVS-PLATFORM-1, title: IPC, title_ar: ص, stages: [manifest]}\n")
    prof = tmp_path / "p.yml"
    prof.write_text(f"""brand: SawOne-A
report_title: "Mobile Application Security<br/>Assessment Report"
report_title_ar: "تقرير الجوال"
stages:
  - {{id: manifest, phase: code, after: sast, title: Android manifest, intro: Exported components., title_ar: بيان أندرويد}}
  - {{id: apk, phase: test, after: container, title: APK analysis, intro: The built app.}}
semgrep_rules: [{rules}]
compliance: {controls}
frameworks: [masvs, asvs]
evidence: {{manifest: ["sarif/*manifest*.sarif"]}}
elsewhere: {{deploy: "store release (Play Console)"}}
""")
    out = run("""
import json, phases, sawone_scan as s, report
print(json.dumps({"stages": s.STAGES, "phase": phases.phase_of("manifest"), "apk": phases.phase_of("apk"),
  "detail": report.DETAIL_STAGES, "title": report.stage_title("manifest"), "frameworks": s.DEFAULTS["compliance"]["frameworks"],
  "evidence": s.EVIDENCE_FILES["manifest"], "deploy": phases.ELSEWHERE["deploy"],
  "comp": [c["id"] for c in s.compliance_status([{"stage": "manifest", "tool": "x", "status": "passed"}], frameworks=["masvs"])]}))
""", prof, tmp_path)
    d = json.loads(out)
    assert d["stages"].index("manifest") == d["stages"].index("sast") + 1 and "apk" in d["stages"]
    assert d["phase"] == "code" and d["apk"] == "test" and d["title"] == "Android manifest"
    assert d["detail"].index("apk") == d["detail"].index("container") + 1
    assert d["frameworks"] == ["masvs", "asvs"] and d["comp"] == ["MASVS-PLATFORM-1"]
    assert d["evidence"] == ["sarif/*manifest*.sarif"] and d["deploy"].startswith("store release")
    r = tmp_path / "r"
    r.mkdir()
    (r / "findings.json").write_text("[]")
    (r / "findings-consolidated.json").write_text("[]")
    (r / "summary.json").write_text(json.dumps({"repository": "acme/app", "stages": [
        {"stage": "manifest", "tool": "Manifest checks", "status": "failed", "gate": True, "findings": "3"}]}))
    html = run(f"""
import report
from pathlib import Path
print(report.build(Path({str(r)!r}), "en")); print("=====AR====="); print(report.build(Path({str(r)!r}), "ar"))
""", prof, tmp_path)
    en, ar = html.split("=====AR=====")
    assert "SawOne-A" in en and ">Sawone<" not in en and "Mobile Application Security" in en
    assert "Code · Android manifest" in en
    assert "بيان أندرويد" in ar and "تقرير الجوال" in ar


def test_without_a_profile_nothing_changes(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "SAWONE_PROFILE"}
    p = subprocess.run([sys.executable, "-c", "import sawone_scan as s, report; print(len(s.STAGES), report.REPORT_TITLE)"],
                       env=dict(env, PYTHONPATH=str(ROOT / "scanner")), capture_output=True, text=True, cwd=tmp_path)
    assert p.stdout.strip() == "12 Application Security<br/>Assessment Report", p.stderr


def test_steps_can_be_overridden():
    sys.path.insert(0, str(ROOT / "scanner"))
    import sawone_scan as ds

    class Mobile(ds.Scan):
        def steps(self):
            return [("secrets", self.scan_secrets)]
    assert [s for s, _ in Mobile.steps(Mobile.__new__(Mobile))] == ["secrets"]


def test_the_job_summary_carries_the_brand(tmp_path):
    prof = tmp_path / "p.yml"
    prof.write_text("brand: SawOne-A\n")
    r = tmp_path / "r"
    (r / "logs").mkdir(parents=True)
    out = run(f"""
import sawone_scan as s
from pathlib import Path
s.render_outputs(Path({str(r)!r}), {{"stages": [{{"stage": "sast", "tool": "Semgrep CE", "status": "passed", "gate": True}}],
                                    "only": ["sast"]}})
print(Path({str(r)!r}, "summary.md").read_text().splitlines()[0])
""", prof, tmp_path)
    assert out.strip().endswith("## SawOne-A scan")


def test_a_profile_adds_report_chapters_in_place(tmp_path):
    (tmp_path / "sec.py").write_text(
        "def section(rep, R):\n"
        "    return rep.h1('AI security profile', 'ai') + '<p>' + R.T('Models found') + ' ' + R.esc(rep.d.repo) + '</p>'\n"
        "def broken(rep, R):\n"
        "    raise ValueError('boom')\n")
    prof = tmp_path / "p.yml"
    prof.write_text("brand: SawOne-SI\nreport_sections:\n  - {module: sec.py, after: details}\n"
                    "  - {module: sec.py, function: broken, after: compliance}\n"
                    "translations: {\"Models found\": \"النماذج\"}\n")
    r = tmp_path / "r"
    r.mkdir()
    (r / "findings.json").write_text("[]")
    (r / "findings-consolidated.json").write_text("[]")
    (r / "summary.json").write_text(json.dumps({"repository": "acme/ai", "stages": [
        {"stage": "sast", "tool": "Semgrep CE", "status": "passed", "gate": True, "findings": "0"}]}))
    html = run(f"""
import report
from pathlib import Path
print(report.build(Path({str(r)!r}), "en")); print("=====AR====="); print(report.build(Path({str(r)!r}), "ar"))
""", prof, tmp_path)
    en, ar = html.split("=====AR=====")
    assert en.index('id="details"') < en.index('id="ai"') < en.index('id="compliance"') if 'id="compliance"' in en \
        else en.index('id="details"') < en.index('id="ai"')
    assert "Models found acme/ai" in en and "AI security profile" in en and 'href="#ai"' in en
    assert "A product section could not be rendered: ValueError: boom" in en          # never costs the report
    assert "النماذج" in ar
