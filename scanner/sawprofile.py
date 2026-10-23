"""Product profiles: how another product built on the Sawone engine (SawOne-A for Android) adds its own stages.

SAWONE_PROFILE points to a YAML or JSON file. Without it, nothing changes. A profile may declare:

  brand: SawOne-A
  report_title: "Mobile Application Security<br/>Assessment Report"     # cover title (English)
  report_title_ar: "تقرير تقييم<br/>أمن تطبيقات الأجهزة المحمولة"
  stages:                       # new stages, in the order they run; each after an existing stage
    - {id: manifest, phase: code, after: sast, title: Android manifest, intro: "...", title_ar: ..., intro_ar: ...}
  semgrep_rules: [/opt/sawone-a/rules]      # extra local Semgrep rule files or directories
  compliance: /opt/sawone-a/masvs.yml       # extra controls (same format as defaults/compliance.yml)
  frameworks: [masvs, asvs, ssdf, ecc, cscc, sama, pdpl]   # default framework selection
  evidence: {manifest: ["sarif/*manifest*.sarif"]}           # evidence-pack files per stage
  phase_intros: {test: "..."}                                # replace a phase's introduction
  phase_intros_ar: {test: "..."}
  elsewhere: {deploy: "store release (Play Console)", monitor: "..."}   # phases done outside the scan
  translations: {"English text": "Arabic text"}             # extra report strings
"""
import json
import os
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def load(path=None):
    path = path or os.environ.get("SAWONE_PROFILE")
    if not path:
        return {}
    p = Path(path)
    try:
        text = p.read_text()
        data = json.loads(text) if p.suffix == ".json" else (yaml.safe_load(text) if yaml else {})
    except (OSError, ValueError) as e:
        raise SystemExit(f"ERROR: SAWONE_PROFILE {path}: {e}")
    if not isinstance(data, dict):
        raise SystemExit(f"ERROR: SAWONE_PROFILE {path}: not a mapping")
    for s in data.get("stages") or []:
        if not s.get("id") or not s.get("phase"):
            raise SystemExit(f"ERROR: SAWONE_PROFILE {path}: every stage needs an id and a phase")
    # file references are relative to the profile itself
    base = p.resolve().parent
    if data.get("semgrep_rules"):
        data["semgrep_rules"] = [str(base / r) if not Path(r).is_absolute() else r for r in data["semgrep_rules"]]
    if data.get("compliance") and not Path(data["compliance"]).is_absolute():
        data["compliance"] = str(base / data["compliance"])
    return data


PROFILE = load()
BRAND = PROFILE.get("brand") or "Sawone"
STAGES = PROFILE.get("stages") or []


def insert_stages(order, stages=None):
    """The base stage order with the profile's stages placed after their anchors (or at the end)."""
    out = list(order)
    for s in stages if stages is not None else STAGES:
        if s["id"] in out:
            continue
        after = s.get("after")
        out.insert(out.index(after) + 1 if after in out else len(out), s["id"])
    return out
