#!/usr/bin/env python3
"""
Sawone — enterprise security assessment report (PDF + HTML).

usage: report.py --reports sawone-reports --out security-report.pdf [--html security-report.html]

Reads everything a scan (or a merged pipeline run) left in the reports directory; every input is
optional and a missing one is reported as such, never silently skipped:

  summary.json                    stages, jobs, release facts, findings summary, compliance, PR facts
  findings.json                   every normalised finding, per tool (severity, gating, KEV, EPSS, baseline)
  findings-consolidated.json      the same findings with cross-tool duplicates merged
  sarif/*.sarif                   tools that only report SARIF (Checkov, OSV, kube-linter, Hadolint, Nuclei …)
  zap.json, zap-full.json, zap-api.json   OWASP ZAP alerts with instances and remediation
  waf-results.txt                 runtime-protection checks
  raw/**/threats.json             OWASP pytm output
  raw/**/sbom-*.cdx.json          CycloneDX SBOMs;  raw/**/images.json   images that were scanned
  tools.json                      tool versions resolved for the run
  logs/**                         tool logs (tail shown for failed pass/fail-only tools)
  env REPO, SHA, REF, RUN_URL     run context

Layout: cover · contents · 1 executive summary · 2 scope and method · 3 gate results ·
4 risk-ranked findings · 5 detailed results (one section per stage, one subsection per tool) ·
6 compliance evidence · 7 accepted risks · 8 supply chain · appendices.
"""
import argparse
import datetime as dt
import glob
import html
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

try:
    from report_i18n import AR
except ImportError:  # pragma: no cover — report.py copied on its own
    AR = {}

LANG = "en"


def T(text, **kw):
    """Translate a fixed English text (or template) into the report language, then fill it in.
    Keys are the English text with whitespace collapsed; anything without a translation stays English
    (tool output — finding titles, rule IDs, paths — is never translated)."""
    key = re.sub(r"\s+", " ", text).strip()
    out = AR.get(key, text) if LANG == "ar" else _plurals(text, kw)
    return out.format(**kw) if kw else out


def _plurals(text, kw):
    """English: 'vulnerability(ies)' / 'scanner(s)' agree with the nearest number placeholder before them."""
    def fix(m):
        before = [v for v in re.findall(r"\{(\w+)\}", text[:m.start()]) if isinstance(kw.get(v), int)]
        many = kw[before[-1]] != 1 if before else True
        stem, suffix = m.group(1), m.group(2)
        if suffix == "ies":   # vulnerability(ies)
            return stem[:-1] + ("ies" if many else "y")
        return stem + ("s" if many else "")
    return re.sub(r"(\w+)\((s|ies)\)", fix, text) if kw else text

# ------------------------------------------------------------------ vocabulary
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEV_LABEL = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Unrated"}
SEV_RANK = {s: i for i, s in enumerate(SEVS)}
LEVEL_SEV = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}
STATUS_LABEL = {"passed": "Passed", "failed": "Failed", "error": "Scanner error", "skipped": "Skipped",
                "report": "Report only", "success": "Passed", "failure": "Failed", "cancelled": "Cancelled"}
STATUS_CLS = {"passed": "ok", "success": "ok", "failed": "bad", "failure": "bad", "error": "warn",
              "cancelled": "warn", "skipped": "skip", "report": "info"}

STAGE_INFO = {
    "policy": ("Risk policy",
               "Baseline exceptions and the threat-intelligence feeds (CISA KEV, FIRST EPSS) that decide which "
               "findings block."),
    "pipeline": ("Pipeline integrity", "Jobs that crashed or produced no report."),
    "scanner": ("Scanner", "The scanner's own health."),
    "threat-model": ("Threat modelling",
                     "Design-level threats derived from the threat model kept in the repository. Every threat at or "
                     "above the configured severity must be fixed or carry a recorded decision."),
    "secrets": ("Secrets detection",
                "Credentials, keys and tokens committed to the repository, including its full Git history "
                "(Gitleaks), and secrets verified live against their provider (TruffleHog)."),
    "sast": ("Static application security testing (SAST)",
             "Source code analysed for injection, unsafe deserialisation, weak cryptography and other code-level "
             "flaws (Semgrep)."),
    "sca": ("Software composition analysis (SCA)",
            "Third-party dependencies checked against vulnerability databases (Trivy, with OSV-Scanner as a "
            "cross-check), and a software bill of materials of the repository itself (Syft)."),
    "licences": ("Licence compliance", "Dependency licences checked for restricted or forbidden terms (Trivy)."),
    "iac": ("Infrastructure as code (IaC)",
            "Terraform, Dockerfiles and other configuration checked for insecure settings (Trivy config, with "
            "Checkov as a second opinion, and Hadolint for Dockerfiles)."),
    "kubernetes": ("Kubernetes and Helm",
                   "Manifests validated against the Kubernetes schemas (kubeconform) and reviewed for workload "
                   "hardening (kube-linter, optional OPA policies)."),
    "cicd": ("CI/CD pipeline security",
             "Workflow definitions checked for errors (actionlint) and for supply-chain risks such as script "
             "injection, excessive permissions and unpinned actions (zizmor)."),
    "container": ("Container image security",
                  "The image built from this commit: its software bill of materials (Syft), known vulnerabilities "
                  "in OS and language packages (Trivy, cross-checked by Grype), secrets left in its layers, and "
                  "CIS image benchmark checks (Dockle)."),
    "dast": ("Dynamic application security testing (DAST)",
             "The running application attacked from outside: passive baseline, active full scan and API scan "
             "driven by the OpenAPI specification (OWASP ZAP), plus template checks (Nuclei). When credentials "
             "are configured the scans run as a logged-in user."),
    "iast": ("Interactive application security testing (IAST)",
             "An agent inside the running application observed data flows during the scanner's traffic."),
    "runtime": ("Runtime protection",
                "A web application firewall (ModSecurity with the OWASP Core Rule Set) placed in front of the "
                "application, checked to block common attacks while letting legitimate traffic through."),
    "tracking": ("Vulnerability tracking", "Results imported into DefectDojo for triage and tracking."),
}
DETAIL_STAGES = ["threat-model", "secrets", "sast", "sca", "licences", "iac", "kubernetes", "cicd",
                 "container", "dast", "iast", "runtime", "tracking"]
GATE_ORDER = ["policy", "pipeline", "scanner"] + DETAIL_STAGES

# SARIF category (from automationDetails "sawone/<category>/<n>/") for each tool, used when a tool's
# findings are not in findings.json (report-only tools, or an older scanner)
TOOL_SARIF = {"Gitleaks": "gitleaks", "Semgrep CE": "semgrep", "Trivy (dependencies)": "trivy-sca",
              "Trivy config": "trivy-iac", "Checkov": "checkov", "OSV-Scanner": "osv", "kube-linter": "kube-linter",
              "Hadolint": "hadolint", "Nuclei": "nuclei", "zizmor": "zizmor"}
UNRATED_TOOLS = {"checkov"}          # the tool assigns no real severity (Checkov without its platform key)
PASS_FAIL_TOOLS = {"actionlint": "actionlint", "kubeconform": "kubeconform", "Conftest (OPA)": "conftest",
                   "Hadolint": "hadolint-"}
VULN_TOOLS = ("Trivy (dependencies)", "Trivy image", "Grype")
MAX_ROWS = 40


# ------------------------------------------------------------------ helpers
def esc(x):
    return html.escape(str(x if x is not None else ""))


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def read_lines(path):
    try:
        return [line.rstrip("\n") for line in open(path) if line.strip()]
    except OSError:
        return None


def norm_sev(s):
    s = str(s or "UNKNOWN").strip().upper()
    s = {"NEGLIGIBLE": "LOW", "INFO": "LOW", "INFORMATIONAL": "LOW", "WARNING": "MEDIUM", "MODERATE": "MEDIUM",
         "ERROR": "HIGH", "IMPORTANT": "HIGH", "VERY HIGH": "CRITICAL"}.get(s, s)
    return s if s in SEV_RANK else "UNKNOWN"


def strip_html(s, n=400):
    s = re.sub(r"<[^>]+>", " ", str(s or ""))
    s = re.sub(r"\s+", " ", html.unescape(s)).strip()
    return s if len(s) <= n else s[: n - 1].rsplit(" ", 1)[0] + "…"


def first_sentence(s, n=170):
    """The first sentence of a long advice text, capped at n characters."""
    m = re.match(r"(.+?[.!?])(\s|$)", s or "")
    return short(m.group(1) if m else s, n)


def short(s, n=140):
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def vkey(v):
    """Rough version ordering, good enough to pick the highest fix version to recommend."""
    return [int(x) if x.isdigit() else 0 for x in re.split(r"[^0-9]+", str(v)) if x != ""]


def plural(n, word, many=None):
    return f"{n} {word if n == 1 else (many or word + 's')}"


def stage_title(st):
    return T(STAGE_INFO.get(st, (st, ""))[0])


def stage_intro(st):
    return T(STAGE_INFO.get(st, (st, ""))[1])


def short_tool(t):
    """Tool name without the image label: 'Trivy image (app:sha)' -> 'Trivy image'."""
    t = str(t or "")
    return t.split(" (")[0] if t.startswith(("Trivy image (", "Grype (")) else t


def compact_path(p, n=48):
    p = str(p or "")
    if len(p) <= n or "/" not in p:
        return p
    parts = p.split("/")
    tail = "/".join(parts[-2:])
    return "…/" + (tail if len(tail) <= n else parts[-1])


def sev_pill(sev):
    sev = norm_sev(sev)
    return f'<span class="sev sev-{sev.lower()}">{T(SEV_LABEL[sev])}</span>'


def status_pill(status):
    return f'<span class="pill {STATUS_CLS.get(status, "warn")}">{esc(T(STATUS_LABEL.get(status, status)))}</span>'


def finding_state(f):
    if f.get("baselined"):
        fp = (f["baselined"] or {}).get("type") == "false-positive" if isinstance(f["baselined"], dict) else False
        return f'<span class="pill skip">{T("False positive") if fp else T("Accepted")}</span>'
    if f.get("gating"):
        return f'<span class="pill bad">{T("Blocking")}</span>'
    return f'<span class="pill neutral">{T("Tracked")}</span>'


def signals(f):
    out = []
    if f.get("kev"):
        out.append('<span class="tag kev">KEV' + (" · ransomware" if f.get("kev_ransomware") else "") + "</span>")
    if f.get("epss"):
        out.append(f'<span class="tag">EPSS {f["epss"]:.2f}</span>')
    if f.get("verified"):
        out.append(f'<span class="tag kev">{T("LIVE")}</span>')
    if f.get("new"):
        out.append(f'<span class="tag new">{T("New")}</span>')
    if f.get("overdue"):
        out.append(f'<span class="tag kev">{T("overdue since {d}", d=esc(f.get("sla_due")))}</span>')
    if f.get("escalated") and f.get("gating"):
        out.append(f'<span class="tag">{T("escalated")}</span>')
    if f.get("exception_expired"):
        out.append(f'<span class="tag">{T("exception expired {d}", d=esc(f["exception_expired"]))}</span>')
    if f.get("related"):
        rel = ", ".join(short(x.split(".")[-1], 40) for x in f["related"][:3])
        more = " +" + str(len(f["related"]) - 3) if len(f["related"]) > 3 else ""
        out.append(f'<span class="tag">{T("also: {r}", r=esc(rel) + more)}</span>')
    return " ".join(out)


def sarif_category(run, path):
    cid = (run.get("automationDetails") or {}).get("id") or ""
    parts = [p for p in cid.split("/") if p]
    cat = parts[1] if len(parts) >= 2 else Path(path).stem
    return re.sub(r"-\d+$", "", cat) if cat.startswith("hadolint") else cat


def parse_sarif_dir(reports):
    """{category: [finding]} for every SARIF file, with severity normalised per tool."""
    out = defaultdict(list)
    for path in sorted(glob.glob(str(reports / "**" / "*.sarif"), recursive=True)):
        data = load_json(path) or {}
        for run in data.get("runs", []) or []:
            cat = sarif_category(run, path)
            rules = {r.get("id"): r for r in (run.get("tool") or {}).get("driver", {}).get("rules", []) or []}
            for r in run.get("results", []) or []:
                rule = rules.get(r.get("ruleId")) or {}
                sev = None
                for props in (r.get("properties") or {}, rule.get("properties") or {}):
                    try:
                        s = float(props.get("security-severity"))
                        sev = "CRITICAL" if s >= 9 else "HIGH" if s >= 7 else "MEDIUM" if s >= 4 else "LOW"
                        break
                    except (TypeError, ValueError):
                        continue
                if sev is None:
                    sev = "UNKNOWN" if cat in UNRATED_TOOLS else LEVEL_SEV.get(
                        r.get("level") or (rule.get("defaultConfiguration") or {}).get("level"), "MEDIUM")
                loc = ""
                try:
                    pl = r["locations"][0]["physicalLocation"]
                    loc = pl["artifactLocation"]["uri"]
                    line = (pl.get("region") or {}).get("startLine")
                    loc += f":{line}" if line else ""
                except (KeyError, IndexError, TypeError):
                    pass
                msg = ((r.get("message") or {}).get("text") or "").strip().split("\n")[0]
                title = (rule.get("shortDescription") or {}).get("text") or msg
                out[cat].append({"id": r.get("ruleId", ""), "severity": sev, "location": loc.removeprefix("file://"),
                                 "title": short(title, 200), "detail": short(msg, 200), "gating": False,
                                 "package": "", "version": "", "fixed_version": ""})
    return out


# ------------------------------------------------------------------ data
class Data:
    def __init__(self, reports: Path):
        env = os.environ
        self.reports = reports
        self.summary = load_json(reports / "summary.json") or {}
        s = self.summary
        stages = s.get("stages") or []
        if not stages and env.get("RESULTS"):  # legacy: job results only
            stages = [{"stage": k, "tool": "", "status": {"success": "passed", "failure": "failed"}.get(
                v.get("result"), v.get("result")), "gate": True, "findings": "", "reason": ""}
                for k, v in json.loads(env["RESULTS"]).items()]
        self.stages = stages
        self.enforce = s.get("enforce", True) is not False
        self.threshold = "/".join(s.get("severity") or ["HIGH", "CRITICAL"])
        self.release = s.get("release") or {}
        self.jobs = s.get("jobs") or []
        self.inv = s.get("inventory") or load_json(reports / "inventory.json") or {}
        self.pr = s.get("pr") or {}
        self.fs = s.get("findings") or {}
        self.compliance = s.get("compliance") or []
        tools = load_json(reports / "tools.json") or s.get("tools") or {}
        rel_tv = (s.get("release") or {}).get("Tool versions") or ""
        self.version_policy = rel_tv or tools.get("_policy", "")
        self.tools = {k: v for k, v in tools.items() if not k.startswith("_")}
        self.repo = env.get("REPO") or s.get("repository") or "repository"
        self.sha, self.ref, self.run_url = env.get("SHA", ""), env.get("REF", ""), env.get("RUN_URL", "")
        self.generated = dt.datetime.now(dt.timezone.utc)

        self.raw = load_json(reports / "findings.json") or []
        self.merged = load_json(reports / "findings-consolidated.json") or []
        new_fp = {f["fingerprint"] for f in self.merged if f.get("new")}
        for f in self.raw:
            f["severity"] = norm_sev(f.get("severity"))
            if f.get("fingerprint") in new_fp:
                f["new"] = True
        for f in self.merged:
            f["severity"] = norm_sev(f.get("severity"))
        self.sarif = parse_sarif_dir(reports)
        self.zap = {name: load_json(reports / name) for name in ("zap.json", "zap-full.json", "zap-api.json")}
        self.waf = read_lines(reports / "waf-results.txt")
        tm_files = sorted(glob.glob(str(reports / "raw" / "**" / "threats.json"), recursive=True)) + \
            [str(p) for p in (reports / "threats.json", reports / "threat-model" / "threats.json") if p.exists()]
        self.threats = next((d for d in map(load_json, tm_files) if d), None)
        self.sboms = []
        for p in sorted(glob.glob(str(reports / "raw" / "**" / "sbom-*.cdx.json"), recursive=True)):
            d = load_json(p) or {}
            comps = d.get("components", []) or []
            self.sboms.append({"source": Path(p).name == "sbom-source.cdx.json", "file": Path(p).name, "packages": sum(1 for c in comps if c.get("type") != "file"),
                               "files": sum(1 for c in comps if c.get("type") == "file"),
                               "types": Counter(c.get("type") for c in comps if c.get("type") != "file")})
        self.images = []
        for p in sorted(glob.glob(str(reports / "raw" / "**" / "images.json"), recursive=True)):
            for img in load_json(p) or []:
                if img.get("dockerfile") not in [i.get("dockerfile") for i in self.images]:
                    self.images.append(img)

        gate_rows = [r for r in stages if r.get("gate", True) and r["status"] != "skipped"]
        self.failed = [r for r in stages if r["status"] == "failed" and r.get("gate", True)]
        self.errors = [r for r in stages if r["status"] == "error"]
        self.passed = [r for r in gate_rows if r["status"] == "passed"]
        self.gates_total = len([r for r in gate_rows if r["status"] in ("passed", "failed", "error")])
        self.blocking = [f for f in self.merged if f.get("gating")]

    # findings of one gate row: normalised findings first, then that tool's SARIF
    def tool_findings(self, row):
        items = [f for f in self.raw if f.get("stage") == row["stage"] and f.get("tool") == row["tool"]]
        if items:
            return items, "findings.json"
        tool = row.get("tool") or ""
        cat = TOOL_SARIF.get(tool) or TOOL_SARIF.get(tool.split(" (")[0])
        if tool.startswith(("Trivy image (", "Grype (")):
            label = tool[tool.index("(") + 1:-1]
            img = next((i for i in self.images if i.get("dockerfile") == label), None)
            if img:
                cat = ("trivy-image-" if tool.startswith("Trivy") else "grype-") + img["name"]
        if cat and self.sarif.get(cat):
            return self.sarif[cat], f"sarif ({cat})"
        return [], None

    def log_tail(self, name, n=14):
        hits = sorted(glob.glob(str(self.reports / "logs" / "**" / f"{name}*.log"), recursive=True))
        if not hits:
            return None
        lines = [line for line in (read_lines(hits[0]) or []) if not line.startswith("[exit code")]
        return lines[-n:]


# ------------------------------------------------------------------ rendering primitives
def table(headers, rows, cls="", widths=None):
    cols = "".join(f'<col style="width:{w}"/>' for w in widths) if widths else ""
    head = "".join(f"<th>{T(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<table class="{cls}"><colgroup>{cols}</colgroup><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def kv(rows):
    return '<table class="kv">' + "".join(
        f"<tr><th>{esc(T(k))}</th><td>{v}</td></tr>" for k, v in rows) + "</table>"


def note(text, cls="muted"):
    return f'<p class="{cls}">{text}</p>'


def callout(text, kind="info"):
    return f'<div class="callout {kind}">{text}</div>'


def sev_counts(items):
    c = Counter(norm_sev(f.get("severity")) for f in items)
    return c


def sev_strip(c):
    """Inline severity counts: Critical 3 · High 12 …"""
    return " ".join(f'<span class="cnt sev-{s.lower()}">{T(SEV_LABEL[s])} <b>{c.get(s, 0)}</b></span>'
                    for s in SEVS if c.get(s, 0))


def bar_svg(c, width=150, height=9):
    total = sum(c.get(s, 0) for s in SEVS)
    if not total:
        return ""
    x, parts = 0.0, []
    colors = {"CRITICAL": "#7f1d1d", "HIGH": "#dc2626", "MEDIUM": "#f59e0b", "LOW": "#3b82f6", "UNKNOWN": "#9ca3af"}
    for s in SEVS:
        w = width * c.get(s, 0) / total
        if w:
            parts.append(f'<rect x="{x:.2f}" y="0" width="{w:.2f}" height="{height}" fill="{colors[s]}"/>')
            x += w
    return (f'<svg class="bar" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
            f'xmlns="http://www.w3.org/2000/svg">{"".join(parts)}</svg>')


def sort_findings(items):
    return sorted(items, key=lambda f: (not f.get("gating"), not f.get("kev"), SEV_RANK[norm_sev(f.get("severity"))],
                                        -(f.get("epss") or 0), str(f.get("id"))))


def where(f):
    if f.get("package"):
        pv = f"{f['package']} {f.get('version') or ''}".strip()
        return f'<span class="mono">{esc(pv)}</span>' + (
            f'<br/><span class="muted small">{esc(compact_path(f.get("location")))}</span>' if f.get("location") else "")
    locs = f.get("locations")
    if locs:
        shown = ", ".join(compact_path(x, 40) for x in locs[:6])
        more = f' <span class="muted small">{T("+{n} more", n=len(locs) - 6)}</span>' if len(locs) > 6 else ""
        return f'<span class="mono">{esc(shown)}</span>{more}'
    return f'<span class="mono">{esc(compact_path(f.get("location"), 80))}</span>'


def group_by_rule(items):
    """One row per rule: the same check firing in several places becomes one row with every location."""
    groups = {}
    for f in items:
        k = (str(f.get("id")), str(f.get("title")), f.get("severity"), bool(f.get("gating")), bool(f.get("baselined")))
        g = groups.get(k)
        if g is None:
            g = dict(f)
            g["locations"] = []
            groups[k] = g
        loc = f.get("location")
        if loc and loc not in g["locations"]:
            g["locations"].append(loc)
        for x in ("kev", "new"):
            g[x] = g.get(x) or f.get(x)
    out = list(groups.values())
    for g in out:
        if len(g["locations"]) <= 1:
            g.pop("locations")
    return out


def findings_table(items, limit=MAX_ROWS, show_tool=False, source=None, group=False):
    items = sort_findings(group_by_rule(items) if group else items)
    rows = []
    for f in items[:limit]:
        title = esc(short(f.get("title") or f.get("id"), 180))
        idl = esc(short(f.get("id"), 120))
        desc = f'<span class="mono small">{idl}</span><br/>{title}' if title and title != idl else f'<span class="mono">{idl}</span>'
        extra = signals(f)
        row = [sev_pill(f.get("severity")), desc + (f"<br/>{extra}" if extra else ""), where(f)]
        if show_tool:
            row.append(esc(", ".join(dict.fromkeys(short_tool(t) for t in (f.get("tools") or [f.get("tool", "")])))))
        row.append(finding_state(f))
        rows.append(row)
    headers = ["Severity", "Finding", "Location"] + (["Found by"] if show_tool else []) + ["Status"]
    widths = (["10%", "42%", "23%", "14%", "11%"] if show_tool else ["11%", "52%", "26%", "11%"])
    out = table(headers, rows, "findings", widths)
    if len(items) > limit:
        out += note(T("Showing the {limit} highest-priority of {total} rules. Full list: {src} in the report artefact."
                      if group else
                      "Showing the {limit} highest-priority of {total} findings. Full list: {src} in the report artefact.",
                      limit=limit, total=len(items), src=f'<span class="mono">{esc(source or "findings.json")}</span>'))
    return out


def vuln_by_cve(items, limit=MAX_ROWS, source=None):
    """Vulnerabilities grouped by advisory: one row per CVE with every affected package."""
    groups = {}
    for f in items:
        g = groups.setdefault(f.get("id") or "?", {"id": f.get("id"), "severity": f["severity"], "pk": {},
                                                    "fixed": set(), "gating": False, "kev": False, "epss": 0,
                                                    "baselined": None, "title": f.get("title"), "new": False})
        g["pk"].setdefault(f.get("package") or "?", f.get("version") or "")
        if f.get("fixed_version"):
            g["fixed"].add(f["fixed_version"])
        if SEV_RANK[f["severity"]] < SEV_RANK[g["severity"]]:
            g["severity"] = f["severity"]
        for k in ("gating", "kev", "new"):
            g[k] = g[k] or bool(f.get(k))
        g["epss"] = max(g["epss"], f.get("epss") or 0)
        g["baselined"] = g["baselined"] or f.get("baselined")
        g["kev_ransomware"] = g.get("kev_ransomware") or f.get("kev_ransomware")
    rows = []
    ordered = sort_findings(list(groups.values()))
    for g in ordered[:limit]:
        pk = ", ".join(f"{p} {v}".strip() for p, v in sorted(g["pk"].items()))
        fixed = ", ".join(sorted(g["fixed"], key=vkey)) or f'<span class="muted">{T("no fix yet")}</span>'
        title = short(g["title"], 110) if g["title"] and g["title"] != g["id"] else ""
        cell = f'<span class="mono">{esc(g["id"])}</span>' + (f"<br/>{esc(title)}" if title else "")
        sig = signals(g)
        rows.append([sev_pill(g["severity"]), cell + (f"<br/>{sig}" if sig else ""),
                     f'<span class="mono small">{esc(short(pk, 160))}</span>',
                     f'<span class="mono small">{fixed if not g["fixed"] else esc(fixed)}</span>', finding_state(g)])
    out = table(["Severity", "Advisory", "Affected packages", "Fixed in", "Status"], rows, "findings",
                ["11%", "33%", "28%", "17%", "11%"])
    if len(ordered) > limit:
        out += note(T("Showing {limit} of {total} advisories. Full list: {src}.", limit=limit, total=len(ordered),
                      src=f'<span class="mono">{esc(source or "findings.json")}</span>'))
    return out, len(ordered)


def remediation_by_package(items, limit=25):
    """What to upgrade: one row per package, the highest fix version that clears its blocking advisories."""
    pk = {}
    for f in items:
        if not f.get("gating") or not f.get("package"):
            continue
        p = pk.setdefault((f["package"], f.get("version") or ""), {"ids": set(), "fix": [], "sev": "UNKNOWN",
                                                                   "kev": False, "loc": f.get("location") or ""})
        p["ids"].add(f.get("id"))
        p["fix"] += [x.strip() for x in str(f.get("fixed_version") or "").split(",") if x.strip()]
        p["kev"] = p["kev"] or bool(f.get("kev"))
        if SEV_RANK[f["severity"]] < SEV_RANK[p["sev"]]:
            p["sev"] = f["severity"]
    if not pk:
        return "", 0
    ordered = sorted(pk.items(), key=lambda kv_: (not kv_[1]["kev"], SEV_RANK[kv_[1]["sev"]], -len(kv_[1]["ids"])))
    rows = []
    for (name, ver), p in ordered[:limit]:
        target = max(p["fix"], key=vkey) if p["fix"] else "—"
        rows.append([sev_pill(p["sev"]), f'<span class="mono">{esc(name)}</span>'
                     + (' <span class="tag kev">KEV</span>' if p["kev"] else ""),
                     f'<span class="mono small">{esc(ver)}</span>', f'<span class="mono small"><b>{esc(target)}</b></span>',
                     str(len(p["ids"])), f'<span class="small muted">{esc(compact_path(p["loc"], 36))}</span>'])
    out = table(["Worst", "Package", "Installed", "Upgrade to", "Advisories", "Where"], rows, "findings",
                ["11%", "21%", "17%", "17%", "12%", "22%"])
    if len(ordered) > limit:
        out += note(T("{n} more packages need upgrading.", n=len(ordered) - limit))
    return out, len(ordered)


# ------------------------------------------------------------------ CSS
CSS = r"""
@page {
  size: A4; margin: 22mm 16mm 20mm 16mm;
  @top-left { content: "Sawone  ·  Security Assessment Report"; font: 600 7.5pt "Inter", "DejaVu Sans", sans-serif; color: #64748b; }
  @top-right { content: string(section); font: 7.5pt "Inter", "DejaVu Sans", sans-serif; color: #64748b; }
  @bottom-left { content: "CONFIDENTIAL"; font: 700 7pt "Inter", "DejaVu Sans", sans-serif; color: #b91c1c; letter-spacing: .6pt; width: 30mm; }
  @bottom-center { content: "__REPO__"; font: 7pt "Inter", "DejaVu Sans", sans-serif; color: #94a3b8; width: 110mm; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 7.5pt "Inter", "DejaVu Sans", sans-serif; color: #64748b; }
}
@page cover { margin: 0; @top-left { content: none } @top-right { content: none } @bottom-left { content: none }
              @bottom-center { content: none } @bottom-right { content: none } }
html { font-family: "Inter", "DejaVu Sans", Helvetica, Arial, sans-serif; font-size: 8.6pt; color: #0f172a; line-height: 1.42; }
body { margin: 0; }

/* cover */
.cover { page: cover; height: 297mm; position: relative; background: #0b1220; color: #e2e8f0; page-break-after: always; }
.cover .band { position: absolute; top: 0; left: 0; right: 0; height: 6mm; background: linear-gradient(90deg, #1d4ed8, #7c3aed); }
.cover .inner { position: absolute; top: 38mm; left: 20mm; right: 20mm; }
.cover .brand { font-size: 10pt; font-weight: 700; letter-spacing: 2.5pt; text-transform: uppercase; color: #93c5fd; }
.cover h1 { font-size: 30pt; line-height: 1.12; margin: 6mm 0 3mm 0; color: #fff; font-weight: 700; string-set: none; }
.cover .subtitle { font-size: 12pt; color: #cbd5e1; margin-bottom: 14mm; }
.cover .verdict { display: inline-block; padding: 3mm 6mm; border-radius: 2mm; font-size: 13pt; font-weight: 700; margin-bottom: 12mm; }
.cover .verdict.fail { background: #7f1d1d; color: #fecaca; } .cover .verdict.pass { background: #14532d; color: #bbf7d0; }
.cover .verdict.incomplete { background: #78350f; color: #fde68a; }
.cover table.meta { width: 100%; border-collapse: collapse; font-size: 9pt; }
.cover table.meta th { background: none; text-transform: none; letter-spacing: 0; font-size: 9pt; text-align: left; color: #94a3b8; font-weight: 500; width: 34%; padding: 2.2mm 0; border-bottom: .5pt solid #1e293b; vertical-align: top; }
.cover table.meta td { color: #f1f5f9; padding: 2.2mm 0; border-bottom: .5pt solid #1e293b; font-family: "DejaVu Sans Mono", monospace; font-size: 8pt; word-break: break-all; }
.cover .foot { position: absolute; bottom: 16mm; left: 20mm; right: 20mm; font-size: 7.5pt; color: #94a3b8; border-top: .5pt solid #334155; padding-top: 4mm; }
.cover .foot b { color: #fca5a5; letter-spacing: .6pt; }

/* headings */
h1.section { font-size: 17pt; color: #0f172a; margin: 0 0 1mm 0; padding-bottom: 2mm; border-bottom: 1.6pt solid #1d4ed8;
             string-set: section attr(data-title); page-break-before: always; font-weight: 700; }
h1.section.cont { page-break-before: auto; margin-top: 9mm; }
h1.section .num { color: #1d4ed8; margin-right: 3mm; }
h2 { font-size: 12pt; margin: 7mm 0 1.5mm 0; color: #0f172a; page-break-after: avoid; font-weight: 700; }
h2 .num { color: #1d4ed8; margin-right: 2mm; }
h3 { font-size: 10pt; margin: 5mm 0 1mm 0; color: #1e293b; page-break-after: avoid; font-weight: 600; }
.lead { color: #475569; margin: 1mm 0 3mm 0; font-size: 8.8pt; }
p { margin: 1.5mm 0; }
.muted { color: #64748b; } .small { font-size: 7.2pt; }
.mono { font-family: "DejaVu Sans Mono", Menlo, monospace; font-size: 7.4pt; word-break: break-all; }

/* tables */
table { width: 100%; border-collapse: collapse; margin: 2mm 0 3mm 0; table-layout: fixed; }
thead { display: table-header-group; }
tr { page-break-inside: avoid; }
th { background: #f1f5f9; color: #334155; text-align: left; font-weight: 600; font-size: 7.4pt; text-transform: uppercase;
     letter-spacing: .3pt; padding: 1.6mm 2mm; border-bottom: .8pt solid #cbd5e1; }
td { padding: 1.5mm 2mm; border-bottom: .4pt solid #e2e8f0; vertical-align: top; word-wrap: break-word; }
table.findings td { font-size: 7.8pt; }
table.kv th { width: 30%; text-transform: none; letter-spacing: 0; font-size: 8pt; background: #f8fafc; border-bottom: .4pt solid #e2e8f0; }
table.kv td { font-size: 8pt; }
tr.row-fail td { background: #fef2f2; } tr.row-err td { background: #fffbeb; }

/* pills */
.pill { display: inline-block; padding: .3mm 1.8mm; border-radius: 3mm; font-size: 6.8pt; font-weight: 600; white-space: nowrap; }
.ok { background: #dcfce7; color: #166534; } .bad { background: #fee2e2; color: #991b1b; } .warn { background: #fef3c7; color: #92400e; }
.skip { background: #f1f5f9; color: #475569; } .info { background: #e0e7ff; color: #3730a3; } .neutral { background: #f1f5f9; color: #334155; }
.sev { display: inline-block; min-width: 13mm; text-align: center; padding: .3mm 1.2mm; border-radius: 1mm; font-size: 6.8pt; font-weight: 700; color: #fff; }
.sev-critical { background: #7f1d1d; } .sev-high { background: #dc2626; } .sev-medium { background: #f59e0b; color: #1f2937; }
.sev-low { background: #3b82f6; } .sev-unknown { background: #9ca3af; }
.cnt { display: inline-block; margin-right: 3mm; font-size: 7.6pt; background: none !important; }
.cnt.sev-critical b { color: #7f1d1d; } .cnt.sev-high b { color: #dc2626; } .cnt.sev-medium b { color: #b45309; }
.cnt.sev-low b { color: #1d4ed8; } .cnt.sev-unknown b { color: #6b7280; } .cnt { color: #475569; }
.tag { display: inline-block; font-size: 6.4pt; padding: .1mm 1.2mm; border-radius: 1mm; background: #eef2ff; color: #3730a3; margin-right: 1mm; font-weight: 600; }
.tag.kev { background: #7f1d1d; color: #fff; } .tag.new { background: #0e7490; color: #fff; }
svg.bar { vertical-align: middle; }

/* summary blocks */
.verdict-box { border-radius: 2mm; padding: 4mm 5mm; margin: 3mm 0 4mm 0; }
.verdict-box.fail { background: #fef2f2; border-left: 2mm solid #b91c1c; }
.verdict-box.pass { background: #f0fdf4; border-left: 2mm solid #15803d; }
.verdict-box.incomplete { background: #fffbeb; border-left: 2mm solid #b45309; }
.verdict-box .v { font-size: 14pt; font-weight: 700; }
.verdict-box.fail .v { color: #991b1b; } .verdict-box.pass .v { color: #166534; } .verdict-box.incomplete .v { color: #92400e; }
table.tiles { table-layout: fixed; border-collapse: separate; border-spacing: 2mm 0; margin: 2mm -2mm 4mm -2mm; width: calc(100% + 4mm); }
table.tiles td { border: .6pt solid #e2e8f0; border-radius: 1.5mm; padding: 3mm 3mm 2.5mm 3mm; background: #f8fafc; vertical-align: top; }
.tile-n { font-size: 17pt; font-weight: 700; line-height: 1.05; } .tile-l { font-size: 6.9pt; color: #64748b; text-transform: uppercase; letter-spacing: .3pt; margin-top: 1mm; }
.tile-n.red { color: #b91c1c; } .tile-n.dark { color: #7f1d1d; } .tile-n.amber { color: #b45309; } .tile-n.green { color: #15803d; } .tile-n.blue { color: #1d4ed8; }
.callout { border-radius: 1.5mm; padding: 2.5mm 3.5mm; margin: 2mm 0 3mm 0; font-size: 8.2pt; }
.callout.info { background: #eff6ff; border-left: 1.2mm solid #3b82f6; }
.callout.danger { background: #fef2f2; border-left: 1.2mm solid #b91c1c; }
.callout.warn { background: #fffbeb; border-left: 1.2mm solid #d97706; }
.callout.ok { background: #f0fdf4; border-left: 1.2mm solid #16a34a; }
.tool { border: .6pt solid #e2e8f0; border-radius: 2mm; padding: 0 4mm 2mm 4mm; margin: 4mm 0; }
.tool-head { margin: 0 -4mm 2mm -4mm; padding: 2.5mm 4mm; background: #f8fafc; border-bottom: .6pt solid #e2e8f0; border-radius: 2mm 2mm 0 0; page-break-after: avoid; }
.tool-head .name { font-size: 10pt; font-weight: 700; } .tool-head .ver { font-size: 6.8pt; color: #64748b; font-family: "DejaVu Sans Mono", monospace; }
.tool-head table { margin: 0; } .tool-head td { border: none; padding: 0; vertical-align: middle; }
.alert-h { margin-top: 3mm; page-break-after: avoid; }
pre.log { font-family: "DejaVu Sans Mono", monospace; font-size: 6.6pt; background: #0f172a; color: #e2e8f0; padding: 2.5mm; border-radius: 1.5mm; white-space: pre-wrap; word-break: break-all; }

/* contents */
.toc { margin-top: 4mm; }
.toc a { color: #0f172a; text-decoration: none; display: block; padding: .9mm 0; border-bottom: .4pt dotted #cbd5e1; }
.toc a::after { content: leader(' ') target-counter(attr(href), page); color: #64748b; }
.toc a.l1 { font-weight: 600; font-size: 9.2pt; margin-top: 1.2mm; }
.toc a.l2 { padding-left: 7mm; font-size: 8.4pt; color: #334155; }
ol.actions { padding-left: 0; list-style: none; margin: 2mm 0; }
ol.actions li { margin: 0 0 2mm 0; padding: 2.2mm 3mm; border: .5pt solid #e2e8f0; border-radius: 1.5mm; page-break-inside: avoid; }
.prio { display: inline-block; font-weight: 700; font-size: 7pt; padding: .3mm 1.6mm; border-radius: 1mm; margin-right: 2mm; color: #fff; }
.prio.p1 { background: #b91c1c; } .prio.p2 { background: #d97706; } .prio.p3 { background: #2563eb; }
"""


# ------------------------------------------------------------------ report
RTL_CSS = r"""
html { direction: rtl; font-family: "Noto Sans Arabic", "Noto Naskh Arabic", "DejaVu Sans", sans-serif; }
th, .cover table.meta th { text-align: right; }
h1.section .num { margin-right: 0; margin-left: 3mm; } h2 .num { margin-right: 0; margin-left: 2mm; }
.verdict-box.fail, .verdict-box.pass, .verdict-box.incomplete { border-left: none; }
.verdict-box.fail { border-right: 2mm solid #b91c1c; } .verdict-box.pass { border-right: 2mm solid #15803d; }
.verdict-box.incomplete { border-right: 2mm solid #b45309; }
.callout.info, .callout.danger, .callout.warn, .callout.ok { border-left: none; }
.callout.info { border-right: 1.2mm solid #3b82f6; } .callout.danger { border-right: 1.2mm solid #b91c1c; }
.callout.warn { border-right: 1.2mm solid #d97706; } .callout.ok { border-right: 1.2mm solid #16a34a; }
.toc a.l2 { padding-left: 0; padding-right: 7mm; }
.cnt, .tag { margin-right: 0; margin-left: 2mm; } .prio { margin-right: 0; margin-left: 2mm; }
.mono, pre.log { direction: ltr; unicode-bidi: isolate; }
.tile-l, th { letter-spacing: 0; text-transform: none; }
"""
PAGE_AR = r"""
@page {
  @top-left { content: "Sawone  ·  تقرير تقييم أمن التطبيقات"; font: 600 7.5pt "Noto Sans Arabic", sans-serif; }
  @top-right { content: string(section); font: 7.5pt "Noto Sans Arabic", sans-serif; }
  @bottom-left { content: "سري"; font: 700 7pt "Noto Sans Arabic", sans-serif; }
  @bottom-right { content: "صفحة " counter(page) " من " counter(pages); font: 7.5pt "Noto Sans Arabic", sans-serif; }
}
"""
SLA_CSS = r"""
table.trend td { text-align: center; } table.trend td:first-child { text-align: inherit; }
.ev { font-size: 6.8pt; }
"""


class Report:
    def __init__(self, d: Data):
        self.d = d
        self.toc = []          # (level, anchor, title)
        self.n1 = 0
        self.opts = d.summary.get("options") or {}

    # numbering
    def h1(self, title, anchor):
        self.n1 += 1
        self.n2 = 0
        title = T(title)
        self.toc.append((1, anchor, f"{self.n1}  {title}"))
        return (f'<h1 class="section" id="{anchor}" data-title="{self.n1}  {esc(title)}">'
                f'<span class="num">{self.n1}</span>{esc(title)}</h1>')

    def h2(self, title, anchor, toc=True, raw=False):
        self.n2 += 1
        num = f"{self.n1}.{self.n2}"
        title = title if raw else T(title)
        if toc:
            self.toc.append((2, anchor, f"{num}  {title}"))
        return f'<h2 id="{anchor}"><span class="num">{num}</span>{esc(title)}</h2>'

    def appendix(self, letter, title, anchor, cont=False):
        label = T("Appendix {x}", x=letter)
        title = T(title)
        self.toc.append((1, anchor, f"{label}  {title}"))
        return (f'<h1 class="section{" cont" if cont else ""}" id="{anchor}" data-title="{esc(label)}  {esc(title)}">'
                f'<span class="num">{letter}</span>{esc(title)}</h1>')

    # ---------------------------------------------------------------- verdict
    def verdict(self):
        d = self.d
        if not d.stages:
            return "incomplete", T("NO RESULTS"), T("The scan produced no gate results.")
        if d.errors and not d.failed:
            return ("incomplete", T("INCOMPLETE"),
                    T("{n} scanner(s) did not complete, so results are missing. The other gates passed.", n=len(d.errors)))
        if d.failed:
            txt = T("{f} of {t} security gates failed", f=len(d.failed), t=d.gates_total)
            if d.errors:
                txt += T(" and {n} scanner(s) did not complete", n=len(d.errors))
            txt += "." + ("" if d.enforce else " " + T("Report-only mode: the pipeline was not blocked; in enforce mode "
                                                     "it would have been."))
            return "fail", T("FAILED"), txt
        return "pass", T("PASSED"), T("All {t} security gates passed.", t=d.gates_total)

    # ---------------------------------------------------------------- cover
    def cover(self):
        d = self.d
        cls, word, txt = self.verdict()
        meta = [("Repository", d.repo), ("Branch / ref", d.ref or "—"), ("Commit", d.sha or "—"),
                ("Pipeline run", d.run_url or "—"), ("Generated", d.generated.strftime("%Y-%m-%d %H:%M UTC")),
                ("Enforcement", T("Enforce — failed gates block the pipeline") if d.enforce
                 else T("Report only — gates evaluated, pipeline not blocked")),
                ("Gate threshold", T("{t} (fixable) · CISA KEV at any severity", t=d.threshold))]
        if d.pr.get("note"):
            meta.append(("Pull request", T("Only findings new in this change block")))
        rows = "".join(f"<tr><th>{esc(T(k))}</th><td>{esc(v)}</td></tr>" for k, v in meta)
        return (f'<section class="cover"><div class="band"></div><div class="inner">'
                f'<div class="brand">Sawone</div>'
                f'<h1>{T("Application Security<br/>Assessment Report")}</h1>'
                f'<div class="subtitle">{esc(d.repo)}</div>'
                f'<div class="verdict {cls}">{word} — {esc(txt)}</div>'
                f'<table class="meta">{rows}</table></div>'
                f'<div class="foot"><b>{T("CONFIDENTIAL")}</b> — '
                + T("this report describes unremediated security weaknesses. Share it only with people responsible "
                    "for fixing or governing them.") + '<br/>'
                + T("Generated automatically by Sawone from open-source scanners pinned for this run. Findings are "
                    "tool output and may include false positives; validate before acting on them.")
                + '</div></section>')

    # ---------------------------------------------------------------- contents
    def contents(self):
        links = "".join(f'<a class="l{lvl}" href="#{a}">{esc(t)}</a>' for lvl, a, t in self.toc)
        return (f'<h1 class="section" id="toc" data-title="{T("Contents")}">{T("Contents")}</h1>'
                f'<div class="toc">{links}</div>')

    # ---------------------------------------------------------------- 1 executive summary
    def executive(self):
        d = self.d
        out = [self.h1("Executive summary", "exec")]
        cls, word, txt = self.verdict()
        out.append(f'<div class="verdict-box {cls}"><div class="v">{word}</div><div>{esc(txt)}</div>'
                   + (f'<div class="small" style="margin-top:1.5mm">{esc(d.pr["note"])}</div>' if d.pr.get("note") else "")
                   + "</div>")
        b = d.blocking
        c = sev_counts(b)
        kev = len({f["id"] for f in d.merged if f.get("kev")})
        live = sum(1 for f in d.merged if f.get("verified"))
        overdue = sum(1 for f in b if f.get("overdue"))
        tiles = [(f"{len(d.failed)}<span class='small muted'> / {d.gates_total}</span>", "Gates failed", "red" if d.failed else "green"),
                 (len(b), "Blocking findings", "red" if b else "green"),
                 (c.get("CRITICAL", 0), "Critical (blocking)", "dark" if c.get("CRITICAL") else "green"),
                 (kev, "Known exploited (KEV)", "dark" if kev else "green"),
                 (live, "Live secrets", "dark" if live else "green"),
                 (overdue, "Past fix deadline", "red" if overdue else "green")]
        out.append('<table class="tiles"><tr>' + "".join(
            f'<td><div class="tile-n {col}">{n}</div><div class="tile-l">{esc(T(lbl))}</div></td>' for n, lbl, col in tiles)
            + "</tr></table>")
        if d.fs:
            line = T("{u} unique findings after merging {m} duplicates reported by more than one tool · {a} accepted "
                     "in the baseline", u=d.fs.get("unique", len(d.merged)), m=d.fs.get("duplicates_merged", 0),
                     a=d.fs.get("baselined", 0))
            if d.fs.get("new") is not None:
                line += " · " + T("{n} new in this change", n=d.fs["new"])
            if d.errors:
                line += " · " + T("{n} scanner error(s)", n=len(d.errors))
            out.append(note(line + "."))

        # results by stage
        out.append(self.h2("Results by stage", "exec-stages"))
        rows = []
        for st in DETAIL_STAGES:
            srows = [r for r in d.stages if r["stage"] == st]
            if not srows:
                continue
            gating = [r for r in srows if r.get("gate", True) and r["status"] != "skipped"]
            status = ("error" if any(r["status"] == "error" for r in srows) else
                      "failed" if any(r["status"] == "failed" and r.get("gate", True) for r in srows) else
                      "passed" if any(r["status"] == "passed" for r in gating) else
                      "report" if any(r["status"] == "report" for r in srows) else "skipped")
            sb = [f for f in b if st in (f.get("stages") or [f.get("stage")])]
            sc = sev_counts(sb)
            tools = ", ".join(sorted({short_tool(r["tool"]) for r in srows if r.get("tool") and r["tool"] != "—"}))
            rows.append([f"<b>{esc(stage_title(st))}</b><br/><span class='small muted'>{esc(tools)}</span>",
                         status_pill(status), str(len(sb)) if sb else "—", bar_svg(sc, 120) + "<br/>" + sev_strip(sc) if sb else ""])
        out.append(table(["Stage", "Result", "Blocking", "Severity of blocking findings"], rows, "",
                         ["40%", "14%", "10%", "36%"]))

        # top risks
        top = [f for f in b][:8]
        if top:
            out.append(self.h2("Most significant risks", "exec-risks"))
            rows = [[sev_pill(f["severity"]),
                     f'<b>{esc(short(f.get("title") or f.get("id"), 120))}</b><br/>'
                     f'<span class="mono small">{esc(f.get("id"))}</span> {signals(f)}',
                     where(f), esc(stage_title((f.get("stages") or [f.get("stage")])[0]))]
                    for f in top]
            out.append(table(["Severity", "Risk", "Location", "Area"], rows, "findings", ["11%", "47%", "24%", "18%"]))

        acts = self.actions()
        if acts:
            out.append(self.h2("Priority actions", "exec-actions"))
            out.append('<ol class="actions">' + "".join(
                f'<li><span class="prio p{p}">P{p}</span><b>{esc(T(area))}</b> — {text}</li>' for p, area, text in acts)
                + "</ol>")
            out.append(note(T("P1: fix before release · P2: fix in the current cycle · P3: schedule. Derived "
                              "automatically from the gate results; adjust to your risk appetite.")))
        return "".join(out)

    def actions(self):
        d, acts = self.d, []
        b = d.blocking
        failed_stages = {r["stage"] for r in d.failed}

        def stage_items(st):
            return [f for f in b if st in (f.get("stages") or [f.get("stage")])]

        secrets = [f for f in b if f.get("kind") == "secret"]
        if secrets or "secrets" in failed_stages:
            n = len({(f.get("id"), str(f.get("location", "")).rsplit("/", 1)[-1]) for f in secrets}) or \
                sum(1 for r in d.failed if r["stage"] == "secrets")
            live = sum(1 for f in secrets if f.get("verified"))
            text = T("Revoke and rotate the {n} exposed credential(s) now, then remove them from the code, the image "
                     "and the Git history. Treat every leaked secret as compromised: removing it from the latest "
                     "commit does not make it safe.", n=n)
            if live:
                text += " " + T("{n} of them were verified as live against their provider.", n=live)
            acts.append((1, "Secrets", text))
        kev = sorted({f["id"] for f in b if f.get("kev")})
        if kev:
            acts.append((1, "Known-exploited vulnerabilities",
                         T("Patch the {n} vulnerability(ies) listed in CISA's Known Exploited Vulnerabilities "
                           "catalogue first: {ids}.", n=len(kev), ids=f"<span class='mono'>{esc(', '.join(kev[:4]))}</span>")))
        dast = [f for f in stage_items("dast") if f["severity"] in ("CRITICAL", "HIGH")]
        if dast:
            names = sorted({re.sub(r"\s*\(.*$", "", f.get("title") or "") for f in dast} - {""})
            acts.append((1, "Running application",
                         T("Fix the {n} high-risk issue(s) confirmed by attacking the running application: {names}.",
                           n=len(names), names=esc(", ".join(names[:6])))))
        sast = stage_items("sast")
        if sast:
            rules = Counter(str(f.get("id")).split(".")[-1] for f in sast)
            acts.append((2 if not any(f["severity"] == "CRITICAL" for f in sast) else 1, "Source code",
                         T("Fix {n} high-severity code finding(s); most frequent: {rules}.", n=len(sast),
                           rules=f"<span class='mono'>{esc(', '.join(r for r, _ in rules.most_common(4)))}</span>")))
        sca = [f for f in stage_items("sca") if f.get("package")]
        if sca:
            pk = {}
            for f in sca:
                pk.setdefault(f["package"], []).extend(x.strip() for x in str(f.get("fixed_version") or "").split(",") if x.strip())
            ex = ", ".join(f"{p} → {max(v, key=vkey)}" for p, v in list(pk.items())[:4] if v)
            text = T("Upgrade {p} dependency(ies) with fixable advisories ({n} in total)", p=len(pk), n=len(sca))
            acts.append((2, "Dependencies", text + (T(", for example {ex}.", ex=f"<span class='mono'>{esc(ex)}</span>")
                                                    if ex else ".")))
        cont = [f for f in stage_items("container") if f.get("kind") == "vuln"]
        if cont:
            ids = {f["id"] for f in cont}
            os_ids = {f["id"] for f in cont if str(f.get("location", "")).startswith(("OS package", "deb", "apk", "rpm"))}
            text = T("Rebuild the image to clear {n} fixable advisory(ies)", n=len(ids))
            if os_ids:
                text += T(": {n} are in operating-system packages and are fixed by rebuilding on a current base image",
                          n=len(os_ids))
            acts.append((2, "Container image", esc(text) + T("; the rest need the application dependency upgrades above.")))
        iac = stage_items("iac")
        if iac:
            files = sorted({str(f.get("location", "")).rsplit(":", 1)[0] for f in iac} - {""})
            acts.append((3 if not any(f["severity"] == "CRITICAL" for f in iac) else 2, "Infrastructure as code",
                         T("Fix {n} misconfiguration(s) in {files} before the next apply; they ship to every environment "
                           "built from this code.", n=len(iac),
                           files=f"<span class='mono'>{esc(', '.join(files[:4]))}</span>")))
        if "kubernetes" in failed_stages:
            acts.append((3, "Kubernetes", T("Fix the manifest validation and policy failures listed in the Kubernetes "
                                            "section.")))
        cicd = stage_items("cicd")
        if cicd or "cicd" in failed_stages:
            acts.append((2, "CI/CD", T("Harden the workflows: {n} high-risk pattern(s) flagged by zizmor (for example "
                                       "script injection, broad permissions or unpinned actions).", n=len(cicd) or 1)))
        tm = stage_items("threat-model")
        if tm:
            acts.append((3, "Threat model", T("Record a decision for the {n} open threat(s) in {f}: implement the "
                                              "mitigation, or add it to {m} with an owner and reason.", n=len(tm),
                                              f="<span class='mono'>threatmodel/tm.py</span>",
                                              m="<span class='mono'>MITIGATED</span>")))
        if "runtime" in failed_stages:
            acts.append((2, "Runtime protection", T("The WAF let an attack through or blocked legitimate traffic; "
                                                    "review its rules.")))
        overdue = [f for f in b if f.get("overdue")]
        if overdue:
            acts.append((1, "Fix deadlines", T("{n} blocking finding(s) are past their fix deadline (SLA). Escalate them "
                                               "to their owners.", n=len(overdue))))
        if d.errors:
            acts.append((1, "Scan coverage", T("{n} scanner(s) failed to complete ({tools}). Their results are missing; "
                                               "fix and re-run before relying on this report.", n=len(d.errors),
                                               tools=esc(", ".join(sorted({r["tool"] for r in d.errors}))))))
        return sorted(acts, key=lambda a: a[0])

    # ---------------------------------------------------------------- 2 scope
    def scope(self):
        d = self.d
        out = [self.h1("Scope and method", "scope")]
        out.append(self.h2("What was assessed", "scope-target"))
        inv = d.inv
        img = d.release.get("Image built") or d.summary.get("image") or ""
        rows = [("Repository", esc(d.repo)), ("Branch / ref", f'<span class="mono">{esc(d.ref or "—")}</span>'),
                ("Commit", f'<span class="mono">{esc(d.sha or "—")}</span>'),
                ("Pipeline run", f'<span class="mono">{esc(d.run_url or "—")}</span>')]
        if img:
            rows.append(("Container image", f'<span class="mono">{esc(img)}</span>'))
        out.append(kv(rows))
        if inv:
            out.append(self.h2("What was detected", "scope-detected"))
            langs = ", ".join(T("{k} ({v} files)", k=k, v=v) for k, v in (inv.get("languages") or {}).items())
            items = [("Languages", langs), ("Frameworks", ", ".join(inv.get("frameworks") or [])),
                     ("Dependency ecosystems", ", ".join(inv.get("ecosystems") or [])),
                     ("Dependency manifests", ", ".join(inv.get("manifests") or [])),
                     ("Dockerfiles", ", ".join(inv.get("dockerfiles") or [])),
                     ("Terraform", ", ".join(inv.get("terraform") or [])),
                     ("Kubernetes manifests", ", ".join(inv.get("kubernetes") or [])),
                     ("Helm charts", ", ".join(inv.get("helm_charts") or [])),
                     ("CloudFormation / Bicep / ARM", ", ".join((inv.get("cloudformation") or []) + (inv.get("bicep_arm") or []))),
                     ("CI systems", ", ".join(inv.get("ci") or [])),
                     ("Threat model", inv.get("threat_model") or inv.get("threagile") or ""),
                     ("OpenAPI specification", inv.get("openapi") or "")]
            out.append(kv([(k, esc(v) if v else f'<span class="muted">{T("none found")}</span>') for k, v in items]))
        out.append(self.h2("How results are judged", "scope-policy"))
        sla = (d.summary.get("trend") or {}).get("sla") or self.opts.get("sla") or {}
        sla_txt = " · ".join(f"{T(SEV_LABEL[k])} {v}" for k, v in sla.items() if k in SEV_LABEL)
        pol_rows = [("Enforcement", T("Enforce: a failed gate fails the pipeline") if d.enforce
                     else T("Report only: gates are evaluated and reported, the pipeline is not blocked")),
                    ("Blocking threshold", T("Fixable findings rated {t}", t=d.threshold)),
                    ("Known exploited", T("CVEs in the CISA KEV catalogue block at any severity")),
                    ("Accepted risks", T("Exceptions in .sawone-baseline.yml, each with an owner, a reason and an expiry "
                                         "date; an expired exception stops suppressing. False positives are recorded "
                                         "the same way, with type: false-positive")),
                    ("Report-only tools", T("Second-opinion tools (Checkov, OSV-Scanner, kube-linter, Nuclei, Dockle) "
                                            "are shown but never block")),
                    ("Noise profile", T("Balanced: low-severity findings from second-opinion tools are counted but not "
                                        "listed") if self.opts.get("profile", "balanced") == "balanced"
                     else T("Full: every finding is listed")),
                    ("Duplicates", T("The same flaw reported by several tools, or by several rules of one tool, is merged "
                                     "into one finding in chapters 1 and 4; each tool's own list in chapter 5 is complete")),
                    ("Fix deadlines (SLA)", (T("Days to fix from first seen: {s}", s=sla_txt) if sla_txt else "—")),
                    ("Tool versions", T("Version policy “{p}”: every tool resolved once and pinned by digest for the "
                                        "whole run (see Appendix A)", p=esc(d.version_policy)) if d.version_policy
                     else T("See Appendix A"))]
        for r in [r for r in d.stages if r["stage"] == "policy"]:
            pol_rows.append((r["tool"], f'{status_pill(r["status"])} {esc(r.get("findings") or r.get("reason") or "")}'))
        out.append(kv([(k, v if "<" in str(v) else esc(v)) for k, v in pol_rows]))
        return "".join(out)

    # ---------------------------------------------------------------- 3 gate results
    def gates(self):
        d = self.d
        out = [self.h1("Security gate results", "gates")]
        out.append('<p class="lead">' + T("Every check the pipeline ran, in pipeline order. A failed gate found blocking "
                                          "issues; a scanner error means the tool did not finish, so its results are "
                                          "missing (never treat it as clean); report-only tools are tracked but never "
                                          "block.") + '</p>')
        order = {s: i for i, s in enumerate(GATE_ORDER)}
        rows = []
        for r in sorted(d.stages, key=lambda r: order.get(r["stage"], 99)):
            detail = esc(r.get("findings") or r.get("reason") or "")
            if r.get("pr_preexisting"):
                detail += f' <span class="tag">{T("pre-existing on base branch")}</span>'
            tool = r.get("tool") or "—"
            label = tool[tool.index("(") + 1:-1] if tool.startswith(("Trivy image (", "Grype (")) else ""
            tcell = f'<b>{esc(short_tool(tool))}</b>' + (f'<br/><span class="mono small muted">{esc(label)}</span>' if label else "")
            rows.append((r["status"], [esc(stage_title(r["stage"])), tcell,
                                       status_pill(r["status"] if r.get("gate", True) or r["status"] != "failed" else "report"),
                                       detail]))
        body = "".join(f'<tr class="{"row-fail" if s == "failed" else "row-err" if s == "error" else ""}">'
                       + "".join(f"<td>{c}</td>" for c in cells) + "</tr>" for s, cells in rows)
        out.append('<table><colgroup><col style="width:22%"/><col style="width:20%"/><col style="width:13%"/>'
                   '<col style="width:45%"/></colgroup><thead><tr>' + "".join(
                       f"<th>{T(h)}</th>" for h in ["Stage", "Tool", "Result", "Details"])
                   + f'</tr></thead><tbody>{body}</tbody></table>')

        out.append(self.h2("Findings by tool", "gates-tools"))
        rows = []
        for r in sorted(d.stages, key=lambda r: order.get(r["stage"], 99)):
            if r["stage"] in ("policy", "pipeline", "scanner") or r.get("tool") in (None, "", "—"):
                continue
            items, src = d.tool_findings(r)
            c = sev_counts(items)
            nb = sum(1 for f in items if f.get("gating"))
            name = (f'<b>{esc(short_tool(r["tool"]))}</b><br/><span class="small muted">'
                    f'{esc(stage_title(r["stage"]))}</span>')
            if not items:
                mid = ('<td colspan="6" class="muted small">' + (T("Pass/fail check — no individual findings")
                       if src is None else T("No findings")) + "</td>")
            else:
                mid = "".join(f"<td>{c.get(s, 0) or '·'}</td>" for s in SEVS) + f"<td>{f'<b>{nb}</b>' if nb else '·'}</td>"
            rows.append(f"<tr><td>{name}</td>{mid}<td>{status_pill(r['status'])}</td></tr>")
        cols = "".join(f'<col style="width:{w}"/>' for w in ["30%", "8.5%", "8.5%", "8.5%", "8.5%", "8.5%", "9.5%", "18%"])
        out.append(f'<table><colgroup>{cols}</colgroup><thead><tr>' + "".join(
            f"<th>{T(h)}</th>" for h in ["Tool", "Critical", "High", "Medium", "Low", "Unrated", "Blocking", "Result"])
            + f'</tr></thead><tbody>{"".join(rows)}</tbody></table>')
        out.append(note(T("Counts are every finding a tool reported. Only findings that break the gate policy block "
                          "(see 2.3); the rest are tracked. Pass/fail tools report a result, not individual findings.")))
        if d.jobs:
            out.append(self.h2("Pipeline jobs", "gates-jobs"))
            jrows = [[f"<b>{esc(j['job'])}</b>", status_pill(j["result"])] for j in d.jobs]
            out.append(table(["Job", "Result"], jrows, "", ["60%", "40%"]))
            if not d.enforce and d.failed:
                out.append(note(T("Jobs pass in report-only mode even when their gates fail; the gate results above "
                                  "are what would block in enforce mode.")))
        return "".join(out)

    # ---------------------------------------------------------------- 4 risk-ranked
    def risk_ranked(self):
        d = self.d
        out = [self.h1("Risk-ranked findings", "risk")]
        out.append('<p class="lead">' + T("Unique findings across every tool, duplicates merged, ordered by: blocking, "
                                          "known exploited, severity, then exploit probability (EPSS). At most 8 "
                                          "findings per tool are shown here so one noisy scanner cannot hide the "
                                          "others; every finding appears in its tool's section in chapter 5.") + '</p>')
        cand = [f for f in d.merged if f.get("gating") or f.get("kev")]
        if not cand:
            out.append(callout(T("No blocking or known-exploited findings."), "ok"))
            return "".join(out)
        per, top = Counter(), []
        for f in cand:
            t = (f.get("tools") or [f.get("tool")])[0]
            if per[t] < 8:
                per[t] += 1
                top.append(f)
        out.append(findings_table(top, limit=60, show_tool=True, source="findings-consolidated.json", group=True))
        if len(top) < len(cand):
            out.append(note(T("{n} further blocking findings are listed in their tool sections.", n=len(cand) - len(top))))
        return "".join(out)

    # ---------------------------------------------------------------- trend and SLA
    def trend(self):
        d = self.d
        tr = d.summary.get("trend") or {}
        b = d.blocking
        if not tr and not b:
            return ""
        out = [self.h1("Trend and fix deadlines", "trend")]
        out.append('<p class="lead">' + T("Each finding keeps the date it was first seen, carried over from the "
                                          "previous report of this branch. Its fix deadline is that date plus the SLA "
                                          "for its severity.") + '</p>')
        if tr.get("previous"):
            out.append(table(["New since last scan", "Fixed since last scan", "Blocking open", "Past deadline"],
                             [[str(tr.get("new", 0)), str(tr.get("fixed", 0)), str(tr.get("open", len(b))),
                               str(tr.get("overdue", 0))]], "trend", ["25%", "25%", "25%", "25%"]))
        else:
            out.append(callout(T("No previous report of this branch was found, so every finding is first seen today. "
                                 "Trends appear from the next scan."), "info"))
        ages = tr.get("by_age") or {}
        if ages and b:
            out.append(self.h2("Age of blocking findings", "trend-age"))
            out.append(table(["0–7 days", "8–30 days", "31–90 days", "Over 90 days"],
                             [[str(ages.get("0-7", 0)), str(ages.get("8-30", 0)), str(ages.get("31-90", 0)),
                               str(ages.get("90+", 0))]], "trend", ["25%", "25%", "25%", "25%"]))
        overdue = sort_findings([f for f in b if f.get("overdue")])
        if overdue:
            out.append(self.h2("Past their fix deadline", "trend-overdue"))
            rows = [[sev_pill(f["severity"]), f'<span class="mono small">{esc(short(f.get("id"), 60))}</span><br/>'
                     f'{esc(short(f.get("title"), 110))}', where(f), esc(f.get("first_seen", "")[:10]),
                     f'<b>{esc(f.get("sla_due", ""))}</b>'] for f in overdue[:40]]
            out.append(table(["Severity", "Finding", "Location", "First seen", "Due"], rows, "findings",
                             ["11%", "40%", "23%", "13%", "13%"]))
        return "".join(out)

    # ---------------------------------------------------------------- 5 detailed results
    def details(self):
        d = self.d
        out = [self.h1("Detailed results", "details")]
        out.append('<p class="lead">' + T("One section per pipeline stage and one panel per tool: what the tool checked, "
                                          "its result, and its findings ordered by priority.") + '</p>')
        for st in DETAIL_STAGES:
            srows = [r for r in d.stages if r["stage"] == st]
            if not srows:
                continue
            out.append(self.h2(stage_title(st), f"st-{st}", raw=True))
            out.append(f'<p class="lead">{esc(stage_intro(st))}</p>')
            if all(r["status"] == "skipped" for r in srows):
                out.append(callout(T("Not run: {why}", why=esc("; ".join(r.get("reason") or "" for r in srows))), "info"))
                continue
            if st == "sca":
                src = [x for x in d.sboms if x["source"]]
                if src:
                    types = ", ".join(f"{k} {v}" for k, v in src[0]["types"].most_common(5))
                    out.append(kv([("Source SBOM", T("{n} packages (CycloneDX, {f})", n=f"<b>{src[0]['packages']}</b>",
                                                     f="<span class='mono'>raw/sbom-source.cdx.json</span>")
                                    + (f" · {esc(types)}" if types else ""))]))
            special = {"threat-model": self.stage_threats, "container": self.stage_container,
                       "dast": self.stage_dast, "runtime": self.stage_runtime}.get(st)
            if special:
                out.append(special(srows))
            else:
                for r in srows:
                    out.append(self.tool_panel(r))
        return "".join(out)

    def panel_head(self, r, extra=""):
        ver = self.d.tools.get(self.tool_key(r.get("tool", "")), "")
        tool = r.get("tool") or ""
        label = tool[tool.index("(") + 1:-1] if tool.startswith(("Trivy image (", "Grype (")) else ""
        align = "left" if LANG == "ar" else "right"
        return (f'<div class="tool-head"><table><tr><td style="width:72%"><span class="name">{esc(short_tool(tool))}</span>'
                + (f'<br/><span class="ver">{T("image")} {esc(label)}</span>' if label else "")
                + (f'<br/><span class="ver">{esc(short(ver, 90))}</span>' if ver else "")
                + f'</td><td style="text-align:{align}">{status_pill(r["status"])}</td></tr></table>'
                + (f'<div class="small" style="margin-top:1mm">{esc(r.get("findings") or r.get("reason") or "")}</div>'
                   if (r.get("findings") or r.get("reason")) else "") + extra + "</div>")

    @staticmethod
    def tool_key(tool):
        t = tool.lower().split(" (")[0]
        return {"syft (source sbom)": "syft", "semgrep ce": "semgrep", "owasp pytm": "pytm", "trivy image": "trivy",
                "trivy config": "trivy", "trivy": "trivy", "osv-scanner": "osv", "kube-linter": "kubelinter",
                "modsecurity + owasp crs": "waf", "zap baseline": "zap", "zap full scan": "zap",
                "zap api scan": "zap"}.get(t, t)

    def quiet(self, r, items):
        """Balanced profile: second-opinion tools list medium and above (and unrated); muted rules are hidden."""
        muted = {str(x) for x in self.opts.get("mute_rules") or []}
        kept = [f for f in items if str(f.get("id")) not in muted]
        hidden_muted = len(items) - len(kept)
        hidden_low = 0
        if r["status"] == "report" and self.opts.get("profile", "balanced") == "balanced":
            low = [f for f in kept if f["severity"] == "LOW"]
            hidden_low = len(low)
            kept = [f for f in kept if f["severity"] != "LOW"]
        msg = []
        if hidden_low:
            msg.append(T("{n} low-severity finding(s) from this second-opinion tool are counted above but not listed "
                         "(noise profile: balanced).", n=hidden_low))
        if hidden_muted:
            msg.append(T("{n} finding(s) of muted rules are hidden (noise.mute_rules).", n=hidden_muted))
        return kept, " ".join(msg)

    def tool_panel(self, r):
        d = self.d
        if r["status"] == "skipped":
            return f'<div class="tool">{self.panel_head(r)}</div>'
        items, src = d.tool_findings(r)
        body = []
        if r["status"] == "error":
            body.append(callout(T("The tool did not complete, so its results are missing.") + " "
                                + esc(r.get("reason") or ""), "warn"))
        tool = r.get("tool") or ""
        if items:
            c = sev_counts(items)
            nb = sum(1 for f in items if f.get("gating"))
            body.append(f'<p>{bar_svg(c, 160)} &nbsp;{sev_strip(c)} <span class="cnt">{T("Blocking")} <b>{nb}</b></span></p>')
            if tool.startswith(VULN_TOOLS):
                rem, n = remediation_by_package(items)
                if rem:
                    body.append(f"<h3>{T('Remediation plan — {n} package(s) to upgrade', n=n)}</h3>" + rem)
                tbl, n = vuln_by_cve(items, source=src)
                body.append(f"<h3>{T('Advisories ({n})', n=n)}</h3>" + tbl)
            else:
                if tool.split(" (")[0] in ("Checkov",):
                    body.append(note(T("Checkov does not rate severity without its commercial platform key, so these "
                                       "findings are shown as Unrated; Trivy config is the rated, blocking IaC gate.")))
                shown, why = self.quiet(r, items)
                kinds = {f.get("kind") for f in shown}
                group = not ({"secret", "dast", "threat"} & kinds)
                if shown:
                    body.append(findings_table(shown, limit=15 if r["status"] == "report" else MAX_ROWS,
                                               source=src, group=group))
                if why:
                    body.append(note(why))
        elif r["status"] in ("passed", "report") and src is not None:
            body.append(callout(T("No findings."), "ok"))
        else:
            key = next((v for k, v in PASS_FAIL_TOOLS.items() if tool.startswith(k)), None)
            if key and r["status"] == "failed":
                tail = d.log_tail(key)
                body.append(note(T("This tool reports pass or fail, not individual findings. Last lines of its output:")))
                if tail:
                    body.append(f'<pre class="log">{esc(chr(10).join(tail))}</pre>')
            elif r["status"] in ("passed", "report"):
                body.append(callout(T("Passed. This tool reports pass or fail rather than individual findings."), "ok"))
        return f'<div class="tool">{self.panel_head(r)}{"".join(body)}</div>'

    # threat model
    def stage_threats(self, srows):
        d, out = self.d, []
        for r in srows:
            items, _ = d.tool_findings(r)
            tm = d.threats or {}
            src = {f'{f.get("threat_id")}@{f.get("target")}': f for f in tm.get("findings", []) or []}
            body = []
            if tm.get("findings"):
                orig = Counter(f.get("severity") for f in tm["findings"])
                labels = {"Very High": "Very high", "High": "High", "Medium": "Medium", "Low": "Low"}
                body.append("<p>" + T("{n} threats identified:", n=len(tm["findings"])) + " "
                            + " · ".join(f"{T(labels[k])} <b>{orig.get(k, 0)}</b>" for k in labels) + "</p>")
            if items:
                open_ = sort_findings([f for f in items if f.get("gating")])
                rows = []
                for f in open_[:MAX_ROWS]:
                    tid, target = f.get("id"), (f.get("title") or "").rsplit(" — ", 1)[-1]
                    s = src.get(f"{tid}@{target}") or {}
                    mit = first_sentence(strip_html(s.get("mitigations") or "", 600), 170)
                    rows.append([sev_pill(f["severity"]),
                                 f'<span class="mono small">{esc(tid)}</span><br/>{esc(short(s.get("description") or f.get("title"), 140))}',
                                 esc(target), f'<span class="small">{esc(mit) or "—"}</span>'])
                if rows:
                    body.append(f"<h3>{T('Open threats requiring a decision ({n})', n=len(open_))}</h3>")
                    body.append(table(["Severity", "Threat", "Element", "Suggested mitigation"], rows, "findings",
                                      ["11%", "37%", "16%", "36%"]))
                    if len(open_) > MAX_ROWS:
                        body.append(note(T("Showing {limit} of {total}.", limit=MAX_ROWS, total=len(open_))))
                rest = [f for f in items if not f.get("gating")]
                if rest:
                    body.append(note(T("{n} further threat(s) below the gate threshold or already decided are listed "
                                       "in findings.json.", n=len(rest))))
            elif r["status"] == "passed":
                body.append(callout(T("Every threat at or above the threshold has a recorded decision."), "ok"))
            out.append(f'<div class="tool">{self.panel_head(r)}{"".join(body)}</div>')
        return "".join(out)

    # container
    def stage_container(self, srows):
        d, out = self.d, []
        if any(not x["source"] for x in d.sboms) or d.release:
            facts = []
            if d.release.get("Image built"):
                facts.append(("Image", f'<span class="mono">{esc(d.release["Image built"])}</span>'))
            if d.release.get("Image ID"):
                facts.append(("Image ID", f'<span class="mono">{esc(d.release["Image ID"])}</span>'))
            for s in (x for x in d.sboms if not x["source"]):
                types = ", ".join(f"{k} {v}" for k, v in s["types"].most_common(5))
                facts.append((f"SBOM ({s['file']})", T("{n} packages (CycloneDX)", n=f"<b>{s['packages']}</b>")
                              + (f" · {esc(types)}" if types else "")
                              + (f' <span class="muted small">· {T("{n} catalogued files not counted", n=s["files"])}</span>'
                                 if s["files"] else "")))
            out.append(kv(facts))
        secrets = [f for r in srows for f in d.tool_findings(r)[0] if f.get("kind") == "secret"]
        if secrets:
            out.append(callout("<b>" + T("{n} secret(s) found inside the image layers.", n=len(secrets)) + "</b> "
                               + T("Anyone who can pull the image can read them: rotate them and remove them from the "
                                   "build.") + " "
                               + ", ".join(f'<span class="mono">{esc(f.get("id"))}</span> — '
                                           f'<span class="mono">{esc(f.get("location"))}</span>' for f in secrets[:5]),
                               "danger"))
        trivy_ids, grype_rows = set(), []
        for r in srows:
            tool = r.get("tool") or ""
            if tool.startswith("Grype ("):
                grype_rows.append(r)
                continue
            if tool.startswith("Trivy image ("):
                items, _ = d.tool_findings(r)
                trivy_ids |= {f.get("id") for f in items if f.get("gating")}
                vulns = [f for f in items if f.get("kind", "vuln") == "vuln"]
                out.append(self.vuln_panel(dict(r), vulns))
            else:
                out.append(self.tool_panel(r))
        for r in grype_rows:
            items, src = d.tool_findings(r)
            if not items or not trivy_ids:
                out.append(self.tool_panel(r))
                continue
            gb = [f for f in items if f.get("gating")]
            g_ids = {f.get("id") for f in gb}
            only = [f for f in gb if f.get("id") not in trivy_ids]
            kinds = Counter()
            for vid in {f.get("id") for f in only}:
                f = next(x for x in only if x.get("id") == vid)
                loc = str(f.get("location") or "")
                kinds["OS packages" if loc.startswith(("deb", "apk", "rpm")) else
                      "language runtime" if loc.startswith("binary") else
                      "application packages" if loc.startswith(("python", "java", "npm", "go", "gem")) else
                      "other"] += 1
            why = ", ".join(T("{n} in {k}", n=n, k=T(k)) for k, n in kinds.most_common())
            body = ["<p>" + T("Grype scanned the SBOM independently. It agrees with Trivy on {a} blocking advisories, "
                              "and reports {b} that Trivy did not", a=f"<b>{len(g_ids & trivy_ids)}</b>",
                              b=f"<b>{len({f.get('id') for f in only})}</b>")
                    + (f" ({esc(why)})" if why else "") + ". "
                    + T("The usual causes are a different vulnerability database (Grype also matches upstream "
                        "advisories for Debian packages that Debian has not yet triaged) and Grype seeing the language "
                        "runtime itself as a package. Duplicates are merged in chapter 4.") + "</p>"]
            if only:
                tbl, _ = vuln_by_cve(only, source=src)
                body.append(f"<h3>{T('Blocking advisories found only by Grype')}</h3>" + tbl)
            else:
                body.append(callout(T("Grype found nothing that Trivy missed."), "ok"))
            out.append(f'<div class="tool">{self.panel_head(r)}{"".join(body)}</div>')
        return "".join(out)

    def vuln_panel(self, r, items):
        if not items:
            return self.tool_panel(r)
        c = sev_counts(items)
        nb = sum(1 for f in items if f.get("gating"))
        body = [f'<p>{bar_svg(c, 160)} &nbsp;{sev_strip(c)} <span class="cnt">{T("Blocking")} <b>{nb}</b></span></p>']
        os_items = [f for f in items if str(f.get("location", "")).startswith("OS package")]
        app_items = [f for f in items if f not in os_items]
        for label, group in (("Operating-system packages", os_items), ("Application packages", app_items)):
            if not group:
                continue
            rem, n = remediation_by_package(group)
            body.append(f"<h3>{T(label)}</h3>")
            if rem:
                body.append('<p class="small muted">' + (
                    T("{n} package(s) to upgrade — usually cleared by rebuilding on a current base image.", n=n)
                    if group is os_items else T("{n} package(s) to upgrade.", n=n)) + "</p>" + rem)
            tbl, n = vuln_by_cve(group, limit=30)
            body.append(tbl)
        return f'<div class="tool">{self.panel_head(r)}{"".join(body)}</div>'

    # DAST
    def stage_dast(self, srows):
        d, out = self.d, []
        files = {"ZAP baseline": "zap.json", "ZAP full scan": "zap-full.json", "ZAP API scan": "zap-api.json"}
        explained = set()
        for r in srows:
            tool = r.get("tool") or ""
            fname = files.get(tool)
            if not fname:
                out.append(self.tool_panel(r))
                continue
            data = d.zap.get(fname)
            if not data:
                out.append(self.tool_panel(r))
                continue
            blocking_ids = {str(f.get("id")) for f in d.raw if f.get("tool") == tool and f.get("gating")}
            alerts = []
            for site in data.get("site", []) or []:
                for a in site.get("alerts", []) or []:
                    sev = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "UNKNOWN"}.get(str(a.get("riskcode")), "UNKNOWN")
                    alerts.append((sev, a))
            alerts.sort(key=lambda x: SEV_RANK[x[0]])
            c = Counter(s for s, _ in alerts)
            body = [f'<p>{bar_svg(c, 160)} &nbsp;{sev_strip(Counter({k: v for k, v in c.items() if k != "UNKNOWN"}))}'
                    f' <span class="cnt">{T("Informational")} <b>{c.get("UNKNOWN", 0)}</b></span></p>']
            rows = []
            for sev, a in alerts:
                rows.append([sev_pill(sev) if sev != "UNKNOWN" else f'<span class="sev sev-unknown">{T("Info")}</span>',
                             f'<b>{esc(a.get("alert") or a.get("name"))}</b>',
                             f'CWE-{esc(a.get("cweid"))}' if str(a.get("cweid") or "-1") not in ("-1", "0", "") else "—",
                             str(a.get("count") or len(a.get("instances") or [])),
                             f'<span class="pill bad">{T("Blocking")}</span>' if str(a.get("pluginid")) in blocking_ids
                             else f'<span class="pill neutral">{T("Tracked")}</span>'])
            body.append(table(["Risk", "Alert", "CWE", "Instances", "Status"], rows, "findings",
                              ["11%", "51%", "13%", "12%", "13%"]))
            serious = [(s, a) for s, a in alerts if s in ("HIGH", "MEDIUM")]
            if serious:
                body.append(f"<h3>{T('Evidence and remediation')}</h3>")
            for sev, a in serious[:12]:
                inst = a.get("instances") or []
                irows = [[f'<span class="mono small">{esc(i.get("method", ""))}</span>',
                          f'<span class="mono small">{esc(short(i.get("uri"), 90))}</span>',
                          f'<span class="mono small">{esc(i.get("param") or "—")}</span>',
                          f'<span class="mono small">{esc(short(i.get("attack") or i.get("evidence") or "", 60)) or "—"}</span>']
                         for i in inst[:5]]
                body.append(f'<p class="alert-h">{sev_pill(sev)} <b>{esc(a.get("alert") or a.get("name"))}</b></p>')
                if irows:
                    body.append(table(["Method", "URL", "Parameter", "Attack / evidence"], irows, "findings",
                                      ["10%", "45%", "15%", "30%"]))
                    if len(inst) > 5:
                        body.append(note(T("{n} more instances in {f}.", n=len(inst) - 5, f=fname)))
                sol = strip_html(a.get("solution"), 360)
                name = a.get("alert") or a.get("name")
                if name in explained:
                    sol = ""
                explained.add(name)
                if sol:
                    body.append(f'<p class="small"><b>{T("Remediation:")}</b> <span dir="ltr">{esc(sol)}</span></p>')
            if not alerts:
                body.append(callout(T("No alerts."), "ok"))
            out.append(f'<div class="tool">{self.panel_head(r)}{"".join(body)}</div>')
        return "".join(out)

    # runtime
    def stage_runtime(self, srows):
        d, out = self.d, []
        for r in srows:
            body = []
            if d.waf and r["status"] != "skipped":
                rows = []
                for line in d.waf:
                    ok, info = line.startswith("PASS"), line.startswith("INFO")
                    m = re.match(r"^(PASS|FAIL|INFO)\s+(.*?)\s*→\s*(\S+)$", line)
                    desc, code = (m.group(2), m.group(3)) if m else (line[5:].strip(), "")
                    kind, _, target = desc.partition(" → ")
                    expect = (T("allowed") if kind.startswith("legitimate") else
                              T("informational") if info or kind.startswith("template injection") else
                              T("blocked (HTTP 403)"))
                    pill = (f'<span class="pill ok">{T("As expected")}</span>' if ok else
                            f'<span class="pill neutral">{T("Not blocked (info)")}</span>' if info else
                            f'<span class="pill bad">{T("Not as expected")}</span>')
                    cell = esc(T(kind)) + (f'<br/><span class="mono small">{esc(target)}</span>' if target else "")
                    rows.append([cell, expect, f'<span class="mono">{esc(code)}</span>', pill])
                body.append(table(["Request", "Expected", "Response", "Result"], rows, "", ["40%", "22%", "14%", "24%"]))
                body.append(note(T("Generic attacks first, then the same attacks against each real endpoint and "
                                   "parameter from the OpenAPI specification. Template injection is informational: "
                                   "the OWASP Core Rule Set at paranoia level 1 does not claim to block it. A passing "
                                   "WAF is a compensating control, not a fix: the application flaws in the DAST "
                                   "section remain exploitable wherever the WAF is absent or bypassed.")))
            out.append(f'<div class="tool">{self.panel_head(r)}{"".join(body)}</div>' if body else self.tool_panel(r))
        return "".join(out)

    # ---------------------------------------------------------------- compliance, baseline, supply chain
    CTRL_CLS = {"evidenced": "ok", "gap": "bad", "unverified": "warn", "not assessed": "skip"}
    CTRL_LABEL = {"evidenced": "Evidenced", "gap": "Gap", "unverified": "Unverified", "not assessed": "Not assessed"}

    def compliance(self):
        d = self.d
        if not d.compliance:
            return ""
        out = [self.h1("Compliance evidence", "compliance")]
        out.append('<p class="lead">' + T("Which controls this run produced technical evidence for. This is an evidence "
                                          "map, not a compliance attestation: each control also needs process and "
                                          "governance evidence that a pipeline cannot produce. Appendix D lists the "
                                          "exact artefacts, with their SHA-256 hashes, behind each control.") + '</p>')
        c = Counter(x["status"] for x in d.compliance)
        out.append("<p>" + " ".join(f'<span class="pill {self.CTRL_CLS.get(k, "info")}">{esc(T(self.CTRL_LABEL[k]))} '
                                    f'{c.get(k, 0)}</span>' for k in self.CTRL_LABEL) + "</p>")
        by_fw = defaultdict(list)
        for x in d.compliance:
            by_fw[x["framework"]].append(x)
        for fw, ctrls in by_fw.items():
            out.append(f"<h3>{esc(T(fw))}</h3>")
            rows = [[f'<b class="mono">{esc(x["id"])}</b>', esc(x.get("title_ar") if LANG == "ar" and x.get("title_ar")
                                                             else x["title"]),
                     f'<span class="pill {self.CTRL_CLS.get(x["status"], "info")}">{esc(T(self.CTRL_LABEL.get(x["status"], x["status"])))}</span>',
                     f'<span class="small">{esc(", ".join(stage_title(s).split(" (")[0] for s in x["stages"]))}</span>']
                    for x in ctrls]
            out.append(table(["Control", "Requirement", "Status", "Evidence from"], rows, "",
                             ["13%", "43%", "14%", "30%"]))
        out.append(note(T("Evidenced: every stage mapped to the control ran and passed. Gap: a mapped stage failed. "
                          "Unverified: a mapped scanner errored. Not assessed: no mapped stage ran.")))
        return "".join(out)

    def baseline(self):
        d = self.d
        accepted = [f for f in d.merged if f.get("baselined")]
        expired = [f for f in d.merged if f.get("exception_expired") and f.get("gating")]
        if not accepted and not expired:
            return ""
        out = [self.h1("Accepted risks and false positives", "baseline")]
        out.append('<p class="lead">' + T("Findings that would block but are covered by an active exception in "
                                          ".sawone-baseline.yml. Each exception has an owner and an expiry date; when it "
                                          "expires the finding blocks again.") + '</p>')
        fps = [f for f in accepted if (f["baselined"] or {}).get("type") == "false-positive"]
        if accepted:
            rows = [[sev_pill(f["severity"]), f'<span class="mono small">{esc(f["id"])}</span>', where(f),
                     finding_state(f), esc(f["baselined"].get("owner")), esc(f["baselined"].get("expires")),
                     f'<span class="small">{esc(short(f["baselined"].get("reason"), 120))}</span>']
                    for f in sort_findings(accepted)[:80]]
            out.append(table(["Severity", "Finding", "Location", "Type", "Owner", "Expires", "Reason"], rows, "findings",
                             ["9%", "16%", "18%", "11%", "10%", "11%", "25%"]))
        if fps:
            by_tool = Counter((f.get("tools") or [f.get("tool")])[0] for f in fps)
            tot = Counter((f.get("tools") or [f.get("tool")])[0] for f in d.merged)
            rows = [[esc(short_tool(t)), str(n), str(tot.get(t, n)), f"{100 * n / max(tot.get(t, n), 1):.0f}%"]
                    for t, n in by_tool.most_common()]
            out.append(self.h2("False-positive rate by tool", "baseline-fp"))
            out.append(table(["Tool", "False positives", "All findings", "Rate"], rows, "", ["40%", "20%", "20%", "20%"]))
            out.append(note(T("A high rate means that tool's rules need tuning (noise.mute_rules, or a rule-level "
                              "exception) for this codebase.")))
        if expired:
            out.append(callout("<b>" + T("{n} exception(s) expired", n=len(expired)) + "</b> " + T("and now block again:")
                               + " " + ", ".join(f'<span class="mono">{esc(f["id"])}</span> ({esc(f["exception_expired"])})'
                                                 for f in expired[:10]), "warn"))
        return "".join(out)

    def supply_chain(self):
        d = self.d
        if not d.release:
            return ""
        out = [self.h1("Supply chain and release", "supply")]
        out.append('<p class="lead">' + T("How the scanned artefact was built and what happens to it next. Publishing, "
                                          "signing and SLSA provenance are done only by the release workflow, on "
                                          "trusted pushes. The release workflow also signs this report's evidence "
                                          "manifest.") + '</p>')
        out.append(kv([(k, f'<span class="mono">{esc(v)}</span>') for k, v in d.release.items()]))
        return "".join(out)

    # ---------------------------------------------------------------- appendices
    def appendices(self):
        d = self.d
        out = [self.appendix("A", "Tool versions", "app-tools")]
        if d.tools:
            out.append('<p class="lead">' + T("Each tool was resolved once at the start of the run and pinned by digest "
                                              "for every job, so this report states exactly what scanned the build.")
                       + (" " + T("Version policy: {p}.", p=f"<b>{esc(d.version_policy)}</b>") if d.version_policy else "")
                       + "</p>")
            out.append(table(["Tool", "Version / image digest"],
                             [[f"<b>{esc(k)}</b>", f'<span class="mono small">{esc(v)}</span>'] for k, v in sorted(d.tools.items())],
                             "", ["22%", "78%"]))
        else:
            out.append(note(T("Tool manifest not available.")))
        out.append(self.appendix("B", "Definitions", "app-defs", cont=True))
        out.append(table(["Severity", "Meaning"], [
            [sev_pill("CRITICAL"), T("Likely to be exploited with severe impact; fix immediately.")],
            [sev_pill("HIGH"), T("Serious weakness; fix before release.")],
            [sev_pill("MEDIUM"), T("Exploitable under some conditions; fix in the normal cycle.")],
            [sev_pill("LOW"), T("Limited impact or hardening advice.")],
            [sev_pill("UNKNOWN"), T("The tool does not rate severity (for example Checkov without its platform key).")]],
            "", ["16%", "84%"]))
        out.append(table(["Status", "Meaning"], [
            [f'<span class="pill bad">{T("Blocking")}</span>', T("Breaks the gate policy: fixable at the threshold "
                                                                "severity, known exploited, or a failed check.")],
            [f'<span class="pill neutral">{T("Tracked")}</span>', T("Reported for awareness; does not block.")],
            [f'<span class="pill skip">{T("Accepted")}</span>', T("Would block, but covered by an active baseline "
                                                                 "exception.")],
            [f'<span class="pill skip">{T("False positive")}</span>', T("Recorded in the baseline as not a real issue; "
                                                                       "counted in the false-positive rate.")],
            [f'<span class="tag kev">{T("LIVE")}</span>', T("A secret verified as working against its provider.")],
            ['<span class="tag kev">KEV</span>', T("Listed in CISA's Known Exploited Vulnerabilities catalogue.")],
            ['<span class="tag">EPSS</span>', T("FIRST Exploit Prediction Scoring System: probability of exploitation "
                                               "in the next 30 days.")],
            [status_pill("error"), T("The tool did not finish; its results are missing, not clean.")]], "", ["16%", "84%"]))
        out.append(self.appendix("C", "Report artefacts", "app-files", cont=True))
        files = [("summary.json / summary.md", "Gate results, release facts and the findings summary"),
                 ("findings.json", "Every normalised finding, per tool"),
                 ("findings-consolidated.json", "Findings with cross-tool duplicates merged, first seen and fix deadline"),
                 ("evidence/index.json", "Compliance controls and the artefacts that evidence each one"),
                 ("evidence/manifest.sha256", "SHA-256 of every file in this report set (sha256sum -c)"),
                 ("sarif/", "SARIF from every tool (also uploaded to code scanning when enabled)"),
                 ("zap*.json, zap*.html", "OWASP ZAP reports"), ("raw/", "Raw tool output, SBOMs and the threat model"),
                 ("logs/", "Every tool's log"), ("junit.xml", "Gate results for CI test views")]
        out.append(table(["File", "Contents"], [[f'<span class="mono">{esc(a)}</span>', esc(T(b))] for a, b in files],
                         "", ["32%", "68%"]))
        out.append(self.evidence_appendix())
        return "".join(out)

    def evidence_appendix(self):
        ev = load_json(self.d.reports / "evidence" / "index.json")
        if not ev or not ev.get("controls"):
            return ""
        out = [self.appendix("D", "Evidence index", "app-evidence")]
        out.append('<p class="lead">' + T("For each control: the artefacts in this report set that evidence it, with the "
                                          "first 16 characters of their SHA-256. evidence/manifest.sha256 covers every "
                                          "file; verify it with sha256sum -c and, on trusted pushes, the signature "
                                          "made by the release workflow.") + '</p>')
        rows = []
        for c in ev["controls"]:
            arts = c.get("artifacts") or []
            cell = "<br/>".join(f'<span class="mono">{esc(a["path"])}</span> <span class="muted">{a["sha256"][:16]}</span>'
                                for a in arts[:6]) or f'<span class="muted">{T("no artefact (stage not run)")}</span>'
            if len(arts) > 6:
                cell += f'<br/><span class="muted">{T("+{n} more", n=len(arts) - 6)}</span>'
            rows.append([f'<b class="mono">{esc(c["id"])}</b><br/><span class="small muted">{esc(T(c["framework"]))}</span>',
                         f'<span class="pill {self.CTRL_CLS.get(c["status"], "info")}">'
                         f'{esc(T(self.CTRL_LABEL.get(c["status"], c["status"])))}</span>', f'<span class="ev">{cell}</span>'])
        out.append(table(["Control", "Status", "Evidence artefacts"], rows, "findings", ["20%", "14%", "66%"]))
        return "".join(out)

    # ---------------------------------------------------------------- assemble
    def build(self):
        body = [self.executive(), self.scope(), self.gates(), self.risk_ranked(), self.trend(), self.details(),
                self.compliance(), self.baseline(), self.supply_chain(), self.appendices()]
        doc = self.cover() + self.contents() + "".join(body)
        css = CSS.replace("__REPO__", re.sub(r'["\\\n]', "", self.d.repo)) + SLA_CSS
        if LANG == "ar":
            css += RTL_CSS + PAGE_AR
        return (f'<!doctype html><html lang="{LANG}" dir="{"rtl" if LANG == "ar" else "ltr"}"><head><meta charset="utf-8"/>'
                f'<title>Security Assessment — {esc(self.d.repo)}</title><style>{css}</style></head>'
                f'<body>{doc}</body></html>')


def build(reports: Path, lang="en"):
    global LANG
    LANG = lang if lang in ("en", "ar") else "en"
    try:
        return Report(Data(reports)).build()
    finally:
        LANG = "en"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--out", default="security-report.pdf")
    ap.add_argument("--html", default="")
    ap.add_argument("--lang", default="en", choices=["en", "ar"])
    a = ap.parse_args()
    doc = build(Path(a.reports), a.lang)
    if a.html:
        Path(a.html).write_text(doc)
    from weasyprint import HTML  # imported late so --html works without it
    HTML(string=doc, base_url=str(Path(a.reports).resolve())).write_pdf(a.out)
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
