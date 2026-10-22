"""Threat model analysis: STRIDE, evidence from the scanners, risk decisions, diagrams.

Input is OWASP pytm's JSON (`tm.py --json`), which carries the whole model (actors, processes,
datastores, trust boundaries, ordered dataflows) and the threats pytm derived from it.

  STRIDE      every pytm threat gets its primary STRIDE category (pytm itself has none)
  evidence    each threat is matched to scanner findings of the same attack class on the same
              element: DAST/Nuclei proof makes it *confirmed*, a SAST/IaC/secret finding makes it
              *found in code*, nothing makes it *theoretical*
  decisions   `threats:` in the baseline file records mitigate / accept / transfer, with an owner and
              an expiry; a mitigation contradicted by scanner evidence is flagged, not trusted
  gaps        scanner evidence for an attack class the model has no threat for
  diagrams    data-flow diagram (Graphviz) and sequence diagram (SVG), elements coloured by status
"""
import datetime as dt
import html
import re
import shutil
import subprocess
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

STRIDE = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information disclosure",
          "D": "Denial of service", "E": "Elevation of privilege"}

# primary STRIDE category of every threat in pytm's library; unknown IDs fall back to their prefix
_SID = {
    "S": "AA01 AA02 AA03 AA04 AC05 AC11 AC16 AC17 AC18 AC19 AC20 AC22 AC24 CR01 CR03 CR04",
    "T": "INP02 INP03 INP04 INP06 INP07 INP08 INP09 INP10 INP12 INP13 INP14 INP15 INP17 INP20 INP21 INP23 "
         "INP25 INP27 INP28 INP29 INP30 INP32 INP35 INP36 INP37 INP38 INP39 INP40 AC02 AC04 AC06 AC08 AC09 "
         "AC15 AC21 CR06 CR07 CR08 DE02 LB01 SC02 SC03 SC04 SC05 DS04 LLM01 LLM02 LLM04",
    "R": "DE04",
    "I": "DE01 DE03 DS01 DS02 DS03 DS05 DS06 DR01 HA01 HA02 HA03 HA04 INP11 INP18 CR02 CR05 AC10 AC23 SC01 "
         "LLM03 LLM08",
    "D": "DO01 DO02 DO03 DO04 DO05 INP19 INP22 INP34",
    "E": "INP01 INP05 INP16 INP24 INP26 INP31 INP33 INP41 AC01 AC03 AC07 AC12 AC13 AC14 API01 API02 "
         "LLM05 LLM06 LLM07 LLM09",
}
SID_STRIDE = {sid: k for k, v in _SID.items() for sid in v.split()}
PREFIX_STRIDE = {"INP": "T", "AC": "E", "AA": "S", "CR": "I", "DE": "I", "DO": "D", "DS": "I", "HA": "I",
                 "SC": "T", "LB": "T", "API": "E", "DR": "I", "LLM": "T"}


def stride_of(sid):
    sid = str(sid or "")
    if sid in SID_STRIDE:
        return SID_STRIDE[sid]
    m = re.match(r"[A-Z]+", sid)
    return PREFIX_STRIDE.get(m.group(0) if m else "", "T")


# Attack classes: which pytm threats they cover, and how a scanner finding is recognised as one.
#   cwe   CWE numbers on SAST/DAST findings     zap   ZAP plugin IDs (the finding's id)
#   rule  regex on rule ID + title              stages  restrict the class to findings of these stages
CLASSES = {
    "sql-injection": {"title": "SQL injection", "sids": "INP05 INP06 INP10 INP14",
                      "cwe": [89, 564, 943], "zap": [40018, 40019, 40020, 40021, 40022, 40024, 40027, 90039],
                      "rule": r"sql|nosql"},
    "command-injection": {"title": "OS command injection", "sids": "INP31 INP13 INP41 INP05 INP15 AC03",
                          "cwe": [77, 78, 88], "zap": [90020],
                          "rule": r"command.?injection|shell.?true|subprocess|os[.-]system|popen|child.?process"},
    "code-injection": {"title": "Code or template injection", "sids": "INP26 INP33 INP16 INP23 API02",
                       "cwe": [94, 95, 96, 502, 1336, 470, 913], "zap": [90035, 90036, 90019, 20018],
                       "rule": r"\beval\b|eval-detected|exec-detected|template.?injection|ssti|render.?template.?string|"
                               r"deserial|pickle|yaml.?load|unsafe-load|marshal"},
    "xss": {"title": "Cross-site scripting", "sids": "INP27 INP28 INP29 INP30 INP38 INP39 INP40 SC02 SC03 SC04 INP17 DS04",
            "cwe": [79, 80, 83, 87], "zap": [40012, 40014, 40016, 40017, 40026],
            "rule": r"xss|cross.?site.?scripting|mark.?safe|innerhtml|dangerouslysetinnerhtml|unescaped"},
    "path-traversal": {"title": "Path traversal and file inclusion", "sids": "HA01 INP11 INP25 INP23 INP16",
                       "cwe": [22, 23, 36, 73, 98, 99], "zap": [6, 7, 43],
                       "rule": r"path.?traversal|directory.?traversal|file.?inclusion|path-traversal-open"},
    "memory": {"title": "Buffer and integer overflow", "sids": "INP01 INP02 INP07 INP12 INP24 INP34",
               "cwe": [119, 120, 121, 122, 190, 680, 787], "zap": [30001, 30003], "rule": r"overflow"},
    "format-string": {"title": "Format string injection", "sids": "INP08", "cwe": [134], "zap": [30002],
                      "rule": r"format.?string"},
    "ssrf": {"title": "Server-side request forgery", "sids": "", "cwe": [918], "zap": [40046],
             "rule": r"ssrf|server.?side.?request"},
    "xml": {"title": "XML injection and entity expansion", "sids": "INP32 INP19 INP21 INP22 AC04 DO03 DO04 DO05",
            "cwe": [91, 611, 776, 827], "zap": [90023, 90017], "rule": r"\bxxe\b|xml.?external|xml.?injection|lxml|etree"},
    "csrf": {"title": "Cross-site request forgery", "sids": "AC21", "cwe": [352], "zap": [10202, 20012],
             "rule": r"csrf"},
    "clickjacking": {"title": "Clickjacking (UI redress)", "sids": "INP20", "cwe": [1021], "zap": [10020],
                     "rule": r"clickjack|anti.?clickjacking|x-frame-options"},
    "session": {"title": "Session handling", "sids": "AC11 AC16 AC17 AC18 AC19 AC20 CR01 CR04",
                "cwe": [384, 565, 613, 614, 1004, 539], "zap": [3, 10010, 10011, 10054, 90033],
                "rule": r"cookie|session.?fixation|session.?id"},
    "transport": {"title": "Unencrypted or weak transport", "sids": "DE01 DE03 CR02 CR06 CR07 CR08 AC10 DR01 DS06",
                  "cwe": [295, 297, 311, 319, 326, 523, 757], "zap": [10035, 10040, 10098],
                  "rule": r"\btls\b|\bssl\b|https|in.?transit|plaintext|insecure.?transport|hsts|strict.?transport|"
                          r"verify.?false|certificate"},
    "weak-crypto": {"title": "Weak cryptography and password storage", "sids": "CR03 CR05 AC22",
                    "cwe": [261, 326, 327, 328, 759, 760, 916], "zap": [],
                    "rule": r"md5|sha1|weak.?hash|weak.?cipher|insecure.?hash|\bdes\b|rc4|ecb"},
    "authentication": {"title": "Authentication", "sids": "AA01 AA02 AA04", "stages": ["sast", "dast"],
                       "cwe": [287, 288, 290, 306, 307, 521, 1390], "zap": [10105, 40034],
                       "rule": r"authenticat|login|brute.?force|password.?policy|\bmfa\b"},
    "privilege": {"title": "Authorisation and privilege", "sids": "AC01 AC07 AC12 AC13 AC09 API01",
                  "cwe": [250, 269, 284, 285, 639, 862, 863], "zap": [],
                  "rule": r"privilege|run.?as.?root|runs?.?as.?root|root.?user|capabilit|access.?control|idor|"
                          r"missing.?authori|permission"},
    "credentials": {"title": "Hard-coded or leaked credentials", "sids": "AC23 AC24 AA03",
                    "cwe": [259, 321, 522, 798], "zap": [], "stages_any": ["secrets"],
                    "rule": r"hard.?coded|secret|password|api.?key|private.?key|credential|token"},
    "info-disclosure": {"title": "Information disclosure", "sids": "DS01 DS03 DS05 HA03 INP18",
                        "cwe": [200, 209, 215, 497, 532, 538, 540, 541, 548, 489], "zap": [2, 43, 10023, 10024, 10025, 10026,
                                                                                         10027, 10036, 10037, 10096, 90022],
                        "rule": r"disclosure|debug|stack.?trace|version.?(information|leak)|directory.?listing|"
                                r"server.?leaks|x-powered-by"},
    "dos": {"title": "Denial of service", "sids": "DO01 DO02 DO03 DO04 DO05",
            "cwe": [400, 674, 770, 799, 1333], "zap": [], "rule": r"redos|regular.?expression.?denial|unbounded|"
                                                                    r"rate.?limit|resource.?exhaust"},
    "at-rest": {"title": "Data at rest and storage access", "sids": "CR05 AC01 AC02 DS05", "stages": ["iac"],
                "kinds": ["Datastore"],
                "cwe": [311, 312, 313, 732, 922], "zap": [],
                "rule": r"encrypt|unencrypted|public|\bacl\b|bucket|storage|backup|snapshot"},
    "logging": {"title": "Logging and audit trail", "sids": "DE04", "cwe": [117, 223, 778], "zap": [],
                "rule": r"log.?injection|audit.?log|logging.?disabled|no.?logging"},
}
for _c in CLASSES.values():
    _c["sids"] = set(_c["sids"].split())
    _c.setdefault("zap", [])
    _c["_rule"] = re.compile(_c["rule"], re.I)

# stages that produce evidence; supply-chain CVEs are component risk, not a design threat
EVIDENCE_STAGES = {"sast", "dast", "iac", "kubernetes", "secrets", "runtime", "iast"}
STATUS_ORDER = ["contradicted", "confirmed", "in-code", "theoretical", "transferred", "accepted", "mitigated"]
STATUS_LABEL = {"confirmed": "Confirmed exploitable", "in-code": "Found in code or config",
                "theoretical": "Theoretical", "mitigated": "Mitigated", "accepted": "Risk accepted",
                "transferred": "Risk transferred", "contradicted": "Mitigation contradicted by evidence"}
STATUS_COLOR = {"confirmed": "#b91c1c", "contradicted": "#7f1d1d", "in-code": "#c2410c", "theoretical": "#64748b",
                "mitigated": "#15803d", "accepted": "#0369a1", "transferred": "#0369a1"}
SEV_ORDER = ["Low", "Medium", "High", "Very High"]


# ---------------------------------------------------------------- finding classification
def _cwes(f):
    out = set()
    for c in f.get("cwe") or []:
        m = re.search(r"(\d+)", str(c))
        if m:
            out.add(int(m.group(1)))
    return out


def classify(f):
    """Attack classes a normalised finding is evidence for."""
    stage = f.get("stage")
    stages = set(f.get("stages") or [stage])
    if not stages & EVIDENCE_STAGES:
        return set()
    text = f"{f.get('id') or ''} {f.get('title') or ''}"
    cwes, out = _cwes(f), set()
    zap_id = None
    if "dast" in stages and str(f.get("id") or "").isdigit():
        zap_id = int(f["id"])
    for key, c in CLASSES.items():
        if c.get("stages") and not stages & set(c["stages"]):
            continue
        if stages & set(c.get("stages_any") or []):
            out.add(key)
        elif zap_id is not None and str(f.get("tool", "")).startswith("ZAP"):
            if zap_id in c["zap"]:
                out.add(key)
        elif cwes & set(c["cwe"]) or c["_rule"].search(text):
            out.add(key)
    return out


def strength(f):
    """confirmed: an attack on the running app (or a verified live secret) succeeded; code: static evidence."""
    stages = set(f.get("stages") or [f.get("stage")])
    if stages & {"dast", "runtime", "iast"} or f.get("verified"):
        return "confirmed"
    return "code"


# ---------------------------------------------------------------- model structure
def _elements(model):
    """name -> {kind, boundary, sourceFiles} for actors, processes, datastores, and dataflows."""
    out = {}
    for e in (model.get("actors") or []) + (model.get("elements") or []) + (model.get("assets") or []):
        name = e.get("name")
        if not name or name in out:
            continue
        out[name] = {"kind": e.get("__class__") or "Element", "boundary": e.get("inBoundary"),
                     "files": [str(x) for x in e.get("sourceFiles") or []], "name": name}
    for fl in model.get("flows") or []:
        out.setdefault(fl.get("name"), {"kind": "Dataflow", "boundary": None, "name": fl.get("name"),
                                        "files": [str(x) for x in fl.get("sourceFiles") or []],
                                        "source": fl.get("source"), "sink": fl.get("sink")})
    return out


def _exposed(model, elems):
    """Elements an outside party reaches: the sink of a flow from an actor or across a trust boundary,
    and every flow that crosses one. DAST evidence attaches to these."""
    exposed = set()
    for fl in model.get("flows") or []:
        src, dst = elems.get(fl.get("source"), {}), elems.get(fl.get("sink"), {})
        crosses = src.get("boundary") != dst.get("boundary") or src.get("kind") == "Actor"
        if crosses:
            exposed.add(fl.get("name"))
            if dst.get("kind") in ("Process", "Server", "Lambda"):
                exposed.add(dst.get("name"))
    return exposed


def _external(model, elems):
    """Elements outside the system under review: external entities, and processes that share a trust
    boundary with an actor without receiving any flow from one (a third-party website, a partner API).
    An element with sourceFiles is always ours. External elements never take our scanners' evidence."""
    actor_bounds = {e.get("boundary") for e in elems.values() if e["kind"] == "Actor"}
    entry = {fl.get("sink") for fl in model.get("flows") or [] if elems.get(fl.get("source"), {}).get("kind") == "Actor"}
    out = set()
    for name, e in elems.items():
        if e.get("files"):
            continue
        if e["kind"] == "ExternalEntity" or (e["kind"] in ("Process", "Server", "Lambda")
                                             and e.get("boundary") in actor_bounds and name not in entry):
            out.add(name)
    return out


CI_PATHS = re.compile(r"(^|/)(\.github/|\.gitlab-ci\.ya?ml$|\.gitlab/|azure-pipelines[^/]*\.ya?ml$|"
                      r"Jenkinsfile$|\.circleci/|bitbucket-pipelines\.ya?ml$)")


def _path(f):
    loc = str(f.get("location") or "")
    p = loc.split(":", 1)[0].split(" ", 1)[0]
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def _in_files(f, files):
    """The finding sits in one of the element's sourceFiles (a file or a directory, relative to the model's
    project, which may itself be a subdirectory of the scanned workspace)."""
    p = "/" + _path(f)
    for x in files:
        x = str(x).strip()
        while x.startswith("./"):
            x = x[2:]
        x = "/" + x.strip("/")
        if x == "/":
            continue
        if p.endswith(x) or (x + "/") in (p + "/"):
            return True
    return False


# ---------------------------------------------------------------- decisions
def load_decisions(path, today=None, max_days=365):
    """`threats:` entries of the baseline file. Returns (active, expired, errors). An invalid entry is
    ignored (the threat stays open) and reported, so a typo can never hide a threat."""
    today = today or dt.date.today()
    active, expired, errors = [], [], []
    p = Path(path)
    if not p.exists() or yaml is None:
        return active, expired, errors
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except (OSError, ValueError) as e:
        return active, expired, [f"{p.name}: cannot read threats ({e})"]
    for i, e in enumerate(data.get("threats") or [], 1):
        if not isinstance(e, dict):
            errors.append(f"threats[{i}]: not a mapping")
            continue
        miss = [k for k in ("threat", "decision", "owner", "expires") if not e.get(k)]
        dec = str(e.get("decision") or "").lower()
        if miss:
            errors.append(f"threats[{i}] ({e.get('threat')}): missing {', '.join(miss)}")
            continue
        if dec not in ("mitigate", "accept", "transfer"):
            errors.append(f"threats[{i}] ({e['threat']}): decision must be mitigate, accept or transfer")
            continue
        if dec == "mitigate" and not e.get("control"):
            errors.append(f"threats[{i}] ({e['threat']}): mitigate needs the control that mitigates it")
            continue
        if dec != "mitigate" and not e.get("reason"):
            errors.append(f"threats[{i}] ({e['threat']}): {dec} needs a reason")
            continue
        try:
            exp = e["expires"] if isinstance(e["expires"], dt.date) else dt.date.fromisoformat(str(e["expires"]))
        except ValueError:
            errors.append(f"threats[{i}] ({e['threat']}): expires must be YYYY-MM-DD")
            continue
        if (exp - today).days > max_days:
            errors.append(f"threats[{i}] ({e['threat']}): expires more than {max_days} days ahead")
            continue
        entry = {"threat": str(e["threat"]), "element": str(e.get("element") or "*"), "decision": dec,
                 "owner": str(e["owner"]), "expires": exp.isoformat(),
                 "control": str(e.get("control") or ""), "reason": str(e.get("reason") or "")}
        (expired if exp < today else active).append(entry)
    return active, expired, errors


def _decision_for(sid, target, decisions):
    for d in decisions:
        if d["threat"] == sid and d["element"] in ("*", target):
            return d
    return None


# ---------------------------------------------------------------- analysis
def analyse(model, findings, decisions=(), mitigated=None, min_severity="Very High"):
    """Per threat: STRIDE, status, evidence; per element: STRIDE matrix; plus model gaps."""
    mitigated = mitigated or {}
    elems = _elements(model)
    exposed = _exposed(model, elems)
    external = _external(model, elems)
    floor = SEV_ORDER.index(min_severity) if min_severity in SEV_ORDER else 3
    evidence = {}                                     # class -> [finding]
    for f in findings:
        b = f.get("baselined")
        if isinstance(b, dict) and b.get("type") == "false-positive":
            continue
        for c in classify(f):
            evidence.setdefault(c, []).append(f)
    sid_classes = {}
    for key, c in CLASSES.items():
        for sid in c["sids"]:
            sid_classes.setdefault(sid, []).append(key)

    threats = []
    for t in model.get("findings") or []:
        sid, target = t.get("threat_id"), t.get("target")
        el = elems.get(target, {"kind": "Element", "files": []})
        ev = []
        for cls in ([] if target in external else sid_classes.get(sid, [])):
            for f in evidence.get(cls, []):
                stages = set(f.get("stages") or [f.get("stage")])
                dynamic = bool(stages & {"dast", "runtime", "iast"})
                if el.get("files") and not dynamic and not _in_files(f, el["files"]):
                    continue                          # static evidence must sit in the element's own files
                if not dynamic and not el.get("files") and CI_PATHS.search(_path(f)):
                    continue                          # a pipeline weakness is not evidence about the app
                if el["kind"] == "Datastore" and not dynamic and not el.get("files"):
                    continue                          # IaC proves a store's controls only when the model names its files
                if dynamic and target not in exposed:
                    continue                          # an attack from outside proves nothing about inner elements
                if CLASSES[cls].get("kinds") and el["kind"] not in CLASSES[cls]["kinds"]:
                    continue
                if el["kind"] == "Datastore" and cls not in ("at-rest", "sql-injection", "weak-crypto", "credentials"):
                    continue
                if el["kind"] == "Dataflow" and not dynamic and not el.get("files"):
                    continue                          # a flow's transport is proven on the live app, not by any repo file
                if el["kind"] == "Dataflow" and cls not in ("transport", "info-disclosure", "credentials", "session",
                                                            "xml", "csrf"):
                    continue
                if el["kind"] == "Actor":
                    continue
                ev.append({"class": cls, "strength": strength(f), "tool": f.get("tool"), "id": f.get("id"),
                           "title": f.get("title"), "location": f.get("location"), "severity": f.get("severity")})
        seen, uniq = set(), []
        for e in sorted(ev, key=lambda e: (e["strength"] != "confirmed", str(e["id"]))):
            k = (e["tool"], e["id"], e["location"])
            if k not in seen:
                seen.add(k)
                uniq.append(e)
        best = "confirmed" if any(e["strength"] == "confirmed" for e in uniq) else ("in-code" if uniq else "theoretical")
        dec = _decision_for(sid, target, decisions)
        key = f"{sid}@{target}"
        if dec is None and key in mitigated:
            dec = {"threat": sid, "element": target, "decision": "mitigate", "owner": "", "expires": "",
                   "control": str(mitigated[key]), "reason": "", "legacy": True}
        if dec:
            status = {"accept": "accepted", "transfer": "transferred"}.get(dec["decision"], "mitigated")
            if status == "mitigated" and best != "theoretical":
                status = "contradicted"
        else:
            status = best
        sev = t.get("severity") or "Medium"
        open_ = status in ("confirmed", "in-code", "theoretical", "contradicted")
        threats.append({"sid": sid, "target": target, "kind": el["kind"], "external": target in external, "title": t.get("description") or sid,
                        "severity": sev, "likelihood": t.get("likelihood"), "stride": stride_of(sid),
                        "status": status, "evidence_level": best, "evidence": uniq[:12], "evidence_total": len(uniq),
                        "decision": dec, "mitigations": _tidy(t.get("mitigations")), "references": t.get("references") or "",
                        "exposed": target in exposed,
                        "gating": open_ and target not in external
                                  and (SEV_ORDER.index(sev) >= floor if sev in SEV_ORDER else False)})

    model_classes = {k for sid in {t["sid"] for t in threats} for k in sid_classes.get(sid, [])}
    gaps = []
    for cls, fs in sorted(evidence.items()):
        if cls not in model_classes:
            gaps.append({"class": cls, "title": CLASSES[cls]["title"], "findings": len(fs),
                         "confirmed": sum(1 for f in fs if strength(f) == "confirmed"),
                         "examples": [f"{f.get('tool')}: {f.get('title')}" for f in fs[:3]]})
    gaps.sort(key=lambda g: (-g["confirmed"], -g["findings"]))

    matrix = {}
    for t in threats:
        row = matrix.setdefault(t["target"], {"kind": t["kind"], "cells": {k: [] for k in STRIDE}})
        row["cells"][t["stride"]].append(t["status"])
    for name, e in elems.items():
        if e["kind"] != "Actor":
            matrix.setdefault(name, {"kind": e["kind"], "cells": {k: [] for k in STRIDE}})
    counts = {s: sum(1 for t in threats if t["status"] == s) for s in STATUS_ORDER}
    owned = [n for n, e in elems.items() if e["kind"] in ("Process", "Server", "Lambda") and n not in external]
    unscoped = sorted(n for n in owned if not elems[n].get("files")) if len(owned) > 1 else []
    worst = {}
    for t in threats:
        cur = worst.get(t["target"])
        if t["status"] in ("confirmed", "contradicted", "in-code", "theoretical") and \
                (cur is None or STATUS_ORDER.index(t["status"]) < STATUS_ORDER.index(cur)):
            worst[t["target"]] = t["status"]
    return {"name": model.get("name"), "description": model.get("description"), "threats": threats,
            "counts": counts, "total": len(threats), "gating": sum(1 for t in threats if t["gating"]),
            "by_stride": {k: sum(1 for t in threats if t["stride"] == k) for k in STRIDE},
            "matrix": matrix, "gaps": gaps, "worst": worst, "exposed": sorted(x for x in exposed if x),
            "unscoped": unscoped,
            "external": sorted(external)}


# ---------------------------------------------------------------- diagrams
def _q(s):
    """DOT string literal; \\n inside stays a DOT line break."""
    return '"' + str(s).replace('"', '\\"') + '"'


def dfd_dot(model, analysis=None):
    """Graphviz source of the data-flow diagram: trust boundaries as dashed clusters, actors as boxes,
    processes as ellipses, datastores as cylinders, numbered flows; red border = confirmed threat."""
    worst = (analysis or {}).get("worst") or {}
    elems = _elements(model)
    lines = ["digraph DFD {", '  graph [rankdir=LR, fontname="Inter", fontsize=11, nodesep=0.5, ranksep=0.9, pad=0.2, bgcolor="white"];',
             '  node [fontname="Inter", fontsize=10, color="#334155", penwidth=1.2, style=filled, fillcolor="#f8fafc"];',
             '  edge [fontname="Inter", fontsize=8.5, color="#475569", arrowsize=0.7];']
    shapes = {"Actor": "box", "Process": "ellipse", "Server": "ellipse", "Lambda": "ellipse", "Datastore": "cylinder",
              "ExternalEntity": "box"}
    ids, by_boundary = {}, {}
    for i, (name, e) in enumerate(elems.items()):
        if e["kind"] == "Dataflow":
            continue
        ids[name] = f"n{i}"
        by_boundary.setdefault(e.get("boundary") or "", []).append(name)

    def node(name):
        e = elems[name]
        st = worst.get(name)
        col = STATUS_COLOR.get(st, "#334155")
        width = "2.4" if st in ("confirmed", "contradicted") else "1.2"
        fill = {"Actor": "#eef2ff", "Datastore": "#f0fdf4"}.get(e["kind"], "#f8fafc")
        return (f'    {ids[name]} [label={_q(name)}, shape={shapes.get(e["kind"], "ellipse")}, color="{col}", '
                f'penwidth={width}, fillcolor="{fill}"];')
    for b, (bname, names) in enumerate(sorted(by_boundary.items())):
        if bname:
            lines += [f"  subgraph cluster_{b} {{", f'    label={_q(bname)}; style="dashed,rounded"; color="#dc2626"; '
                      'fontcolor="#dc2626"; fontsize=10;']
            lines += [node(n) for n in names]
            lines.append("  }")
        else:
            lines += [node(n) for n in names]
    for fl in sorted(model.get("flows") or [], key=lambda f: (f.get("order") if isinstance(f.get("order"), int) and f.get("order") >= 0 else 999)):
        s, d = fl.get("source"), fl.get("sink")
        if s not in ids or d not in ids:
            continue
        enc = (fl.get("controls") or {}).get("isEncrypted")
        cross = elems[s].get("boundary") != elems[d].get("boundary")
        proto = fl.get("protocol") or ""
        port = fl.get("dstPort")
        meta = proto + (f":{port}" if isinstance(port, int) and port > 0 else "")
        order = fl.get("order")
        label = (f"{order}. " if isinstance(order, int) and order > 0 else "") + str(fl.get("name"))
        if meta:
            label += f"\\n{meta}"
        if cross and not enc:
            label += "\\n(unencrypted)"
        st = worst.get(fl.get("name"))
        col = STATUS_COLOR.get(st, "#dc2626" if cross and not enc else "#475569")
        style = "dashed" if fl.get("isResponse") or fl.get("responseTo") else "solid"
        lines.append(f'  {ids[s]} -> {ids[d]} [label={_q(label)}, '
                     f'color="{col}", fontcolor="{col}", style={style}];')
    lines.append("}")
    return "\n".join(lines)


def render_dot(dot_src, out_svg):
    """dot -> SVG; False when Graphviz is not installed or fails (the report then says so)."""
    exe = shutil.which("dot")
    if not exe:
        return False
    try:
        p = subprocess.run([exe, "-Tsvg"], input=dot_src, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if p.returncode != 0 or "<svg" not in p.stdout:
        return False
    Path(out_svg).write_text(p.stdout[p.stdout.index("<svg"):])
    return True


def sequence_svg(model, width_per=150):
    """Sequence diagram of the ordered dataflows, as standalone SVG (no Java/PlantUML needed)."""
    flows = sorted([f for f in model.get("flows") or [] if f.get("source") and f.get("sink")],
                   key=lambda f: (f.get("order") if isinstance(f.get("order"), int) and f.get("order") >= 0 else 999))
    if not flows:
        return ""
    elems = _elements(model)
    parts = []
    for f in flows:
        for n in (f["source"], f["sink"]):
            if n not in parts:
                parts.append(n)
    w = max(width_per * len(parts), 300)
    top, step = 46, 34
    h = top + step * (len(flows) + 1) + 10
    x = {n: width_per * i + width_per // 2 for i, n in enumerate(parts)}
    e = html.escape
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
           f'font-family="Inter, DejaVu Sans, sans-serif" font-size="10">',
           '<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
           '<path d="M0,0 L10,5 L0,10 z" fill="#475569"/></marker>'
           '<marker id="r" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
           '<path d="M0,0 L10,5 L0,10 z" fill="#dc2626"/></marker></defs>']
    for n in parts:
        kind = elems.get(n, {}).get("kind", "")
        fill = {"Actor": "#eef2ff", "Datastore": "#f0fdf4"}.get(kind, "#f8fafc")
        bw = width_per - 16
        out.append(f'<rect x="{x[n] - bw / 2}" y="6" width="{bw}" height="26" rx="4" fill="{fill}" stroke="#334155"/>')
        out.append(f'<text x="{x[n]}" y="23" text-anchor="middle" font-weight="600">{e(_clip(n, 22))}</text>')
        out.append(f'<line x1="{x[n]}" y1="32" x2="{x[n]}" y2="{h - 6}" stroke="#94a3b8" stroke-dasharray="4 3"/>')
    for i, f in enumerate(flows):
        y = top + step * (i + 1)
        x1, x2 = x[f["source"]], x[f["sink"]]
        s, d = elems.get(f["source"], {}), elems.get(f["sink"], {})
        unenc = s.get("boundary") != d.get("boundary") and not (f.get("controls") or {}).get("isEncrypted")
        col, mk = ("#dc2626", "r") if unenc else ("#475569", "a")
        dash = ' stroke-dasharray="5 3"' if f.get("isResponse") or f.get("responseTo") else ""
        if x1 == x2:
            out.append(f'<path d="M{x1},{y - 8} h40 v14 h-38" fill="none" stroke="{col}" marker-end="url(#{mk})"{dash}/>')
            tx = x1 + 46
            anchor = "start"
        else:
            out.append(f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{col}" stroke-width="1.3" '
                       f'marker-end="url(#{mk})"{dash}/>')
            tx, anchor = (x1 + x2) / 2, "middle"
        order = f.get("order")
        label = (f"{order}. " if isinstance(order, int) and order > 0 else "") + str(f.get("name"))
        meta = f.get("protocol") or ""
        out.append(f'<text x="{tx}" y="{y - 5}" text-anchor="{anchor}" fill="{col}">{e(_clip(label, 46))}'
                   + (f' <tspan fill="#64748b">[{e(meta)}]</tspan>' if meta else "") + "</text>")
    out.append("</svg>")
    return "".join(out)


def _tidy(s):
    """pytm joins the phases of a mitigation without a space ("…privilegeDesign: Validate…")."""
    return re.sub(r"(?<=[^\s>])(?=(Design|Implementation|Operation|Configuration|Architecture|Build and Compilation|"
                  r"Testing|Requirements|System Configuration):)", " ", str(s or ""))


def _clip(s, n):
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


def build(reports, model, findings, decisions=(), expired=(), errors=(), mitigated=None, min_severity="Very High"):
    """Write threat-model.json and the diagrams under reports/threatmodel/; return the analysis."""
    import json
    reports = Path(reports)
    out = reports / "threatmodel"
    out.mkdir(parents=True, exist_ok=True)
    a = analyse(model, findings, decisions, mitigated, min_severity)
    a["decision_errors"] = list(errors)
    a["decisions_expired"] = list(expired)
    dot_src = dfd_dot(model, a)
    (out / "dfd.dot").write_text(dot_src)
    a["dfd"] = "threatmodel/dfd.svg" if render_dot(dot_src, out / "dfd.svg") else None
    seq = sequence_svg(model)
    if seq:
        (out / "sequence.svg").write_text(seq)
    a["sequence"] = "threatmodel/sequence.svg" if seq else None
    (reports / "threat-model.json").write_text(json.dumps(a, indent=1, default=str))
    return a
