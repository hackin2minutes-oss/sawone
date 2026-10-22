"""
Sawone — normalised findings, risk policy and baseline (exceptions).

Every gate that can name its individual findings hands them to Policy.apply() as plain dicts:

  {fingerprint, kind, stage, tool, id, title, severity, package, version, fixed_version,
   location, gating}

  kind      vuln | code | secret | config | threat | dast | licence
  gating    True when the finding would block under the severity rule (set by the gate)

Policy.apply() then
  1. enriches CVEs with CISA KEV (known exploited) and FIRST EPSS (exploit probability),
  2. escalates: a KEV CVE blocks at any severity (block_kev), and so does EPSS >= epss_threshold,
  3. suppresses: a blocking finding covered by an active baseline exception stops blocking.
     Expired exceptions no longer suppress, so the finding blocks again on its own.

Fingerprints are stable across tools and line shifts:
  vuln   CVE + package + version          (Trivy, Grype and friends collapse into one finding)
  others kind + rule + path + hash of the line's text (not its number)
"""
import csv
import datetime as dt
import fnmatch
import gzip
import hashlib
import io
import json
import re
from pathlib import Path

SEVERITIES = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_SEV_ALIASES = {"NEGLIGIBLE": "LOW", "INFO": "LOW", "INFORMATIONAL": "LOW", "WARNING": "MEDIUM", "MODERATE": "MEDIUM",
                "ERROR": "HIGH", "IMPORTANT": "HIGH", "VERY HIGH": "CRITICAL"}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_URL_FALLBACK = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def norm_sev(s):
    s = str(s or "UNKNOWN").strip().upper()
    s = _SEV_ALIASES.get(s, s)
    return s if s in SEVERITIES else "UNKNOWN"


def _h(*parts):
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:20]


def line_text(ws, path, line):
    """The (whitespace-normalised) text of a source line, so fingerprints survive code moving."""
    try:
        if not path or not line:
            return ""
        lines = (Path(ws) / path).read_text(errors="ignore").splitlines()
        return " ".join(lines[int(line) - 1].split()) if 0 < int(line) <= len(lines) else ""
    except (OSError, ValueError):
        return ""


def pkg_key(name):
    """Package identity for de-duplication: tools disagree on case and separators
    (Trivy 'Pillow' / Grype 'pillow', 'typing_extensions' / 'typing-extensions')."""
    return re.sub(r"[-_.]+", "-", str(name or "").strip().lower())


def vuln(stage, tool, vid, package, version, severity, fixed_version="", location="", title="", gating=False,
         aliases=()):
    """A CVE-style finding. vid should be the CVE when one exists (aliases may hold GHSA etc.)."""
    vid = str(vid or "").strip()
    return {"fingerprint": _h("vuln", vid.upper(), pkg_key(package), version or ""), "kind": "vuln", "stage": stage,
            "tool": tool, "id": vid, "aliases": sorted({a for a in aliases if a and a != vid}),
            "title": title or vid, "severity": norm_sev(severity), "package": package or "",
            "version": version or "", "fixed_version": fixed_version or "", "location": location or "",
            "gating": bool(gating)}


def issue(stage, tool, kind, rule, path, line, severity, title, ws=None, gating=False, key=None):
    """A code / secret / config / threat / DAST finding at a location."""
    anchor = key if key is not None else (line_text(ws, path, line) if ws else "") or str(line or "")
    loc = f"{path}:{line}" if path and line else (path or "")
    return {"fingerprint": _h(kind, rule, path or "", anchor), "kind": kind, "stage": stage, "tool": tool,
            "id": str(rule), "aliases": [], "title": title or str(rule), "severity": norm_sev(severity),
            "package": "", "version": "", "fixed_version": "", "location": loc, "gating": bool(gating)}


# ------------------------------------------------------------------ intelligence (KEV / EPSS)
class Intel:
    def __init__(self, kev=None, epss=None, source=""):
        self.kev = kev            # {CVE: {"date_added", "ransomware"}} or None when unavailable
        self.epss = epss          # {CVE: (score, percentile)} or None when unavailable
        self.source = source

    @classmethod
    def load(cls, directory):
        d = Path(directory)
        kev, epss = None, None
        try:
            data = json.loads((d / "kev.json").read_text())
            kev = {v["cveID"].upper(): {"date_added": v.get("dateAdded", ""),
                                        "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known"}
                   for v in data.get("vulnerabilities", []) if v.get("cveID")}
        except (OSError, ValueError, KeyError):
            pass
        try:
            raw = (d / "epss.csv.gz").read_bytes()
            epss = parse_epss(raw)
        except OSError:
            pass
        return cls(kev, epss, str(d))

    def kev_hit(self, ids):
        if not self.kev:
            return None
        for i in ids:
            if str(i).upper() in self.kev:
                return self.kev[str(i).upper()]
        return None

    def epss_of(self, ids):
        if not self.epss:
            return None
        best = None
        for i in ids:
            v = self.epss.get(str(i).upper())
            if v and (best is None or v[0] > best[0]):
                best = v
        return best


def parse_epss(gz_bytes):
    text = gzip.decompress(gz_bytes).decode("utf-8", "ignore")
    out = {}
    rows = csv.reader(line for line in io.StringIO(text) if not line.startswith("#"))
    header = next(rows, None)
    if not header:
        return out
    idx = {h.strip().lower(): i for i, h in enumerate(header)}
    ci, si, pi = idx.get("cve", 0), idx.get("epss", 1), idx.get("percentile", 2)
    for r in rows:
        try:
            out[r[ci].upper()] = (float(r[si]), float(r[pi]))
        except (IndexError, ValueError):
            continue
    return out


def fetch_intel(directory, opener=None):
    """Download KEV and EPSS into directory. Returns a list of error strings (empty = both fetched)."""
    import urllib.request
    opener = opener or (lambda url: urllib.request.urlopen(urllib.request.Request(
        url, headers={"User-Agent": "sawone"}), timeout=60).read())
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    errors = []
    try:
        body = opener(KEV_URL)
        if not json.loads(body).get("vulnerabilities"):
            raise ValueError("empty catalogue")
        (d / "kev.json").write_bytes(body)
    except Exception as e:  # noqa: BLE001 — reported to the caller
        errors.append(f"CISA KEV: {e}")
    for url in (EPSS_URL, EPSS_URL_FALLBACK):
        try:
            body = opener(url)
            if not parse_epss(body):
                raise ValueError("empty score file")
            (d / "epss.csv.gz").write_bytes(body)
            break
        except Exception as e:  # noqa: BLE001
            last = f"EPSS ({url}): {e}"
    else:
        errors.append(last)
    return errors


# ------------------------------------------------------------------ baseline (exceptions)
REQUIRED = ("reason", "owner", "expires")


def load_baseline(path, today=None, max_days=365):
    """Read .sawone-baseline.yml. Returns (active, expired, errors).

    exceptions:
      - id: CVE-2024-1234          # CVE / rule ID, wildcards allowed (AVD-AWS-*), or fingerprint: <hash>
        package: urllib3           # optional: narrow to a package
        path: "src/legacy/*"       # optional: narrow to a location glob
        reason: no fix available; not reachable from our code
        owner: sawan
        expires: 2026-12-31        # required; at most max_days ahead
    """
    today = today or dt.date.today()
    p = Path(path)
    if not p.exists():
        return [], [], []
    try:
        import yaml
        data = yaml.safe_load(p.read_text()) or {}
    except Exception as e:  # noqa: BLE001
        return [], [], [f"{p.name} is not valid YAML: {e}"]
    entries = data.get("exceptions") if isinstance(data, dict) else None
    if entries is None:
        return [], [], [f"{p.name} has no 'exceptions:' list"]
    active, expired, errors = [], [], []
    for n, e in enumerate(entries, 1):
        if not isinstance(e, dict):
            errors.append(f"exception #{n} is not a mapping")
            continue
        missing = [k for k in REQUIRED if not str(e.get(k) or "").strip()]
        if not (e.get("id") or e.get("fingerprint")):
            missing.append("id or fingerprint")
        if missing:
            errors.append(f"exception #{n} ({e.get('id') or e.get('fingerprint') or '?'}) is missing {', '.join(missing)}")
            continue
        try:
            exp = e["expires"] if isinstance(e["expires"], dt.date) else dt.date.fromisoformat(str(e["expires"]))
        except ValueError:
            errors.append(f"exception #{n} ({e.get('id') or e.get('fingerprint')}): expires must be YYYY-MM-DD")
            continue
        if (exp - today).days > max_days:
            errors.append(f"exception #{n} ({e.get('id') or e.get('fingerprint')}): expires {exp} is more than "
                          f"{max_days} days ahead")
            continue
        kind = str(e.get("type") or "accepted-risk").strip().lower()
        if kind not in ("accepted-risk", "false-positive"):
            errors.append(f"exception #{n} ({e.get('id') or e.get('fingerprint')}): type must be accepted-risk or "
                          f"false-positive, got {kind!r}")
            continue
        entry = {"n": n, "id": str(e.get("id") or ""), "fingerprint": str(e.get("fingerprint") or ""),
                 "package": str(e.get("package") or ""), "path": str(e.get("path") or ""), "type": kind,
                 "reason": str(e["reason"]), "owner": str(e["owner"]), "expires": exp.isoformat(), "used": 0}
        (expired if exp < today else active).append(entry)
    return active, expired, errors


def _matches(entry, f):
    if entry["fingerprint"]:
        return entry["fingerprint"] == f["fingerprint"]
    ids = {f["id"].upper(), *[a.upper() for a in f.get("aliases", [])]}
    want = entry["id"].upper()
    if want not in ids and not ("*" in want and any(fnmatch.fnmatch(i, want) for i in ids)):
        return False
    if entry["package"] and entry["package"] != f.get("package"):
        return False
    if entry["path"]:
        loc = (f.get("location") or "").rsplit(":", 1)[0] if ":" in (f.get("location") or "") else f.get("location", "")
        if not (fnmatch.fnmatch(loc, entry["path"]) or fnmatch.fnmatch(f.get("location") or "", entry["path"])):
            return False
    return True


# ------------------------------------------------------------------ policy
class Policy:
    def __init__(self, active=(), expired=(), intel=None, block_kev=True, epss_threshold=0.0):
        self.active, self.expired = list(active), list(expired)
        self.intel = intel or Intel()
        self.block_kev, self.epss_threshold = block_kev, float(epss_threshold or 0)

    def apply(self, items):
        for f in items:
            ids = [f["id"], *f.get("aliases", [])] if f["kind"] == "vuln" else []
            if ids:
                k = self.intel.kev_hit(ids)
                if k:
                    f["kev"] = True
                    f["kev_ransomware"] = k["ransomware"]
                e = self.intel.epss_of(ids)
                if e:
                    f["epss"], f["epss_percentile"] = round(e[0], 5), round(e[1], 5)
            if not f["gating"]:
                if self.block_kev and f.get("kev"):
                    f["gating"], f["escalated"] = True, "known exploited (CISA KEV)"
                elif self.epss_threshold and f.get("epss", 0) >= self.epss_threshold:
                    f["gating"], f["escalated"] = True, f"EPSS {f['epss']:.2f} ≥ {self.epss_threshold}"
            if f["gating"]:
                for entry in self.active:
                    if _matches(entry, f):
                        f["gating"], entry["used"] = False, entry["used"] + 1
                        f["baselined"] = {"owner": entry["owner"], "expires": entry["expires"], "reason": entry["reason"],
                                          "type": entry.get("type", "accepted-risk")}
                        break
                else:
                    for entry in self.expired:
                        if _matches(entry, f):
                            f["exception_expired"] = entry["expires"]
                            break
        return items


# ------------------------------------------------------------------ consolidation
# Rule IDs that describe the same weakness in different tools (same file → one finding)
EQUIVALENT_RULES = {
    "container-runs-as-root": {"DS-0002", "AVD-DS-0002", "DS002", "dockerfile.security.missing-user.missing-user",
                               "dockerfile.security.missing-user-entrypoint.missing-user-entrypoint", "DL3002",
                               "CKV_DOCKER_3"},
    "k8s-privileged": {"KSV-0017", "AVD-KSV-0017", "KSV017", "privileged-container", "CKV_K8S_16",
                       "yaml.kubernetes.security.privileged-container.privileged-container"},
    "k8s-host-network": {"KSV-0009", "AVD-KSV-0009", "KSV009", "host-network", "CKV_K8S_19",
                         "yaml.kubernetes.security.hostnetwork-pod.hostnetwork-pod"},
    "k8s-privilege-escalation": {"KSV-0001", "AVD-KSV-0001", "KSV001", "privilege-escalation-container", "CKV_K8S_20",
                                 "yaml.kubernetes.security.allow-privilege-escalation-no-securitycontext.allow-privilege-escalation-no-securitycontext"},
    "k8s-run-as-root": {"KSV-0012", "AVD-KSV-0012", "KSV012", "run-as-non-root", "CKV_K8S_23",
                        "yaml.kubernetes.security.run-as-non-root.run-as-non-root"},
}
_RULE_CLASS = {r.upper(): c for c, rules in EQUIVALENT_RULES.items() for r in rules}
_SECRET_RULE = ("secret", "private-key", "private_key", "api-key", "apikey", "password", "token", "credential")


def _path_of(f):
    loc = str(f.get("location") or "")
    path, _, line = loc.rpartition(":") if re.search(r":\d+$", loc) else (loc, "", "")
    return path.lstrip("/"), line


def correlation_keys(f):
    """Keys under which findings from different tools or rules are the same weakness:
      secrets      same file (a key file holds one key) or same file:line for other secret types
      code         same file:line and a shared CWE (Semgrep's flask / sqlalchemy rules on one query)
      known rules  the equivalence table above, same file
    Vulnerabilities are already merged by CVE + package + version in their fingerprint."""
    if f.get("kind") == "vuln":
        return []
    path, line = _path_of(f)
    base = path.rsplit("/", 1)[-1]
    rid = str(f.get("id") or "")
    keys = []
    if f.get("kind") == "secret" or (f.get("kind") == "code" and any(w in rid.lower() for w in _SECRET_RULE)
                                     and ".secrets." in rid.lower()):
        priv = "private" in (rid + " " + str(f.get("title"))).lower()
        keys.append(("secret", base) if priv else ("secret", base, line))
    if f.get("kind") == "code" and line:
        keys += [("code", path, line, c) for c in f.get("cwe") or []]
    cls = _RULE_CLASS.get(rid.upper())
    if cls:
        keys.append(("rule", cls, base))
    return keys


def consolidate(findings):
    """Merge duplicates into one finding each: the same fingerprint from several tools or stages, then the
    same weakness reported under different rule IDs (see correlation_keys). The merged finding keeps every
    member's fingerprint (a baseline written from it covers all of them) and lists the other rule IDs."""
    merged = {}
    for f in findings:
        m = merged.get(f["fingerprint"])
        if m is None:
            m = dict(f)
            m["tools"] = [f["tool"]]
            m["stages"] = [f["stage"]]
            m["fingerprints"] = [f["fingerprint"]]
            merged[f["fingerprint"]] = m
            continue
        if f["tool"] not in m["tools"]:
            m["tools"].append(f["tool"])
        if f["stage"] not in m["stages"]:
            m["stages"].append(f["stage"])
        if SEVERITIES.index(f["severity"]) > SEVERITIES.index(m["severity"]):
            m["severity"] = f["severity"]
        for k in ("gating", "kev", "kev_ransomware", "verified"):
            m[k] = bool(m.get(k) or f.get(k))
        if f.get("epss", 0) > m.get("epss", 0):
            m["epss"], m["epss_percentile"] = f["epss"], f.get("epss_percentile")
        m["fixed_version"] = m["fixed_version"] or f["fixed_version"]
        for k in ("baselined", "escalated", "exception_expired"):
            if f.get(k) and not m.get(k):
                m[k] = f[k]
    out = _correlate(list(merged.values()))
    out.sort(key=lambda f: (not f.get("gating"), not f.get("kev"), -SEVERITIES.index(f["severity"]),
                            -(f.get("epss") or 0), f["id"]))
    return out


def _correlate(items):
    parent = list(range(len(items)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    seen = {}
    for i, f in enumerate(items):
        for k in correlation_keys(f):
            if k in seen:
                parent[find(i)] = find(seen[k])
            else:
                seen[k] = i
    groups = {}
    for i in range(len(items)):
        groups.setdefault(find(i), []).append(items[i])
    out = []
    for members in groups.values():
        if len(members) == 1:
            out.append(members[0])
            continue
        members.sort(key=lambda f: (not f.get("gating"), -SEVERITIES.index(f["severity"])))
        m = dict(members[0])
        m["tools"] = list(dict.fromkeys(t for x in members for t in x["tools"]))
        m["stages"] = list(dict.fromkeys(s for x in members for s in x["stages"]))
        m["fingerprints"] = [fp for x in members for fp in x["fingerprints"]]
        m["related"] = sorted({x["id"] for x in members[1:] if x["id"] != m["id"]})
        for k in ("gating", "kev", "new", "verified"):
            m[k] = any(x.get(k) for x in members)
        m["baselined"] = m.get("baselined") if not m["gating"] else None
        if not m.get("baselined"):
            m.pop("baselined", None)
        out.append(m)
    return out


def write_baseline(findings, path, owner, days=90, reason="Existing finding at baseline creation — triage before expiry",
                   only_gating=True, today=None):
    """Write a baseline that accepts the given findings (for adopting the gate on an existing repo)."""
    today = today or dt.date.today()
    exp = (today + dt.timedelta(days=days)).isoformat()
    seen, lines = set(), ["# Sawone baseline — accepted findings. Every entry needs an owner, a reason",
                          "# and an expiry date; expired entries stop suppressing and the finding blocks again.",
                          "exceptions:"]
    for f in consolidate(findings):
        if only_gating and not f.get("gating"):
            continue
        for fp in f.get("fingerprints") or [f["fingerprint"]]:   # every tool's copy of a merged finding
            if fp in seen:
                continue
            seen.add(fp)
            lines += [f"  - fingerprint: {fp}",
                      f"    id: {json.dumps(f['id'])}  # {f['severity']} {f['kind']} · {json.dumps(f.get('location') or f.get('package') or '')[1:-1]}",
                      f"    reason: {json.dumps(reason, ensure_ascii=False)}",
                      f"    owner: {json.dumps(owner, ensure_ascii=False)}",
                      f"    expires: {exp}"]
    Path(path).write_text("\n".join(lines) + "\n")
    return len(seen)


# ------------------------------------------------------------------ history: first seen, trend, SLA
DEFAULT_SLA = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180}


def apply_history(merged, previous=None, now=None, sla=None):
    """Carry each finding's first-seen date forward from the previous report of this branch (or the base
    branch on pull requests), then age it against the SLA (days to fix, by severity). Returns the trend:
    {previous, new, fixed, open, overdue, by_age}. Without a previous report every finding is first seen now."""
    now = now or dt.datetime.now(dt.timezone.utc)
    sla = {**DEFAULT_SLA, **{str(k).upper(): int(v) for k, v in (sla or {}).items()}}
    seen = {}
    for p in previous or []:
        fs = p.get("first_seen")
        for fp in p.get("fingerprints") or [p.get("fingerprint")]:
            if fp and fs and (fp not in seen or fs < seen[fp]):
                seen[fp] = fs
    prev_fps = {fp for p in previous or [] for fp in (p.get("fingerprints") or [p.get("fingerprint")]) if fp}
    today = now.date().isoformat()
    new = overdue = 0
    by_age = {"0-7": 0, "8-30": 0, "31-90": 0, "90+": 0}
    for f in merged:
        fps = f.get("fingerprints") or [f["fingerprint"]]
        known = [seen[fp] for fp in fps if fp in seen]
        f["first_seen"] = min(known) if known else today
        if previous is not None and not any(fp in prev_fps for fp in fps):
            new += 1
        if not f.get("gating"):
            continue
        age = (now.date() - dt.date.fromisoformat(f["first_seen"][:10])).days
        f["age_days"] = age
        days = sla.get(f["severity"])
        if days is not None:
            due = dt.date.fromisoformat(f["first_seen"][:10]) + dt.timedelta(days=days)
            f["sla_due"] = due.isoformat()
            if now.date() > due:
                f["overdue"] = True
                overdue += 1
        by_age["0-7" if age <= 7 else "8-30" if age <= 30 else "31-90" if age <= 90 else "90+"] += 1
    cur = {fp for f in merged for fp in (f.get("fingerprints") or [f["fingerprint"]])}
    fixed = len({p.get("fingerprint") for p in previous or []
                 if not any(fp in cur for fp in (p.get("fingerprints") or [p.get("fingerprint")]))})
    return {"previous": previous is not None, "new": new if previous is not None else None,
            "fixed": fixed if previous is not None else None, "open": sum(1 for f in merged if f.get("gating")),
            "overdue": overdue, "by_age": by_age, "sla": sla}
