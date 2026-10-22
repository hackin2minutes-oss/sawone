#!/usr/bin/env python3
"""
sawone-scan — point it at any repository; it works out what is there and scans it.

  sawone-scan [--path .] [--config .sawone.yml] [--reports sawone-reports] [--plan-only]

Detects:   languages, package ecosystems, frameworks, Dockerfiles, Terraform, Kubernetes,
           Helm, CloudFormation, Bicep/ARM, Compose, CI configs, threat models, OpenAPI specs
Updates:   resolves the latest image of every scanner (pinned by digest for the run),
           refreshes Trivy/Grype databases, Nuclei templates, ZAP add-ons
Scans:     threat model · secrets · SAST · SCA + licences · IaC · Kubernetes/Helm ·
           CI/CD workflows · container image (+SBOM) · DAST (baseline, full, API) ·
           runtime protection (WAF) · optional IAST
Writes:    <reports>/summary.json, summary.md, junit.xml, inventory.json, tools.json,
           sarif/*.sarif, security-report.pdf (+.html), every raw tool report, logs/
Exit code: 0 = all gates passed (or enforce: false), 1 = a gate failed, 2 = scanner error

Tools run as sibling containers. The workspace must be mounted at the SAME path inside
the scanner container (-v "$PWD:$PWD" -w "$PWD") so those containers can see it.
"""
import argparse
import datetime as dt
import fnmatch
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import xml.sax.saxutils as sx
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import findings as F
import threatmodel as TMA  # noqa: E402

try:
    import yaml  # PyYAML, present in the scanner image
except ImportError:  # pragma: no cover
    yaml = None

HERE = Path(__file__).resolve().parent

# --------------------------------------------------------------------------- tools
IMAGES = {
    "gitleaks": "zricethezav/gitleaks:latest",
    "trufflehog": "trufflesecurity/trufflehog:latest",
    "trivy": "aquasec/trivy:latest",
    "osv": "ghcr.io/google/osv-scanner:latest",
    "checkov": "bridgecrew/checkov:latest",
    "hadolint": "hadolint/hadolint:latest",
    "kubeconform": "ghcr.io/yannh/kubeconform:latest",
    "kubelinter": "stackrox/kube-linter:latest",
    "helm": "alpine/helm:latest",
    "conftest": "openpolicyagent/conftest:latest",
    "actionlint": "rhysd/actionlint:latest",
    "threagile": "threagile/threagile:latest",
    "syft": "anchore/syft:latest",
    "grype": "anchore/grype:latest",
    "zap": "ghcr.io/zaproxy/zaproxy:stable",
    "nuclei": "projectdiscovery/nuclei:latest",
    "dockle": "goodwithtech/dockle:latest",
    "waf": "owasp/modsecurity-crs:nginx",
    "curl": "curlimages/curl:latest",
}

DEFAULTS = {
    "severity": "HIGH,CRITICAL",
    "enforce": True,
    "exclude": [],
    "skip": [],
    "self_update": True,
    "semgrep": {"configs": [], "extra_configs": [], "framework_filter": True},
    "container": {"enabled": True, "max_images": 3, "build_args": {}},
    "dast": {"enabled": "auto", "port": None, "health_path": None, "env": {}, "startup_timeout": 60,
             "full_scan": True, "max_minutes": 20, "openapi": None, "nuclei": True, "nuclei_mode": "auto",
             "ajax_spider": False,
             # authenticated scanning: a fixed header (DAST_AUTH_VALUE) or a login call that returns a token
             "auth": {"header": "Authorization", "login_url": None, "login_body": None, "token_field": "token",
                      "token_prefix": "Bearer "}},
    "image_config": {"enabled": True},      # Dockle: CIS checks on the built image (report only)
    # noise control: what the report shows from second-opinion (report-only) tools
    "report": {"profile": "balanced", "languages": ["en", "ar"]},
    "noise": {"mute_rules": []},            # rule IDs hidden from the report (report-only tools; never gates)
    "sla": {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180},   # days to fix, from first seen
    "compliance": {"frameworks": ["asvs", "ssdf", "ecc", "cscc", "ccc", "sama", "pdpl"]},
    "source_sbom": {"enabled": True},       # Syft: CycloneDX SBOM of the repository itself
    "waf": {"enabled": True},
    "threat_model": {"min_severity": "Very High"},
    "policy": {"block_kev": True, "epss_threshold": 0},   # KEV CVEs block at any severity; EPSS off by default
    "baseline": {"file": ".sawone-baseline.yml", "max_days": 365},
}

ALWAYS_EXCLUDE = [".git", "node_modules", "vendor", ".venv", "venv", "env", "__pycache__",
                  "dist", "build", "target", ".terraform", ".tox", ".mypy_cache", ".next",
                  "bower_components", "Pods", ".gradle", ".idea", ".vscode"]

LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".rs": "rust", ".scala": "scala",
    ".swift": "swift", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".sh": "bash", ".bash": "bash", ".ps1": "powershell", ".tf": "terraform", ".bicep": "bicep",
    ".sol": "solidity", ".dart": "dart", ".ex": "elixir", ".exs": "elixir", ".lua": "lua",
}

MANIFESTS = {
    "requirements*.txt": "pypi", "Pipfile.lock": "pypi", "poetry.lock": "pypi", "pyproject.toml": "pypi",
    "uv.lock": "pypi", "setup.py": "pypi",
    "package.json": "npm", "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle", "gradle.lockfile": "gradle",
    "go.mod": "go", "go.sum": "go", "Gemfile.lock": "rubygems", "Gemfile": "rubygems",
    "composer.json": "packagist", "composer.lock": "packagist", "Cargo.lock": "cargo", "Cargo.toml": "cargo",
    "*.csproj": "nuget", "packages.lock.json": "nuget", "packages.config": "nuget",
    "mix.lock": "hex", "pubspec.lock": "pub", "Package.resolved": "swift", "conan.lock": "conan",
}

FRAMEWORK_HINTS = {  # (ecosystem, dependency substring) -> framework
    ("pypi", "flask"): "flask", ("pypi", "django"): "django", ("pypi", "fastapi"): "fastapi",
    ("npm", "\"express\""): "express", ("npm", "\"react\""): "react", ("npm", "\"next\""): "nextjs",
    ("npm", "\"@angular/core\""): "angular", ("npm", "\"vue\""): "vue", ("npm", "\"@nestjs/core\""): "nestjs",
    ("maven", "spring-boot"): "spring", ("gradle", "spring-boot"): "spring",
    ("rubygems", "rails"): "rails", ("packagist", "laravel/framework"): "laravel",
    ("go", "gin-gonic/gin"): "gin", ("nuget", "Microsoft.AspNetCore"): "aspnetcore",
}

SEMGREP_PACKS = {
    "python": ["p/python"], "javascript": ["p/javascript"], "typescript": ["p/typescript"],
    "java": ["p/java"], "kotlin": ["p/kotlin"], "go": ["p/golang"], "ruby": ["p/ruby"],
    "php": ["p/php"], "csharp": ["p/csharp"], "rust": ["p/rust"], "c": ["p/c"], "cpp": ["p/c"],
    "scala": ["p/scala"], "swift": ["p/swift"],
    "flask": ["p/flask"], "django": ["p/django"], "react": ["p/react"],
    "terraform": ["p/terraform"], "docker": ["p/dockerfile"], "kubernetes": ["p/kubernetes"],
}

# Semgrep rules written for one framework, dropped when the repository does not use that framework
# (p/default ships Django, Flask, Express … rules together, so a Flask app got Django duplicates)
FRAMEWORK_RULES = {
    "django": ("python.django.",), "flask": ("python.flask.",), "fastapi": ("python.fastapi.",),
    "express": ("javascript.express.", "typescript.express."), "nestjs": ("typescript.nestjs.",),
    "rails": ("ruby.rails.",), "laravel": ("php.laravel.",), "spring": ("java.spring.",),
    "angular": ("typescript.angular.",), "react": ("typescript.react.", "javascript.react."),
}

CI_FILES = {".gitlab-ci.yml": "gitlab", "Jenkinsfile": "jenkins", "azure-pipelines.yml": "azure-devops",
            "bitbucket-pipelines.yml": "bitbucket", ".circleci/config.yml": "circleci"}

SEV_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
STAGES = ["threat-model", "secrets", "sast", "sca", "iac", "kubernetes", "cicd",
          "container", "dast", "iast", "runtime", "tracking"]
PIP_TOOLS = ["semgrep", "zizmor", "pytm"]


# --------------------------------------------------------------------------- utils
def log(msg):
    print(f"[sawone] {msg}", flush=True)


def deep_merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


class Scan:
    def __init__(self, ws: Path, reports: Path, cfg: dict, plan_only=False):
        self.ws, self.reports, self.cfg, self.plan_only = ws, reports, cfg, plan_only
        self.stages = []           # list of dicts (see record())
        self.pinned = {}           # tool -> pinned image ref
        self.tool_versions = {}    # tool -> version/image string for the report
        self.docker_ok = shutil.which("docker") is not None and self.run(["docker", "info"], quiet=True)[0] == 0
        self.sev = [s.strip().upper() for s in cfg["severity"].split(",") if s.strip()]
        self.network = f"sawone-{os.getpid()}"
        self.only = set(cfg.get("only") or [])
        self.prebuilt = cfg.get("image") or None
        self.lock = cfg.get("tools_lock")      # dict from --resolve-tools, or None = latest now
        self.images, self.target, self.iast_attached = [], None, False
        self.findings = []         # normalised findings (findings.py), written to findings.json
        self.policy = F.Policy(block_kev=cfg["policy"]["block_kev"], epss_threshold=cfg["policy"]["epss_threshold"]) \
            if "policy" in cfg else F.Policy()
        self.baseline_state = None
        self.cache_dir = cfg.get("cache_dir")  # host dir for vulnerability DBs (shared via CI cache)
        # pull requests: the base commit, so secret and code scans look only at what the change adds
        self.base_sha = cfg.get("base_sha") if re.fullmatch(r"[0-9a-f]{7,40}", str(cfg.get("base_sha") or "")) else None
        for d in ["sarif", "raw", "logs"]:
            (reports / d).mkdir(parents=True, exist_ok=True)
        # some scanner images run as non-root: let them write their reports
        for d in [reports, reports / "sarif", reports / "raw", reports / "logs"]:
            os.chmod(d, 0o777)

    # ---------------------------------------------------------------- process
    def run(self, cmd, log_name=None, timeout=3600, quiet=False, stdout_file=None):
        stdout = ""
        try:
            p = subprocess.run(cmd, cwd=self.ws, capture_output=True, text=True, timeout=timeout)
            stdout = p.stdout
            out = p.stdout + ("\n" + p.stderr if p.stderr else "")
            code = p.returncode
        except subprocess.TimeoutExpired:
            out, code = f"timeout after {timeout}s", 124
        except FileNotFoundError as e:
            out, code = str(e), 127
        if stdout_file:
            Path(stdout_file).write_text(stdout)
        if log_name:
            (self.reports / "logs" / f"{log_name}.log").write_text(
                " ".join(map(str, cmd)) + "\n\n" + out + f"\n\n[exit code: {code}]\n")
        if not quiet and code not in (0,):
            tail = "\n".join(out.strip().splitlines()[-15:])
            log(f"  exit {code} ({log_name or cmd[0]}):\n" + "\n".join("      " + l for l in tail.splitlines()))
        return code, out

    def docker(self, tool, args, log_name, extra=None, timeout=3600, stdout_file=None, mount=True):
        image = self.pinned.get(tool, IMAGES[tool])
        cmd = ["docker", "run", "--rm"]
        if mount:
            cmd += ["-v", f"{self.ws}:{self.ws}", "-w", str(self.ws)]
        cmd += (extra or []) + [image] + list(args)
        return self.run(cmd, log_name=log_name, timeout=timeout, stdout_file=stdout_file)

    def cache_mount(self, name, container_path):
        """Persistent tool data (vulnerability DBs): a host directory when SCAN_CACHE_DIR is set, so CI
        can cache it between jobs and runs; otherwise a named Docker volume on this machine."""
        if self.cache_dir:
            d = Path(self.cache_dir) / name
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o777)
            return ["-v", f"{d}:{container_path}"]
        return ["-v", f"sawone-{name}:{container_path}"]

    def rel(self, p):
        return str(Path(p).resolve().relative_to(self.ws))

    # ---------------------------------------------------------------- results
    def last_error(self, log_name):
        try:
            lines = [l.strip() for l in (self.reports / "logs" / f"{log_name}.log").read_text().splitlines() if l.strip()]
        except OSError:
            return f"see logs/{log_name}.log"
        lines = [l for l in lines[1:] if not l.startswith("[exit code:")]   # drop the command line and footer
        hits = [l for l in lines if re.search(r"error|fatal|denied|invalid|not found|failed|unauthori[sz]ed|"
                                                 r"rate.?limit|toomanyrequests|manifest unknown|timeout|refused", l, re.I)]
        return ((hits or lines or ["no output"])[-1])[:240] + f" (logs/{log_name}.log)"

    def record(self, stage, tool, status, reason="", gate=True, findings=""):
        self.stages.append({"stage": stage, "tool": tool, "status": status, "reason": reason,
                            "gate": gate, "findings": findings})
        icon = {"passed": "✓", "failed": "✗", "skipped": "-", "error": "!", "report": "i"}.get(status, "?")
        log(f"{icon} {stage:<18} {tool:<26} {status}{(' — ' + reason) if reason else ''}{(' · ' + findings) if findings else ''}")

    def skipped(self, name):
        return name in self.cfg.get("skip", [])

    def wants(self, stage):
        return (not self.only or stage in self.only) and not self.skipped(stage)

    def iast_configured(self):
        return bool(os.environ.get("DONGTAI_URL") and os.environ.get("IAST_RUN_ARGS"))

    def has_iac(self):
        inv = self.inv
        return any([inv["dockerfiles"], inv["terraform"], inv["kubernetes"], inv["helm_charts"],
                    inv["cloudformation"], inv["bicep_arm"], inv["compose"]])

    def image_source(self):
        return bool(self.prebuilt or (self.inv["dockerfiles"] and self.cfg["container"]["enabled"]))

    # =========================================================== 1. detect
    def detect(self):
        ex = set(ALWAYS_EXCLUDE) | {self.reports.name}
        ex_globs = self.cfg.get("exclude", [])
        langs, ecos, manifests, dockerfiles, k8s, charts, tf, cfn, bicep, compose, ci, gha = (
            {}, set(), [], [], [], [], set(), [], [], [], set(), [])
        tm_py, threagile, openapi, rego = None, None, None, []
        for root, dirs, files in os.walk(self.ws):
            rel_root = Path(root).relative_to(self.ws)
            dirs[:] = [d for d in dirs if d not in ex and not any(
                fnmatch.fnmatch(str(rel_root / d), g.rstrip("/")) or fnmatch.fnmatch(str(rel_root / d), g) for g in ex_globs)]
            for f in files:
                rp = rel_root / f
                if any(fnmatch.fnmatch(str(rp), g) for g in ex_globs):
                    continue
                ext = Path(f).suffix.lower()
                if ext in LANG_BY_EXT:
                    langs[LANG_BY_EXT[ext]] = langs.get(LANG_BY_EXT[ext], 0) + 1
                for pat, eco in MANIFESTS.items():
                    if fnmatch.fnmatch(f, pat):
                        ecos.add(eco); manifests.append(str(rp))
                if f == "Dockerfile" or f.startswith("Dockerfile.") or f.endswith(".dockerfile") or f == "Containerfile":
                    dockerfiles.append(str(rp))
                if f == "Chart.yaml":
                    charts.append(str(rel_root))
                if ext == ".tf":
                    tf.add(str(rel_root))
                if ext == ".bicep" or (ext == ".json" and self._is_arm(Path(root) / f)):
                    bicep.append(str(rp))
                if f in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
                    compose.append(str(rp))
                if str(rp) in CI_FILES or f in CI_FILES:
                    ci.add(CI_FILES.get(str(rp), CI_FILES.get(f)))
                if str(rel_root).startswith(".github/workflows") and ext in (".yml", ".yaml"):
                    gha.append(str(rp)); ci.add("github-actions")
                if f == "tm.py" and "pytm" in self._head(Path(root) / f):
                    tm_py = str(rp)
                if f in ("threagile.yaml", "threagile.yml"):
                    threagile = str(rp)
                if re.match(r"^(openapi|swagger)\.(ya?ml|json)$", f, re.I):
                    openapi = openapi or str(rp)
                if ext == ".rego":
                    rego.append(str(rp))
                if ext in (".yaml", ".yml") and not str(rel_root).startswith(".github"):
                    kind = self._yaml_kind(Path(root) / f)
                    if kind == "k8s" and not any(str(rp).startswith(c + "/") for c in charts if c != "."):
                        k8s.append(str(rp))
                    elif kind == "cfn":
                        cfn.append(str(rp))
        # helm templates are not plain YAML: drop anything under a chart dir
        k8s = [p for p in k8s if not any(p.startswith(c.rstrip("/") + "/") for c in charts if c not in (".", ""))]
        frameworks = set()
        for m in manifests:
            text = self._head(self.ws / m, 200_000)
            for (eco, needle), fw in FRAMEWORK_HINTS.items():
                if MANIFESTS.get(Path(m).name, MANIFESTS.get("*" + Path(m).suffix)) == eco or eco in ecos:
                    if needle.lower() in text.lower():
                        frameworks.add(fw)
        inv = {
            "languages": dict(sorted(langs.items(), key=lambda x: -x[1])),
            "ecosystems": sorted(ecos), "manifests": sorted(manifests), "frameworks": sorted(frameworks),
            "dockerfiles": sorted(dockerfiles), "kubernetes": sorted(k8s), "helm_charts": sorted(charts),
            "terraform": sorted(tf), "cloudformation": sorted(cfn), "bicep_arm": sorted(bicep),
            "compose": sorted(compose), "ci": sorted(ci), "github_workflows": sorted(gha),
            "threat_model": tm_py, "threagile": threagile, "openapi": self.cfg["dast"].get("openapi") or openapi,
            "rego_policies": sorted(rego), "git": (self.ws / ".git").exists(),
        }
        self.inv = inv
        (self.reports / "inventory.json").write_text(json.dumps(inv, indent=2))
        return inv

    def _head(self, path, n=4000):
        try:
            with open(path, errors="ignore") as f:
                return f.read(n)
        except OSError:
            return ""

    def _yaml_kind(self, path):
        t = self._head(path, 20000)
        if "AWSTemplateFormatVersion" in t or re.search(r"^Resources:\s*$", t, re.M) and "Type: AWS::" in t:
            return "cfn"
        if re.search(r"^apiVersion:\s*\S+", t, re.M) and re.search(r"^kind:\s*\S+", t, re.M):
            return "k8s"
        return None

    def _is_arm(self, path):
        return "deploymentTemplate.json" in self._head(path, 2000)

    # ========================================================== 2. update
    def needed_tools(self):
        inv, need, w = self.inv, set(), self.wants
        if w("secrets"):
            need |= {"gitleaks", "trufflehog"}
        if w("sca") and inv["manifests"]:
            need |= {"trivy", "osv"} | ({"syft"} if self.cfg["source_sbom"]["enabled"] else set())
        if w("iac") and self.has_iac():
            need |= {"trivy", "checkov"} | ({"hadolint"} if inv["dockerfiles"] else set())
        if w("kubernetes") and (inv["kubernetes"] or inv["helm_charts"]):
            need |= {"kubeconform", "kubelinter"} | ({"helm"} if inv["helm_charts"] else set())
            if inv["rego_policies"]:
                need |= {"conftest"}
        if w("cicd") and inv["github_workflows"]:
            need |= {"actionlint"}
        if w("threat-model") and inv["threagile"] and not inv["threat_model"]:
            need |= {"threagile"}
        if self.image_source():
            if w("container"):
                need |= {"syft", "grype", "trivy"}
                # Dockle is new in 2.0.2: a pinned lock file from before it existed simply skips it
                if self.cfg["image_config"]["enabled"] and (not self.lock or "dockle" in self.lock.get("images", {})):
                    need |= {"dockle"}
            if w("dast") and self.cfg["dast"]["enabled"] is not False:
                need |= {"zap", "curl"} | ({"nuclei"} if self.cfg["dast"].get("nuclei") else set())
            if w("runtime") and self.cfg["waf"]["enabled"]:
                need |= {"waf", "curl"}
            if w("iast") and self.iast_configured():
                need |= {"zap", "curl"}
        return sorted(t for t in need if not self.skipped(t))

    def _pin(self, tool):
        """Pull one scanner image and return repo@sha256 — or None after recording an error."""
        ref = (self.lock.get("images", {}).get(tool) if self.lock else IMAGES[tool])
        if not ref:
            self.record("scanner", f"resolve {tool}", "error", f"{tool} is missing from the tool lock file")
            return None
        code, _ = self.run(["docker", "pull", "-q", ref], log_name=f"pull-{tool}", timeout=900)
        if code:
            self.record("scanner", f"resolve {tool}", "error",
                        f"could not pull {ref} (registry unavailable or rate-limited?): {self.last_error(f'pull-{tool}')}")
            return None
        if "@sha256:" in ref:
            return ref
        repo = ref.rsplit(":", 1)[0]
        digests = self.run(["docker", "image", "inspect", "--format",
                            "{{range .RepoDigests}}{{println .}}{{end}}", ref], quiet=True)[1].split()
        match = [d for d in digests if d.split("@")[0] == repo] or digests
        if not match:
            self.record("scanner", f"resolve {tool}", "error", f"no immutable digest available for {ref}")
            return None
        return match[0]

    def update_tools(self):
        """Pin every needed scanner image by digest — from the lock file, or the latest release now.
        Returns False if any required tool cannot be resolved (a scanner error: there is no silent
        fallback to a mutable tag). Data refreshes (vulnerability DBs, templates) happen afterwards."""
        log("resolving tools (" + ("tool lock file" if self.lock else "latest releases") + ") …")
        ok = True
        for tool in self.needed_tools():
            pinned = self._pin(tool)
            if pinned:
                self.pinned[tool] = self.tool_versions[tool] = pinned
            else:
                ok = False
        pins = (self.lock or {}).get("pip") or {}
        if pins:
            specs = [f"{k}=={v}" for k, v in pins.items() if k in PIP_TOOLS]
            code, _ = self.run([sys.executable, "-m", "pip", "install", "-q", *specs], log_name="update-pip", timeout=900)
            if code:
                self.record("scanner", "pip tools", "error", f"could not install {' '.join(specs)}: {self.last_error('update-pip')}")
                ok = False
        elif self.cfg.get("self_update", True):
            code, _ = self.run([sys.executable, "-m", "pip", "install", "-q", "-U", *PIP_TOOLS],
                               log_name="update-pip", quiet=True, timeout=900)
            if code:
                log("  pip upgrade failed: using the versions bundled in the scanner image")
        from importlib.metadata import version, PackageNotFoundError
        for pkg in PIP_TOOLS + ["weasyprint"]:
            try:
                self.tool_versions[pkg] = "pip " + version(pkg)
            except PackageNotFoundError:
                pass
        self.tool_versions["_policy"] = ("pinned for this run (" + str(self.lock.get("resolved", "lock file")) + ")"
                                         if self.lock else "latest at scan time")
        (self.reports / "tools.json").write_text(json.dumps(self.tool_versions, indent=2))
        if not ok:
            return False
        if "trivy" in self.pinned:
            code, _ = self.docker("trivy", ["image", "--download-db-only"], "update-trivy-db",
                                  extra=self.cache_mount("trivy", "/root/.cache/trivy"), mount=False)
            if code:
                self.record("scanner", "Trivy DB update", "error", self.last_error("update-trivy-db"))
        if "grype" in self.pinned:
            code, _ = self.docker("grype", ["db", "update"], "update-grype-db",
                                  extra=["-u", "0:0", *self.cache_mount("grype", "/grype-db"),
                                         "-e", "GRYPE_DB_CACHE_DIR=/grype-db"], mount=False)
            if code:
                self.record("scanner", "Grype DB update", "error", self.last_error("update-grype-db"))
        if "nuclei" in self.pinned:
            self.docker("nuclei", ["-update-templates"], "update-nuclei-templates",
                        extra=self.cache_mount("nuclei", "/root"), mount=False)
        return True

    # ========================================================= 3. scanners
    def gate(self, stage, tool, failed_count, label, report_only=False, items=None):
        """Record a gate result. With items (normalised findings), the risk policy decides what blocks:
        KEV/EPSS escalation, then baseline exceptions; failed_count is recomputed from the items."""
        if items is not None:
            self.policy.apply(items)
            for it in items:
                it["stage"], it["tool"] = stage, tool
            self.findings.extend(items)
            if not report_only:
                failed_count = sum(1 for it in items if it["gating"])
            notes = []
            n_base = sum(1 for it in items if it.get("baselined"))
            n_kev = sum(1 for it in items if it.get("kev"))
            n_esc = sum(1 for it in items if it.get("escalated") and it["gating"])
            n_exp = sum(1 for it in items if it.get("exception_expired") and it["gating"])
            if n_kev:
                notes.append(f"{n_kev} known-exploited (KEV)")
            if n_esc:
                notes.append(f"{n_esc} escalated by KEV/EPSS")
            if n_base:
                notes.append(f"{n_base} accepted in baseline")
            if n_exp:
                notes.append(f"{n_exp} with an expired exception")
            if notes:
                label = f"{label} · " + " · ".join(notes)
        if report_only:
            self.record(stage, tool, "report", gate=False, findings=label)
        elif failed_count:
            self.record(stage, tool, "failed", findings=label)
        else:
            self.record(stage, tool, "passed", findings=label)

    def sarif_tag(self, path, category):
        """Give every SARIF run a unique category so code-scanning accepts a whole directory."""
        d = load_json(path)
        if not d:
            return
        ws = str(self.ws).rstrip("/") + "/"
        for i, run in enumerate(d.get("runs", [])):
            run["automationDetails"] = {"id": f"sawone/{category}/{i}/"}
            for r in run.get("results", []) or []:
                for loc in r.get("locations", []) or []:
                    al = (loc.get("physicalLocation") or {}).get("artifactLocation") or {}
                    uri = al.get("uri") or ""
                    bare = uri[len("file://"):] if uri.startswith("file://") else uri
                    if bare.startswith(ws):
                        al["uri"] = bare[len(ws):]
        Path(path).write_text(json.dumps(d))

    def _sarif_items(self, sarif, stage, tool, kind, default_sev, gating, key_fn=None, sev_fn=None):
        """Normalised findings from a SARIF file. gating may be a bool or a function of the severity."""
        items = []
        for run in (load_json(sarif) or {}).get("runs", []):
            rules = {x.get("id"): x for x in (run.get("tool") or {}).get("driver", {}).get("rules", []) or []}
            for r in run.get("results", []) or []:
                sev = sev_fn(r, rules.get(r.get("ruleId")) or {}) if sev_fn else default_sev
                loc = ((r.get("locations") or [{}])[0].get("physicalLocation") or {})
                path = (loc.get("artifactLocation") or {}).get("uri", "")
                path = self.rel(path) if path.startswith(str(self.ws)) else path.removeprefix("file://")
                line = (loc.get("region") or {}).get("startLine")
                key = key_fn(r) if key_fn else None
                anchor = f"{key}:{line}" if key else None
                items.append(F.issue(stage, tool, kind, r.get("ruleId"), path, line, sev,
                                     ((r.get("message") or {}).get("text") or r.get("ruleId") or "")[:200],
                                     ws=self.ws if not key else None,
                                     gating=gating(F.norm_sev(sev)) if callable(gating) else gating, key=anchor))
        return items

    @staticmethod
    def trivy_location(r, v):
        """Where a Trivy finding lives, readable: OS packages by distro, language packages by file.
        Never the runner's path to the saved image archive."""
        if v.get("PkgPath"):
            return v["PkgPath"]
        if r.get("Class") == "os-pkgs":
            return f'OS package ({r.get("Type") or "os"})'
        target = r.get("Target") or ""
        return target if not target.endswith(".tar") else (r.get("Type") or "image")

    def _trivy_vuln_items(self, data, stage, tool):
        items = []
        for r in (data or {}).get("Results", []) or []:
            for v in r.get("Vulnerabilities", []) or []:
                items.append(F.vuln(stage, tool, v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion"),
                                    v.get("Severity"), v.get("FixedVersion"), self.trivy_location(r, v),
                                    v.get("Title") or v.get("VulnerabilityID"),
                                    gating=v.get("Severity") in self.sev and bool(v.get("FixedVersion"))))
        return items

    # ---- threat model
    def scan_threat_model(self):
        inv = self.inv
        if inv["threat_model"] and not self.skipped("pytm"):
            out = self.reports / "raw" / "threats.json"
            code, _ = self.run([sys.executable, inv["threat_model"], "--json", str(out)], log_name="pytm")
            data = load_json(out)
            if code or not data:
                self.record("threat-model", "OWASP pytm", "error", "model failed to run (see logs/pytm.log)")
            else:
                mitigated = self._load_mitigated(inv["threat_model"])
                decisions, expired, derrs = self.threat_decisions()
                order = ["Low", "Medium", "High", "Very High"]
                floor = order.index(self.cfg["threat_model"]["min_severity"])

                def decided(f):
                    return (f'{f["threat_id"]}@{f["target"]}' in mitigated
                            or TMA._decision_for(f["threat_id"], f["target"], decisions) is not None)
                external = TMA._external(data, TMA._elements(data))    # third-party systems: listed, never blocking
                at_floor = [f for f in data.get("findings", [])
                            if f.get("severity") in order and order.index(f["severity"]) >= floor and not decided(f)]
                open_items = [f for f in at_floor if f.get("target") not in external]
                (self.reports / "raw" / "threat-decisions.json").write_text(json.dumps(
                    {"active": decisions, "expired": expired, "errors": derrs, "mitigated": mitigated,
                     "min_severity": self.cfg["threat_model"]["min_severity"]}, indent=1))
                open_keys = {f'{f["threat_id"]}@{f["target"]}' for f in open_items}
                items = [F.issue("threat-model", "OWASP pytm", "threat", f.get("threat_id"), inv["threat_model"], None,
                                 {"Very High": "CRITICAL"}.get(f.get("severity"), f.get("severity")),
                                 f'{f.get("description") or f.get("threat_id")} — {f.get("target")}',
                                 key=f.get("target"), gating=f'{f.get("threat_id")}@{f.get("target")}' in open_keys)
                         for f in data.get("findings", []) if f.get("threat_id")]
                for it in items:
                    it["location"] = f'{inv["threat_model"]} · {it["title"].rsplit(" — ", 1)[-1]}'
                ext_n = len(at_floor) - len(open_items)
                note = "".join([f" · {ext_n} on external elements (not blocking)" if ext_n else "",
                                f" · {len(decisions)} decision(s)" if decisions else "",
                                f" · {len(expired)} expired decision(s)" if expired else "",
                                f" · {len(derrs)} invalid decision(s) ignored" if derrs else ""])
                self.gate("threat-model", "OWASP pytm", len(open_items),
                          f"{len(data.get('findings', []))} threats, {len(open_items)} open at ≥ {order[floor]}{note}",
                          items=items)
        elif inv["threagile"] and not self.skipped("threagile"):
            outdir = self.reports / "raw" / "threagile"
            outdir.mkdir(parents=True, exist_ok=True)
            os.chmod(outdir, 0o777)
            code, _ = self.docker("threagile", ["-model", str(self.ws / inv["threagile"]), "-output", str(outdir)], "threagile")
            risks = load_json(outdir / "risks.json") or []
            open_items = [r for r in risks if str(r.get("severity", "")).lower() in ("high", "critical")
                          and (r.get("risk_status") or "unchecked") in ("unchecked", "in-discussion")]
            if code and not risks:
                self.record("threat-model", "Threagile", "error", "model failed (see logs/threagile.log)")
            else:
                items = [F.issue("threat-model", "Threagile", "threat", r.get("category") or r.get("synthetic_id"),
                                 self.inv["threagile"], None, r.get("severity"), r.get("title") or r.get("synthetic_id"),
                                 key=r.get("synthetic_id"), gating=r in open_items) for r in risks]
                self.gate("threat-model", "Threagile", len(open_items), f"{len(risks)} risks, {len(open_items)} open HIGH/CRITICAL",
                          items=items)
        else:
            self.record("threat-model", "—", "skipped", "no threatmodel/tm.py (pytm) or threagile.yaml found", gate=False)

    def threat_decisions(self):
        """`threats:` in the baseline file: mitigate / accept / transfer, each with an owner and expiry."""
        name = self.cfg["baseline"]["file"]
        if name == ".sawone-baseline.yml" and not (self.ws / name).exists() and (self.ws / ".sawanb-baseline.yml").exists():
            name = ".sawanb-baseline.yml"
        return TMA.load_decisions(self.ws / name, max_days=int(self.cfg["baseline"].get("max_days", 365)))

    def _load_mitigated(self, tm_path):
        code = ("import importlib.util,json,sys;s=importlib.util.spec_from_file_location('tm',sys.argv[1]);"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(json.dumps(getattr(m,'MITIGATED',{})))")
        p = subprocess.run([sys.executable, "-c", code, tm_path], cwd=self.ws, capture_output=True, text=True)
        try:
            return json.loads(p.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {}

    # ---- secrets
    def scan_secrets(self):
        sarif = self.reports / "sarif" / "gitleaks.sarif"
        if not self.skipped("gitleaks"):
            args = ["detect", "--source", str(self.ws), "--redact", "--no-banner", "--report-format", "sarif",
                    "--report-path", str(sarif)]
            if not self.inv["git"]:
                args.append("--no-git")
            elif self.base_sha:
                args.append(f"--log-opts={self.base_sha}..HEAD")    # only the commits this change adds
            code, out = self.docker("gitleaks", args, "gitleaks")
            m = re.search(r"leaks found: (\d+)", out)
            n = int(m.group(1)) if m else (0 if code == 0 else -1)
            if n < 0:
                self.record("secrets", "Gitleaks", "error", self.last_error("gitleaks"))
            else:
                items = self._sarif_items(sarif, "secrets", "Gitleaks", "secret", "HIGH", gating=True,
                                          key_fn=lambda r: (r.get("partialFingerprints") or {}).get("commitSha", ""))
                scope = (" (commits in this change)" if self.base_sha else " (full Git history)") if self.inv["git"] else ""
                self.gate("secrets", "Gitleaks", n, f"{n} leaks" + scope,
                          items=items if len(items) == n else None)
            self.sarif_tag(sarif, "gitleaks")
        if not self.skipped("trufflehog"):
            excl = self.reports / "raw" / "trufflehog-exclude.txt"
            excl.write_text(re.escape(str(self.reports)) + "\n" + r".*/\.git/.*" + "\n")
            fs_out = self.reports / "raw" / "trufflehog.jsonl"
            code, out = self.docker("trufflehog", ["filesystem", str(self.ws), "--only-verified", "--fail", "--no-update",
                                                   "--json", f"--exclude-paths={excl}"], "trufflehog", stdout_file=fs_out)
            codes, files = [code], [fs_out]
            if self.inv["git"]:
                # the history too: a key deleted from the code is still live if it was never rotated
                git_out = self.reports / "raw" / "trufflehog-git.jsonl"
                gargs = ["git", f"file://{self.ws}", "--only-verified", "--fail", "--no-update", "--json"]
                if self.base_sha:
                    gargs += ["--since-commit", self.base_sha]
                gcode, _ = self.docker("trufflehog", gargs, "trufflehog-git", stdout_file=git_out)
                codes.append(gcode)
                files.append(git_out)
            if any(c not in (0, 183) for c in codes):
                bad = "trufflehog" if codes[0] not in (0, 183) else "trufflehog-git"
                self.record("secrets", "TruffleHog", "error", self.last_error(bad))
            else:
                items, seen = [], set()
                for f in files:
                    for line in (f.read_text().splitlines() if f.exists() else []):
                        try:
                            r = json.loads(line)
                        except ValueError:
                            continue
                        if not r.get("Verified"):
                            continue
                        data = (r.get("SourceMetadata") or {}).get("Data") or {}
                        src = data.get("Filesystem") or data.get("Git") or {}
                        path = src.get("file", "")
                        path = self.rel(path) if path.startswith(str(self.ws)) else path
                        k = (r.get("DetectorName"), path, src.get("line"), r.get("Raw", "")[:12])
                        if k in seen:
                            continue
                        seen.add(k)
                        where = f' (commit {str(src.get("commit"))[:8]})' if src.get("commit") else ""
                        it = F.issue("secrets", "TruffleHog", "secret", r.get("DetectorName"), path, src.get("line"),
                                     "CRITICAL", f'verified live {r.get("DetectorName")} credential{where}',
                                     ws=self.ws if not src.get("commit") else None, gating=True,
                                     key=None if not src.get("commit") else f'{src.get("commit")}:{src.get("line")}')
                        it["verified"] = True
                        items.append(it)
                self.gate("secrets", "TruffleHog", len(items),
                          f"{len(items)} verified live secrets" + (" (code and Git history)" if self.inv["git"] else ""),
                          items=items)

    # ---- SAST
    def semgrep_configs(self):
        c = self.cfg["semgrep"]
        if c.get("configs"):
            return c["configs"]
        packs = ["p/default"]
        keys = list(self.inv["languages"]) + self.inv["frameworks"]
        if self.inv["dockerfiles"]:
            keys.append("docker")
        if self.inv["kubernetes"]:
            keys.append("kubernetes")
        for k in keys:
            for p in SEMGREP_PACKS.get(k, []):
                if p not in packs:
                    packs.append(p)
        return packs + list(c.get("extra_configs", []))

    def scan_sast(self):
        if self.skipped("semgrep"):
            return self.record("sast", "Semgrep CE", "skipped", "skipped by config", gate=False)
        if not self.inv["languages"]:
            return self.record("sast", "Semgrep CE", "skipped", "no source code detected", gate=False)
        configs = self.semgrep_configs()
        sarif, js = self.reports / "sarif" / "semgrep.sarif", self.reports / "raw" / "semgrep.json"

        def go(cfgs, log_name="semgrep"):
            args = ["semgrep", "scan", "--metrics=off", "--quiet", f"--sarif-output={sarif}", f"--json-output={js}",
                    "--exclude", self.reports.name]
            for g in self.cfg.get("exclude", []):
                args += ["--exclude", g]
            for cfg in cfgs:
                args += ["--config", cfg]
            if self.base_sha and (self.ws / ".git").exists():
                args += ["--baseline-commit", self.base_sha]   # report only what the change introduces
            # Semgrep runs from the scanner image (pip, upgraded at scan time), scanning the workspace
            return self.run(args + [str(self.ws)], log_name=log_name, timeout=3600)

        code, out = go(configs)
        if code not in (0, 1):
            log("  semgrep: retrying with p/default only (a language pack may be unavailable)")
            configs = ["p/default"]
            code, out = go(configs, "semgrep-retry")
        data = load_json(js)
        if not data:
            if code == 0:
                # clean exit with no output: nothing in the repo matched the selected rule packs
                return self.record("sast", "Semgrep CE", "passed",
                                   findings=f"no files matched the rule packs ({' '.join(configs)})")
            return self.record("sast", "Semgrep CE", "error",
                               self.last_error("semgrep-retry" if configs == ["p/default"] else "semgrep"))
        res = data.get("results", [])
        dropped = 0
        if self.cfg["semgrep"].get("framework_filter", True) and self.inv["frameworks"]:
            unused = [pfx for fw, pfxs in FRAMEWORK_RULES.items() if fw not in self.inv["frameworks"] for pfx in pfxs]
            kept = [r for r in res if not str(r.get("check_id", "")).startswith(tuple(unused))]
            dropped, res = len(res) - len(kept), kept
        errors = [r for r in res if (r.get("extra") or {}).get("severity") == "ERROR"]
        self.sarif_tag(sarif, "semgrep")
        items = []
        for r in res:
            path = r.get("path", "")
            path = self.rel(path) if path.startswith(str(self.ws)) else path
            sev = (r.get("extra") or {}).get("severity")
            it = F.issue("sast", "Semgrep CE", "code", r.get("check_id"), path, (r.get("start") or {}).get("line"),
                         {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(sev, sev),
                         ((r.get("extra") or {}).get("message") or "").strip().split("\n")[0][:200],
                         ws=self.ws, gating=sev == "ERROR")
            cwe = ((r.get("extra") or {}).get("metadata") or {}).get("cwe") or []
            it["cwe"] = sorted({m for c in (cwe if isinstance(cwe, list) else [cwe])
                                for m in re.findall(r"CWE-\d+", str(c))})
            items.append(it)
        self.gate("sast", "Semgrep CE", len(errors), f"{len(errors)} ERROR / {len(res)} total"
                  + (" in this change" if self.base_sha and (self.ws / ".git").exists() else "")
                  + f" · rules: {' '.join(configs)}"
                  + (f" · {dropped} results from rules for frameworks not in use dropped" if dropped else ""),
                  items=items)

    # ---- SCA + licences
    def trivy(self, args, log_name, extra=None):
        return self.docker("trivy", list(args), log_name,
                           extra=self.cache_mount("trivy", "/root/.cache/trivy") + (extra or []))

    LOCKS = {"package.json": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"],
             "pyproject.toml": ["poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock", "requirements.txt"],
             "Gemfile": ["Gemfile.lock"], "composer.json": ["composer.lock"], "Cargo.toml": ["Cargo.lock"]}

    def lockfile_gaps(self):
        gaps = []
        for m in self.inv["manifests"]:
            p = self.ws / m
            locks = self.LOCKS.get(p.name)
            if locks and not any((p.parent / l).exists() for l in locks):
                gaps.append(m)
        return gaps

    def scan_sca(self):
        gaps = self.lockfile_gaps()
        if gaps:
            self.record("sca", "lock files", "report", gate=False,
                        findings="no lock file next to " + ", ".join(gaps) + " — exact versions unknown, so SCA "
                                 "under-reports. Commit the lock file.")
        if not self.inv["manifests"]:
            self.record("sca", "Trivy", "skipped", "no dependency manifests found", gate=False)
        elif not self.skipped("trivy"):
            sarif, js = self.reports / "sarif" / "trivy-sca.sarif", self.reports / "raw" / "trivy-sca.json"
            skip = ["--skip-dirs", str(self.reports)] + sum([["--skip-dirs", g] for g in self.cfg.get("exclude", [])], [])
            self.trivy(["fs", "--skip-db-update", "--scanners", "vuln,license", *skip, "--format", "sarif",
                        "--output", str(sarif), str(self.ws)], "trivy-sca-sarif")
            code, _ = self.trivy(["fs", "--skip-db-update", "--scanners", "vuln,license", *skip, "--format", "json",
                                  "--output", str(js), str(self.ws)], "trivy-sca")
            data = load_json(js)
            if not data:
                self.record("sca", "Trivy", "error", self.last_error("trivy-sca"))
            else:
                vulns = [v for r in data.get("Results", []) or [] for v in r.get("Vulnerabilities", []) or []
                         if v.get("Severity") in self.sev and v.get("FixedVersion")]
                lic = [l for r in data.get("Results", []) or [] for l in r.get("Licenses", []) or []
                       if l.get("Severity") in ("HIGH", "CRITICAL")]
                items = self._trivy_vuln_items(data, "sca", "Trivy (dependencies)")
                lic_items = [F.issue("licences", "Trivy (licences)", "licence", l.get("Name"), l.get("FilePath") or r.get("Target"),
                                     None, l.get("Severity"), f'{l.get("PkgName")}: {l.get("Name")} ({l.get("Category")})',
                                     key=l.get("PkgName"), gating=l.get("Severity") in ("HIGH", "CRITICAL"))
                             for r in data.get("Results", []) or [] for l in r.get("Licenses", []) or []]
                self.gate("sca", "Trivy (dependencies)", len(vulns), f"{len(vulns)} fixable {'/'.join(self.sev)} CVEs", items=items)
                self.gate("licences", "Trivy (licences)", len(lic), f"{len(lic)} forbidden/restricted licences", items=lic_items)
                self.sarif_tag(sarif, "trivy-sca")
        if self.inv["manifests"] and self.cfg["source_sbom"]["enabled"] and "syft" in self.pinned:
            sbom = self.reports / "raw" / "sbom-source.cdx.json"
            code, _ = self.docker("syft", [f"dir:{self.ws}", "--exclude", f"./{self.reports.name}/**",
                                           "-o", f"cyclonedx-json={sbom}"], "syft-source")
            if code or not load_json(sbom):
                self.record("sca", "Syft (source SBOM)", "error", self.last_error("syft-source"))
            else:
                self.gate("sca", "Syft (source SBOM)", 0,
                          f"{sbom_packages(load_json(sbom))} packages (CycloneDX, raw/sbom-source.cdx.json)", report_only=True)
        if self.inv["manifests"] and not self.skipped("osv"):
            sarif = self.reports / "sarif" / "osv.sarif"
            code, _ = self.docker("osv", ["scan", "source", "-r", str(self.ws), "--format", "sarif",
                                          "--output-file", str(sarif)], "osv")
            if code not in (0, 1, 128):   # 1 = vulnerabilities found, 128 = no packages found
                self.record("sca", "OSV-Scanner", "error", self.last_error("osv"))
            else:
                n = sum(len(r.get("results", [])) for r in (load_json(sarif) or {}).get("runs", []))
                self.sarif_tag(sarif, "osv")
                self.gate("sca", "OSV-Scanner", 0, f"{n} findings (cross-check)", report_only=True)

    # ---- IaC
    def scan_iac(self):
        inv = self.inv
        has_iac = any([inv["dockerfiles"], inv["terraform"], inv["kubernetes"], inv["helm_charts"],
                       inv["cloudformation"], inv["bicep_arm"], inv["compose"]])
        if not has_iac:
            return self.record("iac", "Trivy config", "skipped", "no IaC or Dockerfiles found", gate=False)
        if not self.skipped("trivy"):
            sarif, js = self.reports / "sarif" / "trivy-iac.sarif", self.reports / "raw" / "trivy-iac.json"
            skip = ["--skip-dirs", str(self.reports)] + sum([["--skip-dirs", g] for g in self.cfg.get("exclude", [])], [])
            self.trivy(["config", *skip, "--format", "sarif", "--output", str(sarif), str(self.ws)], "trivy-iac-sarif")
            self.trivy(["config", *skip, "--format", "json", "--output", str(js), str(self.ws)], "trivy-iac")
            data = load_json(js)
            if data is None:
                self.record("iac", "Trivy config", "error", self.last_error("trivy-iac"))
            else:
                mis = [m for r in data.get("Results", []) or [] for m in r.get("Misconfigurations", []) or []
                       if m.get("Status") == "FAIL" and m.get("Severity") in self.sev]
                items = []
                for r in data.get("Results", []) or []:
                    for m in r.get("Misconfigurations", []) or []:
                        if m.get("Status") != "FAIL":
                            continue
                        line = (m.get("CauseMetadata") or {}).get("StartLine")
                        items.append(F.issue("iac", "Trivy config", "config", m.get("AVDID") or m.get("ID"), r.get("Target"), line,
                                             m.get("Severity"), m.get("Title") or m.get("Message"), ws=self.ws,
                                             gating=m.get("Severity") in self.sev))
                self.gate("iac", "Trivy config", len(mis), f"{len(mis)} {'/'.join(self.sev)} misconfigurations", items=items)
                self.sarif_tag(sarif, "trivy-iac")
        if not self.skipped("checkov"):
            outdir = self.reports / "raw" / "checkov"
            outdir.mkdir(parents=True, exist_ok=True)
            self.docker("checkov", ["-d", str(self.ws), "--quiet", "--soft-fail", "-o", "sarif",
                                    "--output-file-path", str(outdir), "--skip-path", self.reports.name,
                                    *sum([["--skip-path", g.replace("*", ".*")] for g in self.cfg.get("exclude", [])], [])], "checkov")
            src = outdir / "results_sarif.sarif"
            if src.exists():
                shutil.move(src, self.reports / "sarif" / "checkov.sarif")
                self.sarif_tag(self.reports / "sarif" / "checkov.sarif", "checkov")
                n = sum(len(r.get("results", [])) for r in
                        (load_json(self.reports / "sarif" / "checkov.sarif") or {}).get("runs", []))
                self.gate("iac", "Checkov", 0, f"{n} findings (second opinion)", report_only=True)
            else:   # --soft-fail never fails on findings, so a missing report means Checkov itself failed
                self.record("iac", "Checkov", "error", self.last_error("checkov"))
        if inv["dockerfiles"] and not self.skipped("hadolint"):
            bad = 0
            for i, df in enumerate(inv["dockerfiles"]):
                sarif = self.reports / "sarif" / f"hadolint-{i}.sarif"
                self.docker("hadolint", ["hadolint", "--format", "sarif", str(self.ws / df)], f"hadolint-{i}-sarif", stdout_file=sarif)
                self.sarif_tag(sarif, f"hadolint-{i}")
                code, _ = self.docker("hadolint", ["hadolint", "--failure-threshold", "error", str(self.ws / df)], f"hadolint-{i}")
                if code not in (0, 1):
                    self.record("iac", f"Hadolint ({df})", "error", self.last_error(f"hadolint-{i}"))
                bad += 1 if code == 1 else 0
            self.gate("iac", "Hadolint", bad, f"{len(inv['dockerfiles'])} Dockerfile(s), {bad} with errors")

    # ---- Kubernetes / Helm
    def scan_k8s(self):
        inv = self.inv
        if not (inv["kubernetes"] or inv["helm_charts"]):
            return self.record("kubernetes", "—", "skipped", "no Kubernetes manifests or Helm charts", gate=False)
        rendered = self.reports / "raw" / "k8s-rendered"
        rendered.mkdir(parents=True, exist_ok=True)
        files = [str(self.ws / f) for f in inv["kubernetes"]]
        for i, chart in enumerate(inv["helm_charts"]):
            out = rendered / f"chart-{i}.yaml"
            code, _ = self.docker("helm", ["template", "devsecops", str(self.ws / chart)], f"helm-{i}", stdout_file=out)
            if code == 0 and out.stat().st_size:
                files.append(str(out))
        if not files:
            return self.record("kubernetes", "kubeconform", "error", "Helm rendering failed (see logs/helm-*.log)")
        code, _ = self.docker("kubeconform", ["-strict", "-summary", "-ignore-missing-schemas", *files], "kubeconform")
        if code not in (0, 1):
            self.record("kubernetes", "kubeconform", "error", self.last_error("kubeconform"))
        else:
            self.gate("kubernetes", "kubeconform", code, f"{len(files)} manifest file(s)")
        sarif = self.reports / "sarif" / "kube-linter.sarif"
        self.docker("kubelinter", ["lint", "--format", "sarif", *files], "kube-linter", stdout_file=sarif)
        self.sarif_tag(sarif, "kube-linter")
        self.gate("kubernetes", "kube-linter", 0, "best-practice report", report_only=True)
        if inv["rego_policies"] and not self.skipped("conftest"):
            pol = str(Path(inv["rego_policies"][0]).parent)
            code, _ = self.docker("conftest", ["test", "--all-namespaces", "--policy", str(self.ws / pol), *files], "conftest")
            self.gate("kubernetes", "Conftest (OPA)", 1 if code else 0, f"policies in {pol}")

    # ---- CI/CD
    def scan_cicd(self):
        if not self.inv["github_workflows"]:
            return self.record("cicd", "—", "skipped",
                               "no GitHub Actions workflows" + (f" (found: {', '.join(self.inv['ci'])})" if self.inv["ci"] else ""), gate=False)
        if not self.skipped("actionlint"):
            code, _ = self.docker("actionlint", ["-color"], "actionlint")
            self.gate("cicd", "actionlint", 1 if code else 0, f"{len(self.inv['github_workflows'])} workflow(s)")
        if not self.skipped("zizmor"):
            cfg = self.ws / ".github" / "zizmor.yml"
            cfg = cfg if cfg.exists() else HERE / "defaults" / "zizmor.yml"
            sarif = self.reports / "sarif" / "zizmor.sarif"
            env_args = ["--config", str(cfg)]
            self.run(["zizmor", *env_args, "--format", "sarif", ".github/workflows"], "zizmor-sarif", stdout_file=sarif, quiet=True)
            self.sarif_tag(sarif, "zizmor")
            code, _ = self.run(["zizmor", *env_args, "--min-severity", "high", ".github/workflows"], "zizmor")
            items = self._sarif_items(sarif, "cicd", "zizmor", "config", "MEDIUM",
                                      gating=lambda sev: sev in ("HIGH", "CRITICAL"), sev_fn=sarif_severity)
            high = sum(1 for it in items if it["gating"])
            consistent = bool(code) == bool(high)
            self.gate("cicd", "zizmor", 1 if code else 0,
                      (f"{high} HIGH workflow risk(s) · {len(items)} total" if consistent and items
                       else "HIGH workflow risks" + (" found" if code else ": none")),
                      items=items if consistent else None)

    # ---- container: build (or take a prebuilt image), SBOM, scan
    def collect_images(self):
        """Images to scan and attack: SCAN_IMAGE if given, else build each Dockerfile once per run."""
        if self.images:
            return self.images
        if self.prebuilt:
            ref = self.prebuilt
            if self.run(["docker", "image", "inspect", ref], quiet=True)[0] != 0:
                code, _ = self.run(["docker", "pull", ref], log_name="pull-app-image", timeout=1800)
                if code:
                    self.record("container", "image", "error", f"cannot pull {ref}: {self.last_error('pull-app-image')}")
                    return []
            self.images = [{"dockerfile": ref, "tag": ref, "name": "img0", "prebuilt": True}]
            return self.images
        if not self.inv["dockerfiles"] or not self.cfg["container"]["enabled"]:
            return []
        for i, df in enumerate(self.inv["dockerfiles"][: self.cfg["container"]["max_images"]]):
            name, tag = f"img{i}", f"sawone-scan/img{i}:{int(time.time())}"
            build = ["docker", "build", "-f", str(self.ws / df), "-t", tag, str((self.ws / df).parent)]
            for k, v in (self.cfg["container"].get("build_args") or {}).items():
                build[2:2] = ["--build-arg", f"{k}={v}"]
            code, _ = self.run(build, log_name=f"build-{name}", timeout=3600)
            if code:
                self.record("container", f"build {df}", "failed", self.last_error(f"build-{name}"))
                continue
            self.images.append({"dockerfile": df, "tag": tag, "name": name, "prebuilt": False})
        return self.images

    def scan_containers(self):
        if not self.image_source():
            return self.record("container", "—", "skipped",
                               "no Dockerfile" if not self.inv["dockerfiles"] else "disabled by config", gate=False)
        (self.reports / "trivy-image-blocking.txt").touch()
        images = self.collect_images()
        for img in images:
            self._scan_image(img)
        (self.reports / "raw" / "images.json").write_text(json.dumps(images, indent=2))

    def _scan_image(self, img):
        name, tag, label = img["name"], img["tag"], img["dockerfile"]
        tar = self.reports / "raw" / f"{name}.tar"
        code, _ = self.run(["docker", "save", "-o", str(tar), tag], log_name=f"save-{name}")
        if code:
            return self.record("container", f"image ({label})", "error", self.last_error(f"save-{name}"))
        # pip's embedded SBOM: ignore it only when pip is verifiably gone from the image
        skip = []
        has_pip = self.run(["docker", "run", "--rm", "--entrypoint", "sh", tag, "-c",
                            "ls -d /usr/local/lib/python3*/site-packages/pip /usr/lib/python3*/site-packages/pip "
                            "2>/dev/null | grep -q ."], quiet=True)[0]
        has_sh = self.run(["docker", "run", "--rm", "--entrypoint", "sh", tag, "-c", "true"], quiet=True)[0] == 0
        if has_sh and has_pip != 0:
            skip = ["--skip-files", "**/pip/_vendor/bom.cdx.json"]
        sbom = self.reports / "raw" / f"sbom-{name}.cdx.json"
        code, _ = self.docker("syft", [f"docker-archive:{tar}", "-o", f"cyclonedx-json={sbom}"], f"syft-{name}")
        if code or not load_json(sbom):
            self.record("container", f"SBOM ({label})", "error", self.last_error(f"syft-{name}"))
        sarif = self.reports / "sarif" / f"trivy-image-{name}.sarif"
        js = self.reports / "raw" / f"trivy-image-{name}.json"
        self.trivy(["image", "--skip-db-update", "--input", str(tar), "--scanners", "vuln,secret", *skip,
                    "--format", "sarif", "--output", str(sarif)], f"trivy-image-{name}-sarif")
        self.sarif_tag(sarif, f"trivy-image-{name}")
        self.trivy(["image", "--skip-db-update", "--input", str(tar), "--scanners", "vuln,secret", *skip,
                    "--format", "json", "--output", str(js)], f"trivy-image-{name}")
        data = load_json(js)
        blocking = []
        for r in (data or {}).get("Results", []) or []:
            for v in r.get("Vulnerabilities", []) or []:
                if v.get("Severity") not in self.sev or not v.get("FixedVersion"):
                    continue
                blocking.append(f'{v.get("Severity")}\t{v.get("VulnerabilityID")}\t{v.get("PkgName")} '
                                f'{v.get("InstalledVersion")} -> {v.get("FixedVersion")}\t{self.trivy_location(r, v)}')
            for sec in r.get("Secrets", []) or []:
                blocking.append(f'SECRET\t{sec.get("RuleID")}\t\t{r.get("Target")}')
        with open(self.reports / "trivy-image-blocking.txt", "a") as f:
            f.write("".join(f"[{label}] {b}\n" for b in blocking))
        if data is None:
            self.record("container", f"Trivy image ({label})", "error", self.last_error(f"trivy-image-{name}"))
        else:
            items = self._trivy_vuln_items(data, "container", f"Trivy image ({label})")
            items += [F.issue("container", f"Trivy image ({label})", "secret", sec.get("RuleID"), r.get("Target"),
                              sec.get("StartLine"), sec.get("Severity") or "HIGH", sec.get("Title") or sec.get("RuleID"),
                              key=f'{label}:{sec.get("Match", "")[:40]}', gating=True)
                      for r in (data or {}).get("Results", []) or [] for sec in r.get("Secrets", []) or []]
            self.gate("container", f"Trivy image ({label})", len(blocking), f"{len(blocking)} blocking findings", items=items)
        gsarif = self.reports / "sarif" / f"grype-{name}.sarif"
        gjson = self.reports / "raw" / f"grype-{name}.json"
        if load_json(sbom):
            self.docker("grype", [f"sbom:{sbom}", "-o", f"json={gjson}", "-o", f"sarif={gsarif}"], f"grype-{name}",
                        extra=["-u", "0:0", *self.cache_mount("grype", "/grype-db"), "-e", "GRYPE_DB_CACHE_DIR=/grype-db",
                               "-e", "GRYPE_DB_AUTO_UPDATE=false"])
            self.sarif_tag(gsarif, f"grype-{name}")
        comps = sbom_packages(load_json(sbom))
        gdata = load_json(gjson)
        if gdata is None:
            self.record("container", f"Grype ({label})", "error", self.last_error(f"grype-{name}"))
        else:
            hits = [m for m in gdata.get("matches", []) or []
                    if str((m.get("vulnerability") or {}).get("severity", "")).upper() in self.sev
                    and ((m.get("vulnerability") or {}).get("fix") or {}).get("state") == "fixed"]
            ids = sorted({(m.get("vulnerability") or {}).get("id") for m in hits})
            items = []
            for m in gdata.get("matches", []) or []:
                v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
                related = [x.get("id") for x in m.get("relatedVulnerabilities") or [] if x.get("id")]
                vid = v.get("id", "")
                cve = vid if vid.upper().startswith("CVE-") else next((x for x in related if x.upper().startswith("CVE-")), vid)
                sev = str(v.get("severity", "")).upper()
                fixed = (v.get("fix") or {}).get("state") == "fixed"
                gloc = ((a.get("locations") or [{}])[0] or {}).get("path") or ""
                items.append(F.vuln("container", f"Grype ({label})", cve, a.get("name"), a.get("version"), sev,
                                    ", ".join((v.get("fix") or {}).get("versions") or []),
                                    f'{a.get("type") or "package"}: {gloc}' if gloc else (a.get("type") or label),
                                    (v.get("description") or cve)[:200], gating=sev in self.sev and fixed,
                                    aliases=[vid, *related]))
            self.gate("container", f"Grype ({label})", len(hits),
                      f"SBOM {comps} components · {len(hits)} fixable {'/'.join(self.sev)} ({len(ids)} unique CVEs)", items=items)
        if "dockle" in self.pinned:
            self._dockle(tar, label, name)
        try:
            tar.unlink()
        except OSError:
            pass

    def _dockle(self, tar, label, name):
        """CIS Docker benchmark checks on the built image: root user, setuid files, secrets and keys left
        in layers, missing HEALTHCHECK … Report only: it complements Hadolint, which sees only the Dockerfile."""
        out = self.reports / "raw" / f"dockle-{name}.json"
        code, _ = self.docker("dockle", ["--input", str(tar), "-f", "json", "-o", str(out), "--exit-code", "0"],
                              f"dockle-{name}")
        data = load_json(out)
        if code or data is None:
            return self.record("container", "Dockle", "error", self.last_error(f"dockle-{name}"))
        sev = {"FATAL": "HIGH", "WARN": "MEDIUM", "INFO": "LOW"}
        items = [F.issue("container", "Dockle", "config", d.get("code"), label, None, sev[d.get("level")],
                         f'{d.get("title")}: {"; ".join(d.get("alerts") or [])}'[:200], key=label)
                 for d in data.get("details", []) or [] if d.get("level") in sev]
        fatal = sum(1 for d in data.get("details", []) or [] if d.get("level") == "FATAL")
        self.gate("container", "Dockle", 0, f"{fatal} FATAL · {len(items)} total (CIS image benchmark)",
                  report_only=True, items=items)

    # ---- DAST + WAF + IAST
    def _exposed_port(self, tag):
        out = subprocess.run(["docker", "image", "inspect", "--format", "{{json .Config.ExposedPorts}}", tag],
                             capture_output=True, text=True).stdout.strip()
        try:
            ports = [int(p.split("/")[0]) for p in (json.loads(out) or {}) if p.endswith("/tcp")]
            return sorted(ports)[0] if ports else None
        except (ValueError, TypeError):
            return None

    def _curl(self, url, extra=None):
        code, out = self.docker("curl", ["-s", "-o", "/dev/null", "-w", "%{http_code}", "-A", "Mozilla/5.0",
                                         "--max-time", "10", *(extra or []), url], "curl", mount=False,
                                extra=["--network", self.network])
        return out.strip()[-3:] if code == 0 else "000"

    def ensure_app(self, stage, with_iast=False):
        """Start the app (prebuilt SCAN_IMAGE or the first built image) on a private network and wait
        until it answers. Returns the target dict, or None after recording why (skip or error)."""
        if self.target:
            return self.target
        images = self.collect_images()
        if not images:
            self.record(stage, "—", "skipped", "no image to run (no Dockerfile and no SCAN_IMAGE)", gate=False)
            return None
        d, img = self.cfg["dast"], images[0]
        port = d.get("port") or self._exposed_port(img["tag"])
        if not port:
            self.record(stage, "—", "skipped", f"{img['dockerfile']} has no EXPOSE (set the app port to enable)", gate=False)
            return None
        self.run(["docker", "network", "create", self.network], quiet=True)
        envs = sum([["-e", f"{k}={v}"] for k, v in (d.get("env") or {}).items()], [])
        if with_iast:
            # IAST: the agent runs inside the app while scanner traffic exercises it
            envs += shlex.split(os.environ["IAST_RUN_ARGS"])
            if os.environ.get("DONGTAI_TOKEN"):
                envs += ["-e", "DONGTAI_TOKEN"]
            self.iast_attached = True
        self.run(["docker", "run", "-d", "--name", f"{self.network}-app", "--network-alias", "app",
                  "--network", self.network, *envs, img["tag"]], log_name="app-start")
        health = d.get("health_path")
        candidates = [health] if health else ["/health", "/healthz", "/actuator/health", "/ready", "/"]
        base, found = f"http://app:{port}", None
        deadline = time.time() + int(d.get("startup_timeout", 60))
        while time.time() < deadline and not found:
            for path in candidates:
                c = self._curl(base + path)
                if c.isdigit() and c != "000" and int(c) < 500:
                    found = path
                    break
            if not found:
                time.sleep(2)
        if not found:
            self.run(["docker", "logs", f"{self.network}-app"], log_name="app-logs")
            self.record(stage, "app startup", "error",
                        f"app did not become ready on port {port} within {d.get('startup_timeout', 60)}s "
                        f"(tried {', '.join(candidates)}; see logs/app-logs.log)")
            return None
        self.target = {"base": base, "health": found, "port": port, "image": img["tag"]}
        return self.target

    # ---- authenticated DAST
    def prepare_auth(self, base):
        """Set up the credential ZAP sends on every request. Either DAST_AUTH_VALUE (a fixed header value,
        e.g. 'Bearer …' or 'session=…'), or a login call: POST dast.auth.login_body to dast.auth.login_url
        with ${DAST_USERNAME} / ${DAST_PASSWORD} substituted, then read dast.auth.token_field from the JSON
        reply. Secrets travel only through environment variables: never on a command line or in a log.
        Returns False (after recording an error) when login was configured but failed."""
        a, env = self.cfg["dast"]["auth"], os.environ
        self.auth_mode = None
        for k in ("DAST_AUTH_VALUE", "DAST_USERNAME", "DAST_PASSWORD"):
            if re.fullmatch(r"\$\(\w+\)", env.get(k, "")):   # an unset Azure DevOps variable arrives as "$(NAME)"
                env.pop(k)
        if env.get("DAST_AUTH_VALUE"):
            env["ZAP_AUTH_HEADER_VALUE"], self.auth_mode = env["DAST_AUTH_VALUE"], "fixed header"
        elif a.get("login_url"):
            if not (env.get("DAST_USERNAME") and env.get("DAST_PASSWORD")):
                self.record("dast", "authentication", "error", "dast.auth.login_url is set but DAST_USERNAME / "
                            "DAST_PASSWORD are not")
                return False
            body = str(a.get("login_body") or '{"username": "${DAST_USERNAME}", "password": "${DAST_PASSWORD}"}')
            env["SAWONE_LOGIN_BODY"] = (body.replace("${DAST_USERNAME}", json.dumps(env["DAST_USERNAME"])[1:-1])
                                        .replace("${DAST_PASSWORD}", json.dumps(env["DAST_PASSWORD"])[1:-1]))
            url = a["login_url"] if a["login_url"].startswith("http") else base + a["login_url"]
            # no log_name: the reply contains the token
            code, out = self.run(["docker", "run", "--rm", "--network", self.network, "-e", "SAWONE_LOGIN_BODY",
                                  "--entrypoint", "sh", self.pinned.get("curl", IMAGES["curl"]), "-c",
                                  'curl -s --max-time 20 -X POST -H "Content-Type: application/json" '
                                  '--data "$SAWONE_LOGIN_BODY" "$0"', url], quiet=True)
            env.pop("SAWONE_LOGIN_BODY", None)
            token = None
            try:
                token = json.loads(out.strip().splitlines()[0])
                for part in str(a.get("token_field") or "token").split("."):
                    token = token[part]
            except (ValueError, IndexError, KeyError, TypeError):
                token = None
            if code or not isinstance(token, str) or not token:
                self.record("dast", "authentication", "error",
                            f"login to {a['login_url']} did not return a '{a.get('token_field')}' token (HTTP call "
                            f"exit {code}); the scan would only see anonymous pages")
                return False
            env["ZAP_AUTH_HEADER_VALUE"], self.auth_mode = (a.get("token_prefix") or "") + token, "login token"
        if self.auth_mode:
            env["ZAP_AUTH_HEADER"] = env.get("ZAP_AUTH_HEADER") or a.get("header") or "Authorization"
            env["ZAP_AUTH_HEADER_SITE"] = "app"
            self.record("dast", "authentication", "report", gate=False,
                        findings=f"{self.auth_mode} sent as the {env['ZAP_AUTH_HEADER']} header on every request")
        return True

    def zap_auth_env(self):
        """docker -e NAME (value inherited, so it never appears on the command line or in logs)."""
        if not getattr(self, "auth_mode", None):
            return []
        return sum([["-e", k] for k in ("ZAP_AUTH_HEADER", "ZAP_AUTH_HEADER_VALUE", "ZAP_AUTH_HEADER_SITE")], [])

    def _zap_dir(self):
        wrk = self.reports / "raw" / "zap"
        wrk.mkdir(parents=True, exist_ok=True)
        os.chmod(wrk, 0o777)
        rules_src = self.ws / ".zap" / "rules.tsv"
        if not (wrk / "rules.tsv").exists():
            shutil.copy(rules_src if rules_src.exists() else HERE / "defaults" / "zap-rules.tsv", wrk / "rules.tsv")
        return wrk

    def _zap(self, stage, tool, script, base, wrk, out, extra_args=(), timeout=3600):
        """Run one ZAP packaged scan. ZAP exits 0 = pass, 1 = FAIL rules hit, 2 = warnings only
        (we pass -I), 3 = scanner error."""
        ajax = ["-j"] if self.cfg["dast"].get("ajax_spider") and script != "zap-api-scan.py" else []
        code, _ = self.docker("zap", [script, "-t", base, *extra_args, *ajax, "-c", "rules.tsv", "-I", "-z", "-addonupdate",
                                      "-r", f"{out}.html", "-x", f"{out}.xml", "-J", f"{out}.json"],
                              out, extra=["--network", self.network, "-v", f"{wrk}:/zap/wrk:rw", *self.zap_auth_env()],
                              mount=False, timeout=timeout)
        if code not in (0, 1, 2) or not (wrk / f"{out}.json").exists():
            self.record(stage, tool, "error", self.last_error(out))
        else:
            self._zap_gate(stage, tool, code, wrk, out)
            shutil.copy(wrk / f"{out}.json", self.reports / f"{out}.json")

    def _zap_fail_rules(self, wrk):
        fail = set()
        try:
            for line in (wrk / "rules.tsv").read_text().splitlines():
                parts = line.split("\t")
                if len(parts) >= 2 and parts[1].strip().upper() == "FAIL":
                    fail.add(parts[0].strip())
        except OSError:
            pass
        return fail

    def _zap_gate(self, stage, tool, code, wrk, out):
        """ZAP's exit code 1 means a FAIL rule fired; the alerts of those rules become blocking findings,
        so they can be baselined individually. If the alerts cannot be read, the exit code decides."""
        fail = self._zap_fail_rules(wrk)
        items = []
        for site in (load_json(wrk / f"{out}.json") or {}).get("site", []) or []:
            for a in site.get("alerts", []) or []:
                risk = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "LOW"}.get(str(a.get("riskcode")), "UNKNOWN")
                for inst in (a.get("instances") or [{}])[:20]:
                    uri = re.sub(r"^https?://[^/]+", "", inst.get("uri", "")) or "/"
                    items.append(F.issue(stage, tool, "dast", a.get("pluginid"), uri.split("?")[0], None, risk,
                                         f'{a.get("alert") or a.get("name")} ({inst.get("method", "GET")} {uri}'
                                         f'{" · param " + inst["param"] if inst.get("param") else ""})',
                                         key=f'{inst.get("method", "GET")} {inst.get("param", "")}',
                                         gating=str(a.get("pluginid")) in fail))
        consistent = (code == 1) == any(i["gating"] for i in items)
        self.gate(stage, tool, 1 if code == 1 else 0, self._zap_counts(wrk / f"{out}.json"),
                  items=items if consistent else None)
        if not consistent:
            self.findings.extend(items)

    def scan_dast(self):
        d = self.cfg["dast"]
        if d["enabled"] is False or self.skipped("zap"):
            return self.record("dast", "—", "skipped", "disabled by config", gate=False)
        attach = self.iast_configured() and self.wants("iast")
        t = self.ensure_app("dast", with_iast=attach)
        if not t:
            return
        wrk, base = self._zap_dir(), t["base"]
        if not self.prepare_auth(base):
            return
        self._zap("dast", "ZAP baseline", "zap-baseline.py", base, wrk, "zap")
        if d.get("full_scan", True):
            mins = int(d.get("max_minutes", 20))
            self._zap("dast", "ZAP full scan", "zap-full-scan.py", base, wrk, "zap-full",
                      extra_args=["-m", "2", "-T", str(mins)], timeout=60 * (mins + 10))
        spec = self.inv.get("openapi")
        if spec:
            shutil.copy(self.ws / spec, wrk / "openapi-spec")
            # zap-api-scan.py takes the spec as the target and the app URL via -O
            code, _ = self.docker("zap", ["zap-api-scan.py", "-t", "/zap/wrk/openapi-spec", "-f", "openapi", "-O", base,
                                          "-c", "rules.tsv", "-I", "-r", "zap-api.html", "-x", "zap-api.xml",
                                          "-J", "zap-api.json"], "zap-api",
                                  extra=["--network", self.network, "-v", f"{wrk}:/zap/wrk:rw", *self.zap_auth_env()],
                                  mount=False)
            if code not in (0, 1, 2) or not (wrk / "zap-api.json").exists():
                self.record("dast", "ZAP API scan", "error", self.last_error("zap-api"))
            else:
                self._zap_gate("dast", "ZAP API scan", code, wrk, "zap-api")
                shutil.copy(wrk / "zap-api.json", self.reports / "zap-api.json")
        if d.get("nuclei", True) and not self.skipped("nuclei"):
            sarif = self.reports / "sarif" / "nuclei.sarif"
            jsonl = self.reports / "raw" / "nuclei.jsonl"
            def nuclei(tech, log_name):
                return self.docker("nuclei", ["-u", base, *tech, "-severity", "medium,high,critical", "-silent",
                                              "-disable-update-check", "-sarif-export", str(sarif),
                                              "-jsonl-export", str(jsonl)], log_name,
                                   extra=["--network", self.network, *self.cache_mount("nuclei", "/root")])[0]
            auto = d.get("nuclei_mode", "auto") == "auto"
            code, run_log = nuclei(["-as"] if auto else [], "nuclei"), "nuclei"   # -as: detected stack only
            if auto and code != 0 and not sarif.exists():
                # -as needs templates already installed and never fetches them; a plain run installs them
                log(f"Nuclei technology-filtered scan failed ({self.last_error('nuclei')}); running every template")
                code, run_log = nuclei([], "nuclei-all"), "nuclei-all"
            if code != 0 and not sarif.exists():
                self.record("dast", "Nuclei", "error", self.last_error(run_log))
            else:
                self.sarif_tag(sarif, "nuclei")
                items = []
                for line in (jsonl.read_text().splitlines() if jsonl.exists() else []):
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    info = r.get("info") or {}
                    url = re.sub(r"^https?://[^/]+", "", str(r.get("matched-at") or r.get("host") or "")) or "/"
                    items.append(F.issue("dast", "Nuclei", "dast", r.get("template-id"), url, None, info.get("severity"),
                                         f'{info.get("name") or r.get("template-id")} ({url})',
                                         key=str(r.get("matcher-name") or ""), gating=False))
                n = len(items) or sum(len(r.get("results", [])) for r in (load_json(sarif) or {}).get("runs", []))
                self.gate("dast", "Nuclei", 0, f"{n} findings · template matches, verify before acting", report_only=True,
                          items=items or None)

    def _zap_counts(self, path):
        data = load_json(path)
        if not data:
            return "no report"
        c = {}
        for s in data.get("site", []) or []:
            for a in s.get("alerts", []) or []:
                r = (a.get("riskdesc") or "Info").split(" ")[0]
                c[r] = c.get(r, 0) + 1
        return ", ".join(f"{k} {c.get(k, 0)}" for k in ["High", "Medium", "Low", "Informational"])

    def scan_waf(self):
        if not self.cfg["waf"]["enabled"] or self.skipped("waf"):
            return self.record("runtime", "ModSecurity + CRS", "skipped", "disabled by config", gate=False)
        t = self.ensure_app("runtime")
        if not t:
            return
        self.run(["docker", "run", "-d", "--name", f"{self.network}-waf", "--network-alias", "waf",
                  "--network", self.network, "-e", "PORT=8080", "-e", f"BACKEND={t['base']}", "-e", "PARANOIA=1",
                  "-e", "ANOMALY_INBOUND=5", "-e", "MODSEC_RULE_ENGINE=On",
                  self.pinned.get("waf", IMAGES["waf"])], log_name="waf")
        h, ready = t["health"], False
        for _ in range(45):
            if self._curl(f"http://waf:8080{h}") not in ("000", "502", "503"):
                ready = True
                break
            time.sleep(2)
        if not ready:
            self.run(["docker", "logs", f"{self.network}-waf"], log_name="waf-logs")
            return self.record("runtime", "ModSecurity + OWASP CRS", "error",
                               "WAF did not start or cannot reach the app (see logs/waf-logs.log)")
        checks = [("legitimate request", f"http://waf:8080{h}", "allow"),
                  ("SQL injection", "http://waf:8080/?q=1%27%20OR%20%271%27=%271", "block"),
                  ("command injection", "http://waf:8080/?q=127.0.0.1;cat%20/etc/passwd", "block"),
                  ("cross-site scripting", "http://waf:8080/?q=%3Cscript%3Ealert(1)%3C/script%3E", "block"),
                  ("path traversal", "http://waf:8080/?q=../../../../etc/passwd", "block")]
        lines, bad = [], 0
        for desc, url, want in checks:
            code = self._curl(url)
            ok = (code == "403") if want == "block" else (code not in ("403", "000"))
            bad += 0 if ok else 1
            lines.append(f"{'PASS' if ok else 'FAIL'}  {desc} → {code}")
        # the same attacks against the application's real endpoints and parameters (from its OpenAPI spec)
        ep, ep_bad, info = self.waf_endpoint_checks(), 0, 0
        for desc, method, url, body, want in ep:
            extra = ["-X", method] + (["-H", "Content-Type: application/json", "--data", body] if body else [])
            code = self._curl(url, extra)
            if want == "info":
                info += 1
                lines.append(f"{'PASS' if code == '403' else 'INFO'}  {desc} → {code}")
                continue
            ok = code == "403"
            ep_bad += 0 if ok else 1
            lines.append(f"{'PASS' if ok else 'FAIL'}  {desc} → {code}")
        (self.reports / "waf-results.txt").write_text("\n".join(lines) + "\n")
        total = len(checks) + len(ep) - info
        txt = f"{total - bad - ep_bad}/{total} checks as expected"
        if ep:
            txt += f" · {len(ep) - info} attacks on {len({e[2].split('?')[0] for e in ep})} real endpoints"
        self.gate("runtime", "ModSecurity + OWASP CRS", bad + ep_bad, txt)

    WAF_PAYLOADS = [("SQL injection", "' OR '1'='1' --", "block"), ("cross-site scripting", "<script>alert(1)</script>", "block"),
                    ("command injection", ";cat /etc/passwd", "block"), ("path traversal", "../../../../etc/passwd", "block"),
                    ("template injection", "{{7*7}}", "info")]

    def waf_endpoint_checks(self, limit=40):
        """(description, method, url, json body or None, block|info) for each parameter in the OpenAPI spec.
        Template injection is informational: CRS at paranoia level 1 does not claim to block it."""
        spec_path = self.inv.get("openapi")
        if not spec_path:
            return []
        try:
            text = (self.ws / spec_path).read_text()
            spec = json.loads(text) if spec_path.endswith(".json") else (yaml.safe_load(text) if yaml else None)
        except (OSError, ValueError, Exception):  # noqa: BLE001 — an unreadable spec just means no endpoint checks
            return []
        from urllib.parse import quote
        out = []
        for path, ops in ((spec or {}).get("paths") or {}).items():
            for method, op in (ops or {}).items():
                if method.lower() not in ("get", "post", "put", "patch", "delete") or not isinstance(op, dict):
                    continue
                url_path = re.sub(r"\{[^}]+\}", "1", path)
                params = [p.get("name") for p in (op.get("parameters") or []) if isinstance(p, dict) and p.get("in") == "query"]
                props = list(((((op.get("requestBody") or {}).get("content") or {}).get("application/json") or {})
                              .get("schema") or {}).get("properties") or {})
                for desc, payload, want in self.WAF_PAYLOADS:
                    for name in params[:2]:
                        out.append((f"{desc} → {method.upper()} {path}?{name}", method.upper(),
                                    f"http://waf:8080{url_path}?{name}={quote(payload)}", None, want))
                    for name in props[:2]:
                        out.append((f"{desc} → {method.upper()} {path} {{{name}}}", method.upper(),
                                    f"http://waf:8080{url_path}", json.dumps({name: payload}), want))
        return out[:limit]

    def scan_iast(self):
        url = os.environ.get("DONGTAI_URL")
        if not self.iast_configured():
            return self.record("iast", "DongTai", "skipped", "not configured (DONGTAI_URL + IAST_RUN_ARGS)", gate=False)
        if not re.match(r"^https?://", url):
            return self.record("iast", "DongTai", "error", "DONGTAI_URL must start with http:// or https://")
        if not self.iast_attached:
            # IAST running on its own: start the app with the agent and drive traffic through it
            if self.target:
                return self.record("iast", "DongTai", "skipped",
                                   "app already started without the agent in this run", gate=False)
            t = self.ensure_app("iast", with_iast=True)
            if not t:
                return
            wrk = self._zap_dir()
            code, _ = self.docker("zap", ["zap-baseline.py", "-t", t["base"], "-I", "-r", "iast-traffic.html"], "iast-traffic",
                                  extra=["--network", self.network, "-v", f"{wrk}:/zap/wrk:rw"], mount=False)
            if code not in (0, 1, 2):
                return self.record("iast", "DongTai", "error", "could not drive traffic: " + self.last_error("iast-traffic"))
        self.record("iast", "DongTai", "report", gate=False,
                    findings=f"agent observed the app during scanner traffic; review findings in {url}")

    # ---- DefectDojo
    def defectdojo(self):
        url, tok = os.environ.get("DEFECTDOJO_URL"), os.environ.get("DEFECTDOJO_TOKEN")
        if not url and not tok:
            return self.record("tracking", "DefectDojo", "skipped", "not configured", gate=False)
        if not (url and tok):
            return self.record("tracking", "DefectDojo", "error", "DEFECTDOJO_URL and DEFECTDOJO_TOKEN must both be set")
        if not re.match(r"^https://[^\s/]+", url) and not os.environ.get("DEFECTDOJO_ALLOW_HTTP"):
            return self.record("tracking", "DefectDojo", "error", "DEFECTDOJO_URL must be https:// (token would travel in clear text)")
        self.record_defectdojo(import_reports(self.reports, url, tok,
                                              os.environ.get("DEFECTDOJO_PRODUCT") or self.ws.name,
                                              os.environ.get("DEFECTDOJO_ENGAGEMENT") or "sawone-scan", self.run))

    def record_defectdojo(self, result):
        ok, total, err = result
        if err:
            self.record("tracking", "DefectDojo", "error", err)
        elif total == 0:
            self.record("tracking", "DefectDojo", "skipped", "no reports to import", gate=False)
        elif ok < total:
            self.record("tracking", "DefectDojo", "error", f"only {ok}/{total} reports imported (see logs/defectdojo-*.log)")
        else:
            self.record("tracking", "DefectDojo", "report", gate=False, findings=f"{ok}/{total} reports imported")

    # ======================================================== 4. outputs
    def cleanup(self):
        if not self.docker_ok:
            return
        for c in [f"{self.network}-app", f"{self.network}-waf"]:
            self.run(["docker", "rm", "-f", c], quiet=True)
        self.run(["docker", "network", "rm", self.network], quiet=True)
        for img in self.images:
            if not img.get("prebuilt"):
                self.run(["docker", "rmi", "-f", img["tag"]], quiet=True)

    def prepare_policy(self):
        """Load the baseline and the KEV/EPSS feeds. Problems are recorded as visible 'policy' rows:
        an invalid baseline is an error (a typo must not silently un-suppress or over-suppress), and so
        is a missing KEV feed while block_kev is on (the gate would otherwise be weaker without saying so)."""
        pol, base = self.cfg["policy"], self.cfg["baseline"]
        if base["file"] == ".sawone-baseline.yml" and not (self.ws / base["file"]).exists() \
                and (self.ws / ".sawanb-baseline.yml").exists():
            base["file"] = ".sawanb-baseline.yml"     # baseline from SawanB DevSecOps still works
        active, expired, errors = F.load_baseline(self.ws / base["file"], max_days=int(base["max_days"]))
        self.baseline_state = {"file": base["file"], "active": active, "expired": expired, "errors": errors,
                               "present": (self.ws / base["file"]).exists()}
        intel_dir = os.environ.get("SCAN_INTEL_DIR")
        fetch_errors = []
        if not intel_dir:
            intel_dir = str(self.reports / "raw" / "intel")
            if pol["block_kev"] or pol["epss_threshold"]:
                fetch_errors = F.fetch_intel(intel_dir)
        intel = F.Intel.load(intel_dir)
        self.policy = F.Policy(active, expired, intel, block_kev=pol["block_kev"], epss_threshold=pol["epss_threshold"])
        parts, problems = [], []
        if intel.kev is not None:
            parts.append(f"CISA KEV: {len(intel.kev)} known-exploited CVEs")
        elif pol["block_kev"]:
            problems.append("CISA KEV feed unavailable while block_kev is on")
        if intel.epss is not None:
            parts.append(f"EPSS: {len(intel.epss)} scores" + (f", blocking ≥ {pol['epss_threshold']}" if pol["epss_threshold"] else ""))
        elif pol["epss_threshold"]:
            problems.append("EPSS feed unavailable while epss_threshold is set")
        if problems:
            self.record("policy", "Risk intelligence (KEV/EPSS)", "error",
                        "; ".join(problems) + (" — " + "; ".join(fetch_errors) if fetch_errors else ""))
        elif pol["block_kev"] or pol["epss_threshold"]:
            self.record("policy", "Risk intelligence (KEV/EPSS)", "report", gate=False, findings=" · ".join(parts))
        if errors:
            self.record("policy", f"Baseline ({base['file']})", "error", "; ".join(errors[:5])
                        + (f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""))

    def baseline_row(self):
        b = self.baseline_state
        if not b or b["errors"] or not b["present"]:
            return
        txt = f"{len(b['active'])} active exception(s)"
        if b["expired"]:
            txt += f" · {len(b['expired'])} expired (no longer suppressing): " + ", ".join(
                f"{e['id'] or e['fingerprint'][:10]} ({e['expires']})" for e in b["expired"][:5])
        self.record("policy", f"Baseline ({b['file']})", "report", gate=False, findings=txt)

    def report_options(self):
        c = self.cfg
        return {"profile": c["report"].get("profile", "balanced"), "languages": c["report"].get("languages", ["en"]),
                "mute_rules": list(c["noise"].get("mute_rules") or []), "sla": dict(c.get("sla") or {}),
                "frameworks": list(c["compliance"].get("frameworks") or [])}

    def write_outputs(self):
        self.baseline_row()
        (self.reports / "findings.json").write_text(json.dumps(self.findings, indent=1))
        if self.baseline_state:
            (self.reports / "raw" / "baseline.json").write_text(json.dumps(
                {k: v for k, v in self.baseline_state.items()}, indent=1, default=str))
        summary = {"repository": os.environ.get("REPO") or self.ws.name, "enforce": self.cfg.get("enforce", True),
                   "severity": self.sev, "stages": self.stages, "inventory": getattr(self, "inv", {}),
                   "tools": self.tool_versions, "image": self.prebuilt, "options": self.report_options(),
                   "only": sorted(self.only), "generated": dt.datetime.now(dt.timezone.utc).isoformat()}
        return render_outputs(self.reports, summary)

    # ========================================================== main flow
    def main(self):
        inv = self.detect()
        log("detected: " + json.dumps({k: v for k, v in inv.items() if v}, separators=(",", ":"))[:1500])
        log("stages: " + (", ".join(s for s in STAGES if self.wants(s))))
        log("plan: tools " + ", ".join(self.needed_tools()))
        if self.wants("sast"):
            log("plan: semgrep rules " + " ".join(self.semgrep_configs()))
        if self.plan_only:
            return 0
        if not self.docker_ok:
            log("ERROR: Docker is not available. Mount the Docker socket (-v /var/run/docker.sock:/var/run/docker.sock).")
            self.record("scanner", "docker", "error", "Docker not available")
            return self.write_outputs()
        steps = [("threat-model", self.scan_threat_model), ("secrets", self.scan_secrets), ("sast", self.scan_sast),
                 ("sca", self.scan_sca), ("iac", self.scan_iac), ("kubernetes", self.scan_k8s),
                 ("cicd", self.scan_cicd), ("container", self.scan_containers), ("dast", self.scan_dast),
                 ("iast", self.scan_iast), ("runtime", self.scan_waf), ("tracking", self.defectdojo)]
        try:
            try:
                self.prepare_policy()
            except Exception as e:  # noqa: BLE001 — the policy must never take the scan down silently
                self.record("policy", "risk policy", "error", f"{type(e).__name__}: {e}")
            if self.update_tools():
                for stage, step in steps:
                    if not self.wants(stage):
                        continue
                    try:
                        step()
                    except Exception as e:  # one broken scanner must not hide the others
                        self.record(stage, "scanner", "error", f"{type(e).__name__}: {e}")
            else:
                log("ERROR: required tools could not be resolved; no scans were run.")
        finally:
            self.cleanup()
        return self.write_outputs()


# ============================================================ shared helpers
LEVEL_SEV = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}


def sarif_severity(result, rule):
    """A SARIF result's severity: the CVSS-style security-severity when the tool gives one,
    else the result's or rule's level."""
    for props in ((result.get("properties") or {}), (rule.get("properties") or {})):
        try:
            s = float(props.get("security-severity"))
        except (TypeError, ValueError):
            continue
        return "CRITICAL" if s >= 9 else "HIGH" if s >= 7 else "MEDIUM" if s >= 4 else "LOW"
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    return LEVEL_SEV.get(level, "UNKNOWN")


def sbom_packages(sbom):
    """Packages in a CycloneDX SBOM. Syft also lists catalogued files as components; those are not packages."""
    return sum(1 for c in (sbom or {}).get("components", []) or [] if c.get("type") != "file")


def import_reports(reports, url, token, product, engagement, runner):
    """Import every SARIF and ZAP XML report into DefectDojo. Returns (imported, total, error)."""
    reports = Path(reports)
    files = [(p, "SARIF") for p in sorted((reports / "sarif").glob("*.sarif"))]
    files += [(p, "ZAP Scan") for p in sorted(reports.rglob("zap*.xml"))]
    ok = 0
    for path, kind in files:
        code, out = runner(["curl", "-sS", "--fail-with-body", "-X", "POST", f"{url.rstrip('/')}/api/v2/reimport-scan/",
                            "-H", f"Authorization: Token {token}", "-F", f"scan_type={kind}", "-F", f"file=@{path}",
                            "-F", f"test_title={path.stem}", "-F", "product_type_name=Applications",
                            "-F", f"product_name={product}", "-F", f"engagement_name={engagement}",
                            "-F", "auto_create_context=true", "-F", "close_old_findings=true"],
                           log_name=f"defectdojo-{path.stem}", quiet=True)
        if code and re.search(r"\b(401|403)\b", out or ""):
            return ok, len(files), "DefectDojo rejected the token (401/403): check DEFECTDOJO_TOKEN and its permissions"
        ok += 0 if code else 1
    return ok, len(files), None


ICON = {"passed": "✅", "failed": "❌", "skipped": "⏭️", "error": "⚠️", "report": "ℹ️"}
CTRL_ICON = {"evidenced": "✅", "gap": "❌", "unverified": "⚠️", "not assessed": "➖"}


def compliance_status(stages, mapping=None, frameworks=None):
    """Per control: gap (a mapped gate failed), unverified (a mapped scanner errored), evidenced
    (mapped stages ran clean), not assessed (none of its stages ran). frameworks limits the set."""
    if mapping is None:
        mapping = load_yaml_file(HERE / "defaults" / "compliance.yml") or {}
    if frameworks:
        mapping = dict(mapping, controls=[c for c in mapping.get("controls", []) if c["framework"] in frameworks])
    by_stage = {}
    for s in stages:
        by_stage.setdefault(s["stage"], []).append("failed" if s.get("pr_preexisting") else s["status"])
    out = []
    for c in mapping.get("controls", []):
        sts = [st for stage in c["stages"] for st in by_stage.get(stage, [])]
        ran = [st for st in sts if st != "skipped"]
        status = ("gap" if "failed" in ran else "unverified" if "error" in ran
                  else "evidenced" if ran else "not assessed")
        out.append({"framework": mapping.get("frameworks", {}).get(c["framework"], c["framework"]), "key": c["framework"],
                    "title_ar": c.get("title_ar", ""),
                    "id": c["id"], "title": c["title"], "stages": c["stages"], "status": status})
    return out


def load_yaml_file(path):
    try:
        return yaml.safe_load(Path(path).read_text()) if yaml else None
    except (OSError, ValueError):
        return None


def findings_summary(reports, base_fps=None):
    """Consolidate findings.json (duplicates across tools merged) and mark what is new versus base_fps."""
    raw = load_json(Path(reports) / "findings.json") or []
    merged = F.consolidate(raw)
    if base_fps is not None:
        for f in merged:
            f["new"] = f["fingerprint"] not in base_fps
    (Path(reports) / "findings-consolidated.json").write_text(json.dumps(merged, indent=1))
    return {"raw": len(raw), "unique": len(merged), "duplicates_merged": len(raw) - len(merged),
            "blocking": sum(1 for f in merged if f.get("gating")),
            "kev": sum(1 for f in merged if f.get("kev")),
            "baselined": sum(1 for f in merged if f.get("baselined")),
            "expired_exceptions": sum(1 for f in merged if f.get("exception_expired") and f.get("gating")),
            "new": sum(1 for f in merged if f.get("new")) if base_fps is not None else None,
            "new_blocking": sum(1 for f in merged if f.get("new") and f.get("gating")) if base_fps is not None else None,
            "fixed": len(set(base_fps) - {f["fingerprint"] for f in merged}) if base_fps is not None else None,
            }, merged


def _f_row(f):
    pkgs = f.get("_pkgs") or []
    where = (", ".join(pkgs[:3]) + (f" +{len(pkgs) - 3} more" if len(pkgs) > 3 else "") if pkgs else
             f.get("package") and f"{f['package']} {f['version']}".strip() or f.get("location") or "")
    risk = " · ".join(x for x in ["🔥 KEV" if f.get("kev") else "",
                                  f"EPSS {f['epss']:.2f}" if f.get("epss") else "",
                                  f"fix: {f['fixed_version']}" if f.get("fixed_version") else ""] if x)
    tag = "🆕 " if f.get("new") else ""
    # name what was found, not only its ID (ZAP plugin IDs and threat IDs mean nothing on their own)
    title = re.sub(r"\s*\((GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) .*$", "", str(f.get("title") or ""))
    what = f"`{f['id']}`" + (f" {title[:80]}" if f.get("kind") != "vuln" and title and title != f["id"] else "")
    tools = dict.fromkeys(t.split(" (")[0] if t.startswith(("Trivy image (", "Grype (")) else t
                          for t in f.get("tools", [f.get("tool", "")]))
    return (f"| {tag}{f['severity']} | {what.replace('|', '/')} | {str(where).replace('|', '/')[:110]} | "
            f"{', '.join(tools)} | {risk} |")


EVIDENCE_FILES = {
    "threat-model": ["raw/**/threats.json", "raw/**/threagile/risks.json", "threat-model.json",
                     "threatmodel/*.svg", "raw/**/threat-decisions.json"],
    "secrets": ["sarif/*gitleaks*.sarif", "raw/**/trufflehog*.jsonl"],
    "sast": ["sarif/*semgrep*.sarif"],
    "sca": ["sarif/*trivy-sca*.sarif", "sarif/*osv*.sarif", "raw/**/sbom-source.cdx.json"],
    "licences": ["raw/**/trivy-sca.json"],
    "iac": ["sarif/*trivy-iac*.sarif", "sarif/*checkov*.sarif", "sarif/*hadolint*.sarif"],
    "kubernetes": ["sarif/*kube-linter*.sarif", "logs/**/kubeconform*.log"],
    "cicd": ["sarif/*zizmor*.sarif", "logs/**/actionlint*.log"],
    "container": ["sarif/*trivy-image*.sarif", "sarif/*grype*.sarif", "raw/**/sbom-img*.cdx.json", "raw/**/dockle-*.json"],
    "dast": ["zap*.json", "sarif/*nuclei*.sarif", "raw/**/nuclei.jsonl"],
    "iast": ["logs/**/iast*.log"],
    "runtime": ["waf-results.txt"],
    "policy": ["raw/**/baseline.json"],
}
COMMON_EVIDENCE = ["summary.json", "findings.json", "findings-consolidated.json", "tools.json", "junit.xml"]


def _sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_evidence(reports, summary, comp):
    """evidence/index.json: for every control, its status and the exact artifacts (with SHA-256) that
    show it — what an auditor asks for. The PDF's evidence appendix is drawn from this file."""
    reports = Path(reports)
    ev = reports / "evidence"
    ev.mkdir(exist_ok=True)
    cache = {}

    def files(stage):
        out = []
        for pat in EVIDENCE_FILES.get(stage, []):
            for p in sorted(reports.glob(pat)):
                if p.is_file():
                    rel = str(p.relative_to(reports))
                    cache.setdefault(rel, _sha256(p))
                    out.append({"path": rel, "sha256": cache[rel]})
        return out
    run = {k: os.environ.get(k, "") for k in ("REPO", "SHA", "REF", "RUN_URL")}
    controls = []
    for c in comp:
        arts = [a for st in c["stages"] for a in files(st)]
        controls.append({**c, "artifacts": list({a["path"]: a for a in arts}.values())})
    common = []
    for n in COMMON_EVIDENCE:
        p = reports / n
        if p.is_file():
            common.append({"path": n, "sha256": _sha256(p)})
    index = {"generated": dt.datetime.now(dt.timezone.utc).isoformat(), "run": run,
             "repository": summary.get("repository"), "tools": summary.get("tools"),
             "verdict": "passed" if summary.get("passed") else "failed", "common": common, "controls": controls,
             "note": "Evidence map, not a compliance attestation: controls also need process and governance evidence."}
    (ev / "index.json").write_text(json.dumps(index, indent=1))
    return index


def write_manifest(reports):
    """evidence/manifest.sha256 over every file in the report set (sha256sum -c format), so the
    whole package can be verified — and signed by sawone-release.yml on trusted pushes."""
    reports = Path(reports)
    lines = []
    for p in sorted(reports.rglob("*")):
        rel = str(p.relative_to(reports))
        if p.is_file() and not rel.startswith("evidence/manifest") and not rel.endswith(".tar"):
            lines.append(f"{_sha256(p)}  {rel}")
    (reports / "evidence").mkdir(exist_ok=True)
    (reports / "evidence" / "manifest.sha256").write_text("\n".join(lines) + "\n")


def threat_analysis(reports, merged):
    """STRIDE, scanner evidence and decisions for the pytm model of this run (threat-model.json, diagrams)."""
    reports = Path(reports)
    files = sorted(reports.glob("raw/**/threats.json"))
    model = load_json(files[0]) if files else None
    if not model or not model.get("findings"):
        return None
    dfiles = sorted(reports.glob("raw/**/threat-decisions.json"))
    dec = (load_json(dfiles[0]) if dfiles else None) or {}
    try:
        return TMA.build(reports, model, merged, dec.get("active") or [], dec.get("expired") or [],
                         dec.get("errors") or [], dec.get("mitigated") or {}, dec.get("min_severity") or "Very High")
    except Exception as e:      # the analysis must never cost the run its report
        log(f"threat-model analysis failed: {e}")
        return None


def regate_contradicted(tm, stages, raw, reports):
    """A mitigation recorded for a threat the scanners still prove is not a mitigation: the gate job could
    not know (it runs before the other scanners), so the threat blocks again here, once the evidence is in."""
    bad = [x for x in tm["threats"] if x["status"] == "contradicted" and x["gating"]]
    if not bad:
        return
    keys = {(x["sid"], x["target"]) for x in bad}
    for f in raw:
        if f.get("stage") == "threat-model" and (f.get("id"), (f.get("title") or "").rsplit(" — ", 1)[-1]) in keys:
            f["gating"] = True
    (Path(reports) / "findings.json").write_text(json.dumps(raw, indent=1))
    for s in stages:
        if s["stage"] == "threat-model" and s.get("tool") == "OWASP pytm" and s["status"] in ("passed", "failed"):
            s["status"] = "failed"
            s["findings"] = (s.get("findings") or "") + f" · {len(bad)} mitigation(s) contradicted by scanner evidence"


def render_outputs(reports, summary):
    """Write summary.json/.md, junit.xml and the PDF for a finished (or merged) scan.
    Exit code: 0 = all gates passed or report-only mode, 1 = a gate failed, 2 = scanner error."""
    reports = Path(reports)
    stages = summary["stages"]
    enforce = summary.get("enforce", True)
    tm = None
    if not summary.get("only"):   # the threat model needs every scanner's evidence: whole runs only
        raw = load_json(reports / "findings.json") or []
        tm = threat_analysis(reports, F.consolidate([dict(f) for f in raw]))
        if tm:
            regate_contradicted(tm, stages, raw, reports)
    failed = [s for s in stages if s["status"] == "failed" and s.get("gate", True)]
    errors = [s for s in stages if s["status"] == "error"]
    summary["passed"] = not failed and not errors
    summary["counts"] = {k: sum(1 for s in stages if s["status"] == k) for k in ICON}
    (reports / "summary.json").write_text(json.dumps(summary, indent=2))
    inv = summary.get("inventory") or {}
    result = ("✅ all gates passed" if summary["passed"] else
              "❌ " + ", ".join(x for x in [f"{len(failed)} gate(s) failed" if failed else "",
                                            f"{len(errors)} scanner error(s)" if errors else ""] if x))
    md = ["## Sawone scan", "", f"**Result:** {result}" + ("" if enforce else " _(report-only mode)_"), ""]
    if inv:
        iac = [k for k in ["dockerfiles", "terraform", "kubernetes", "helm_charts", "cloudformation", "bicep_arm", "compose"] if inv.get(k)]
        md += [f"**Detected:** languages: {', '.join(inv.get('languages') or {}) or '—'} · "
               f"frameworks: {', '.join(inv.get('frameworks') or []) or '—'} · IaC: {', '.join(iac) or '—'} · "
               f"CI: {', '.join(inv.get('ci') or []) or '—'}", ""]
    rel = summary.get("release")
    if rel:
        md += ["**Release:** " + " · ".join(f"{k}: {v}" for k, v in rel.items()), ""]
    md += ["| Stage | Tool | Result | Details |", "|---|---|---|---|"]
    for s in stages:
        md.append(f"| {s['stage']} | {s['tool']} | {ICON.get(s['status'], s['status'])} {s['status']} | "
                  f"{(s.get('findings') or s.get('reason') or '').replace('|', '/')} |")
    opts = summary.get("options") or {}
    fs, merged = findings_summary(reports, set(summary["pr"]["base_fingerprints"])
                                  if (summary.get("pr") or {}).get("base_fingerprints") is not None else None)
    if not summary.get("only"):   # first seen, trend and SLA: for a whole run, not a single gate job
        prev = load_json(summary["previous_findings"]) if summary.get("previous_findings") else None
        summary["trend"] = F.apply_history(merged, prev if isinstance(prev, list) else None, sla=opts.get("sla"))
        fs["overdue"] = summary["trend"]["overdue"]
        (reports / "findings-consolidated.json").write_text(json.dumps(merged, indent=1))
    summary["findings"] = fs
    if not summary.get("only"):
        if tm:
            summary["threat_model"] = {k: tm[k] for k in ("counts", "total", "gating", "by_stride")}
            summary["threat_model"]["gaps"] = [g["title"] for g in tm["gaps"]]
            c = tm["counts"]
            md += ["", f"**Threat model:** {tm['total']} threats · 🔴 {c['confirmed']} confirmed exploitable · "
                       f"🟠 {c['in-code']} found in code · {c['theoretical']} theoretical · "
                       f"✅ {c['mitigated'] + c['accepted'] + c['transferred']} decided"
                       + (f" · ⚠️ {c['contradicted']} mitigation(s) contradicted by evidence" if c["contradicted"] else "")
                       + (f" · model gaps: {', '.join(g['title'] for g in tm['gaps'])}" if tm["gaps"] else "")]
    if fs["unique"]:
        line = (f"**Findings:** {fs['unique']} unique ({fs['duplicates_merged']} duplicates across tools merged) · "
                f"{fs['blocking']} blocking · {fs['kev']} known-exploited (KEV) · {fs['baselined']} accepted in baseline")
        if fs["new"] is not None:
            line += f" · **{fs['new']} new in this PR ({fs['new_blocking']} blocking)** · {fs['fixed']} fixed"
        md += ["", line]
        rows, by_cve = [], {}
        for f in (f for f in merged if f.get("gating")):
            if f.get("kind") == "vuln":
                g = by_cve.get((f["id"], f.get("fixed_version"))) if f.get("fixed_version") else None
                if g is not None:
                    pv = f"{f['package']} {f['version']}".strip()
                    if pv not in g["_pkgs"]:
                        g["_pkgs"].append(pv)
                    continue
                f = dict(f, _pkgs=[f"{f['package']} {f['version']}".strip()])
                by_cve[(f["id"], f.get("fixed_version"))] = f
            rows.append(f)
        top = rows[:25]
        if top:
            md += ["", "### Blocking findings" + (f" (top {len(top)} of {fs['blocking']})" if fs["blocking"] > len(top) else ""),
                   "", "| Severity | ID | Where | Found by | Risk |", "|---|---|---|---|---|"] + [_f_row(f) for f in top]
    pr = summary.get("pr") or {}
    if pr.get("note"):
        md += ["", f"_{pr['note']}_"]
    comp = compliance_status(stages, frameworks=opts.get("frameworks"))
    summary["compliance"] = comp
    if comp and not summary.get("only"):   # a single gate job sees only its own stages: no partial compliance
        counts = {k: sum(1 for c in comp if c["status"] == k) for k in CTRL_ICON}
        md += ["", "<details><summary><b>Compliance evidence</b> — "
               + " · ".join(f"{CTRL_ICON[k]} {v} {k}" for k, v in counts.items() if v) + "</summary>", "",
               "| Framework | Control | Status | From stages |", "|---|---|---|---|"]
        md += [f"| {c['framework']} | **{c['id']}** {c['title']} | {CTRL_ICON[c['status']]} {c['status']} | "
               f"{', '.join(c['stages'])} |" for c in comp]
        md += ["", "_Evidence map, not a compliance attestation._", "</details>"]
    tr = summary.get("trend") or {}
    if tr.get("previous"):
        md += ["", f"**Trend:** {tr['new']} new · {tr['fixed']} fixed since the last scan · {tr['open']} blocking open"
                   + (f" · ⏰ **{tr['overdue']} past their fix deadline**" if tr.get("overdue") else "")]
    md += ["", "📄 Full PDF report: `security-report.pdf`"
           + (" (Arabic: `security-report-ar.pdf`)" if "ar" in (opts.get("languages") or []) else "")
           + " · audit evidence: `evidence/`, in the scan artifacts."]
    (reports / "summary.md").write_text("\n".join(md) + "\n")
    (reports / "summary.json").write_text(json.dumps(summary, indent=2))
    cases = []
    for s in stages:
        name = sx.quoteattr(f"{s['stage']} · {s['tool']}")
        body = ""
        if s["status"] == "failed" and s.get("gate", True):
            body = f"<failure message={sx.quoteattr(s.get('findings') or 'gate failed')}/>"
        elif s["status"] == "error":
            body = f"<error message={sx.quoteattr(s.get('reason') or 'scanner error')}/>"
        elif s["status"] == "skipped":
            body = f"<skipped message={sx.quoteattr(s.get('reason') or '')}/>"
        cases.append(f'  <testcase classname="sawone" name={name}>{body}</testcase>')
    (reports / "junit.xml").write_text(
        f'<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="sawone" tests="{len(cases)}" '
        f'failures="{len(failed)}" errors="{len(errors)}">\n' + "\n".join(cases) + "\n</testsuite>\n")
    (reports / "logs").mkdir(exist_ok=True)
    if not summary.get("only"):
        # a single gate job's part is merged later; only a whole run gets the PDF and the evidence pack
        build_evidence(reports, summary, comp)
        env = dict(os.environ)
        env.setdefault("REPO", summary.get("repository") or "")
        logs = []
        for lang in [x for x in (opts.get("languages") or ["en"]) if x in ("en", "ar")] or ["en"]:
            suffix = "" if lang == "en" else f"-{lang}"
            p = subprocess.run([sys.executable, str(HERE / "report.py"), "--reports", str(reports), "--lang", lang,
                                "--out", str(reports / f"security-report{suffix}.pdf"),
                                "--html", str(reports / f"security-report{suffix}.html")],
                               capture_output=True, text=True, env=env)
            logs.append(f"[{lang}]\n{p.stdout}{p.stderr}\n[exit code: {p.returncode}]\n")
            if p.returncode:
                log(f"WARNING: PDF report ({lang}) failed (see logs/report.log); the gate results above still stand.")
        (reports / "logs" / "report.log").write_text("\n".join(logs))
        write_manifest(reports)
    print((reports / "summary.md").read_text())
    if errors and enforce:
        return 2
    if failed and enforce:
        return 1
    return 0


def resolve_lock(out_path):
    """Resolve every scanner image to an immutable digest and every pip tool to an exact version,
    without pulling (registry metadata only). Exit 2 if anything cannot be resolved."""
    import urllib.request
    lock, failures = {"resolved": dt.datetime.now(dt.timezone.utc).isoformat(), "images": {}, "pip": {}}, []
    for tool, ref in sorted(IMAGES.items()):
        p = subprocess.run(["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest}}"],
                           capture_output=True, text=True, timeout=180)
        try:
            digest = json.loads(p.stdout).get("digest") if p.returncode == 0 else None
        except ValueError:
            digest = None
        if not digest or not digest.startswith("sha256:"):
            failures.append(f"{tool} ({ref}): {(p.stderr or 'no digest returned').strip()[:200]}")
            continue
        lock["images"][tool] = f"{ref.rsplit(':', 1)[0]}@{digest}"
    for pkg in PIP_TOOLS:
        try:
            with urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/json", timeout=30) as r:
                lock["pip"][pkg] = json.load(r)["info"]["version"]
        except Exception as e:  # noqa: BLE001 — reported below
            failures.append(f"{pkg} (PyPI): {e}")
    if failures:
        print("ERROR: could not resolve:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 2
    Path(out_path).write_text(json.dumps(lock, indent=2) + "\n")
    print(f"resolved {len(lock['images'])} images and {len(lock['pip'])} pip tools → {out_path}")
    return 0


def load_lock(value, ws):
    """SCAN_TOOLS_LOCK: a path (relative to the workspace or absolute) or 'bundled'."""
    if not value:
        return None
    path = HERE / "defaults" / "tools.lock.json" if value == "bundled" else Path(value)
    if not path.is_absolute():
        path = ws / path
    data = load_json(path)
    if not data or "images" not in data:
        sys.exit(f"ERROR: tool lock {path} is missing or invalid"
                 + (" — this scanner image has no bundled lock; use the latest policy" if value == "bundled" else ""))
    return data


def main():
    ap = argparse.ArgumentParser(description="Sawone scanner")
    ap.add_argument("--path", default=os.environ.get("SCAN_PATH", "."))
    ap.add_argument("--config", default=os.environ.get("SCAN_CONFIG", ".sawone.yml"))
    ap.add_argument("--reports", default=os.environ.get("SCAN_REPORTS", "sawone-reports"))
    ap.add_argument("--plan-only", action="store_true")
    ap.add_argument("--resolve-tools", metavar="LOCK_FILE", help="write a tool lock file and exit")
    ap.add_argument("--fetch-intel", metavar="DIR", help="download the CISA KEV and EPSS feeds into DIR and exit")
    ap.add_argument("--write-baseline", metavar="REPORTS_DIR",
                    help="write a baseline accepting every blocking finding in REPORTS_DIR/findings.json and exit")
    ap.add_argument("--owner", default=os.environ.get("USER", ""), help="owner recorded in a written baseline")
    ap.add_argument("--days", type=int, default=90, help="expiry (days from today) for a written baseline")
    ap.add_argument("--output", default=".sawone-baseline.yml", help="file written by --write-baseline")
    ap.add_argument("--import-defectdojo", metavar="REPORTS_DIR",
                    help="import an existing reports directory into DefectDojo and exit")
    a = ap.parse_args()
    if a.resolve_tools:
        sys.exit(resolve_lock(a.resolve_tools))
    if a.fetch_intel:
        errs = F.fetch_intel(a.fetch_intel)
        intel = F.Intel.load(a.fetch_intel)
        print(f"KEV: {len(intel.kev or {})} CVEs · EPSS: {len(intel.epss or {})} scores"
              + (" — " + "; ".join(errs) if errs else ""))
        sys.exit(2 if errs else 0)
    if a.write_baseline:
        if not a.owner.strip():
            sys.exit("ERROR: --owner is required (who is accountable for the accepted findings)")
        found = load_json(Path(a.write_baseline) / "findings.json")
        if found is None:
            sys.exit(f"ERROR: {a.write_baseline}/findings.json not found — run a scan first")
        n = F.write_baseline(found, a.output, a.owner, a.days)
        print(f"wrote {n} exception(s) to {a.output}, expiring in {a.days} days — review each before committing")
        sys.exit(0)
    if a.import_defectdojo:
        url, tok = os.environ.get("DEFECTDOJO_URL", ""), os.environ.get("DEFECTDOJO_TOKEN", "")
        if not (url and tok):
            sys.exit("ERROR: DEFECTDOJO_URL and DEFECTDOJO_TOKEN are required")
        if not re.match(r"^https://[^\s/]+", url):
            sys.exit("ERROR: DEFECTDOJO_URL must be https://")

        def runner(cmd, log_name=None, quiet=True, **_):
            p = subprocess.run(cmd, capture_output=True, text=True)
            return p.returncode, p.stdout + p.stderr
        ok, total, err = import_reports(a.import_defectdojo, url, tok, os.environ.get("DEFECTDOJO_PRODUCT", "devsecops"),
                                        os.environ.get("DEFECTDOJO_ENGAGEMENT", "sawone-scan"), runner)
        print(f"DefectDojo: {ok}/{total} reports imported" + (f" — {err}" if err else ""))
        sys.exit(2 if err or ok < total else 0)
    ws = Path(a.path).resolve()
    if not ws.is_dir():
        sys.exit(f"ERROR: scan path {ws} does not exist")
    cfg_file = ws / a.config
    if not cfg_file.exists() and a.config == ".sawone.yml":
        # earlier names of this project's config are still accepted
        cfg_file = next((ws / n for n in (".sawanb.yml", ".devsecops.yml") if (ws / n).exists()), cfg_file)
    user_cfg = {}
    if cfg_file.exists():
        if yaml is None:
            sys.exit("PyYAML is required to read " + str(cfg_file))
        user_cfg = yaml.safe_load(cfg_file.read_text()) or {}
    env = os.environ
    if env.get("SCAN_SEVERITY"):
        user_cfg["severity"] = env["SCAN_SEVERITY"]
    if env.get("SCAN_ENFORCE"):
        user_cfg["enforce"] = env["SCAN_ENFORCE"].lower() not in ("false", "0", "no")
    if env.get("SCAN_DAST"):
        user_cfg.setdefault("dast", {})["enabled"] = {"false": False, "true": True}.get(env["SCAN_DAST"].lower(), "auto")
    if env.get("SCAN_SKIP"):
        user_cfg["skip"] = [x.strip() for x in env["SCAN_SKIP"].split(",") if x.strip()]
    if env.get("SCAN_ONLY"):
        only = [x.strip() for x in env["SCAN_ONLY"].split(",") if x.strip()]
        bad = [x for x in only if x not in STAGES]
        if bad:
            sys.exit(f"ERROR: unknown stage(s) in SCAN_ONLY: {', '.join(bad)} (valid: {', '.join(STAGES)})")
        user_cfg["only"] = only
    if env.get("SCAN_IMAGE"):
        user_cfg["image"] = env["SCAN_IMAGE"]
    if env.get("SCAN_APP_PORT"):
        if not env["SCAN_APP_PORT"].isdigit() or not 0 < int(env["SCAN_APP_PORT"]) < 65536:
            sys.exit(f"ERROR: SCAN_APP_PORT must be a TCP port number, got {env['SCAN_APP_PORT']!r}")
        user_cfg.setdefault("dast", {})["port"] = int(env["SCAN_APP_PORT"])
    if env.get("SCAN_HEALTH_PATH"):
        if not env["SCAN_HEALTH_PATH"].startswith("/"):
            sys.exit("ERROR: SCAN_HEALTH_PATH must start with /")
        user_cfg.setdefault("dast", {})["health_path"] = env["SCAN_HEALTH_PATH"]
    if env.get("SCAN_BASE_SHA"):
        user_cfg["base_sha"] = env["SCAN_BASE_SHA"]
    if env.get("SCAN_REPORT_LANGUAGES"):
        user_cfg.setdefault("report", {})["languages"] = [x.strip() for x in env["SCAN_REPORT_LANGUAGES"].split(",")
                                                          if x.strip() in ("en", "ar")] or ["en"]
    if env.get("SCAN_AJAX_SPIDER"):
        user_cfg.setdefault("dast", {})["ajax_spider"] = env["SCAN_AJAX_SPIDER"].lower() in ("true", "1", "yes")
    if env.get("SCAN_DAST_FULL"):
        user_cfg.setdefault("dast", {})["full_scan"] = env["SCAN_DAST_FULL"].lower() not in ("false", "0", "no")
    if env.get("SCAN_BLOCK_KEV"):
        user_cfg.setdefault("policy", {})["block_kev"] = env["SCAN_BLOCK_KEV"].lower() not in ("false", "0", "no")
    if env.get("SCAN_EPSS_THRESHOLD"):
        try:
            thr = float(env["SCAN_EPSS_THRESHOLD"])
        except ValueError:
            thr = -1
        if not 0 <= thr <= 1:
            sys.exit(f"ERROR: SCAN_EPSS_THRESHOLD must be between 0 and 1, got {env['SCAN_EPSS_THRESHOLD']!r}")
        user_cfg.setdefault("policy", {})["epss_threshold"] = thr
    if env.get("SCAN_BASELINE"):
        user_cfg.setdefault("baseline", {})["file"] = env["SCAN_BASELINE"]
    if env.get("SCAN_STARTUP_TIMEOUT"):
        user_cfg.setdefault("dast", {})["startup_timeout"] = int(env["SCAN_STARTUP_TIMEOUT"])
    cfg = deep_merge(DEFAULTS, user_cfg)
    sev = [x.strip().upper() for x in str(cfg["severity"]).split(",") if x.strip()]
    if not sev or any(x not in SEV_ORDER for x in sev):
        sys.exit(f"ERROR: severity must be a comma list of {', '.join(SEV_ORDER)}, got {cfg['severity']!r}")
    cfg["tools_lock"] = load_lock(env.get("SCAN_TOOLS_LOCK"), ws)
    cfg["cache_dir"] = env.get("SCAN_CACHE_DIR") or None
    reports = (ws / a.reports).resolve()
    if reports.exists():
        shutil.rmtree(reports)
    reports.mkdir(parents=True)
    sys.exit(Scan(ws, reports, cfg, plan_only=a.plan_only).main())


if __name__ == "__main__":
    main()
