"""The DevSecOps lifecycle: eight phases, and which Sawone stage belongs to which.

  plan     threat modelling                         code     secrets, SAST
  build    dependencies, licences, IaC, Kubernetes, CI/CD
  test     container image, DAST, IAST              release  risk policy, gate, signing, provenance
  deploy   verified, approved deploy                operate  runtime protection (WAF)
  monitor  rescans of running images, vulnerability tracking

release, deploy and monitor are mostly done by sawone-release.yml and sawone-monitor.yml; the scan
reports what it can see of them (the risk policy, the release record, DefectDojo).
"""
PHASES = ["plan", "code", "build", "test", "release", "deploy", "operate", "monitor"]

TITLES = {"plan": "Plan", "code": "Code", "build": "Build", "test": "Test", "release": "Release",
          "deploy": "Deploy", "operate": "Operate", "monitor": "Monitor"}

INTROS = {
    "plan": "Design-time security: the threat model and the risk decisions taken on it.",
    "code": "The source code and its history: secrets and code-level flaws, found before anything is built.",
    "build": "What the build pulls in and produces: dependencies and their licences, infrastructure as code, "
             "Kubernetes manifests and the CI/CD pipeline itself.",
    "test": "The built artefact under test: the container image, and the running application attacked from outside.",
    "release": "The release decision: risk policy (known-exploited and likely-exploited vulnerabilities, accepted "
               "risks) and, in sawone-release.yml, signing, SBOM attestation and provenance.",
    "deploy": "Deployment only after every gate passed, the signature and attestation verify and a human approved "
              "(sawone-release.yml).",
    "operate": "Protection in production: a web application firewall proven to block attacks on this application.",
    "monitor": "After release: vulnerability tracking, and daily rescans of the images actually running "
               "(sawone-monitor.yml).",
}

STAGE_PHASE = {
    "threat-model": "plan",
    "secrets": "code", "sast": "code",
    "sca": "build", "licences": "build", "iac": "build", "kubernetes": "build", "cicd": "build",
    "container": "test", "dast": "test", "iast": "test",
    "policy": "release",
    "runtime": "operate",
    "tracking": "monitor",
}

# which workflow covers a phase the scan itself cannot
ELSEWHERE = {"release": "sawone-release.yml (signing, SBOM attestation, SLSA provenance)",
             "deploy": "sawone-release.yml (verified, approved deploy)",
             "monitor": "sawone-monitor.yml (daily rescan of running images)"}


def phase_of(stage):
    return STAGE_PHASE.get(stage, "release" if stage in ("scanner", "pr") else "build")


def parse(value):
    """'plan,code' or a list -> ordered phase list; raises ValueError on an unknown phase. Empty = all."""
    if not value:
        return list(PHASES)
    items = value if isinstance(value, (list, tuple)) else str(value).split(",")
    items = [str(x).strip().lower() for x in items if str(x).strip()]
    if not items or items == ["all"]:
        return list(PHASES)
    bad = [x for x in items if x not in PHASES]
    if bad:
        raise ValueError(f"unknown phase(s): {', '.join(bad)} (valid: {', '.join(PHASES)})")
    return [p for p in PHASES if p in items]


def stages_for(phases):
    return [s for s, p in STAGE_PHASE.items() if p in phases]


def status(stages, selected=None, run_failed=None, run_error=None):
    """Result of each phase for one run: failed / error / passed / report / skipped, or 'notsel' (the phase
    was not selected) or 'elsewhere' (done by sawone-release.yml / sawone-monitor.yml, not by the scan).
    Release is the gate decision itself: it fails when any gate fails, so it reflects the whole run."""
    selected = selected or PHASES
    rows = [r for r in stages if r.get("stage") in STAGE_PHASE]
    out = {}
    for ph in PHASES:
        mine = [r for r in rows if STAGE_PHASE[r["stage"]] == ph]
        if ph not in selected and ph not in ("release", "deploy", "monitor"):
            out[ph] = "notsel"
            continue
        if ph == "release":
            failed = run_failed if run_failed is not None else any(
                r["status"] == "failed" and r.get("gate", True) for r in stages)
            err = run_error if run_error is not None else any(r["status"] == "error" for r in stages)
            out[ph] = "error" if err else "failed" if failed else "passed"
            continue
        ran = [r for r in mine if r["status"] != "skipped"]
        if not ran:
            out[ph] = "elsewhere" if ph in ELSEWHERE else "skipped"
        elif any(r["status"] == "error" for r in ran):
            out[ph] = "error"
        elif any(r["status"] == "failed" and r.get("gate", True) for r in ran):
            out[ph] = "failed"
        elif any(r["status"] == "passed" for r in ran):
            out[ph] = "passed"
        else:
            out[ph] = "report"
    return out
