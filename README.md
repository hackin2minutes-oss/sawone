# Sawone

**DevSecOps scanning for any repository, by phase.** Sawone detects what your repository contains (language,
framework, dependencies, IaC, Kubernetes, CI, Dockerfile), runs the open-source scanners that apply, ranks
findings by real-world exploitation (CISA KEV, EPSS) and gives one pass/fail decision with a PDF report in
English and Arabic, SARIF for code scanning and JUnit results.

## Quick start

Save as `.github/workflows/sawone.yml`:

```yaml
name: sawone
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write   # findings in Security → Code scanning
  actions: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hackin2minutes-oss/sawone@v1
        with:
          enforce: "false"   # report only on the first run; remove to block on findings
```

Push it. The results appear in the run summary, in **Security → Code scanning**, and as the `sawone-reports`
artifact (`security-report.pdf`, `security-report-ar.pdf`, `findings.json`, `junit.xml`).

## What it checks

| Phase | Checks | Tools |
|---|---|---|
| **Plan** | threat model as code: data-flow diagram, STRIDE, threats checked against scanner evidence | OWASP pytm, Threagile |
| **Code** | secrets in code and Git history; code flaws for 25+ languages | Gitleaks, TruffleHog, Semgrep |
| **Build** | vulnerable and badly licensed dependencies; IaC, Kubernetes and CI/CD misconfiguration | Trivy, OSV-Scanner, Syft, Checkov, Hadolint, kubeconform, kube-linter, actionlint, zizmor |
| **Test** | the built image's CVEs; attacks on the running app (when the Dockerfile `EXPOSE`s a port) | Trivy, Grype, Dockle, OWASP ZAP, Nuclei |
| **Release** | risk policy: KEV and EPSS escalation, accepted-risk baseline, new-findings-only for pull requests | |
| **Operate** | does a WAF (ModSecurity + OWASP CRS) block attacks on this app | |

Nothing to configure: Sawone only runs what applies to your repository. The report maps results to OWASP ASVS,
NIST SSDF, NCA ECC / CSCC / CCC, SAMA CSF and the Saudi PDPL.

## Options

| Input | Default | |
|---|---|---|
| `enforce` | blocks | `"false"`: report only, never fail the job |
| `phases` | `all` | e.g. `plan,code,build` for a fast pull-request check |
| `severity` | `HIGH,CRITICAL` | severities that fail a gate |
| `dast` | `auto` | `"false"` to skip attacks on the running app |
| `skip` | | tools to skip, e.g. `nuclei,checkov` |
| `path` | `.` | folder to scan (monorepos) |
| `baseline-file` | `.sawone-baseline.yml` | accepted risks, each with an owner and expiry |
| `block-kev` | `true` | CVEs in CISA's KEV catalogue block at any severity |
| `epss-threshold` | `0` (off) | e.g. `"0.5"` also blocks likely-to-be-exploited CVEs |
| `upload-sarif` | `auto` | code scanning upload (public repositories) |
| `artifact-name` | `sawone-reports` | name of the reports artifact |

Outputs: `passed` (`true`/`false`) and `reports` (folder with the reports).

## Full pipeline (reusable workflow)

For parallel jobs per phase, a pull-request comment with new and fixed findings, and app settings for DAST:

```yaml
jobs:
  scan:
    permissions: { contents: read, actions: read, security-events: write }
    uses: hackin2minutes-oss/sawone/.github/workflows/sawone-scan.yml@v1
    with:
      enforce: false
      app-port: 8080          # optional: the port your app listens on
      health-path: /health    # optional
```

All inputs, the PR comment, release, monitoring and dashboard workflows, GitLab CI, Azure DevOps and Jenkins:
see the [reference](docs/reference.md).

## Versions

| You write | You get |
|---|---|
| `@v1` | the latest 1.x release, automatically |
| `@v1.3.4` | exactly that release; releases are immutable and can never change |
| `@<commit SHA>` | the strictest pin, independent of any tag |

## Learn more

- [Reference](docs/reference.md): risk policy, adopting on an existing repository, threat model, compliance
  evidence, gates, inputs, authenticated DAST, other CI systems, results, limitations
- [Changelog](CHANGELOG.md) · [Security policy](SECURITY.md) · [Developing and releasing](docs/development.md)

Requires a Linux runner with Docker (GitHub-hosted runners have it). Licensed MIT.
