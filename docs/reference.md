# Sawone reference

Everything about how Sawone works and how to configure it. Start with the [README](../README.md) for the quick start.

## The DevSecOps lifecycle

Every stage belongs to one of the eight DevSecOps phases. Pipeline jobs are named by phase (`Code · secrets`,
`Build · sca`, `Test · dast`), the report opens with a lifecycle overview (one box per phase with its result),
groups its detailed results by phase, and the job summary / PR comment start with
`DevSecOps lifecycle: ✅ Plan → ❌ Code → …`. Scan only some phases with `phases:` (input, `SCAN_PHASES`,
`SAWONE_PHASES` on GitLab, `phases` parameter on Azure DevOps, or `phases:` in `.sawone.yml`), for example
`phases: plan,code,build` for a fast pull-request check that does not build the image. Stages of phases
that were not selected are listed as "not selected", never as passed.

| Phase | What Sawone does | Where |
|---|---|---|
| **Plan** | threat model as code (pytm / Threagile): data-flow diagram, STRIDE, threats checked against scanner evidence, risk decisions; compliance evidence map | `threat-model` gate, report |
| **Code** | secrets in code and history; SAST with rules per detected language/framework; CI/CD workflow security | Gitleaks, TruffleHog, Semgrep, actionlint, zizmor |
| **Build** | dependencies and licences; IaC and Kubernetes misconfiguration; image build, SBOM, image CVEs | Trivy, OSV-Scanner, Checkov, Hadolint, kubeconform, kube-linter, Conftest, Syft, Grype |
| **Test** | attacks the built image: ZAP baseline, active and API scans, Nuclei; optional DongTai IAST | `attack` jobs |
| **Release** | KEV/EPSS risk policy, baseline, PR delta, merged report; push of the exact scanned image, keyless signing, SBOM attestation, SLSA L3 provenance; DefectDojo | `report`, `sawone-release.yml` |
| **Deploy** | only after every gate passed, the signature and attestation verify, and a human approved | `sawone-release.yml` → `deploy` |
| **Operate** | proves ModSecurity + OWASP CRS blocks attacks against this app | `runtime` gate |
| **Monitor** | daily rescan of running image digests against new CVEs and KEV entries; issue + alert | `sawone-monitor.yml` |

## Workflows

| Workflow | Does | Caller grants |
|---|---|---|
| `sawone-scan.yml` | everything from Plan to the report | `contents: read`, `actions: read`, `security-events: write` |
| `sawone-pr-comment.yml` | one PR comment with the summary, new and fixed findings | `pull-requests: write` |
| `sawone-release.yml` | publish, sign, SBOM attestation, SLSA provenance, approved deploy (pushes to the release branch only) | `contents: read`, `actions: read`, `packages: write`, `id-token: write` |
| `sawone-monitor.yml` | scheduled rescan of running images, issue, alert | `contents: read`, `packages: read`, `issues: write` |
| `sawone-dashboard.yml` | portfolio dashboard across repositories, optional GitHub Pages | `contents: read`, `actions: read` (+ `pages: write`, `id-token: write` to publish) |

They are separate because GitHub checks a called workflow's job permissions **before** it
evaluates any `if:`. In one file, every caller would have to grant every permission.
`examples/` has a minimal, a full-lifecycle, a monitoring and a dashboard consumer.

### Scan job graph

```
validate ─► tools (scanner digest + signature, tool lock, KEV/EPSS feeds, warmed vulnerability DBs)
  ├─► gates  (parallel: threat-model · secrets · sast · sca · iac · kubernetes · cicd)
  └─► build  (image + container gate) ─► attack (parallel: dast · iast · runtime)
report (always: merge parts, de-duplicate, apply policy, compare with base branch, compliance, PDF, SARIF)
  └─► defectdojo (optional)
```

Every scan job is read-only (`contents: read`). Nothing is pushed, signed or deployed from a
pull request.

## Risk policy

Each finding is first judged by severity (e.g. a fixable HIGH/CRITICAL CVE blocks), then:

1. **Escalation.** A CVE in the CISA KEV catalogue blocks at any severity, fix or no fix
   (`block-kev`, default on). With `epss-threshold: "0.5"`, CVEs with at least a 50% EPSS
   exploit probability block too. Both feeds are fetched once per run; if KEV is unavailable
   while `block-kev` is on, that is a visible scanner error, never a silent downgrade.
2. **Baseline.** A blocking finding listed in `.sawone-baseline.yml` stops blocking until its
   expiry date. After that it blocks again on its own.
3. **Pull requests** (`pr-gate: new`, default). A gate whose blocking findings all exist in
   the base branch's last report passes, with a note. Only what the PR introduces blocks.
   This needs the scan to also run on pushes to the base branch (it reads that report).

Results show why each finding blocks: 🔥 KEV, EPSS score, fix version, 🆕 new in this PR.

## Adopting on an existing repository

An established repo usually starts with hundreds of findings. Accept them for a fixed period,
then pay them down:

```bash
# 1. run one scan (report-only), download its report artifact, then:
docker run --rm -v "$PWD:$PWD" -w "$PWD" ghcr.io/hackin2minutes-oss/sawone-scanner:1 \
  --write-baseline ./sawone-report --owner "your-name" --days 90
# 2. review .sawone-baseline.yml, give each entry a real reason, commit it
```

```yaml
# .sawone-baseline.yml
exceptions:
  - id: CVE-2024-1234            # CVE or rule ID; wildcards allowed (AVD-AWS-*)
    package: urllib3             # optional: only this package
    path: "src/legacy/*"         # optional: only these locations
    reason: No fix released; the vulnerable function is not reachable from our code
    owner: sawan
    expires: 2026-12-31          # required, at most 365 days ahead (baseline.max_days)
  - fingerprint: 3f9a…           # or exactly one finding, as written by --write-baseline
    reason: …
    owner: …
    expires: …
```

Missing owner, reason or expiry, or an expiry too far ahead, makes the baseline invalid. That
is a scanner error, so a typo can never silently hide (or un-hide) a finding. The report lists
every accepted risk with its owner and expiry, and every expired one.

## Threat model

Keep the model as code in `threatmodel/tm.py` ([OWASP pytm](https://github.com/OWASP/pytm)): actors, processes,
datastores, trust boundaries and ordered dataflows. On every run Sawone:

1. **runs it** and gates on threats at or above `threat_model.min_severity` (default Very High) without a decision;
2. **draws it**: a data-flow diagram (trust boundaries, unencrypted boundary crossings in red) and a sequence
   diagram of the flows, both in the PDF and as `threatmodel/*.svg`;
3. **classifies** every threat by STRIDE and shows an element × STRIDE matrix;
4. **checks it against the scanners**: each threat is matched to findings of the same attack class (CWE, ZAP
   alert, rule) on the same element. An attack on the running app (ZAP, Nuclei, WAF) or a live secret makes it
   **confirmed exploitable**; a SAST, IaC or secret finding makes it **found in code or config**; nothing makes
   it **theoretical**. Attack evidence only attaches to elements reachable from outside; code evidence only to
   files listed in the element's `sourceFiles` (when set). Third-party elements (an external site in the
   actors' boundary) never take your evidence;
5. **reports gaps**: kinds of weakness the scanners found that no threat in the model covers (for example SSRF
   on a user-supplied URL, or leaked credentials), so the model gets fixed too.

Record decisions in the baseline file, next to accepted findings:

```yaml
# .sawone-baseline.yml
threats:
  - threat: INP31             # pytm threat ID
    element: Flask app        # or * for every element
    decision: mitigate        # mitigate | accept | transfer
    control: ping runs subprocess with an argument list, no shell (PR #14)   # mitigate: the control
    owner: sawan
    expires: 2027-03-31
  - threat: DO01
    element: "*"
    decision: accept          # accept / transfer need a reason
    reason: internal app behind the corporate proxy, which rate-limits
    owner: sawan
    expires: 2027-01-31
```

A decided threat stops blocking until it expires. If the scanners still find the weakness behind a
*mitigate* decision, the report marks it **mitigation contradicted** and it keeps blocking. Invalid entries are
ignored (the threat stays open) and listed. `MITIGATED = {...}` in `tm.py` still works. Threagile models
(`threagile.yaml`) are gated on their open HIGH/CRITICAL risks.

## Compliance evidence

Every report includes an evidence map in the job summary, the PR comment and the PDF. For each
control, the status is:
- **evidenced**: the mapped checks ran and passed;
- **gap**: a mapped gate failed;
- **unverified**: a mapped scanner errored;
- **not assessed**: nothing applicable in this repository.

| Framework | Controls mapped |
|---|---|
| OWASP ASVS 4.0.3 | V1.1.2, V2.10.4, V5.3, V5.5, V14.1.1, V14.1.3, V14.2.1, V14.4 |
| NIST SSDF (SP 800-218) | PO.3.2, PW.1.1, PW.4.4, PW.5.1, PW.7.2, PW.8.2, PW.9.1, RV.1.1, RV.2.1 |
| NCA ECC-2:2024 | 1-6-1, 1-6-2-1, 1-6-2-2, 1-6-3-1, 1-6-3-2, 1-6-3-3, 1-6-3-5, 2-10, 2-15 |
| NCA CSCC-1:2019 | 1-3-2-1, 1-3-2-2, 1-3-2-3, 2-3-1-6, 2-3-1-7, 2-7-1-3, 2-9-1-1, 2-9-1-3, 2-12-1-2 |
| NCA CCC-2:2024 | tenant 2-9-T-1-1; provider 1-5-P-3-1, 2-3-P-1-1, 2-9-P-1-1, 2-14-P-1-1, 2-16-P-3-2 |
| SAMA CSF | 3.3.6 Application Security, 3.3.7 Change Management, 3.3.8 Infrastructure Security, 3.3.17 Vulnerability Management |
| Saudi PDPL | Art. 19 (technical measures protecting personal data) |

Choose frameworks with `compliance.frameworks` in `.sawone.yml` (keys `asvs ssdf ecc cscc ccc sama pdpl`).
Each control's Arabic title appears in the Arabic report.

### Evidence pack

Every full report writes `evidence/index.json` (run, verdict, and per control the report files that
evidence it, each with its SHA-256) and `evidence/manifest.sha256` covering every report file. On pushes
to the release branch `sawone-release.yml` signs the manifest keylessly and uploads
`<prefix>-evidence-signed`. An auditor verifies it with:

```bash
sha256sum -c evidence/manifest.sha256
cosign verify-blob evidence/manifest.sha256 --bundle evidence/manifest.sha256.sigstore.json \
  --certificate-identity-regexp '^https://github.com/<owner>/<repo>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

This is an **evidence map, not a compliance attestation**: controls also need process and
governance evidence a pipeline cannot produce. The mapping lives in
`scanner/defaults/compliance.yml`, so you can adjust it to your organisation's interpretation.

## How it decides what to run

| It finds | It runs |
|---|---|
| anything | Gitleaks (full Git history), TruffleHog (verified live secrets) |
| source code in any of 25+ languages | Semgrep with `p/default` plus a rule pack per detected language and framework |
| dependency manifests (pip, npm/yarn/pnpm, Maven, Gradle, Go, Cargo, NuGet, Composer, RubyGems, Pub, Hex…) | Trivy SCA + licence gate, OSV-Scanner cross-check |
| Dockerfile, Terraform, Kubernetes, Helm, CloudFormation, Bicep/ARM, Compose | Trivy config, Checkov, Hadolint |
| Kubernetes manifests or Helm charts | Helm render → kubeconform, kube-linter, Conftest (when `.rego` policies exist) |
| GitHub Actions workflows | actionlint, zizmor |
| `threatmodel/tm.py` (pytm) or `threagile.yaml` | threat-model gate |
| a Dockerfile | build → Syft SBOM → Trivy + Grype image gates |
| …that EXPOSEs a port | start the app → ZAP baseline (+ active scan on deep runs, + API scan with an OpenAPI spec) → Nuclei → ModSecurity/CRS blocking test |
| `enable-iast` + DongTai settings | IAST agent attached to the app during scanner traffic |

## Gates

| Gate | Fails when |
|---|---|
| Threat model | a threat at or above `min_severity` has no decision, or its mitigation is contradicted by scanner evidence |
| Secrets | any Gitleaks finding; any verified live credential |
| SAST | any Semgrep ERROR finding |
| SCA / licences | fixable CVE at/above `gate-severity`; forbidden/restricted licence |
| IaC | misconfiguration at/above `gate-severity`; Hadolint error |
| Kubernetes | invalid manifest; Conftest `deny` |
| CI/CD | actionlint error; zizmor HIGH |
| Container | fixable CVE at/above `gate-severity` (Trivy or Grype); baked-in secret; build failure |
| DAST | a ZAP rule set to FAIL (`.zap/rules.tsv`, else built-in: injection, XSS, traversal, SSRF, XXE…) |
| Runtime protection | the WAF lets an attack through or blocks normal traffic |
| Any CVE gate | a KEV CVE (`block-kev`) or an EPSS score ≥ `epss-threshold` |

OSV-Scanner, Checkov, kube-linter and Nuclei report without blocking. Gates that report
individual findings (threat model, Gitleaks, TruffleHog, Semgrep, Trivy, Grype, ZAP) honour the
baseline and PR delta. Exit-code tools (Hadolint, kubeconform, Conftest, actionlint, zizmor) use
their own inline ignores.

### Results: passed, failed, error, skipped, report-only

A crash is never a clean scan. A scanner that fails to run, a job that dies before uploading its
report, an invalid baseline or a missing KEV feed all show as **error** rows.
`fail-on-scanner-error: true` (default) fails the run on any error, even in report-only mode.

## Inputs: `sawone-scan.yml`

| Input | Default | |
|---|---|---|
| `path` / `config` | `.` / `.sawone.yml` | directory to scan; config relative to it |
| `dockerfile` / `build-context` | `<path>/Dockerfile` / its directory | image to build and attack |
| `gate-severity` | `HIGH,CRITICAL` | |
| `enforce` | `true` | `false` = report only |
| `fail-on-scanner-error` | `true` | |
| `scan-depth` | `auto` | `auto` (PRs fast, else deep) · `fast` · `deep` |
| `pr-gate` | `new` | `new` · `all` |
| `phases` | `all` | DevSecOps phases to scan: `all` or a comma list of `plan`, `code`, `build`, `test`, `operate` (`release`, `deploy`, `monitor` are the other workflows) |
| `incremental` | `auto` | `auto` (pull requests scan only the change) · `on` · `off` |
| `report-languages` | `en,ar` | PDF languages: `en`, `ar` or both |
| `baseline-file` | `.sawone-baseline.yml` | relative to `path` |
| `block-kev` | `true` | |
| `epss-threshold` | `"0"` (off) | `0`–`1` |
| `skip-tools` | | e.g. `nuclei,checkov` |
| `tool-version-policy` / `tools-lock-file` | `latest` | `latest` · `bundled` · `file` |
| `scanner-image` | `ghcr.io/hackin2minutes-oss/sawone-scanner:1` | tag or digest |
| `scanner-identity-regexp` | this repo's `release.yml` | `''` skips signature verification |
| `enable-threat-model` … `enable-cicd` | `true` | one per static gate |
| `enable-container`, `enable-dast`, `enable-runtime` | `true` | need a Dockerfile |
| `dast-full-scan` | `true` | ZAP active scan on deep runs |
| `dast-ajax-spider` | `false` | also crawl with ZAP's AJAX spider (JavaScript-heavy apps; slower) |
| `dast-auth-header` | `Authorization` | header that carries the DAST credential |
| `enable-iast`, `dongtai-url`, `iast-run-args` | off | DongTai agent |
| `app-port` / `health-path` / `startup-timeout` | EXPOSE / auto / `60` | |
| `upload-sarif` | `auto` | `auto` (public repos) · `always` (GHAS) · `never` |
| `enable-defectdojo`, `defectdojo-url`, `-product`, `-engagement` | off | |
| `artifact-prefix` | `sawone` | must differ per call in one run |
| `runs-on` | `ubuntu-24.04` | Runner label for every job |

Secrets: `defectdojo-token`, `dongtai-token`, and for authenticated DAST `dast-auth-value`
(a fixed credential such as `Bearer …` or `session=…`) or `dast-username` / `dast-password`
(used with a login call configured in `.sawone.yml`, see below). Outputs: `passed`, `failed`, `errors`,
`new-blocking`, `report-artifact`, `image-id`, `local-tag`, `artifact-prefix`.
`sawone-release.yml` and `sawone-monitor.yml` document their inputs at the top of each file.

### Authenticated DAST

Without credentials ZAP sees only what an anonymous visitor sees. Either pass a fixed credential:

```yaml
    secrets:
      dast-auth-value: ${{ secrets.DAST_TOKEN }}   # sent as the dast-auth-header on every request
```

or let the scan log in first: set `dast-username` / `dast-password` secrets and describe the login call
in `.sawone.yml`:

```yaml
dast:
  auth:
    login_url: /api/login                     # POSTed as JSON
    login_body: '{"username": "${DAST_USERNAME}", "password": "${DAST_PASSWORD}"}'
    token_field: token                        # dotted path in the JSON reply, e.g. data.access_token
    token_prefix: "Bearer "
```

Credentials travel only as environment variables (never on a command line or in a log), reach only the
DAST job, and are sent only to the app under test. A failed login is a scanner error, not an anonymous scan.

## Tool versions

| `tool-version-policy` | Behaviour |
|---|---|
| `latest` (default) | the `tools` job resolves every scanner image to its newest digest and every pip tool to its newest version **once**; every job in the run uses exactly that lock |
| `bundled` | the lock file built into the scanner image at release time (reproducible) |
| `file` | your own lock, e.g. produced by `sawone-scan --resolve-tools` |

A tool that cannot be resolved to a digest fails the run; it never falls back to a floating tag.
The scanner image is resolved to a digest and its Cosign signature verified before use. The
lock, every digest and the KEV/EPSS feed sizes appear in the report.

## Use it in any CI

| CI | How |
|---|---|
| **GitHub Actions** | the workflows above, or the single-step action `uses: hackin2minutes-oss/sawone@<sha>` |
| **GitLab CI** | `include: remote: …/ci/gitlab/sawone.gitlab-ci.yml` (parallel gates, MR note, trend, incremental) |
| **Jenkins** | stage from `ci/jenkins/Jenkinsfile` |
| **Azure DevOps** | `template: ci/azure-devops/sawone-scan.yml@sawone` (parallel gates, PR thread, trend, incremental) |
| **anything else / laptop** | `ci/sawone-scan.sh` (needs Docker) |

Every wrapper runs the same image, so results match across CI systems. KEV/EPSS, the baseline
compliance evidence, trend/SLA and the bilingual report work everywhere; the GitLab and Azure templates
also post the merge-request / pull-request comment and scan merge requests incrementally. The
vulnerability-DB cache, signed evidence, monitoring and the dashboard are GitHub workflow features. Requirement: a Docker daemon the job can reach,
with the workspace visible to it.

## Results

| File | What |
|---|---|
| `threat-model.json`, `threatmodel/` | threats with STRIDE, status, evidence and decisions; DFD and sequence diagrams (SVG) |
| `security-report.pdf` / `security-report-ar.pdf` | the whole story in English / Arabic: gates, risk-ranked findings, trend and fix deadlines, accepted risks and false positives, compliance evidence, supply chain, tool versions, evidence index |
| `evidence/` | `index.json` (controls → evidencing files with SHA-256) and `manifest.sha256` |
| `summary.md` / `summary.json` | results table (also the job summary and PR comment) |
| `findings.json` / `findings-consolidated.json` | every finding / merged across tools, with KEV, EPSS, baseline and new-in-PR flags |
| `junit.xml` | one test per gate, for CI test tabs |
| `sarif/` | every SARIF report, uniquely categorised for code scanning |
| `raw/`, `logs/` | raw tool output and one log per tool run |

## Limitations

- Needs a Linux runner with Docker. Scanners, the app and DAST run as containers on the
  runner's Docker daemon. Use GitHub-hosted or other ephemeral runners: scanned code is
  built and run with access to that daemon.
- DAST starts one container. Authentication is a fixed credential or one login call; apps that need a
  database next to them, or a multi-step login, are only partly tested.
- One image per run in the reusable workflow; the single-step action scans every Dockerfile.
- Publishing targets GHCR.
- PR delta needs a report from the base branch. Until one exists, every finding counts as new
  (the report says so).
- The SLSA generator runs nested inside `sawone-release.yml`; `validate.yml` exercises it on
  every push to `main`.
- IAST needs your own DongTai server.
