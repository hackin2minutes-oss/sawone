# Changelog

## 1.0.0 — Sawone

First release under the Sawone name, built on SawanB DevSecOps 2.0.2 (its history is below).
Configuration and baselines from `.sawanb.yml` / `.devsecops.yml` / `.sawanb-baseline.yml` are still read.

**Noise and speed**
- Incremental pull-request scans (`incremental: auto`): Gitleaks and TruffleHog read history from the base
  commit, Semgrep runs with `--baseline-commit`, and the SCA, IaC, Kubernetes, CI/CD and threat-model gates
  are skipped (and reported as "not affected by this change") when nothing they cover changed.
- Verified live secrets: TruffleHog also scans Git history and checks each secret against its provider;
  live ones are tagged and listed first.
- Nuclei runs only templates for the technologies it detects (`-as`).
- Balanced noise profile: low-severity findings from second-opinion tools are counted, not listed;
  `noise.mute_rules` drops rules for good.
- False positives: baseline entries take `type: false-positive` (or `accepted-risk`); the report measures
  the false-positive rate per tool.
- First-seen dates carried between scans, fix deadlines per severity (`sla`), overdue tags, age buckets and
  a new-versus-fixed trend in the report, job summary and PR comment.

**Saudi compliance pack**
- Evidence map adds NCA CSCC-1:2019, NCA CCC-2:2024 (tenant and provider controls) and Saudi PDPL
  (Art. 19) to ASVS, SSDF, NCA ECC-2:2024 and SAMA CSF; `compliance.frameworks` selects them; every
  control has an Arabic title.
- Evidence pack: `evidence/index.json` (each control → evidencing report files with SHA-256) and
  `evidence/manifest.sha256`; release-branch runs sign the manifest with Sigstore (`cosign sign-blob`).
- The full report in Arabic (`security-report-ar.pdf`, right-to-left, Noto Sans Arabic);
  `report-languages` picks `en`, `ar` or both.

**Platforms and dashboard**
- `sawone-dashboard.yml`: a portfolio page across repositories (verdicts, blocking findings, KEV, live
  secrets, overdue fixes, compliance coverage, trend lines), optionally on GitHub Pages.
- GitLab CI and Azure DevOps templates rewritten as full pipelines: tools resolved once, parallel gates,
  image and attacks, merged report, merge-request / pull-request comment, previous-report trend,
  incremental merge-request scans, JUnit test results.

## SawanB DevSecOps 2.0.2 — Accuracy, coverage and authenticated DAST

**Fixes**
- The same CVE under different package spellings (Trivy `Pillow`, Grype `pillow`) is one finding; the KEV
  total no longer double-counts.
- ZAP High alerts now fail the DAST gate: Server Side Template Injection (normal and blind), DOM-based and
  persistent XSS, Source Code Disclosure, XPath, XSLT and CRLF injection were previously only tracked.
- SARIF locations are workspace-relative (OSV and Hadolint wrote `/home/runner/work/…` paths), in the
  report and in code scanning.
- The report states the run's real tool-version policy instead of "lock".
- Priority actions count unique CVEs and advisories, not findings.
- Nuclei findings show the URL they matched (its SARIF has no usable location).
- Gate-job summaries no longer show a partial compliance count; job summaries group a CVE across the
  packages it affects, name each finding, and drop the image tag from tool names.

**Enhancements**
- Cross-tool correlation: one private key found by Gitleaks, Semgrep and Trivy, one SQL injection matched
  by several Semgrep rules, or "runs as root" from Trivy, Semgrep and Hadolint is one finding (listing the
  other rule IDs). A baseline written from it covers every tool's copy.
- Semgrep drops rules for frameworks the repository does not use (Django rules on a Flask app).
- Authenticated DAST: a fixed credential (`dast-auth-value` secret) or a login call (`dast.auth.login_url`
  with `dast-username` / `dast-password`). Credentials travel only as environment variables.
- Optional ZAP AJAX spider (`dast-ajax-spider`) for JavaScript-heavy apps.
- WAF test attacks every real endpoint and parameter from the OpenAPI spec, not only five generic URLs.
- Dockle CIS benchmark of the built image (report only; skipped for lock files made before 2.0.2).
- Source SBOM of the repository (Syft, CycloneDX) alongside the image SBOM.
- Report: shorter threat-model mitigations, a breakdown of what only Grype found, "also reported as" tags
  on merged findings, and the source SBOM in the SCA section.
- Runners pinned to `ubuntu-24.04` (GitHub is moving `ubuntu-latest` to Ubuntu 26).

## SawanB DevSecOps 2.0.1 — Enterprise report

- **New PDF report layout**: cover page, contents with page numbers, executive summary (verdict, KPI tiles,
  results by stage, most significant risks, prioritised actions), scope and method, gate results, findings
  by tool, risk-ranked findings, one section per stage with one panel per tool, compliance evidence,
  accepted risks, supply chain, and appendices (tool versions, definitions, artefacts).
- Every tool now has its own panel: severity breakdown, blocking count, and its findings. The same rule
  firing in several places is one row; vulnerabilities are grouped by advisory with a package upgrade plan;
  OS and application packages are separated; Grype shows only what Trivy missed.
- ZAP sections show CWE, each attacked URL, parameter and payload, and the remediation advice.
- Fixed: threat model shown as "did not run" in merged reports; banner listing only 8 failed gates;
  "image not published" shown for pushes; internal `_policy` row in the tool table; Checkov reported as
  High (now Unrated); Gitleaks shown as Medium; all Trivy scans collapsed into one row.
- Scanner: zizmor findings are now reported individually; image findings show "OS package (debian)" or
  the package file instead of the runner's archive path; the SBOM size counts packages, not files.
- Scanner image: adds the Inter font for the report.

## SawanB DevSecOps 2.0.0

First release under the Sawone name (successor of `devsecops-action` v1).

### Added
- **Risk policy**: CISA KEV catalogue (known-exploited CVEs block at any severity, `block-kev`)
  and FIRST EPSS scores (`epss-threshold`), fetched once per run; a missing feed while the policy
  needs it is a scanner error.
- **Baseline of accepted risks** (`.sawone-baseline.yml`): owner, reason and expiry required,
  at most 365 days ahead; wildcard IDs, package and path narrowing, exact fingerprints; expired
  entries stop suppressing. `--write-baseline` generates one from a report for adoption.
- **Pull-request delta** (`pr-gate: new`): PRs fail only on findings they introduce, compared
  with the base branch's last report; report shows new and fixed counts.
- **Normalised findings** with stable fingerprints (CVE + package + version; rule + path + line
  text) and **duplicate merging** across Trivy, Grype and other tools (`findings-consolidated.json`).
- **Compliance evidence map**: OWASP ASVS 4.0.3, NIST SSDF, NCA ECC-2:2024, SAMA CSF
  (`scanner/defaults/compliance.yml`) in the job summary, PR comment and PDF.
- `sawone-pr-comment.yml`: one PR comment, updated on every push.
- `sawone-monitor.yml`: scheduled rescan of running image digests, monitoring issue, alert on
  known-exploited CVEs.
- **Scan depth**: pull requests run fast (no ZAP active scan), pushes and schedules deep.
- **Vulnerability-DB cache**: Trivy and Grype databases warmed once per run and shared by all jobs.
- ZAP alerts, Semgrep, Gitleaks, TruffleHog, Trivy, Grype and threat-model results are individual
  findings that can be accepted, escalated and compared.

### Changed
- Names: workflows `sawone-scan.yml` / `sawone-release.yml`, image
  `ghcr.io/hackin2minutes-oss/sawone-scanner`, config `.sawone.yml` (`.devsecops.yml`
  still read), reports `sawone-reports/`, CLI `sawone-scan` (`devsecops-scan` kept as an alias).
- Trivy image scans no longer pre-filter by severity, so KEV escalation can see every CVE; the
  blocking rule itself is unchanged.
- Scheduled scanner rebuilds use the latest v2 release tag; manual builds publish `:edge` only.

### Fixed
- A missing `repository` in merged report parts no longer breaks PDF generation.
