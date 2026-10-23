# Developing and releasing Sawone

For maintainers. Users only need the [README](../README.md) and the [reference](reference.md).

## What is tested

| | How |
|---|---|
| Sawone 1.0: first-seen/SLA history, false positives, incremental commands, live-secret verification, compliance frameworks, evidence manifest, Arabic report (every fixed text translated), dashboard | `tests/unit/test_sawone.py` |
| Scanner logic: detection, tool selection, pinning without tag fallback, crash vs finding per tool, fingerprints, duplicate merging, baseline validation/expiry/wildcards, KEV/EPSS escalation, PR new-only gating, compliance status, exit codes, JUnit, PDF | `tests/unit` (pytest), every PR |
| Workflow syntax, shell in every `run:`, injection and permission audit, SHA pinning | actionlint, shellcheck, zizmor; `scripts/pin-actions.sh --check` |
| The reusable workflow called as a consumer: a vulnerable Python app, a Terraform repo, and the same Terraform repo with every finding accepted in a baseline (must pass); the scanner built from the same commit | `validate.yml` |
| The single-step action on all test apps | `selftest.yml` |
| Release: publish, sign, SBOM attestation, provenance | `validate.yml` on pushes to `main` |
| **Not** tested automatically | the deploy step, DefectDojo and DongTai (need servers), the monitor workflow (needs published images), the PR comment (needs a PR from this repo), the dashboard workflow, the GitLab and Azure DevOps templates (syntax-checked only) |

## Building on the engine

Other products reuse Sawone's engine (phases, threat model, risk policy, merge, report, Arabic PDF) through a
profile: `SAWONE_PROFILE` points to a YAML file that adds stages, their phase and wording, Semgrep rules,
compliance controls and a brand (see `scanner/sawprofile.py`). The product's scanner subclasses `Scan`
(overriding `steps()`) and calls `sawone_scan.main(MyScan)`; its image is built `FROM` a Sawone release.
[SawOne-A](https://github.com/hackin2minutes-oss/sawone-a) (Android) is built this way.

## Releasing

1. Push this repo, then tag: `git tag vX.Y.Z && git push origin vX.Y.Z`. `release.yml` resolves
   the bundled tool lock, builds, pushes and signs `ghcr.io/<owner>/sawone-scanner:{1.0.0,1,latest}`.
2. GitHub → **Packages → sawone-scanner → Package settings → Change visibility →
   Public**, so other repos and CI systems can pull it.
3. Releases are immutable (repository setting): a version tag can never move. After each release move the major tag: `git tag -f v1 vX.Y.Z && git push -f origin v1`, and draft the release with "Publish this Action to the GitHub Marketplace" ticked. Every Monday, `release.yml` rebuilds the latest v1
   release with current tools. Manual runs publish `:edge` only.

`scripts/pin-actions.sh` re-pins this repository's own actions to the newest release SHAs;
`--check` fails on any unpinned `uses:`. See `SECURITY.md` for reporting vulnerabilities and
`CHANGELOG.md` for changes. Licensed MIT.
