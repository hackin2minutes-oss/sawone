# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub: this repository → **Security →
Report a vulnerability**. Do not open a public issue. Include the affected file or image
digest, steps to reproduce and the impact you expect. You will get an acknowledgement within
5 working days and a fix or mitigation plan within 30 days for confirmed issues.

## Supported versions

Only the latest release of the reusable workflow, the action and the scanner image
(`ghcr.io/hackin2minutes-oss/sawone-scanner`) receive fixes. v1 (`devsecops-action`) is frozen. Pin a commit SHA and update
when a new release is published.

## How this project protects its users

- Every third-party action is pinned to a full commit SHA (`scripts/pin-actions.sh --check`
  runs in CI). The SLSA generator is the one exception: its builder must be called by tag.
- Every job declares least-privilege permissions; the workflow's default is none.
- No `${{ }}` expression is expanded inside a shell script; inputs reach scripts through
  environment variables, and every input is validated before any scan runs.
- Nothing is pushed, signed, attested or deployed from a pull request.
- Credentials are passed as secrets, never as inputs, and reach only the job that uses them.
- Scanner images and tools are resolved to digests/versions once per run and recorded in the
  report; a tool that cannot be resolved fails the run instead of falling back to a tag.
- The scanner image is signed keylessly with Cosign; the reusable workflow verifies the
  signature before using it (`scanner-identity-regexp`).

## Scope notes

The scanner runs the code under test (`docker build`, the application container, DAST
attacks) with access to the runner's Docker daemon. Run it on GitHub-hosted or otherwise
ephemeral runners; do not point it at untrusted code on a long-lived self-hosted runner.
