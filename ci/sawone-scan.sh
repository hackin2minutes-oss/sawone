#!/usr/bin/env bash
# Any CI system, or your laptop: run from the root of the repository to scan.
#   curl -fsSL https://raw.githubusercontent.com/hackin2minutes-oss/sawone/v1/ci/sawone-scan.sh | bash
# Environment (all optional): SCAN_SEVERITY, SCAN_ENFORCE, SCAN_DAST, SCAN_SKIP,
# SCAN_BASELINE, SCAN_BLOCK_KEV, SCAN_EPSS_THRESHOLD,
# DEFECTDOJO_URL, DEFECTDOJO_TOKEN, DONGTAI_URL, IAST_RUN_ARGS, SAWONE_IMAGE
set -euo pipefail
IMAGE="${SAWONE_IMAGE:-ghcr.io/hackin2minutes-oss/sawone-scanner:1}"
TARGET="$(pwd)"
docker pull -q "$IMAGE" >/dev/null
exec docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$TARGET:$TARGET" -w "$TARGET" \
  -e SCAN_SEVERITY -e SCAN_ENFORCE -e SCAN_DAST -e SCAN_SKIP -e SCAN_BASELINE -e SCAN_BLOCK_KEV -e SCAN_EPSS_THRESHOLD \
  -e DEFECTDOJO_URL -e DEFECTDOJO_TOKEN -e DONGTAI_URL -e IAST_RUN_ARGS -e DONGTAI_TOKEN \
  -e REPO="${REPO:-$(basename "$TARGET")}" -e SHA="${SHA:-$(git rev-parse HEAD 2>/dev/null || true)}" \
  "$IMAGE" --path "$TARGET" "$@"
