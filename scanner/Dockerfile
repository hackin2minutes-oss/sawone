# Universal DevSecOps scanner image.
# Contains the orchestrator, the PDF renderer and the small Python-based tools;
# every other scanner runs as a sibling container pulled at its latest release.
FROM python:3.13-slim

LABEL org.opencontainers.image.title="sawone-scanner" \
      org.opencontainers.image.description="Auto-detecting open-source DevSecOps scanner"

# Docker CLI (to run the scanner containers), git (history scans), PDF libraries, fonts
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git gnupg jq \
       libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu-core fonts-inter fonts-noto-core graphviz \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-buildx-plugin \
    && find /usr/share/fonts/truetype/noto -type f ! -name 'NotoSansArabic*' ! -name 'NotoNaskhArabic*' -delete \
    && { command -v fc-cache >/dev/null && fc-cache -f || true; } \
    && apt-get purge -y gnupg && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Python-based tools (Semgrep, zizmor, pytm): refreshed every weekly rebuild and again at scan time
RUN pip install --no-cache-dir pyyaml weasyprint semgrep zizmor pytm \
    && git config --system --add safe.directory '*'

COPY sawone_scan.py findings.py phases.py report.py report_i18n.py merge_reports.py dashboard.py threatmodel.py /opt/sawone/
# defaults/ may include tools.lock.json, written by release.yml: the tool versions certified
# with this scanner release (used when SCAN_TOOLS_LOCK=bundled)
COPY defaults/ /opt/sawone/defaults/
RUN chmod +x /opt/sawone/sawone_scan.py \
    && ln -s /opt/sawone/sawone_scan.py /usr/local/bin/sawone-scan \
    && ln -s /opt/sawone/sawone_scan.py /usr/local/bin/devsecops-scan

# Runs as root: it needs the Docker socket to launch the scanner containers.
HEALTHCHECK NONE
ENTRYPOINT ["sawone-scan"]
