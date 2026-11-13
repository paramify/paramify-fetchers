# Beta deployment image for the paramify fetchers.
#
# It bundles the tool, its Python deps, AND the system binaries the fetchers
# shell out to (pip does NOT install those):
#   jq (41 fetchers), aws-cli (33), kubectl (3 k8s), git (checkov clone), curl, checkov.
#
# Build (from the REPO ROOT, not deploy/):
#   docker build -f deploy/Dockerfile -t paramify-fetchers:beta .
# or just use docker compose (see deploy/docker-compose.yml).
FROM python:3.14-slim

# ---------------------------------------------------------------------------
# System binaries
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash git curl jq unzip ca-certificates tini cron \
 && rm -rf /var/lib/apt/lists/*

# aws-cli v2 — not on pip; use the official installer (arch-aware).
# Retry + unzip -t: flaky Docker Desktop networking can corrupt the ~50MB zip
# (unzip then fails with "bad CRC" even though curl exits 0).
RUN set -eux; \
    case "$(uname -m)" in \
      x86_64)  url="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" ;; \
      aarch64) url="https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" ;; \
      *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;; \
    esac; \
    for attempt in 1 2 3 4 5; do \
      curl -fsSL --retry 3 --retry-all-errors --retry-delay 2 "$url" -o /tmp/awscliv2.zip \
        && unzip -t /tmp/awscliv2.zip >/dev/null \
        && break; \
      rm -f /tmp/awscliv2.zip; \
      if [ "$attempt" -eq 5 ]; then echo "awscli zip download or integrity check failed" >&2; exit 1; fi; \
      sleep 2; \
    done; \
    unzip -q /tmp/awscliv2.zip -d /tmp; \
    /tmp/aws/install; \
    rm -rf /tmp/aws /tmp/awscliv2.zip

# kubectl — pinned to the current stable channel (arch-aware).
RUN set -eux; \
    case "$(uname -m)" in x86_64) k="amd64" ;; aarch64) k="arm64" ;; esac; \
    ver="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"; \
    curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${ver}/bin/linux/${k}/kubectl"; \
    chmod +x /usr/local/bin/kubectl

# NOTE: one fetcher references `terraform`. Checkov *scans* terraform source
# statically and does not need the binary; uncomment only if a fetcher actually
# invokes terraform.
# RUN curl -fsSLo /tmp/tf.zip https://releases.hashicorp.com/terraform/1.9.8/terraform_1.9.8_linux_amd64.zip \
#  && unzip -q /tmp/tf.zip -d /usr/local/bin && rm /tmp/tf.zip

# ---------------------------------------------------------------------------
# The tool + Python deps
# ---------------------------------------------------------------------------
WORKDIR /app
COPY . .

# tui extra → `paramify tui` works inside the container; checkov extra → the
# checkov scanner fetchers. Toggle for faster local builds:
#   docker build --build-arg INSTALL_EXTRAS=tui ...
ARG INSTALL_EXTRAS=tui,checkov
RUN pip install --no-cache-dir -e ".[${INSTALL_EXTRAS}]"

# Collected evidence lands here; mount a volume to persist it to the host.
ENV EVIDENCE_DIR=/app/evidence
VOLUME ["/app/evidence"]

COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /app/deploy/run-and-upload.sh || true

# tini = clean PID-1 signal handling (matters for the cron scheduler mode).
# Exec-form resolves `tini` via PATH, so it works wherever the package installs it.
ENTRYPOINT ["tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["paramify", "list"]
