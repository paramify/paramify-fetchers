# Hosted sandbox of the terminal console (tools/webdemo/serve.py).
#
# Build (from the REPO ROOT, not deploy/fly/):
#   docker build -f deploy/fly/Dockerfile -t fetcher-demo .
#   docker run --rm -p 8000:8000 fetcher-demo
#
# Deliberately NOT built on deploy/Dockerfile. That image carries aws-cli,
# kubectl and checkov because the fetchers shell out to them; this one never
# runs a fetcher (tools/webdemo/sandbox.py replaces api.run), so shipping those
# binaries would only add ~400 MB and a much larger attack surface to a public
# host.
FROM python:3.14-slim

# No compilers, no cloud CLIs, no shell tools the fetchers would want. tini is
# PID 1 so Fly's SIGTERM reaches the server and the per-session children.
RUN apt-get update && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only what the sandbox reads, rather than `COPY . .`. This image is
# public-facing: an explicit list keeps our own manifests/ (which name real
# stage project ids), deploy/ (which sits next to demo secrets files) and the
# git history out of it by construction, instead of relying on .dockerignore.
COPY pyproject.toml README.md ./
COPY framework/ ./framework/
COPY fetchers/ ./fetchers/
COPY uploaders/ ./uploaders/
COPY comparators/ ./comparators/
COPY catalog/ ./catalog/
# tools/ has no __init__.py in this repo — it resolves as a namespace
# package, which is how `python -m tools.webdemo.serve` already runs locally.
COPY tools/webdemo/ ./tools/webdemo/

RUN pip install --no-cache-dir -e ".[tui,webdemo]"

# Bake the workspace every session is copied from, so a new visitor gets a
# filesystem copy instead of a fresh 183-fetcher catalog scan.
ENV DEMO_WORKSPACE_TEMPLATE=/srv/demo-workspace
RUN python -m tools.webdemo.sandbox --build-template "$DEMO_WORKSPACE_TEMPLATE"

# The server and every session process run unprivileged, and /app stays owned by
# root: a session can edit and delete inside its own /tmp workspace, but the
# shared checkout it symlinks to is read-only to it.
RUN useradd --create-home --uid 10001 demo \
 && chown -R root:root /app /srv/demo-workspace
USER demo

ENV PORT=8000
EXPOSE 8000

# Fly sets PORT; DEMO_PUBLIC_URL has to be the URL the browser sees, because
# it is what the websocket URL is built from (see fly.toml).
ENTRYPOINT ["tini", "--"]
CMD ["python", "-m", "tools.webdemo.serve"]
