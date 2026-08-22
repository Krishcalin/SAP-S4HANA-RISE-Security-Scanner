# The console is a React SPA compiled to static files and served by the SAME
# FastAPI process. Node appears in THIS stage and nowhere else: the runtime image
# below has no JavaScript toolchain, no second service and no reverse proxy, and
# the server's pinned runtime dependency list is unchanged. One app container,
# one PostgreSQL, exactly as before.
#
# THE BUILD IS PART OF THE IMAGE, not something a developer remembers to run. A
# sibling product shipped an image whose bundle was missing a whole feature
# because the build was a manual step with a mode flag nobody set; the artefact
# passed every test because the tests ran against the source, not the image.
FROM node:22-alpine AS spa
WORKDIR /build/frontend
# Manifests first so a source change does not invalidate the install layer.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# `npm run build` type-checks and then emits ../server/spa — see vite.config.ts.
# It fails the image on a type error, which is the point of running it here.
RUN npm run build

FROM python:3.12-slim

# SECURITY UPDATES FROM THE BASE DISTRIBUTION, applied at build time.
#
# `python:3.12-slim` is rebuilt on its own cadence, so between rebuilds it
# carries whatever Debian has since fixed. Trivy is run over this image in CI
# with `ignore-unfixed: true` -- meaning it reports ONLY vulnerabilities with a
# published fix -- and it was failing on 36 findings across nine util-linux
# packages, every one of them fixed upstream and none of them reachable through
# anything this image runs. Shipping a security product on a base with known,
# fixable CVEs is indefensible regardless of reachability, because the customer
# scanning our image cannot tell the difference and should not have to.
#
# `upgrade`, not `dist-upgrade`: this takes security fixes within the release and
# will not pull in a new one. No package is installed, so the runtime dependency
# count -- the property the single-container design rests on -- does not move.
RUN apt-get update  && apt-get upgrade -y --no-install-recommends  && apt-get clean  && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Dependencies first so a source change does not invalidate the wheel layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY modules/ ./modules/
COPY server/ ./server/
COPY data/ ./data/
COPY sap_scanner.py ./

# Connected mode (decision D2). Carried so an operator can run
#   docker compose exec app python -m collect sapcontrol --host ... --out /tmp/x
# from a container that already sits inside the customer's network, which is
# usually the only thing on the right side of the firewall.
#
# IT ADDS NOTHING TO THE IMAGE'S DEPENDENCIES. `collect/` is stdlib-only and the
# `purity` CI job enforces that, so this line cannot quietly grow the runtime
# requirement list — which is the property the whole one-container design rests
# on. Nothing under server/ or modules/ imports it, and tests/test_collect.py
# asserts that too: it is present, not wired in.
COPY collect/ ./collect/

# The compiled console. Copied AFTER server/ so it cannot be shadowed by a stale
# server/spa that happened to exist in the build context.
COPY --from=spa /build/server/spa ./server/spa

# Runs as a non-root user: the process only ever reads uploaded files and writes
# to one directory, so it has no reason to hold root.
RUN useradd --system --create-home --uid 10001 sapsec \
 && mkdir -p /var/lib/sapsec/uploads \
 && chown -R sapsec:sapsec /app /var/lib/sapsec
# BYTECODE IS COMPILED AT BUILD TIME, WHICH IS WHAT LETS THE ROOT FILESYSTEM BE
# READ-ONLY AT RUNTIME.
#
# Python writes __pycache__/*.pyc beside the source on first import — the running
# container was doing exactly that under /app/server. With `read_only: true` that
# write fails, and CPython degrades SILENTLY: it recompiles on every import rather
# than erroring, so the only symptom is a slower start nobody attributes to this.
# Compiling here means the .pyc are already present, and PYTHONDONTWRITEBYTECODE
# stops anything trying to add more.
#
# `|| true` because compileall exits non-zero on any file it cannot compile, and
# one unparseable vendored sample must not fail the build. Anything that matters
# is imported at startup and would fail loudly there instead.
RUN python -m compileall -q /app/server /app/modules /app/collect || true \
 && chown -R sapsec:sapsec /app

USER sapsec

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# THE IMAGE'S DEFAULT UPLOAD DIRECTORY IS THE ONE THE IMAGE ACTUALLY CREATES.
#
# server/config.py falls back to ROOT/var/uploads — a path inside /app that this
# image does not contain and, under a read-only root, cannot create. So
# `docker run --read-only` without an explicit UPLOAD_DIR died at startup with
# FileNotFoundError while compose worked fine, because compose sets the variable.
# An image whose default only works when something else overrides it has the
# wrong default.
#
# Found by the new CI job starting the image the way a customer might, rather
# than the way our compose file does. Compose still sets it explicitly, so
# nothing about that path changes.
ENV UPLOAD_DIR=/var/lib/sapsec/uploads

# Compose waited on the DATABASE's healthcheck and had nothing to wait on for the
# app, so `docker compose up` reported success while the console was still 503.
# urllib rather than curl: the slim base ships no curl, and installing one to
# check a health endpoint would grow the attack surface faster than it describes it.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"

EXPOSE 8000
# --proxy-headers / --forwarded-allow-ips: the session cookie's Secure flag is
# derived from request.url.scheme. Behind a TLS-terminating ingress uvicorn sees
# plain http on the internal hop, so without these the cookie ships WITHOUT Secure
# on exactly the deployments that have TLS — and a downgrade then leaks the session.
# The allow-list is "*" because the ingress is the only thing that can reach this
# port in the one-container-plus-Postgres deployment; narrow it if that changes.
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000",      "--proxy-headers", "--forwarded-allow-ips", "*"]
