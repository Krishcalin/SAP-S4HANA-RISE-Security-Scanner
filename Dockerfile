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
USER sapsec

EXPOSE 8000
# --proxy-headers / --forwarded-allow-ips: the session cookie's Secure flag is
# derived from request.url.scheme. Behind a TLS-terminating ingress uvicorn sees
# plain http on the internal hop, so without these the cookie ships WITHOUT Secure
# on exactly the deployments that have TLS — and a downgrade then leaks the session.
# The allow-list is "*" because the ingress is the only thing that can reach this
# port in the one-container-plus-Postgres deployment; narrow it if that changes.
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000",      "--proxy-headers", "--forwarded-allow-ips", "*"]
