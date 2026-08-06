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

# Runs as a non-root user: the process only ever reads uploaded files and writes
# to one directory, so it has no reason to hold root.
RUN useradd --system --create-home --uid 10001 sapsec \
 && mkdir -p /var/lib/sapsec/uploads \
 && chown -R sapsec:sapsec /app /var/lib/sapsec
USER sapsec

EXPOSE 8000
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]
