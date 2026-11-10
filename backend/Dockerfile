# syntax=docker/dockerfile:1
# Phantom SOAR backend image (FastAPI API and Celery worker share it).
# Build context is ./backend; the package is installed at /app/backend so
# "backend.main:app" resolves with PYTHONPATH=/app.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app \
    REPORTS_DIR=/app/backend/reports \
    DATABASE_URL=sqlite:////app/data/phantom_soar.db

WORKDIR /app

RUN groupadd --system --gid 10001 phantom \
    && useradd --system --uid 10001 --gid phantom --home-dir /app --no-create-home \
       --shell /usr/sbin/nologin phantom

# Runtime dependencies only (psycopg2-binary / argon2 ship wheels, no compiler needed).
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Application code stays root-owned; only the data and reports directories are writable.
COPY . /app/backend
RUN mkdir -p /app/backend/reports /app/data \
    && chown phantom:phantom /app/backend/reports /app/data

USER phantom

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
