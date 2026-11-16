# syntax=docker/dockerfile:1.4
FROM python:3.12-slim-bookworm

# Security hardening: Prevent interactive prompts during apt
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies (libmagic for file type detection)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged dedicated user and group
RUN groupadd -g 10001 pharos && \
    useradd -u 10001 -g pharos -s /usr/sbin/nologin -d /home/pharos -m pharos

WORKDIR /app

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY --chown=pharos:pharos . .

# Prepare runtime directories with unprivileged access
RUN mkdir -p /app/outputs/sanitized /app/user_database && \
    chown -R pharos:pharos /app

# Switch to unprivileged user
USER pharos

EXPOSE 5000

# Run gunicorn WSGI server
CMD ["gunicorn", "web.app:app", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "2", "--timeout", "120"]
