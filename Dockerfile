# Dockerfile for the Argos demo service.
#
# Builds a minimal Python image containing the argos package and the FastAPI
# demo app. The image does NOT contain the LLM runtime or Presidio — those
# are separate services brought up by docker-compose.yml.

FROM python:3.12-slim

# Base tools for package install; kept minimal
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only what's needed for pip install first, so layer caching works
COPY pyproject.toml README.md ./
COPY argos/ ./argos/
COPY demo/ ./demo/
COPY policies/ ./policies/

# Install the package (excluding the production extras — that's vLLM which
# needs CUDA and is irrelevant for the demo image).
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

# Pre-create the audit log directory
RUN mkdir -p /data

# Drop privileges — the demo process does not need root
RUN useradd --create-home --shell /bin/bash argos \
    && chown -R argos:argos /app /data
USER argos

EXPOSE 8080

ENV ARGOS_MODE=demo \
    ARGOS_HTTP_HOST=0.0.0.0 \
    ARGOS_HTTP_PORT=8080 \
    ARGOS_AUDIT_LOG_PATH=/data/audit.log

CMD ["python", "-m", "demo.app"]
