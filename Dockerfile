# syntax=docker/dockerfile:1.7
FROM python:3.13-alpine AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && pip install .

FROM python:3.13-alpine AS runtime

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN apk upgrade --no-cache \
    && addgroup -S -g 10001 gateway \
    && adduser -S -D -H -u 10001 -G gateway gateway
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
# Version-agnostic removal. A hard-coded pythonX.Y path silently stops matching
# when the base image minor version is bumped, which leaves pip and its vendored
# packages (and their CVEs) in the runtime image. The final check fails the build
# if anything survives, so a future base bump cannot regress this silently.
RUN find /opt/venv /usr/local -depth \
        \( -name 'pip' -o -name 'pip-*' \
        -o -name 'setuptools' -o -name 'setuptools-*' \
        -o -name 'wheel' -o -name 'wheel-*' \) \
        -exec rm -rf {} + \
    && ! python -c 'import pip' 2>/dev/null \
    && ! python -c 'import setuptools' 2>/dev/null
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2)"]
CMD ["uvicorn", "guardrail_gateway.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
