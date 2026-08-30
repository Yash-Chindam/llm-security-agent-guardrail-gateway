# LLM Security and Agent Guardrail Gateway

A policy-aware FastAPI gateway that inspects untrusted prompts, retrieved context,
model output, and proposed tool actions before they cross a security boundary.

This repository implements the technical design in
[`04-llm-security-agent-guardrail-gateway.md`](04-llm-security-agent-guardrail-gateway.md)
as a sequence of independently tested milestones.

## Development setup

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
```

## Run the gateway

```bash
uvicorn guardrail_gateway.app:app --reload
```

The API is available at `http://127.0.0.1:8000`, with OpenAPI documentation at
`/docs`. Enforcement endpoints cover input, retrieved context, model output, and
proposed tool actions. Risky actions return an approval identifier that is bound
to the exact action digest, tenant, expiry, and one-time use.

## Test layers

```bash
pytest tests/unit --no-cov
pytest tests/integration --no-cov
pytest tests
npm ci
npm run test:e2e
```

The aggregate test command enforces at least 90% Python coverage. Pull requests
also run strict Ruff, mypy, Bandit, pip-audit, Playwright, and Trivy checks.

Run the complete local gate with:

```bash
python scripts/quality_gate.py
```

## Container delivery

```bash
docker build -t guardrail-gateway:local .
docker run --rm -p 8000:8000 guardrail-gateway:local
```

The production image uses an upgraded Alpine base, runs as UID/GID 10001, and
does not contain pip or other build tooling. That removal matches package
names rather than a `pythonX.Y` path, and the build fails if pip or
setuptools remains importable, so a Dependabot base image bump cannot
silently reintroduce them. On pull requests, CI builds and
scans the image for high/critical vulnerabilities. After `main` passes every
gate, the workflow creates a private OCI image artifact with provenance and SBOM
metadata for controlled deployment.

## Repository automation

- The PR labeler maps changed paths to gateway, tests, documentation, CI/CD,
  container, dependency, and security labels.
- Dependabot opens grouped weekly PRs for Python, npm, GitHub Actions, and Docker.
- Patch/minor Dependabot updates receive the `automerge` label; major updates
  always require manual review.
- A label-gated merge workflow waits for the complete `CI` workflow, verifies
  that the successful run tested the PR's current head SHA, and preserves the
  PR's individual commits with a merge commit.

Apply `automerge` manually to other PRs only when they are ready to merge after
all CI gates succeed.
