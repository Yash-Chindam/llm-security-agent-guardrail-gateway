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

## Adversarial evaluation

`guardrail_gateway.redteam` is a PyRIT-style suite that targets the public
gateway over HTTP, so a run exercises the same policy, evidence, and audit
path as production traffic. It covers every scenario category from section 12
of the design specification (direct and indirect injection, single- and
multi-turn jailbreak, encoded/obfuscated instructions, sensitive-data
extraction, cross-tenant access, tool privilege escalation, approval
manipulation, resource exhaustion, and MCP tool poisoning) alongside a benign
compatibility dataset, and reports the section 17 metrics: attack success
rate, false-positive rate, side-effect prevention rate, and policy latency.

Run it against a live gateway:

```bash
uvicorn guardrail_gateway.app:app &
python -m guardrail_gateway.redteam --target http://127.0.0.1:8000
```

The run is scored against
[`src/guardrail_gateway/redteam/baseline.json`](src/guardrail_gateway/redteam/baseline.json),
a committed record of which attacks are blocked, which are known gaps, and
which benign workflows must stay allowed. The gate fails (exit code 1) on any
scenario not recorded in the baseline or on a regression — an attack that was
previously blocked and no longer is, or a benign workflow that is now
blocked — so weak spots stay visible instead of being silently reintroduced.
Update the baseline deliberately after reviewing a change with
`--refresh-baseline`. `tests/integration/test_redteam_suite.py` runs the same
suite in-process against every pull request, so a policy regression fails CI
before it can reach `main`.

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
gate, a reusable workflow creates a private OCI image artifact with provenance
and SBOM metadata for controlled deployment. Because a merge pushed with
`GITHUB_TOKEN` emits no push event, the automerge job calls that same reusable
workflow directly for the merge commit it creates.

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
