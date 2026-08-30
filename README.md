# LLM Security and Agent Guardrail Gateway

A policy-aware FastAPI gateway that inspects untrusted prompts, retrieved context,
model output, and proposed tool actions before they cross a security boundary.

The current implementation is the first production-shaped milestone from
[`04-llm-security-agent-guardrail-gateway.md`](04-llm-security-agent-guardrail-gateway.md):

- deterministic prompt-injection, PII, and secret detection;
- redact, deny, allow, and require-approval decisions;
- tenant and tool-aware action policy;
- exact-action approval digests with expiry and single-use approval records;
- structured, redacted audit events;
- unit, integration, and Playwright API end-to-end tests;
- container build, security scanning, dependency updates, PR labeling, and
  label-gated automatic merge workflows.

## Quick start

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
uvicorn guardrail_gateway.app:app --reload
```

The API is available at `http://127.0.0.1:8000`, with OpenAPI documentation at
`/docs`.

## Test layers

```bash
pytest tests/unit
pytest tests/integration
npm ci
npx playwright install chromium
npm run test:e2e
```

Run the complete local quality gate with `python scripts/quality_gate.py`.

## Example

```bash
curl -X POST http://127.0.0.1:8000/v1/inspect/input \
  -H "content-type: application/json" \
  -d '{"identity":"user-123","tenant_id":"acme","content":"Email me at dev@example.com"}'
```

The response contains a stable policy reason, redacted detector evidence, a
policy version, trace identifiers, and measured decision latency. Raw prompts
are never written to the audit sink.

## Delivery safety

Pull requests must pass linting, type checking, unit tests, integration tests,
90% aggregate Python coverage, Playwright end-to-end tests, dependency auditing,
and filesystem/container scanning. Applying the `automerge` label enables a
squash merge only after the `CI` workflow succeeds for the current PR head SHA.
Where the GitHub plan supports it, also configure branch protection on `main` to
require all jobs in the `CI` workflow.

## Roadmap

The next milestones replace the local adapters with OPA, Presidio, PostgreSQL,
and Kafka implementations; add authenticated reviewer identities; and exercise
the public gateway through PyRIT adversarial suites.
