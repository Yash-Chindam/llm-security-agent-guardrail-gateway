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
```

The aggregate test command enforces at least 90% Python coverage. Pull requests
also run strict Ruff, mypy, Bandit, pip-audit, and Trivy filesystem checks.
