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

The first milestone supplies strict domain models and environment-based runtime
configuration. Enforcement APIs, test layers, and delivery automation are added
in focused follow-up commits and pull requests.
