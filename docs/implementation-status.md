# Implementation status

The design specification in
[`04-llm-security-agent-guardrail-gateway.md`](../04-llm-security-agent-guardrail-gateway.md)
deliberately excludes an implementation plan. This file is that plan: it tracks
every section of the specification against what the repository actually
enforces, so the gap is visible rather than implied.

Section 4 of the specification forbids inflating protection metrics. The same
rule applies here: a row is only `done` when the behaviour is implemented and
covered by tests, and a partial row names what is missing.

## Legend

| Mark | Meaning |
|---|---|
| done | Implemented and covered by the test layers. |
| partial | Some of the section is enforced; the gap is named. |
| planned | Not implemented; assigned to a milestone below. |

## Specification coverage

| Section | Status | Notes |
|---|---|---|
| §8.1 before the model | partial | Identity, tenant, injection, PII/secret, and size are enforced. Quota, model eligibility, and known-violation history are planned (M5). |
| §8.2 retrieved context | partial | Source/tenant labels, trust class, embedded instructions, and size are enforced. Per-document authorization is planned (M7). |
| §8.3 after the model | partial | PII and secret leakage are enforced. Structured-output schema, grounding/citation, embedded proposed actions, and abstention rules are planned (M6). |
| §8.4 before a tool action | partial | Allowlist, side-effect class, tenant/resource, SQL read-only, argument shape, and approval are enforced. Role authorization, filesystem/URL/shell policy, and execution budgets are planned (M5). |
| §9 policy model | done | Every decision carries point, identity, tenant, policy version, verdict, reason code, evidence, digest, and latency. |
| §10 content inspection | partial | Deterministic detectors with redacted evidence and base64 de-obfuscation. Presidio, reversible pseudonymization, canary leakage measurement, and wider encoding normalization are planned (M8). |
| §11 action broker and sandbox | partial | Allowlist, tenant checks, digest-bound approval. Per-tool Pydantic schemas, a real SQL parser, path/URL canonicalization, and the execution sandbox are planned (M5, M10). |
| §12 red-team design | done | 31 scenarios across every required category plus a benign compatibility set, scored against a committed baseline. |
| §13 information model | partial | SecurityDecision, DetectorEvidence, ActionRequest, ApprovalRecord, and RedTeamRun exist. IncidentCase is planned (M9). |
| §14 events and analytics | partial | Structured, redacted decision events delivered through a transport port with ordered, bounded buffering. Kafka, ClickHouse, PostgreSQL, and Grafana adapters are planned (M9). |
| §15 fail-safe behaviour | done | Policy engine, detectors, and audit transport sit behind ports with a fixed outcome when each is lost: fail closed for side effects, optional restricted read-only mode, bounded audit buffering, and blocking when mandatory audit durability is lost. |
| §16 platform security | partial | Verified bearer identity, non-root image, no build tooling in runtime, Trivy, SBOM, provenance. OIDC discovery, secret manager, NetworkPolicies, image signing, and Falco are planned (M3b, M10). |
| §17 observability | partial | The red-team suite reports the required rates and latency percentiles. A runtime metrics endpoint and traces are planned (M9). |
| §18 deployment topology | planned | Compose and Helm topology (M10). |

## Milestones

Delivered:

- **M1 core gateway** — four enforcement points, deterministic detectors,
  exact-action approval binding, redacted audit events.
- **M2 delivery and automation** — test layers, container hardening, CI gates,
  dependency and merge automation.
- **M3 adversarial evaluation** (`v0.2.0`) — scenario datasets, scorer,
  committed baseline, and a release gate that fails on a regression.
- **M3a verified identity** (`v0.3.0`) — signed bearer credentials, body
  claims bound to the proven principal, reviewer role with separation of
  duties, tenant-scoped approvals, fail-closed when no signing material is
  configured.

- **M4 fail-safe dependency behaviour** (`v0.4.0`) — ports for the policy
  engine, detectors, and audit transport, with the section 15 outcome for each
  failure and an audit state on the readiness probe.

Planned, in the order the specification's risk ordering implies:

- **M3b identity provider integration** — OIDC discovery and JWKS rotation,
  asymmetric verification against a live issuer.
- **M5 authorization, quotas, and action-broker hardening (§8.4, §11)** —
  role-to-tool permissions, per-identity and per-tenant budgets, per-tool
  Pydantic schemas, SQL parsing, path and URL canonicalization.
- **M6 output enforcement (§8.3)** — structured-output schema validation,
  grounding and citation requirements, proposed actions embedded in prose.
- **M7 context authorization (§8.2)** — per-document identity-bound filters.
- **M8 content inspection depth (§10)** — Presidio, pseudonymization with a
  separate mapping store, seeded canary leakage measurement, wider
  encoding normalization.
- **M9 events, analytics, and incidents (§13, §14, §17)** — Kafka transport,
  ClickHouse analytics, PostgreSQL for approvals and incident cases,
  Prometheus and OpenTelemetry.
- **M10 policy-as-code and platform (§7, §16, §18)** — OPA policy bundles with
  fail-closed evaluation, sandboxed execution, compose and Helm topology,
  signed images.
