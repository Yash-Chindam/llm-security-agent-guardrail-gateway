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
| §8.1 before the model | done | Identity, tenant, quota, injection, PII/secret, size, model eligibility, local-only routing, and violation history are enforced. Encoding normalization beyond base64 is tracked under §10. |
| §8.2 retrieved context | done | Per-document tenant, classification, and access-list authorization; trust class; embedded instructions and forged message boundaries; per-document and per-batch size limits; admitted content returned as labeled untrusted evidence. |
| §8.3 after the model | done | Leakage, disallowed categories, structured-output schema, grounding and citations, embedded proposed actions, and disclaimer and abstention rules. Grounding is lexical overlap, not semantic entailment. |
| §8.4 before a tool action | done | Allowlist, role authorization, side-effect class, tenant/resource, argument schema, SQL/filesystem/URL policy, approval, and a per-trace execution budget. Quota and budget counters are per process, so a limit is enforced per replica; a shared counter store is not implemented. |
| §7 technology selection | partial | FastAPI, OPA, Presidio, Kafka, ClickHouse, PostgreSQL, and Trivy are in use. The adversarial suite is the project's own, not PyRIT. NeMo Guardrails, Guardrails AI, Falco, and a Kong or Envoy edge are not implemented. |
| §9 policy model | done | Every decision carries point, identity, tenant, policy version, verdict, reason code, evidence, digest, and latency. The decision point is the built-in policy or an OPA server with a Rego bundle that CI proves equivalent. |
| §10 content inspection | partial | Deterministic detectors with redacted evidence; normalization of base64, hex, percent-encoding, ROT13, letter-spacing, and Unicode tricks; per-tenant allow/redact/pseudonymize/deny rules; a separate pseudonym vault; canary secrets; a fail-closed Presidio adapter. A learned injection classifier and NeMo/Guardrails AI rails are not implemented. |
| §11 action broker and sandbox | done | Allowlist, strict per-tool Pydantic schemas, parsed SQL restricted to read-only queries, canonical paths and URLs, tenant checks, digest-bound approval, and an ephemeral container sandbox for code with no network, no host filesystem, and CPU, memory, process, output, and time limits, tested against real containers in CI. The sandbox uses an ordinary container runtime unless a stronger OCI runtime is configured. |
| §12 red-team design | done | 74 scenarios across every required category plus a benign compatibility set, scored against a committed baseline. |
| §13 information model | done | SecurityDecision, DetectorEvidence, ActionRequest, ApprovalRecord, RedTeamRun, and IncidentCase exist. Approvals and incidents can be kept in PostgreSQL or SQLite; the decision log is in memory. |
| §14 events and analytics | done | Structured, redacted decision events delivered through a transport port with ordered, bounded buffering, and a tenant-scoped decision log for auditors. A Kafka transport (verified by hand against a real broker; CI uses a stand-in), a ClickHouse schema, a Grafana dashboard, and Prometheus alert rules, each checked against what the gateway emits. Approvals and incidents are stored in PostgreSQL, with exactly-once approval use enforced by the database and tested against a real PostgreSQL in CI. Configuration is not stored in PostgreSQL: it comes from the environment. |
| §15 fail-safe behaviour | done | Policy engine, detectors, and audit transport sit behind ports with a fixed outcome when each is lost: fail closed for side effects, optional restricted read-only mode, bounded audit buffering, and blocking when mandatory audit durability is lost. |
| §16 platform security | partial | Verified bearer identity, non-root image, no build tooling in runtime, Trivy, SBOM, provenance. OIDC discovery, secret manager, NetworkPolicies, image signing, and Falco are planned (M3b, M10). |
| §17 observability | done | The red-team suite reports attack-success, false-positive, and leakage rates. `/metrics` exposes decisions, policy and detector latency, approvals, audit lag and drops, and open incidents, with a dashboard and alert rules. Each decision is an OpenTelemetry span with a child span per detector. |
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

- **M5a action-broker hardening** (`v0.5.0`) — role-to-tool authorization,
  strict per-tool argument schemas, parsed SQL, and canonical path and URL
  policy.

- **M5b quotas and execution budgets** (`v0.6.0`) — per-identity and
  per-tenant rate limits and a per-trace action budget, all bounded.

- **M6 output enforcement and model routing** (`v0.7.0`) — structured-output
  schema, grounding and citations, embedded actions, disclaimer and
  abstention rules, model eligibility, local-only routing, and violation
  lockout.

- **M7 context authorization** (`v0.8.0`) — per-document authorization by
  tenant, classification, and access list, with admitted documents returned
  as labeled untrusted evidence.

- **M8 content inspection depth** (`v0.9.0`) — obfuscation normalization,
  per-tenant entity rules, pseudonymization with a separate vault, canary
  secrets, and a Presidio adapter.

- **M9a audit, incidents, and metrics** (`v0.10.0`) — decision log, incident
  cases with automatic canary incidents, approval rejection, the auditor role,
  and a Prometheus metrics endpoint.

- **M9b events, analytics, and tracing** (`v0.11.0`) — Kafka audit transport,
  ClickHouse schema, Grafana dashboard, Prometheus alerts, detector latency,
  and OpenTelemetry traces.

- **M9c durable stores** (`v0.12.0`) — approvals and incident cases in
  PostgreSQL or SQLite, consumed exactly once across replicas, with a defined
  outcome when the database is unreachable.

- **M10a policy as code** (`v0.13.0`) — an OPA policy engine with a Rego
  bundle, its own tests, and a CI check that it decides exactly as the
  built-in policy does.

- **M10b execution sandbox** (`v0.14.0`) — `run_code` and an execute
  endpoint that runs allowed code in a locked-down, ephemeral container.

Planned, in the order the specification's risk ordering implies:

- **M3b identity provider integration** — OIDC discovery and JWKS rotation,
  asymmetric verification against a live issuer.
- **M10c platform (§16, §18)** — compose and Helm topology, NetworkPolicies,
  signed images.
