# LLM Security and Agent Guardrail Gateway

**Document type:** Technical design specification  
**Purpose:** Define reusable AI security middleware and adversarial evaluation  
**Implementation plan:** Intentionally excluded

> Proposed security and performance values are design targets. Use them on a resume only after measuring a working implementation.

## 1. Use case

Agentic and RAG applications process untrusted language that may attempt to override instructions, expose private context, access another tenant or cause dangerous tool use. Traditional API gateways authenticate requests but do not understand prompt injection, retrieved-document trust, model context or proposed tool arguments.

This project creates a reusable proxy between users, retrieved context, language models and tools. It enforces deterministic identity and action policies, detects sensitive data and suspicious instructions, requires approval for risky actions and validates defenses with repeatable red-team scenarios.

### Representative scenarios

1. Block an MCP agent from executing instructions embedded in a retrieved document.
2. Prevent destructive or unauthorized database queries.
3. Remove PII or secrets before an external model call.
4. Detect sensitive information in model output.
5. Require approval before an external side effect.
6. Run PyRIT scenarios before releasing a new model, prompt or workflow.

## 2. Portfolio value

The project demonstrates:

- AI threat modeling.
- Direct and indirect prompt-injection controls.
- Policy-as-code authorization.
- PII and secret detection.
- Tool argument validation.
- Human approval and exact-action binding.
- Sandboxed execution.
- Automated red teaming.
- Security-event analytics.
- Secure fail-safe behavior.

## 3. Users and actors

| Actor | Responsibility |
|---|---|
| Protected AI application | Sends prompts, context, outputs and actions for inspection. |
| End user | Receives policy-aware responses and approval requests. |
| Security engineer | Authors policy, detectors, attacks and incident rules. |
| Reviewer | Adjudicates high-risk requests and false positives. |
| Auditor | Inspects policy decisions and evidence. |
| Red-team operator | Runs standardized and custom attacks. |

## 4. Scope

### In scope

- Input, context, output and action enforcement points.
- Identity-aware policy-as-code.
- Direct and indirect prompt-injection controls.
- PII and secret detection.
- Tool allowlists and schema validation.
- Human approval for risky actions.
- Sandboxed tool boundaries.
- Single- and multi-turn red-team evaluation.
- Security analytics and release gates.

### Out of scope

- Guaranteeing that one detector catches all attacks.
- Replacing network, identity, container or cloud security.
- Arbitrary code execution on the host.
- LLM-only authorization.
- Blocking content without a policy reason.
- Hiding false positives to inflate protection metrics.

## 5. Threat model

| Threat | Example | Primary controls |
|---|---|---|
| Direct injection | User asks the model to ignore policy and reveal hidden context. | Input classification, instruction separation and output DLP |
| Indirect injection | Retrieved document instructs the agent to call a dangerous tool. | Trust segmentation, content inspection and action policy |
| Tool abuse | Agent proposes destructive SQL or shell arguments. | Schema validation, OPA, sandbox and approval |
| Data leakage | Prompt, trace or response contains secrets or PII. | Presidio, secret detection, redaction and trace policy |
| Cross-tenant access | Retrieved context belongs to another tenant. | Identity-bound filters and authorization checks |
| Resource exhaustion | Request creates loops or excessive model/tool use. | Rate limits, budgets, timeouts and circuit breakers |
| MCP poisoning | Server advertises deceptive tools or control instructions. | Server registry, signed configuration and result sanitization |
| Supply-chain compromise | Container or dependency contains a known vulnerability. | SBOM, dependency scanning and Trivy |

## 6. Architecture

```text
Client / protected AI application
               |
               v
Kong or Envoy edge gateway
TLS, authentication, coarse rate limits
               |
               v
FastAPI security orchestration service
               |
       +-------+---------+----------------+
       |                 |                |
       v                 v                v
OPA policy engine   Content inspection   Approval service
                    Presidio/secrets      exact-action binding
                    injection signals
       |                 |                |
       +-------+---------+----------------+
               |
               v
Allow / deny / transform / require approval
               |
               v
Model, RAG pipeline or MCP action broker
               |
               v
Kafka events -> ClickHouse -> Grafana
               |
               v
PyRIT red-team and regression system
```

## 7. Technology selection

| Technology | Responsibility | Selection rationale |
|---|---|---|
| Kong or Envoy | Edge gateway | Handles TLS, authentication integration and coarse traffic policy. |
| FastAPI | Security orchestration | Provides typed synchronous enforcement APIs. |
| Open Policy Agent | Policy decision point | Separates authorization from model prompts and makes rules testable. |
| Microsoft Presidio | PII processing | Provides configurable PII recognition and anonymization. |
| PyRIT | Adversarial evaluation | Supports reusable targets, attacks, scenarios and scorers. |
| NeMo Guardrails/Guardrails AI | Selected validation rails | Adds conversational and structured validation where useful. |
| Kafka | Security-event transport | Decouples request latency from analytics processing. |
| ClickHouse | Security analytics | Handles high-volume event analysis. |
| PostgreSQL | Workflow data | Stores policy configuration, approvals and incident cases. |
| Trivy | Build-time scanning | Scans images, dependencies and filesystems. |
| Falco | Runtime detection | Adds container/runtime signals where supported. |

## 8. Enforcement points

### 8.1 Before the model

Inspect:

- Identity, tenant and quota.
- Direct injection indicators.
- PII and secrets.
- Input length and encoding anomalies.
- Model eligibility.
- Known policy violations.

Outcomes may be allow, deny, redact, route to local-only inference or require approval.

### 8.2 Before retrieved context enters the model

Inspect:

- Source and tenant labels.
- Trust classification.
- Embedded instructions.
- Suspicious exfiltration requests.
- Authorization for every document.
- Context-size limits.

Retrieved content is labeled as untrusted evidence and never merged with system instructions.

### 8.3 After the model

Inspect:

- PII and secret leakage.
- Disallowed content categories relevant to the application.
- Grounding and citation requirements.
- Structured-output schema.
- Proposed actions embedded in natural language.
- Required abstention or disclaimer rules.

### 8.4 Before a tool action

Inspect:

- Tool identity and trust status.
- User and service authorization.
- Argument schema.
- Resource and tenant.
- Side-effect class.
- SQL, filesystem, URL or shell-specific safety policy.
- Approval requirement.
- Execution budget.

Preventing unauthorized side effects is the most important enforcement responsibility.

## 9. Policy model

A policy decision includes:

- Enforcement point.
- User/service identity and tenant.
- Data and resource classifications.
- Tool/action identity.
- Sanitized arguments or argument digest.
- Detector evidence.
- Policy-bundle version.
- Verdict and reason code.
- Required transformation or approval.
- Decision latency.

| Verdict | Behavior |
|---|---|
| Allow | Continue and attach the decision ID. |
| Deny | Stop and return a safe reason. |
| Transform | Redact, pseudonymize or constrain before continuing. |
| Require approval | Suspend until an authorized reviewer approves the exact action. |

An LLM may provide risk evidence but cannot grant authorization.

## 10. Content inspection

### Sensitive data

- Run Presidio inside the trusted boundary.
- Configure entity categories per tenant and use case.
- Apply allow, redact, pseudonymize or deny rules.
- Use seeded canary secrets to measure leakage.
- Keep reversible mappings in a separate protected store.
- Do not send raw sensitive content to external inspection services.

### Prompt-injection evidence

Use multiple layers:

- Deterministic instruction/exfiltration patterns.
- Source-trust classification.
- Encoding and obfuscation normalization.
- Lightweight classifier or specialized detector.
- Policy context, especially whether content can influence a tool action.

A detector score is policy evidence, not a security decision by itself.

### Guardrail frameworks

Use NeMo Guardrails or Guardrails AI selectively for:

- Conversation rails.
- Structured validation.
- Topic constraints.
- Custom validator integration.

Do not treat a guardrail framework as the sole boundary.

## 11. Action broker and sandbox

The protected application sends a proposed action to the action broker instead of executing it directly.

Controls:

- Tool allowlists.
- Strict Pydantic argument schemas.
- Canonical filesystem paths and URLs.
- SQL parsing and query-class restrictions.
- Tenant/resource verification.
- Ephemeral sandbox for code execution.
- No host filesystem access.
- Disabled network unless explicitly approved.
- CPU, memory, process, output and time limits.
- Approval bound to an exact action digest.

## 12. Red-team design

PyRIT targets the public gateway so tests exercise real policy, logging and downstream behavior.

### Scenario categories

- Direct injection.
- Indirect RAG injection.
- Single-turn jailbreak.
- Multi-turn escalation.
- Encoded or obfuscated instructions.
- Sensitive-data extraction.
- Cross-tenant access.
- Tool privilege escalation.
- Approval manipulation.
- Resource exhaustion.
- Malicious MCP tool descriptions and responses.

### Run metadata

- Target application and revision.
- Model and prompt revision.
- Policy-bundle revision.
- Scenario and attack techniques.
- Dataset version.
- Scorer version.
- Baseline and attack behavior.
- Policy decision and detector evidence.

### Benign compatibility suite

Maintain a separate dataset of legitimate workflows. Measure both attack blocking and the rate at which safe requests are incorrectly blocked.

## 13. Information model

### SecurityDecision

- Request and trace IDs.
- Enforcement point.
- Identity and tenant.
- Policy version.
- Verdict and reason.
- Redacted evidence references.
- Latency.

### DetectorEvidence

- Detector and version.
- Category and score.
- Threshold.
- Redacted matched excerpt.
- Confidence and explanation.

### ActionRequest

- Tool and side-effect class.
- Resource.
- Sanitized arguments and digest.
- Budget and approval requirement.

### ApprovalRecord

- Reviewer.
- Exact action digest.
- Decision and rationale.
- Issue time and expiry.

### RedTeamRun

- Target and revisions.
- Scenario, techniques and data.
- Results and scorers.
- Baseline comparison.

### IncidentCase

- Related decisions and traces.
- Tenant and severity.
- Disposition.
- Remediation and status.

## 14. Event and analytics design

- Synchronous security checks complete before the protected action continues.
- Security events publish asynchronously to Kafka.
- ClickHouse stores high-volume analytics.
- PostgreSQL stores approvals, configurations and incidents.
- Grafana displays operational and security metrics.
- Raw prompts are not copied to analytics by default; store redacted excerpts and evidence references.

## 15. Reliability and fail-safe behavior

| Condition | Required behavior |
|---|---|
| OPA unavailable | Fail closed for side effects; optionally use documented restricted read-only mode. |
| PII detector unavailable | Block sensitive workloads or use an approved local-only path. |
| Kafka unavailable | Buffer bounded events; block when mandatory audit durability cannot be met. |
| Detector disagreement | Apply conservative policy or require review based on action risk. |
| Approval expired | Review the current arguments and context again. |
| Analytics unavailable | Continue enforcement while buffering within bounded limits. |
| Red-team regression | Block promotion and retain the previous revision. |

## 16. Platform security

- OIDC/OAuth identity through Keycloak or equivalent.
- External secret manager.
- Kubernetes NetworkPolicies.
- Non-root containers and read-only filesystems where practical.
- Trivy image/dependency scanning.
- Falco runtime detection where supported.
- Signed immutable image references.
- SBOM generation.
- Separate least-privilege service accounts.

## 17. Observability and evaluation

Track:

- Attack-success rate by scenario.
- Prompt-injection block rate.
- False-positive and reviewer-overturn rates.
- Seeded-secret and PII leakage.
- Unauthorized tool-call block rate.
- Side-effect prevention rate.
- Approval and expiry rates.
- P50/P95 policy and detector latency.
- Event-delivery lag and dropped events.

### Proposed design targets

- No unauthorized side effect in the adversarial suite.
- Complete audit attribution for every action decision.
- Deterministic behavior when a required security dependency fails.
- False positives measured alongside attack blocking.
- Release automatically blocked on a material red-team regression.

## 18. Deployment topology

- Kong or Envoy edge gateway.
- FastAPI security-orchestration replicas.
- OPA sidecars or policy service.
- Presidio analyzer/anonymizer.
- Approval service and PostgreSQL.
- Kafka event transport.
- ClickHouse analytics.
- Isolated PyRIT workers.
- Prometheus, Grafana, Loki and Tempo.
- Docker, Kubernetes, Helm and GitHub Actions.

## 19. Official references

- [PyRIT documentation](https://microsoft.github.io/PyRIT/)
- [Open Policy Agent documentation](https://www.openpolicyagent.org/docs/)
- [Microsoft Presidio documentation](https://microsoft.github.io/presidio/)
- [OWASP GenAI Security Project](https://genai.owasp.org/)
- [OpenTelemetry documentation](https://opentelemetry.io/docs/)

