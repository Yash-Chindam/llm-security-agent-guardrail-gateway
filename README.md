# LLM Security and Agent Guardrail Gateway

A policy-aware FastAPI gateway that inspects untrusted prompts, retrieved context,
model output, and proposed tool actions before they cross a security boundary.

This repository implements the technical design in
[`04-llm-security-agent-guardrail-gateway.md`](04-llm-security-agent-guardrail-gateway.md)
as a sequence of independently tested milestones.
[`docs/implementation-status.md`](docs/implementation-status.md) tracks each
section of that specification against what the gateway actually enforces today,
including what is still missing.

## Development setup

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
```

## Run the gateway

```bash
GUARDRAIL_JWT_SECRET="$(openssl rand -hex 32)" uvicorn guardrail_gateway.app:app --reload
```

The API is available at `http://127.0.0.1:8000`, with OpenAPI documentation at
`/docs`. Enforcement endpoints cover input, retrieved context, model output, and
proposed tool actions. Risky actions return an approval identifier that is bound
to the exact action digest, tenant, expiry, and one-time use.

## Caller identity

Every enforcement endpoint requires a signed bearer credential. The principal
comes from the token's `sub`, `tenant`, and `roles` claims, and an `identity` or
`tenant_id` in a request body must agree with it, so a caller cannot assert a
tenant it does not hold. Verification is offline against configured signing
material, which keeps enforcement working while an identity provider is
unreachable.

| Variable | Purpose |
|---|---|
| `GUARDRAIL_JWT_SECRET` | HMAC secret or issuer public key. At least 32 bytes for HS256. |
| `GUARDRAIL_JWT_ALGORITHM` | Pinned verification algorithm, `HS256` by default. |
| `GUARDRAIL_JWT_ISSUER` | Required `iss` claim, when set. |
| `GUARDRAIL_JWT_AUDIENCE` | Required `aud` claim, when set. |

There is deliberately no switch to disable authentication. With no signing
material the gateway cannot prove who is calling, so it reports itself not ready
on `/health/ready` and refuses every enforcement request with
`identity_verification_unavailable` rather than trusting a request body.

Approving a risky action needs the `reviewer` role, and the identity that
proposed an action can never approve it, whatever roles it holds. Approvals are
scoped to their tenant: another tenant sees `404` rather than a refusal that
would confirm the approval exists.

Section 16 of the design specification calls for OIDC/OAuth identity. The
verifier accepts the issuer's asymmetric keys today; discovery and key rotation
against a live provider are tracked in
[`docs/implementation-status.md`](docs/implementation-status.md).

### Identity provider

Instead of a configured key, the gateway can verify tokens against an OIDC
identity provider such as Keycloak and follow its keys as they rotate.

| Setting | Effect |
|---|---|
| `GUARDRAIL_OIDC_ISSUER` | Discover the provider's signing keys from `<issuer>/.well-known/openid-configuration`. Also the issuer tokens must carry. |
| `GUARDRAIL_JWKS_URL` | Fetch keys from this URL directly, for a provider without discovery. Needs `GUARDRAIL_JWT_ISSUER`. |
| `GUARDRAIL_JWT_AUDIENCE` | Required with a provider, so a token issued for another application is refused. |
| `GUARDRAIL_JWT_ALGORITHM` | Must be `RS256`, `RS384`, or `RS512` with a provider. |
| `GUARDRAIL_JWKS_CACHE_SECONDS` | How long fetched keys are used before they are fetched again; default 300. |
| `GUARDRAIL_JWKS_MAX_STALE_SECONDS` | How long keys stay trusted past that when the provider cannot be reached; default 3600. |

A token naming a key the gateway has not seen triggers one fetch, which is how
a rotation is picked up at once; further unknown key ids within ten seconds do
not, so forged tokens cannot be used to flood the provider. Only RSA keys
published for signing are used, the discovery document must describe the
issuer that was asked for, and it may not move key retrieval from HTTPS to
HTTP.

If the provider is unreachable at startup, or stays unreachable past the
staleness limit, every request is refused with
`identity_verification_unavailable` and the gateway reports not ready. A key
revoked during an outage could otherwise stay trusted indefinitely.

The token must carry `sub`, `tenant`, and `exp`, with `roles` and `clearance`
as described above; map them in the provider. This has been tested against a
stand-in provider, not against a running Keycloak.

## Action broker

A protected application proposes a tool action instead of executing it. A tool
that is not registered in
[`tools.py`](src/guardrail_gateway/tools.py) cannot be proposed at all, and
shell execution is deliberately absent because arbitrary code execution on the
host is out of scope.

| Tool | Side effect | Role | Argument policy |
|---|---|---|---|
| `search_documents` | none, read | caller | bounded query and limit |
| `execute_sql` | read | caller | parsed; one read-only `SELECT` |
| `read_file` | read | caller | canonical path inside the workspace root |
| `send_email` | external | operator | one recipient, bounded fields |
| `fetch_url` | external | operator | HTTPS to an allowlisted host |
| `update_record` | write | operator | record identifier, flat scalar changes |
| `delete_record` | destructive | operator | record identifier |

Checks run in order: allowlist, role, side-effect class, tenant-bound resource,
argument schema, tool-specific policy, then approval for any side effect.

- **Roles.** Reading needs the `caller` role and proposing a side effect needs
  `operator`. The `reviewer` role adjudicates and does not by itself permit
  proposing anything.
- **Schemas.** Arguments are validated against a strict, closed Pydantic model
  per tool, so an undeclared field or a coerced type is refused.
- **SQL.** Queries are parsed, not pattern-matched. A statement that changes
  state is refused wherever it sits, including inside a common table
  expression, and so is any function the parser does not recognise. A write
  keyword inside a string literal or comment is not a statement and is allowed.
- **Paths.** A path must stay under `GUARDRAIL_FILE_ROOT` after normalisation.
  Absolute paths, drive letters, backslashes, null bytes, and percent-encoded
  segments are refused.
- **URLs.** Only HTTPS on the default port to a host in
  `GUARDRAIL_ALLOWED_URL_HOSTS` (a JSON list, empty by default). Address
  literals and embedded credentials are refused, which closes the usual routes
  to loopback, private ranges, and cloud metadata endpoints.

## Content inspection

Detectors produce evidence; policy decides. Evidence carries a category, a
score, and an excerpt with the match replaced by `[MATCH]`, never the value.

**Obfuscation.** A pattern only sees the characters it is given, so every
content request is also inspected under each reading an encoding could hide:
base64 and URL-safe base64, hexadecimal and `\x` escapes, percent-encoding,
ROT13, letter-spacing, and Unicode tricks (compatibility forms, zero-width and
bidirectional controls, look-alike letters from other scripts), with one more
pass for doubly wrapped payloads. Something found only in such a reading has no
position in the original text and cannot be redacted, so it is denied with
`obfuscated_content_detected`.

**Entity rules.** Each sensitive category is allowed, redacted, pseudonymized,
or denied, for the deployment and per tenant:

```bash
GUARDRAIL_SENSITIVE_ENTITY_ACTIONS='{"pii_email": "pseudonymize"}'
GUARDRAIL_TENANT_ENTITY_ACTIONS='{"acme": {"pii_phone": "deny"}}'
```

An unlisted category is redacted. A secret may only be redacted or denied; it
is never allowed through or stored reversibly. Sensitive content in model
output is denied whatever the rule.

**Pseudonymization.** A pseudonymized value becomes a token such as
`[EMAIL_1]`, stable within a trace, so the model can still tell two people
apart. The mapping lives in a separate vault, never in a decision or an audit
event, and expires after `GUARDRAIL_PSEUDONYM_TTL_SECONDS`.
`POST /v1/pseudonyms/restore` turns a trace's tokens back into values for the
tenant that owns them; another tenant or another trace resolves nothing, and
each restoration is audited with a count and no values.

**Canaries.** `GUARDRAIL_CANARY_SECRETS` seeds values that have no legitimate
reason to cross any boundary. A sighting at any enforcement point, encoded or
not, is denied with `canary_leak_detected`, which measures leakage directly.

**Presidio.** Setting `GUARDRAIL_PRESIDIO_URL` adds a Presidio analyzer as a
second detector, and what it recognizes is redacted in place by span. It must
run inside the trusted boundary: content is sent to it for inspection. If it
does not return a usable answer the content is denied, not passed.

## Retrieved context

`POST /v1/inspect/context/batch` takes every document a retrieval step wants to
place before the model and decides each one on its own labels. A batch is never
accepted or refused as a whole.

| Document field | Rule | Reason code |
|---|---|---|
| `source_tenant_id` | Must be the caller's tenant. | `cross_tenant_context` |
| `classification` | `public`, `internal`, `confidential`, or `restricted`; the caller's `clearance` claim must be at least as high. | `document_not_authorized` |
| `allowed_identities`, `allowed_roles` | When either is set, the caller must be listed. Clearance never overrides an access list. | `document_not_authorized` |
| `content` | Inspected like any context; sensitive values are redacted. | `prompt_injection_detected`, `embedded_action_detected`, ... |
| size | Each document is bounded, and the batch by `GUARDRAIL_MAX_CONTEXT_CHARS`; documents past the budget are dropped in order. | `content_size_exceeded`, `context_budget_exceeded` |

The batch verdict is `allow` when every document is admitted unchanged,
`transform` (`context_filtered`) when some were dropped or redacted, and `deny`
(`no_authorized_context`) when none survive. Every document decision is audited
as well as the batch.

Admitted content is returned wrapped as untrusted evidence, so the application
never has to merge retrieved text with its instructions:

```text
<untrusted_evidence id="kb-1" source_tenant="acme" trust="untrusted">
Refunds are issued within 14 days of purchase.
</untrusted_evidence>
```

A document cannot open or close that envelope itself. Chat-template control
tokens and envelope tags inside a document are treated as an injection, and the
tag is made inert in anything that is admitted.

## Output enforcement

`POST /v1/inspect/output` checks more than leakage. After content inspection
passes, the application's own requirements are applied, all deterministically:

| Request field | Check | Reason code |
|---|---|---|
| `output_schema` | Output parses as JSON and satisfies the JSON Schema. A malformed schema, or one needing an external reference, is refused; references are never fetched. | `structured_output_invalid`, `structured_output_schema_invalid` |
| `sources` | Every `[id]` citation names a source the model was given, and each cited sentence shares enough terms with its sources. | `citation_unknown_source`, `citation_not_supported` |
| `require_citations` | An answer with no citation is denied, unless it declines to answer. | `citation_required`, `abstention_accepted` |
| `required_disclaimer` | A missing disclaimer is appended and returned as a transform. | `disclaimer_appended` |

A tool call carried in model output or in a retrieved document, as tool-call
markup, a JSON call object, or a registered tool invoked by name, is denied with
`embedded_action_detected`: an action has to be proposed to the action broker,
where it is authorized and bound to an approval.
`GUARDRAIL_DISALLOWED_OUTPUT_TERMS` maps application-specific categories to
terms a response may not contain.

Grounding is lexical overlap (`GUARDRAIL_GROUNDING_MIN_OVERLAP`, 0.5), which
catches an invented or borrowed citation but does not judge whether a
paraphrase is faithful.

## Model eligibility and routing

A content request may name the `model` it is destined for.

- `GUARDRAIL_ELIGIBLE_MODELS` and `GUARDRAIL_LOCAL_ONLY_MODELS` (JSON lists)
  restrict which models are permitted; a model in neither is denied with
  `model_not_eligible`. With both empty, no restriction applies.
- Sensitive content bound for an external model is redacted. Bound for a
  local-only model, it is allowed intact with `route: "local_only"`, so the
  application can keep it inside the trusted boundary.
- `GUARDRAIL_VIOLATION_LOCKOUT_THRESHOLD` locks an identity out with
  `repeated_policy_violations` after that many injection denials inside
  `GUARDRAIL_VIOLATION_WINDOW_SECONDS`. It is off by default.

## Quotas and execution budgets

Resource exhaustion is a named threat in the design specification: a request
that creates loops or excessive model and tool use.

| Variable | Default | Limits |
|---|---|---|
| `GUARDRAIL_IDENTITY_REQUESTS_PER_MINUTE` | 600 | Enforcement requests from one identity. |
| `GUARDRAIL_TENANT_REQUESTS_PER_MINUTE` | 3000 | Enforcement requests shared by a tenant. |
| `GUARDRAIL_MAX_ACTIONS_PER_TRACE` | 25 | Actions one `trace_id` may propose. |

A request past a quota is denied with `quota_exceeded`. The identity limit is
checked first, so one noisy caller is stopped before it spends the quota its
tenant shares. An action past its trace's budget is denied with
`execution_budget_exceeded`, and refused actions spend the budget exactly as
permitted ones do, so a looping agent is stopped whatever it is proposing.
Limiter state is bounded, so inventing identities or trace identifiers cannot
grow the gateway's memory. The counters are per process; a shared store for
multi-replica deployments is tracked in
[`docs/implementation-status.md`](docs/implementation-status.md).

## Fail-safe behaviour

Each security dependency is reached through a port, so losing one is a handled
condition with a fixed outcome rather than an error that leaves a request
half-enforced. The built-in adapters run in process; `create_app` accepts a
`policy`, `inspectors`, and `audit_transport` to replace them.

| Condition | Behaviour | Reason code |
|---|---|---|
| No signing material | Every enforcement request is refused; not ready. | `identity_verification_unavailable` |
| Policy engine unreachable | Everything is denied. A side effect is denied in every mode. | `policy_engine_unavailable` |
| Policy engine unreachable, `GUARDRAIL_RESTRICTED_READ_ONLY_MODE=true` | Content inspection and read-only actions continue under the built-in policy. | `restricted_read_only_mode` |
| Any detector unreachable | Content is denied, even if another detector is healthy. | `content_inspection_unavailable` |
| Detectors disagree | Evidence is unioned, so one detector's finding is never outvoted by another's silence. | the policy's own reason |
| Audit transport down | Enforcement continues while events buffer, in order, up to `GUARDRAIL_AUDIT_BUFFER_SIZE`. | unchanged |
| Audit buffer full, `GUARDRAIL_AUDIT_MANDATORY=true` (default) | Enforcement blocks until the transport recovers; not ready. | `audit_durability_unavailable` |
| Audit buffer full, `GUARDRAIL_AUDIT_MANDATORY=false` | Enforcement continues; events past the bound are counted and dropped. | unchanged |
| Approval expired | The action must be reviewed again. | `invalid_or_expired_approval` |
| Approval store unreachable | An action that needs or presents an approval is denied. | `approval_store_unavailable` |
| Red-team regression | The release gate fails. | n/a |

`/health/ready` reports `audit` as `durable`, `buffering`, or `blocked`.

## Audit, incidents, and metrics

Every decision is kept in a bounded decision log (`GUARDRAIL_DECISION_LOG_SIZE`)
exactly as it was returned to the caller: redacted evidence, no raw content.

| Endpoint | Roles | Purpose |
|---|---|---|
| `GET /v1/decisions/{decision_id}` | `auditor`, `reviewer` | One decision and its evidence. |
| `GET /v1/decisions?trace_id=...` | `auditor`, `reviewer` | Every decision made for a trace. |
| `POST /v1/approvals/{approval_id}/reject` | `reviewer` | Refuse a proposed action. A rejection is final: it cannot be approved afterwards or consumed. |
| `POST /v1/incidents` | `reviewer` | Open a case citing one or more decisions, with a severity. |
| `GET /v1/incidents`, `GET /v1/incidents/{incident_id}` | `auditor`, `reviewer` | Read the tenant's cases. |
| `PATCH /v1/incidents/{incident_id}` | `reviewer` | Set status, disposition (`true_positive`, `false_positive`, `benign`), and remediation. |

All of these are scoped to the caller's tenant. Another tenant's decision,
approval, or incident is reported as missing, and an incident may only cite
decisions the caller's tenant can read. A canary sighting opens a `critical`
incident on its own; further sightings in the same trace join that case.

`GET /metrics` serves the Prometheus exposition format: decisions by
enforcement point, verdict, and reason code; a decision-latency histogram;
detector-latency histogram; credential rejections; approvals by status; audit
events pending, in flight, and dropped; and open incidents. Tenant and identity are never labels. The endpoint is
unauthenticated like the health probes, so expose it to the scraper only.

The decision log is in memory and per process. Approvals and incidents can be
kept in a database; see [Durable approvals and incidents](#durable-approvals-and-incidents).

## Sandboxed code execution

The gateway decides actions; the application that asked runs them. The one
exception is code. `run_code` is a registered tool, and
`POST /v1/actions/execute` decides it exactly as `/v1/inspect/action` would
and, only if the verdict is `allow`, runs it in a sandbox and returns the
decision with the result. It is offered when `GUARDRAIL_SANDBOX_IMAGE` names an
image that has Python.

Each run is a new container, removed when it ends:

| Control | How |
|---|---|
| No host filesystem | Nothing is mounted; the root filesystem is read-only; `/tmp` is a 16 MB in-memory scratch that cannot hold executables. |
| No network | `--network none`. A run that asks for `network: true` must declare an `external` side effect, so it needs a reviewer's approval of that exact code. |
| No privileges | Unprivileged user, every capability dropped, `no-new-privileges`. |
| CPU, memory, processes | `GUARDRAIL_SANDBOX_CPUS` (0.5), `GUARDRAIL_SANDBOX_MEMORY_MB` (128, no swap), `GUARDRAIL_SANDBOX_PIDS` (32). |
| Time and output | `GUARDRAIL_SANDBOX_TIMEOUT_SECONDS` (10) and `GUARDRAIL_SANDBOX_OUTPUT_BYTES` (65536). A run past either has its container killed. |

Only Python is accepted, only the `operator` role may propose it, and the code
is passed on standard input, never on a command line. The code and its output
are returned to the caller and are not written to the audit trail or metrics;
the run is recorded by its outcome and the decision's digest. When no sandbox
can start, the request is refused with `503 sandbox_unavailable` before the
decision is made, so an approval is never spent on code that did not run.

An ordinary container shares the host kernel. For hostile code set
`GUARDRAIL_SANDBOX_OCI_RUNTIME` to a runtime with a stronger boundary, such as
gVisor's `runsc`. The gateway needs access to a container runtime
(`GUARDRAIL_SANDBOX_RUNTIME`, default `docker`) to offer this, which is itself
a privilege: run the replicas that execute code separately from the rest.

## Policy as code

By default decisions are made by the built-in policy, in process. Set
`GUARDRAIL_OPA_URL` to ask an [Open Policy Agent](https://www.openpolicyagent.org/)
server instead, so policy can be reviewed, tested, and released separately
from the gateway.

[`deploy/opa/policy`](deploy/opa/policy) is a bundle that decides exactly as
the built-in policy does: `guardrail/content.rego` for the input, context, and
output points, `guardrail/action.rego` for tools, and `guardrail/data.json`,
the tool registry generated from the gateway's own. Start from it and add
rules.

The gateway tells OPA what it knows, and OPA decides:

- For content: the enforcement point, trust level, tenants, the categories of
  detector evidence, and the tenant's rule for each sensitive category.
- For an action: identity, roles, tool, resource, side effect, a digest of the
  arguments, and what the gateway's parsers found wrong with them.

Content and arguments are never sent. Two things hold whatever a bundle says:

- Arguments the gateway could not parse or found unsafe are denied. A bundle
  can add restrictions; it cannot remove that one.
- No answer, a slow answer (`GUARDRAIL_OPA_TIMEOUT_SECONDS`, default 1), an
  undefined decision, and a malformed one are all `policy_engine_unavailable`,
  handled as under [Fail-safe behaviour](#fail-safe-behaviour). The replica
  also reports not ready, since it would deny everything.

The bundle has Rego unit tests. CI also runs a real OPA and checks the bundle
against the built-in policy across several thousand inputs, then runs the
whole adversarial suite with OPA deciding.

```bash
docker run --rm -v "$PWD/deploy/opa/policy:/policy:ro" openpolicyagent/opa:1.9.0-static test /policy -v
```

## Durable approvals and incidents

By default approvals and incident cases live in memory: they are lost on
restart and each replica has its own. Set `GUARDRAIL_DATABASE_URL` to keep them
in a database instead.

| URL | Use |
|---|---|
| `postgresql://user@host/dbname` | Shared by every replica. Needs the `postgres` extra, which the container image includes. |
| `sqlite:///path/to/gateway.db` | Durable for a single node, with no extra service. |

The tables are created on first use. An approval is consumed by one
conditional `UPDATE`, so when several replicas present the same approval at
once the database lets exactly one of them use it. Expiry is compared against
the gateway's clock, so replicas need synchronized time.

When the database is unreachable:

| Request | Behaviour |
|---|---|
| An action that needs approval, or presents one | Denied with `approval_store_unavailable`. |
| Content inspection, and actions that need no approval | Unaffected. |
| Reading or adjudicating an approval or incident | `503` with `store_unavailable`. |
| A canary sighting | Still denied and audited; the incident is not recorded. |
| `/health/ready` | Stays ready and reports `stores: unavailable`. |
| `/metrics` | Still served; `guardrail_store_available` reads 0. |

The decision log stays in memory, and so do the quota and budget counters;
decisions are published durably as events instead.

## Events, analytics, and tracing

Every decision, credential refusal, and re-identification is published as one
JSON event with an `event_id`, a `schema_version`, and the time it was decided.
Events carry reason codes and evidence categories, never content, arguments,
or evidence excerpts.

| Setting | Effect |
|---|---|
| `GUARDRAIL_KAFKA_BOOTSTRAP_SERVERS` | Publish events to Kafka instead of keeping them in process. Needs the `kafka` extra, which the container image includes. |
| `GUARDRAIL_KAFKA_TOPIC` | Topic name; default `guardrail.security-events`. |
| `GUARDRAIL_KAFKA_CLIENT_CONFIG` | JSON object of extra `kafka-python` producer options, such as TLS and SASL. |
| `GUARDRAIL_OTLP_ENDPOINT` | Export decision traces to an OTLP/HTTP collector. Needs the `otel` extra, which the container image includes. |

The producer is idempotent and waits for every in-sync replica; neither can be
configured away. Events are keyed by tenant, so one tenant's events stay in
order. Publishing happens on a background sender, so a decision does not wait
on a broker. A broker that is down, including at startup, is the audit outage
described under [Fail-safe behaviour](#fail-safe-behaviour): events buffer in
order, an event the broker refuses is sent again before anything newer, and
with mandatory audit the gateway blocks once the buffer is full.

Each enforcement call is one span with a child span per detector. Spans carry
the enforcement point, verdict, reason code, policy version, and evidence
categories; they never carry content, tenant, or identity.

[`deploy/`](deploy) holds the analytics side:

- [`clickhouse/schema.sql`](deploy/clickhouse/schema.sql) consumes the topic
  into a `ReplacingMergeTree` table and defines an hourly rollup of block
  rates and latency percentiles.
- [`grafana/dashboards/guardrail-gateway.json`](deploy/grafana/dashboards/guardrail-gateway.json)
  charts the `/metrics` endpoint: verdicts, block rates, decision and detector
  latency, approvals, audit delivery, and incidents.
- [`prometheus/alerts.yml`](deploy/prometheus/alerts.yml) alerts on dropped or
  backlogged audit events, a dependency failing closed, open incidents, and
  latency.

The unit suite checks these files against the gateway: every published field
has a column, and every metric a panel or alert names is one the gateway
exports. The adapter was also run against a real Kafka broker by hand; no
broker, ClickHouse, or Grafana instance runs in CI.

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

The suite authenticates like any other caller, so it also attacks the credential
path itself: unauthenticated requests, forged and expired credentials, bodies
that claim another identity or tenant, approvals attempted without the reviewer
role, self-approval by the requester, and another tenant reaching for an
approval. Run it against a live gateway with the signing material that gateway
verifies:

```bash
export GUARDRAIL_JWT_SECRET="$(openssl rand -hex 32)"
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
  that the successful run tested the PR's current head SHA, then waits for
  every other check on that commit (for example external secret scanning) and
  refuses to merge over one that failed or is still running. It preserves the
  PR's individual commits with a merge commit.

Apply `automerge` manually to other PRs only when they are ready to merge after
all CI gates succeed.
