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
| Red-team regression | The release gate fails. | n/a |

`/health/ready` reports `audit` as `durable`, `buffering`, or `blocked`.

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
  that the successful run tested the PR's current head SHA, and preserves the
  PR's individual commits with a merge commit.

Apply `automerge` manually to other PRs only when they are ready to merge after
all CI gates succeed.
