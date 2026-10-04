-- ClickHouse analytics for gateway security events (design specification, section 14).
--
-- Events are consumed from the Kafka topic the gateway publishes to and stored
-- in a MergeTree table. They carry reason codes and evidence categories only:
-- the gateway never emits raw prompts, arguments, or evidence excerpts, so
-- there is nothing here to redact. tests/unit/test_analytics_assets.py fails
-- when the gateway emits a field this schema does not store.

CREATE DATABASE IF NOT EXISTS guardrail;

-- Reads the topic. Rows that fail to parse are skipped and counted by
-- ClickHouse rather than stalling the consumer.
CREATE TABLE IF NOT EXISTS guardrail.security_events_queue
(
    event_id String,
    schema_version UInt16,
    occurred_at String,
    decision_id String,
    request_id String,
    trace_id String,
    enforcement_point String,
    tenant_id String,
    policy_version String,
    verdict String,
    reason_code String,
    evidence_categories Array(String),
    latency_ms Float64,
    path String,
    count UInt32
)
ENGINE = Kafka
SETTINGS
    kafka_broker_list = 'kafka:9092',
    kafka_topic_list = 'guardrail.security-events',
    kafka_group_name = 'clickhouse-security-events',
    kafka_format = 'JSONEachRow',
    kafka_skip_broken_messages = 100;

CREATE TABLE IF NOT EXISTS guardrail.security_events
(
    event_id String,
    schema_version UInt16,
    occurred_at DateTime64(3, 'UTC'),
    decision_id String,
    request_id String,
    trace_id String,
    enforcement_point LowCardinality(String),
    tenant_id String,
    policy_version LowCardinality(String),
    verdict LowCardinality(String),
    reason_code LowCardinality(String),
    evidence_categories Array(LowCardinality(String)),
    latency_ms Float64,
    path String,
    count UInt32
)
-- The producer is idempotent, but a consumer restart can re-read a batch.
-- Replacing on event_id makes a re-read harmless.
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, occurred_at, event_id)
TTL toDateTime(occurred_at) + INTERVAL 13 MONTH;

CREATE MATERIALIZED VIEW IF NOT EXISTS guardrail.security_events_consumer
TO guardrail.security_events AS
SELECT
    event_id,
    schema_version,
    parseDateTime64BestEffort(occurred_at, 3, 'UTC') AS occurred_at,
    decision_id,
    request_id,
    trace_id,
    enforcement_point,
    tenant_id,
    policy_version,
    verdict,
    reason_code,
    evidence_categories,
    latency_ms,
    path,
    count
FROM guardrail.security_events_queue;

-- Hourly rollup behind the section 17 rates: block rate, unauthorized
-- tool-call and side-effect prevention, and approval demand, per tenant.
CREATE VIEW IF NOT EXISTS guardrail.decision_rates_hourly AS
SELECT
    toStartOfHour(occurred_at) AS hour,
    tenant_id,
    enforcement_point,
    count() AS decisions,
    countIf(verdict = 'deny') AS denied,
    countIf(verdict = 'transform') AS transformed,
    countIf(verdict = 'require_approval') AS held_for_approval,
    countIf(reason_code = 'prompt_injection_detected') AS injections_blocked,
    round(denied / decisions, 4) AS block_rate,
    quantile(0.5)(latency_ms) AS latency_p50_ms,
    quantile(0.95)(latency_ms) AS latency_p95_ms
FROM guardrail.security_events FINAL
WHERE enforcement_point NOT IN ('credential', 'operation')
GROUP BY hour, tenant_id, enforcement_point;
