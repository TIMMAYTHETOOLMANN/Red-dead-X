-- Historical-tracing DB — ClickHouse migration 0001
-- High-speed columnar store of the address-interaction firehose.
--
-- Scaffold only: ClickHouse mirrors the Postgres edge table (db/postgres/0002)
-- but is optimised for high-volume, append-only ingestion from the Forged Node
-- firehose and fast anomaly/lineage scans across 100+ networks. No app reads it.

CREATE TABLE IF NOT EXISTS address_interactions
(
    chain         LowCardinality(String),
    from_address  String,
    to_address    String,
    -- 'transfer' | 'call' | 'approve' | 'deploy' | 'delegatecall' | 'bridge'.
    interaction   LowCardinality(String) DEFAULT 'call',
    tx_hash       String,
    block_number  UInt64,
    occurred_at   DateTime64(3, 'UTC'),
    -- Ingestion timestamp (firehose receive time).
    ingested_at   DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY (chain, toYYYYMM(occurred_at))
ORDER BY (chain, from_address, to_address, occurred_at);

-- Forward-traversal helper: edges keyed by destination, for "who reached X?".
CREATE TABLE IF NOT EXISTS address_interactions_by_to
(
    chain         LowCardinality(String),
    to_address    String,
    from_address  String,
    interaction   LowCardinality(String) DEFAULT 'call',
    tx_hash       String,
    block_number  UInt64,
    occurred_at   DateTime64(3, 'UTC')
)
ENGINE = MergeTree
PARTITION BY (chain, toYYYYMM(occurred_at))
ORDER BY (chain, to_address, from_address, occurred_at);
