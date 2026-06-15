-- Historical-tracing DB — PostgreSQL migration 0002
-- Address interaction edges + target watchlist (relational graph).
--
-- Scaffold only: defines the directed interaction graph used to traverse from a
-- known-bad root (db 0001) to a current BugRap target, and the watchlist of
-- targets whose risk should be escalated on any lineage hit. No app reads this.

-- Current BugRap targets we want to escalate when lineage touches them.
CREATE TABLE IF NOT EXISTS watched_targets (
    id              BIGSERIAL    PRIMARY KEY,
    address         TEXT         NOT NULL,
    chain           TEXT         NOT NULL,
    -- Program key from targets/bugrap-programs.json (scope-compliance source).
    program         TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT watched_targets_unique UNIQUE (chain, address)
);

-- Directed edge: `from_address` interacted with `to_address` on `chain`.
-- One row per observed interaction (tx). Genealogy traversal walks these edges.
CREATE TABLE IF NOT EXISTS address_interactions (
    id              BIGSERIAL    PRIMARY KEY,
    chain           TEXT         NOT NULL,
    from_address    TEXT         NOT NULL,
    to_address      TEXT         NOT NULL,
    -- 'transfer' | 'call' | 'approve' | 'deploy' | 'delegatecall' | 'bridge'.
    interaction     TEXT         NOT NULL DEFAULT 'call',
    tx_hash         TEXT,
    block_number    BIGINT,
    occurred_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE address_interactions IS
    'Directed interaction edges traversed to build breach-genealogy lineage paths.';

CREATE INDEX IF NOT EXISTS idx_interactions_from ON address_interactions (chain, from_address);
CREATE INDEX IF NOT EXISTS idx_interactions_to   ON address_interactions (chain, to_address);
CREATE INDEX IF NOT EXISTS idx_interactions_txhash ON address_interactions (tx_hash);
