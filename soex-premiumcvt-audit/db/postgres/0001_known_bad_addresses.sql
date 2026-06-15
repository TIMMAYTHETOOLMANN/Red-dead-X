-- Historical-tracing DB — PostgreSQL migration 0001
-- Known-bad address registry (structured relational mapping).
--
-- Scaffold only: defines the catalog of addresses with a known-compromised /
-- malicious history, against which current BugRap targets are later cross-mapped
-- for breach-genealogy escalation. No application reads this yet.

CREATE TABLE IF NOT EXISTS known_bad_addresses (
    id              BIGSERIAL    PRIMARY KEY,
    -- Lower-cased on-chain address (EVM 0x..., or base58 for SVM, etc.).
    address         TEXT         NOT NULL,
    -- Chain key from scripts/lib/chains.ts (e.g. "ethereum", "solana").
    chain           TEXT         NOT NULL,
    -- Why the address is flagged: 'compromised', 'exploiter', 'mixer',
    -- 'phished', 'leaked-key', 'sanctioned', 'rugpull'.
    category        TEXT         NOT NULL,
    -- Free-form severity hint mirroring the analyzer taxonomy
    -- ('critical' | 'high' | 'medium' | 'low' | 'info').
    severity        TEXT         NOT NULL DEFAULT 'high',
    -- Human-readable label / incident name (e.g. "Ronin Bridge 2022").
    label           TEXT,
    -- Provenance of the flag (incident report URL, dataset name, breach dump id).
    source          TEXT,
    -- When the malicious activity is first known to have occurred.
    first_seen_at   TIMESTAMPTZ,
    -- Bookkeeping.
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT known_bad_addresses_unique UNIQUE (chain, address)
);

COMMENT ON TABLE known_bad_addresses IS
    'Known-compromised / malicious addresses used as roots for breach-genealogy tracing.';

CREATE INDEX IF NOT EXISTS idx_known_bad_addresses_address
    ON known_bad_addresses (address);
CREATE INDEX IF NOT EXISTS idx_known_bad_addresses_chain_category
    ON known_bad_addresses (chain, category);
