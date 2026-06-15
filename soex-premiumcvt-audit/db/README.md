# Historical-tracing database (scaffold)

Schema-only scaffold for the **breach-genealogy / historical-tracing** layer of
the "Forged Node" plan (Phase 3 — Deep Historical & Multi-Layered Forensics).

These migrations define the tables that will hold *known-bad* addresses and the
interaction graph between addresses, so the forensic pipeline can later escalate
a current BugRap target when it shares lineage with a known-compromised entity
(e.g. *Wallet A interacted with compromised Contract B in 2021, and Wallet A now
interacts with high-value Contract C → escalate C*).

## Status: migrations only — no live wiring

> Nothing in the offline analyzers reads these databases today. The analyzer core
> remains fully runnable offline against fixtures (`*_INPUT_PATH`). These files
> exist so a future, opt-in consumer service (fed by the Forged Node firehose)
> can stand the stores up without re-deriving the schema.

Two stores mirror the plan's split:

| Store        | Role                                                        | Migrations            |
|--------------|-------------------------------------------------------------|-----------------------|
| **PostgreSQL** | Structured relational mapping of addresses & known-bad tags | `postgres/*.sql`      |
| **ClickHouse** | High-speed columnar querying of the interaction firehose    | `clickhouse/*.sql`    |

## Applying (manually, when a store exists)

```sh
# PostgreSQL
psql "$POSTGRES_URL" -f db/postgres/0001_known_bad_addresses.sql
psql "$POSTGRES_URL" -f db/postgres/0002_address_interactions.sql

# ClickHouse
clickhouse-client --queries-file db/clickhouse/0001_address_interactions.sql
```

## Mapping to the report

When the historical-tracing pass is implemented, lineage paths surface in the
unified report through the `genealogy` field on a finding (see
`scripts/lib/forensic_report.ts`), which renders the **Breach genealogy paths**
section and feeds lineage edges into the **Attack-path graph**.
