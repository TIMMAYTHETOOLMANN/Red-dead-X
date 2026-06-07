# 00 — Scope and Rules of Engagement

> Prime directive: work **only** inside the pasted bounty scope: **Blockchain → PremiumCVT**.
> Web / app / API / account testing is **out of scope** unless the bounty page explicitly expands it.

## Hard rules

- Local-first and evidence-heavy. No live-chain button-mashing, no broad scanners, no chaos.
- Prefer `localnet` / `devnet`. Use `mainnet` **only** for read-only inventory, or for a PoC that the
  bounty explicitly allows and that does not modify user funds or third-party state.
- Never guess the program / contract ID. Pin it from the official bounty portal or official SOEX source.
- Never commit real keys. `.env`, `*.keypair.json`, and `*.log` are git-ignored.
- Keep `READ_ONLY=true` and `ALLOW_TX=false` until a specific, bounded PoC requires otherwise.

## Pin these before testing

Fill from the official bounty portal or official SOEX source (do **not** guess):

```bash
TARGET_PROGRAM_ID=""
TARGET_CLUSTER="devnet"            # devnet/localnet preferred unless bounty explicitly allows mainnet PoC
SOURCE_REPO=""
IDL_PATH=""
PROGRAM_UPGRADE_AUTHORITY=""
KNOWN_ACCOUNTS_FILE="targets/accounts.txt"
```

Then mirror these into `.env` (copy from `.env.example`).

## Context, not targets

SOEX docs mention AK/SK storage, end-to-end encryption, CEX proxy behavior, and social-node
architecture. With a blockchain-only scope these are **context**, not targets.

## Product surface (where value lives)

- **CVT** — "next-gen NFT" / on-chain community certificate; minting triggers `$SOEX` release and
  airdrop mechanics.
- **HVT** — customizable pricing/currency options, staking reward eligibility, burn-to-recover value
  **minus a 5% fee**, and smart-contract lock-up claims.

Richest bug-hunt seams: **mint/burn math, account authority, reward accounting, referral logic,
token custody, and state invariants.**
