# Red-dead-X

Local-first, evidence-heavy, bounty-program-compliant system for hunting
blockchain vulnerabilities across the **BugRap (D5) ecosystem** — every program,
every network, every bounty type — and turning them into reportable findings.
It began as a deep **SOEX PremiumCVT** (Solana) audit scaffold and now extends to
multi-chain forensic analysis powered by the **thirdweb SDK** (TypeScript v5 + .NET).

Everything lives in [`soex-premiumcvt-audit/`](./soex-premiumcvt-audit).

## What this gives you

- **Guardrailed scaffold** — read-only by default (`READ_ONLY=true`, `ALLOW_TX=false`), keys git-ignored.
- **Read-only collectors** — `npm run inventory` (known accounts) and `npm run program-info`
  (program + upgrade authority metadata). No transactions.
- **Deep analysis toolset** (see `soex-premiumcvt-audit/docs/05-deep-analysis.md`):
  - `npm run analyze-idl` — static IDL analyzer that walks every instruction through
    **ten** lanes (authority, account-substitution, token-custody, economic, referral,
    upgrade/admin, CPI/arbitrary-program, init-safety, DoS/compute, and cross-instruction
    correlation), ranks candidates by composite **risk** (severity × confidence), assigns
    stable fingerprints, and emits JSON + Markdown + **SARIF**. Supports baseline
    suppression (`BASELINE_PATH`) and CI severity gating (`FAIL_ON`).
  - `npm run invariant-sim` — economic invariant simulator (exact u64 math: fee rounding,
    overflow, value conservation, supply cap, mint→burn round-trip / dust drain, fee
    monotonicity, and deep referral-chain reward simulation).
  - `npm run poc` — guardrailed PoC harness ("hands"): simulates by default, and only sends on
    localnet/devnet when `EXECUTE=true ALLOW_TX=true`. Mainnet sends are always refused.
  - `npm test` / `npm run typecheck` — tests for the pure-logic analyzers and a full TypeScript pass.
- **Multi-chain forensics** (BugRap / D5 ecosystem — see `soex-premiumcvt-audit/docs/06-multichain-forensics.md`):
  - `npm run surface-map` — enumerate and **payout-rank** every (program × chain × bounty-type) cell
    across the registry so no attack surface is skipped.
  - `npm run forensic-scan` — unified offline report folding Solana IDL + EVM ABI findings into one
    combined SARIF + Markdown brief.
  - `npm run evm-recon` — read-only live EVM recon via the **thirdweb** SDK (resolves ABI +
    proxy implementation, then runs the EVM hunting lanes).
  - `targets/bugrap-programs.json` — the program registry (in-scope chains, bounty classes, contracts,
    payout bands) with a **scope-compliance gate** that refuses out-of-scope targets.
- **thirdweb SDK integration** (TypeScript v5 + .NET — see `soex-premiumcvt-audit/docs/07-thirdweb-sdk.md`):
  read-only contract/ABI/implementation resolution across every EVM chain; a `dotnet/ThirdwebForensics`
  console tool mirrors the TypeScript recon for .NET teams (`make dotnet-build`).
- **A methodical playbook** in `soex-premiumcvt-audit/docs/`:
  - `00-scope-and-rules.md` — scope, rules of engagement, what to pin first.
  - `01-hunting-lanes.md` — six lanes: authority, PDA/account-substitution, economic invariants,
    referral abuse, upgrade/admin risk, local-only DoS.
  - `02-invariants.md` — economic invariant catalog + edge cases.
  - `03-triage-rubric.md` — severity rubric and the "don't report tool noise" bar.
  - `04-daily-loop.md` — the repeatable hunt loop and command reference.
  - `05-deep-analysis.md` — the analyzer, invariant simulator, and PoC harness in detail.
  - `06-multichain-forensics.md` — the multi-chain forensic system (registry, chain catalog,
    bounty taxonomy, EVM analyzer, attack-surface mapper, unified report).
  - `07-thirdweb-sdk.md` — leveraging the thirdweb SDK (TypeScript v5 + .NET), env setup, guardrails.
- **Templates** — `templates/finding-template.md`, `notes/instruction-account-matrix.md`.

## Quick start

```bash
cd soex-premiumcvt-audit
cp .env.example .env        # then fill in pinned values (never guess the program ID)
npm install
make verify                 # check toolchain (after installing the Solana stack)
make safe-config            # pin Solana CLI to devnet
make inventory              # read-only inventory of targets/accounts.txt
make program-info           # read-only program + upgrade-authority metadata
make analyze-idl            # deep static IDL analysis (six lanes, ranked findings)
make invariant-sim          # economic invariant simulation (fee/overflow/conservation)
make surface-map            # payout-ranked attack-surface map across the BugRap ecosystem
make forensic-scan          # unified Solana + EVM forensic report (offline)
make test                   # run analyzer/invariant tests
```

## Multi-chain forensics & thirdweb

```bash
cd soex-premiumcvt-audit

# Map every program/chain/bounty-type cell, ranked by expected payout.
npm run surface-map

# Live read-only EVM recon via thirdweb (TypeScript v5).
THIRDWEB_SECRET_KEY=... EVM_CHAIN=ethereum EVM_ADDRESS=0x... \
  BUGRAP_PROGRAM=bitget npm run evm-recon

# .NET equivalent.
make dotnet-build
```

See `docs/06-multichain-forensics.md` and `docs/07-thirdweb-sdk.md` for the full workflow.

## Pin these before testing

Fill from the official bounty portal or official SOEX source (do **not** guess):

```bash
TARGET_PROGRAM_ID=""
TARGET_CLUSTER="devnet"     # devnet/localnet preferred unless bounty explicitly allows mainnet PoC
SOURCE_REPO=""
IDL_PATH=""
PROGRAM_UPGRADE_AUTHORITY=""
KNOWN_ACCOUNTS_FILE="targets/accounts.txt"
```

> Scope is **Blockchain → PremiumCVT** only. Web/app/API/account testing is out of scope unless the
> bounty page explicitly expands it. See `soex-premiumcvt-audit/docs/00-scope-and-rules.md`.
