# Red-dead-X

Local-first, evidence-heavy, bounty-program-compliant system for hunting **SOEX PremiumCVT**
blockchain vulnerabilities and turning them into reportable findings.

Everything lives in [`soex-premiumcvt-audit/`](./soex-premiumcvt-audit).

## What this gives you

- **Guardrailed scaffold** — read-only by default (`READ_ONLY=true`, `ALLOW_TX=false`), keys git-ignored.
- **Read-only collectors** — `npm run inventory` (known accounts) and `npm run program-info`
  (program + upgrade authority metadata). No transactions.
- **A methodical playbook** in `soex-premiumcvt-audit/docs/`:
  - `00-scope-and-rules.md` — scope, rules of engagement, what to pin first.
  - `01-hunting-lanes.md` — six lanes: authority, PDA/account-substitution, economic invariants,
    referral abuse, upgrade/admin risk, local-only DoS.
  - `02-invariants.md` — economic invariant catalog + edge cases.
  - `03-triage-rubric.md` — severity rubric and the "don't report tool noise" bar.
  - `04-daily-loop.md` — the repeatable hunt loop and command reference.
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
```

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
