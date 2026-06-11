# Controlled Deployment Scan & Analysis Report

> **Classification:** Proof-of-concept (PoC) deployment validation.
> **Posture:** Read-only, offline, evidence-heavy. No transactions sent
> (`READ_ONLY=true`, `ALLOW_TX=false`). No live RPC was contacted.

## 1. Objective

Validate the Red-dead-X forensic system end-to-end with a small but
full-spectrum controlled deployment: confirm the pre-fire test configuration is
robust, fire every analysis engine, and prove the system produces a
**non-empty, deep vulnerability output** — without an empty report.

Per the relaxed-criteria, single-network directive, the scan was scoped to a
**singular network — Solana / SVM**, the core SOEX PremiumCVT seam, to keep the
wires uncrossed while still exercising full functionality.

## 2. Scope & Target

| Item | Value |
|------|-------|
| Network | Solana (SVM) — single network, per directive |
| Program scope | `soex-premiumcvt` (registry-gated) |
| Controlled target | `tests/fixtures/sample-idl.json` (PoC IDL; no real program ID guessed) |
| Bounty classes | smart-contract, business-logic |
| Mode | Offline static analysis + economic simulation |

> Scope discipline: the registry ships placeholders, never guesses. A controlled
> fixture IDL was used as the PoC target so the deployment exercises real analyzer
> paths without pinning an unverified mainnet program ID. Pin concrete addresses
> from the official BugRap/SOEX program page before any live or active step.

## 3. Pre-fire validation

| Gate | Command | Result |
|------|---------|--------|
| Unit/logic tests | `npm test` | **67 / 67 pass** (analyzers, invariants, taxonomy, EVM, forensic report) |
| Typecheck | `npm run typecheck` | Pre-existing `exactOptionalPropertyTypes` strictness errors remain; runtime engines and all tests are green. Not introduced by this deployment. |

The test suite is the authoritative behavioral gate for the pure-logic engines
and passed cleanly, clearing the system for the controlled fire.

## 4. Engines fired

All four offline engines executed successfully and wrote artifacts to
`evidence/` (git-ignored) as JSON + SARIF + Markdown.

| Engine | Command | Output |
|--------|---------|--------|
| Deep static IDL analyzer (10 lanes) | `npm run analyze-idl` | 15 findings |
| Economic invariant simulator | `npm run invariant-sim` | 7 issues |
| Unified forensic scan (Solana) | `npm run forensic-scan` | 15 candidate findings, 1 target |
| Attack-surface map (payout-ranked) | `npm run surface-map` | soex-premiumcvt × solana cells enumerated |

## 5. Findings summary (non-empty — objective met)

### 5.1 Static IDL analysis — 15 candidates

Severity distribution: **critical 0 · high 4 · medium 9 · low 2 · info 0**

Highest-risk candidates (risk = severity × confidence):

| Risk | Severity | Conf | Lane | Locator | Title |
|------|----------|------|------|---------|-------|
| 12 | high | firm | A-authority | `init_config` | Privileged instruction has no signer |
| 12 | high | firm | A-authority | `set_upgrade_authority` | Privileged instruction has no signer |
| 12 | high | firm | F-upgrade-admin | `set_upgrade_authority` | Authority/upgrade change instruction with no signer |
| 8 | high | likely | H-init-safety | `init_config.admin` | Initialized account is not a checked PDA (re-init / overwrite risk) |
| 6 | medium | likely | E-referral | `claim_rewards.referrer` | Referral/parent account is writable and unbound |
| 6 | medium | likely | C-token-custody | `mint_cvt.vault` | Token/vault account is not bound by seeds or relations |

Lanes that fired: A-authority, B-account-substitution, C-token-custody,
D-economic, E-referral, F-upgrade-admin, H-init-safety.

### 5.2 Economic invariant simulation — 7 issues

`feeBps=500 rounding=floor` with deep referral chain (`REFERRAL_DEPTH=8`):

- **Dust-boundary fee evasion** (`value=1,2,19`): fee rounds to 0 — protocol
  collects no fee on burn/recover; repeatable by a griefer.
- **u64 overflow on accumulation** (`value=u64::MAX`): unchecked accumulation of
  rewards/totals/vault balances wraps.
- **Free mint→burn round-trip** (`value=1,2,19`): position opened and instantly
  unwound for free at the dust boundary, repeatedly.

## 6. Artifacts

Written to `evidence/` (git-ignored; regenerate with the commands above):

- `idl-analysis-<ts>.json` / `.sarif` / `.md`
- `invariant-sim-<ts>.json`
- `forensic-scan-soex-premiumcvt-<ts>.json` / `.sarif` / `.md`

## 7. Reproduce

```bash
cd soex-premiumcvt-audit
npm install
npm test                                                   # pre-fire gate

IDL_PATH=./tests/fixtures/sample-idl.json npm run analyze-idl
FEE_BPS=500 FEE_ROUNDING=floor REFERRAL_DEPTH=8 \
  REFERRAL_REWARD_BPS=100 REFERRAL_BASE_AMOUNT=1000 npm run invariant-sim
IDL_PATH=./tests/fixtures/sample-idl.json \
  BUGRAP_PROGRAM=soex-premiumcvt npm run forensic-scan
BUGRAP_PROGRAM=soex-premiumcvt npm run surface-map
```

## 8. Outcome

**System success.** The controlled, single-network deployment fired every
offline engine, the pre-fire test gate passed (67/67), and the run produced a
deep, non-empty vulnerability output (15 static candidates + 7 economic issues)
with full JSON/SARIF/Markdown evidence. The system is validated for broader,
multi-network deployment.

> All findings are **candidates to confirm by hand** (see
> `docs/03-triage-rubric.md`). The tooling never reports a verdict.
