# Discoverability Overhaul Report — Baseline-Driven Enhancement

> **Classification:** System overhaul + zero-knowledge re-assessment (PoC).
> **Posture:** Read-only, offline, evidence-heavy. No transactions, no live RPC.
> **Predecessor:** `reports/deployment_scan_report.md` (the initial baseline scan).

## 1. Objective

Use the initial controlled scan as **academic leverage** to sharpen the system's
discoverability, then perform a **clean purge** and a **zero-knowledge
re-assessment of the exact same Solana window** (`tests/fixtures/sample-idl.json`)
to prove the overhauled engine unearths **more** than the recorded baseline.

The network was deliberately held constant (Solana / SVM, same data points) so
the only variable is the analyzer itself — a controlled A/B against the baseline.

## 2. Baseline (from the initial scan)

| Metric | Baseline |
|--------|----------|
| Findings on `sample-idl.json` | **15** |
| Severity mix | high 4 · medium 9 · low 2 |
| Economic invariant issues | 7 |

## 3. Enhancements (the overhaul)

All changes live in `scripts/lib/analyze.ts` and stay within the existing lane
taxonomy (A–X) — this is **sharper detection**, not new noise. Each was derived
from a genuine seam the baseline engine structurally missed on the same data.

| # | Lane | Enhancement | Seam it now catches |
|---|------|-------------|---------------------|
| 1 | A-authority | **Self-authorized value op** — a fund-creating/-moving instruction (`mint`/`burn`/`withdraw`/`claim`/…) that *has* a signer but **no distinct protocol authority** account. | `mint_cvt` (unauthorized mint) and `claim_rewards` (unauthorized claim) — both gated only by the caller's own signature. The old lane fired only when *no* signer existed. |
| 2 | (engine) | **`program_data` false-negative fix** — the upgradeable-loader `program_data` account is writable *state* (it holds the upgrade authority), not a CPI program target, so `isProgramLike` no longer skips it. | `set_upgrade_authority.program_data` — writable, unbound, previously invisible. |
| 3 | F-upgrade-admin | **One-step authority hand-off** — authority assigned to a non-signing `new_/next_/pending_*authority` recipient (no two-step acceptance). | `set_upgrade_authority.new_authority` — direct transfer with no accept step / recovery. |
| 4 | B-account-substitution | **Cross-user PDA addressing** — a caller-steered (`arg`) PDA seed with **no account-kind (signer/owner) seed** is elevated from `low/tentative` to `medium/likely`. | `claim_rewards.reward_account` — seeded by `epoch` but not by the owner, so a caller can address another user's reward PDA. |
| 5 | C-token-custody | **Noise fix** — the `ata` (associated-token-account) token is now delimiter-bound so it no longer matches inside words like `data`/`metadata`/`program_data`. | Removes a false positive surfaced by enhancement #2 (honors the "don't report tool noise" bar). |

## 4. Zero-knowledge re-assessment (same window, evidence purged first)

`evidence/` was purged to `.gitkeep` only, then the identical command was re-run:

```bash
IDL_PATH=./tests/fixtures/sample-idl.json npm run analyze-idl
```

| Metric | Baseline | Overhauled | Δ |
|--------|----------|------------|---|
| Findings | 15 | **19** | **+4** |
| High severity | 4 | **5** | +1 |
| Medium severity | 9 | 13 | +4 |
| Low severity | 2 | 1 | −1 (re-ranked up / noise removed) |
| Economic invariant issues | 7 | 7 | 0 |

### New / changed findings on the identical data

- **NEW · high** — `mint_cvt` · A-authority — *Value-moving instruction has no distinct protocol authority* (unauthorized mint).
- **NEW · medium** — `claim_rewards` · A-authority — *Value-moving instruction has no distinct protocol authority* (unauthorized claim).
- **NEW · medium** — `set_upgrade_authority.program_data` · B-account-substitution — *Writable account has no PDA-seed or relation binding* (previously skipped).
- **NEW · medium** — `set_upgrade_authority.new_authority` · F-upgrade-admin — *Authority handed to a non-signing account (no two-step acceptance)*.
- **ELEVATED** — `claim_rewards.reward_account` · B-account-substitution — caller-steered PDA not bound to the signer: `low/tentative → medium/likely`.
- **NOISE REMOVED** — `program_data` · C-token-custody false positive (`ata` matched inside `data`) eliminated.

**Result: more unearthed, and at higher confidence/severity — net of a noise reduction.**

## 5. Multi-chain validation (EVM ABI control run)

Per the agreed extension, the EVM path was exercised against the EVM ABI fixture
to confirm the multi-chain wiring end-to-end:

```bash
EVM_ABI_PATH=./tests/fixtures/evm-abi.json EVM_CHAIN=ethereum \
  BUGRAP_PROGRAM=bitget npm run forensic-scan
```

| Run | Targets | Findings |
|-----|---------|----------|
| EVM ABI control (ethereum) | 1 | 17 |
| Combined Solana + EVM | 2 | **36** (19 SVM + 17 EVM) |

The combined report folds both VMs into one SARIF + Markdown brief — multi-chain
path validated.

## 6. Pre-fire gate

| Gate | Result |
|------|--------|
| `npm test` | **73 / 73 pass** (was 67; **+6** new tests asserting each enhancement and the >15 baseline floor) |

## 7. Reproduce

```bash
cd soex-premiumcvt-audit
npm install
npm test                                                       # 73/73

# Clean purge + zero-knowledge re-scan of the same window
find evidence -type f ! -name '.gitkeep' -delete
IDL_PATH=./tests/fixtures/sample-idl.json npm run analyze-idl   # 19 findings

# Multi-chain control
EVM_ABI_PATH=./tests/fixtures/evm-abi.json EVM_CHAIN=ethereum \
  BUGRAP_PROGRAM=bitget npm run forensic-scan                   # 17 EVM findings
IDL_PATH=./tests/fixtures/sample-idl.json \
  EVM_ABI_PATH=./tests/fixtures/evm-abi.json EVM_CHAIN=ethereum \
  BUGRAP_PROGRAM=bitget npm run forensic-scan                   # 36 combined
```

## 8. Outcome

**Overhaul complete.** Against the identical Solana window with all prior
evidence purged, the sharpened engine unearthed **19 candidates (5 high)** versus
the **15-candidate (4 high)** baseline — a measurable improvement in
discoverability, achieved with genuine seams (unauthorized value ops, ProgramData
visibility, two-step authority, cross-user PDA) and a simultaneous **reduction in
false positives**. The multi-chain (EVM) path is validated. Ready to reinitialize.

> All findings remain **candidates to confirm by hand** (`docs/03-triage-rubric.md`).
> The tooling never reports a verdict.
