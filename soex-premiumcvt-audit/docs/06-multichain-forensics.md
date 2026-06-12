# 06 — Multi-chain forensics (BugRap / D5 ecosystem)

The original scaffold hunted one program (SOEX PremiumCVT) on one chain (Solana).
This layer generalises it into a deep, forensic, **multi-chain, multi-bounty-type**
system across the whole [BugRap](https://bugrap.io/) ecosystem — every program,
every network, every bounty type, every payout tier — while keeping the same
read-only, evidence-heavy, scope-compliant guardrails.

> Still candidate-driven: every engine emits **leads to confirm by hand**
> (docs/03-triage-rubric.md), never a verdict.

## The model (pure data + pure analyzers)

| Module | Role |
|--------|------|
| `lib/chains.ts` | Network catalog. Maps a chain key/id to its VM family (EVM / SVM / BTC), numeric chain id, and thirdweb chain handle. Routes each target to the right analyzer + SDK. |
| `lib/taxonomy.ts` | Every BugRap bounty type (smart-contract, auth, input-validation, info-leak, network-config, business-logic, wallet), each mapped to a severity ceiling, the engine(s) that cover it, and a USD payout band. |
| `lib/bugrap.ts` + `targets/bugrap-programs.json` | The program registry: each program's in-scope chains, accepted bounty classes, pinned contracts, and payout overrides. Includes the **scope-compliance gate** (`checkScope`/`assertInScope`). |
| `lib/evm_abi.ts` | Normalizes a JSON or human-readable EVM ABI (the EVM analog of `lib/idl.ts`). |
| `lib/evm_analyze.ts` | Deep static EVM analyzer. Nine lanes, **payout-weighted** ranking. |
| `lib/attack_surface.ts` | Cross-chain coverage mapper — enumerates every (chain × bounty-class) cell so nothing is skipped. |
| `lib/forensic_report.ts` | Folds Solana + EVM results into one combined SARIF + Markdown brief. |

## EVM hunting lanes (`evm_analyze.ts`)

Mirrors the Solana lanes for EVM contract surfaces:

- **EA — access control**: privileged state-mutating functions (`mint`, `withdraw`, `set*`) — verify `onlyOwner`/role.
- **EB — upgradeability**: `upgradeTo*`, `transferOwnership`, admin changes — verify current authority + timelock.
- **EC — arbitrary call**: `execute`/`multicall`/`(address,bytes)` forwarders — `call`/`delegatecall` to attacker code, approval draining.
- **ED — token approval**: `approve`/`permit`/`setApprovalForAll` — approval race, permit replay.
- **EE — signature replay**: signature-consuming functions missing a visible nonce/deadline.
- **EF — reentrancy**: value-moving / payable functions — CEI ordering + reentrancy guard (incl. read-only reentrancy).
- **EG — economic math**: value-moving numeric functions — overflow, rounding, share inflation (cross-ref `invariant-sim`).
- **EH — self-destruct**: `selfdestruct`/`kill` reachability.
- **EX — correlation**: privileged setters with no standard ownership/role getter — ad-hoc/missing access model.

Findings carry `risk` (severity × confidence) **and** `payoutWeight` (USD midpoint
of the severity band, program-tunable), and are ranked by expected payout first —
so the highest-value leads float to the top across the whole ecosystem.

## Commands

```bash
# Map the entire attack surface (every program, chain, bounty type), ranked by payout.
npm run surface-map
# ...or scope to one program:
BUGRAP_PROGRAM=bitget npm run surface-map

# Readiness check: which programs are "armed" (addresses pinned) vs "shell" (placeholders),
# so the coverage numbers above aren't read as more complete than the underlying data.
npm run registry-doctor
# ...or gate CI on it once addresses are expected to be pinned:
FAIL_ON_SHELL=true npm run registry-doctor

# Offline unified forensic report from a Solana IDL and/or an EVM ABI you already hold.
IDL_PATH=./targets/premiumcvt.json \
EVM_ABI_PATH=./targets/contract-abi.json EVM_CHAIN=ethereum \
BUGRAP_PROGRAM=bitget npm run forensic-scan

# Live read-only EVM recon via thirdweb (see docs/07-thirdweb-sdk.md).
THIRDWEB_SECRET_KEY=... EVM_CHAIN=ethereum EVM_ADDRESS=0x... \
BUGRAP_PROGRAM=bitget npm run evm-recon
```

Outputs land in `evidence/` (git-ignored) as JSON + SARIF + Markdown.

## Scope discipline still applies

Every active step is gated by the registry. When `BUGRAP_PROGRAM` is set, the
target chain / bounty-class / address is checked against that program's published
scope and **refused** if out of scope — the same philosophy as the Solana
guardrails (`READ_ONLY=true`, `ALLOW_TX=false`, mainnet sends refused). Always pin
concrete contract addresses and the exact in-scope surface from each official
program page before acting; the registry ships with placeholders, not guesses.
