# 05 — Deep Analysis Tooling

The collectors in `docs/04` tell you *what is on chain*. These tools tell you
*where the bugs probably are* and let you *prove them safely*. They turn the six
hunting lanes (`docs/01`) and the invariant catalog (`docs/02`) into runnable
passes so no instruction/account pair is skipped.

All three are read-only by default and write timestamped evidence to
`evidence/`. They surface **candidates**, not verdicts — the triage rubric
(`docs/03`) still decides what becomes a report.

---

## 1. Static IDL analyzer — `npm run analyze-idl`

Loads the pinned IDL (`IDL_PATH`) and walks **every instruction through all six
lanes**, ranking candidate findings by severity and auto-building the
instruction/account matrix you would otherwise fill in by hand.

What it flags (deep, structural seams, not surface noise):

- **Lane A — authority:** privileged instructions with no signer; authority-like
  accounts that neither sign nor are bound by `relations`/seeds/address.
- **Lane B — account substitution:** writable accounts with no PDA-seed,
  pinned-address, or relation binding; PDA seeds derived from caller-supplied
  args (attacker-steerable PDAs).
- **Lane C — token custody:** token/vault accounts not bound by seeds/relations
  (mint/owner/token-program cannot be proven from the IDL).
- **Lane D — economic:** value-moving instructions taking numeric amounts (hand
  off to the invariant simulator).
- **Lane E — referral:** referral/parent accounts, with parent-injection flagged
  when they are writable and unbound.
- **Lane F — upgrade/admin:** authority/upgrade-change instructions, escalated
  when no signer is enforced.

It normalizes both the legacy (`isMut`/`isSigner`) and modern
(`writable`/`signer`/`pda`) Anchor IDL shapes. Output: `evidence/idl-analysis-*.json`
(machine-readable) and `evidence/idl-analysis-*.md` (findings table + matrix).

```bash
IDL_PATH=./targets/premiumcvt.json npm run analyze-idl
```

> Pin the real IDL first. Never guess it (`docs/00`).

## 2. Economic invariant simulator — `npm run invariant-sim`

Executes the invariant battery from `docs/02` with exact `BigInt` (u64) math:
fee rounding-to-zero at the dust boundary, fee exceeding value under ceil
rounding, burn-refund conservation, u64 overflow on accumulation, and supply-cap
breaches.

Configure (pin from source before trusting output):

```bash
FEE_BPS=500 FEE_ROUNDING=floor SUPPLY_CAP=10000 \
  PROBE_AMOUNTS=0,1,2,19,100,1000,u64max npm run invariant-sim
```

Output: `evidence/invariant-sim-*.json`.

## 3. Guardrailed PoC harness — `npm run poc` (the "hands")

Lets you actually exercise an instruction to prove a bug instead of only reading
state. It is deliberately constrained to stay bounty-compliant (`docs/00`):

- **Simulates by default** (`simulateTransaction`) — never broadcasts.
- **Sending requires ALL of:** `EXECUTE=true`, `ALLOW_TX=true`, and
  `CLUSTER ∈ {localnet, devnet}`. Mainnet/mainnet-beta sends are **always refused**.
- Signing keys come from git-ignored `*.keypair.json` files.

PoC plan (`POC_PLAN`) is a JSON file describing the instruction(s):

```json
{
  "feePayer": "./attacker.keypair.json",
  "signers": [],
  "instructions": [
    {
      "programId": "<base58>",
      "keys": [
        { "pubkey": "<base58>", "isSigner": false, "isWritable": true }
      ],
      "dataBase64": "<base64-encoded instruction data>"
    }
  ]
}
```

```bash
# Safe default: simulate only.
POC_PLAN=./targets/poc-plan.json CLUSTER=devnet npm run poc

# Prove it on a local validator (all guards must be set explicitly):
make validator   # in another terminal
POC_PLAN=./targets/poc-plan.json CLUSTER=localnet \
  EXECUTE=true ALLOW_TX=true npm run poc
```

Output: `evidence/poc-simulate-*.json` or `evidence/poc-execute-*.json`
(captured logs, compute units, and — on send — the confirmed signature).

---

## Tests and types

The pure-logic layers (IDL normalizer, lane analyzer, invariant math) are
covered by `npm test`. Run `npm run typecheck` for a full TypeScript pass.

```bash
npm test
npm run typecheck
```
