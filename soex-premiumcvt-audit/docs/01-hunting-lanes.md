# 01 — Hunting Lanes

Six parallel lanes. For each instruction in the IDL/source, walk every lane and record results in
`notes/` and `findings/`. Promote only reproducible, impact-clear issues to `reports/`.

---

## A. Authority and signer checks

Look for any instruction where the intended authority is not enforced.

Target tests:

- `init_config` with non-admin signer
- `update_config` with non-admin signer
- `mint_cvt` with wrong payer
- `burn_hvt` for someone else's HVT
- `claim_rewards` for someone else's account
- `withdraw_fee` with non-treasury authority
- `set_price` with wrong community/CVT owner

Solana / Anchor red flags:

- missing `Signer<'info>`
- missing owner checks
- missing `has_one` constraints
- missing `seeds`/`bump` constraints
- unchecked `AccountInfo` used as a trusted PDA
- authority stored in account but not compared to signer
- CPI target program not pinned
- token account mint/owner not verified

---

## B. PDA and account-substitution bugs

For every instruction, build the matrix in `notes/instruction-account-matrix.md`:

| Instruction | Account | Expected owner | Expected PDA seeds | Must sign? | Token mint constraint? |

Then test wrong accounts:

- wrong config PDA
- wrong treasury token account
- wrong mint
- wrong metadata account
- wrong community account
- wrong referral parent
- wrong token program
- closed or uninitialized account

Metaplex token metadata uses PDAs derived from mint accounts, so NFT-like CVT/HVT logic should be
checked for correct mint-to-metadata binding, update authority, supply expectations, and
URI/metadata mutability assumptions.

---

## C. Economic invariant tests

Every state transition must conserve value. See `docs/02-invariants.md` for the full catalog and
edge cases. Core idea:

```
vault_after = vault_before + mint_payment - payouts - refunds
```

---

## D. Referral tree abuse

Model referral logic like a payment graph, not a profile feature.

Check:

- A refers A
- A refers B, B refers A
- A changes parent after rewards accrue
- same wallet appears at multiple depths
- reward rounding across long chains
- duplicate parent account injection
- unbounded recursion or compute exhaustion

---

## E. Upgrade / admin risk

Collect evidence with the read-only collector (`npm run program-info`) or:

```bash
solana program show "$TARGET_PROGRAM_ID"
```

Record:

- programdata address
- upgrade authority
- last deploy slot if available
- whether authority is single-key, multisig, or revoked

A live upgrade authority is not automatically a bug, but a mismatched or unintended authority can
support impact if it enables fund theft, mint manipulation, fee theft, or reward drain.

---

## F. Denial-of-service (local only)

DoS testing belongs on local validator / devnet with tiny, controlled inputs.

Check:

- a normal user can create state that blocks future mint/burn/claim
- unbounded vector/account growth
- compute budget exhaustion from valid referral depth
- state account cannot resize safely
- dust values trap funds

---

## Optional EVM lane (only if source confirms Solidity/Vyper)

If SOEX provides EVM contracts too, add Foundry + Slither. Treat Slither output as smoke, not gospel —
manual validation is where bounties hatch.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install slither-analyzer
slither . --config-file slither.config.json | tee evidence/slither.txt
```
