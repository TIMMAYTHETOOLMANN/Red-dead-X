# 04 — Daily Hunt Loop

A repeatable loop. Each step writes evidence so findings are reproducible.

1. **Pin scope and addresses.** Confirm program ID, cluster, source/IDL in `.env` (see `docs/00`).
2. **Inventory known accounts read-only.** `npm run inventory` → writes `evidence/inventory-*.json`.
3. **Collect program/upgrade metadata.** `npm run program-info` (or `solana program show`) → `evidence/`.
4. **Run the deep static IDL analyzer.** `npm run analyze-idl` → ranked candidate findings +
   auto-built instruction/account matrix in `evidence/idl-analysis-*` (see `docs/05`).
5. **Refine the instruction/account matrix** in `notes/instruction-account-matrix.md` from the
   auto-built one plus source.
6. **Write invariants before exploit ideas** (`docs/02-invariants.md`), per instruction, and run
   `npm run invariant-sim` to surface fee/overflow/conservation seams.
7. **Test wrong-authority and wrong-account cases** (lanes A & B), following the analyzer's leads.
8. **Test mint/burn/claim/referral edge cases** (lanes C & D).
9. **Prove candidates with the guardrailed PoC harness** `npm run poc` (simulate first; execute only
   on localnet/devnet with `EXECUTE=true ALLOW_TX=true`).
10. **Save every run to `evidence/`.**
11. **Promote** only reproducible, impact-clear issues to `reports/` using `templates/finding-template.md`.

## Quick command reference

| Goal | Command |
|------|---------|
| Verify toolchain | `make verify` |
| Safe devnet config | `make safe-config` |
| Read-only account inventory | `make inventory` |
| Program/upgrade metadata | `make program-info` |
| Deep static IDL analysis | `make analyze-idl` |
| Economic invariant simulation | `make invariant-sim` |
| Guardrailed PoC (simulate/execute) | `make poc POC_PLAN=...` |
| Run tests | `make test` |
| Type-check | `make typecheck` |
| Local validator | `make validator` |
| Start session notes | `make notes` |

## Session start

```bash
make notes          # stamps notes/session-start.txt and ensures dirs exist
cp .env.example .env # then fill in pinned values
```
