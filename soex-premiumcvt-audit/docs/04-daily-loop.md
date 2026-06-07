# 04 — Daily Hunt Loop

A repeatable loop. Each step writes evidence so findings are reproducible.

1. **Pin scope and addresses.** Confirm program ID, cluster, source/IDL in `.env` (see `docs/00`).
2. **Inventory known accounts read-only.** `npm run inventory` → writes `evidence/inventory-*.json`.
3. **Collect program/upgrade metadata.** `npm run program-info` (or `solana program show`) → `evidence/`.
4. **Build the instruction/account matrix** from IDL/source in `notes/instruction-account-matrix.md`.
5. **Write invariants before exploit ideas** (`docs/02-invariants.md`), per instruction.
6. **Test wrong-authority and wrong-account cases** (lanes A & B).
7. **Test mint/burn/claim/referral edge cases** (lanes C & D).
8. **Save every run to `evidence/`.**
9. **Promote** only reproducible, impact-clear issues to `reports/` using `templates/finding-template.md`.

## Quick command reference

| Goal | Command |
|------|---------|
| Verify toolchain | `make verify` |
| Safe devnet config | `make safe-config` |
| Read-only account inventory | `make inventory` |
| Program/upgrade metadata | `make program-info` |
| Local validator | `make validator` |
| Start session notes | `make notes` |

## Session start

```bash
make notes          # stamps notes/session-start.txt and ensures dirs exist
cp .env.example .env # then fill in pinned values
```
