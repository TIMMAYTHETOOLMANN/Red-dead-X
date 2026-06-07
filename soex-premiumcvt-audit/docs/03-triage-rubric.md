# 03 — Report Triage Rubric

Prioritize findings before writing them up.

| Priority | What to prove |
|----------|---------------|
| **Critical** | Direct theft/loss of locked SOL/SOEX/assets, unauthorized mint/burn, irreversible reward drain |
| **High** | Unauthorized state mutation, bypassed access control, broken custody invariant, claim double-spend |
| **Medium** | Reward/accounting corruption with bounded loss, locked funds under common conditions |
| **Low** | Misconfiguration, weak assumptions, metadata mutability, minor rounding leakage |

## Do not report "tool says vulnerable"

Only report when you have **all** of:

- clear affected program/instruction
- preconditions
- minimal reproduction
- expected vs actual behavior
- economic/security impact
- bounded, non-destructive PoC
- screenshots/logs/hash evidence
- recommended fix

## The money trail

The money trail is likely in: who may mint, who may burn, who may claim, where value is locked,
how fees round, and whether every account passed into an instruction is exactly the account the
program thinks it is. That is the vault door, the hinge, and the little brass screw nobody checks.
