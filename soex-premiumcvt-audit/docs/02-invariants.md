# 02 — Economic Invariants and Edge Cases

Because CVT/HVT involve minting, rewards, fees, staking, and burn recovery, **every state transition
should conserve value.** Write the invariant first, then try to break it.

## Core invariants

```
vault_after            = vault_before + mint_payment - payouts - refunds
total_rewards_claimed <= total_rewards_allocated
burn_refund            = current_hvt_value - fee
fee                    = expected_basis_points * current_hvt_value
same reward cannot be claimed twice
unlock schedule cannot be accelerated
referral rewards cannot exceed configured maximum
mint count cannot exceed supply cap
```

> HVT burn-to-recover is documented as value **minus a 5% fee**. Confirm the exact basis points and
> rounding direction against source/IDL before asserting a bug.

## Edge cases to probe

| Class | Cases |
|-------|-------|
| Amounts | `0`, `1` base unit/lamport, near-`u64` max boundary |
| Fee math | fee rounds to zero, fee rounds up unexpectedly, decimals mismatch |
| Mint/burn timing | same user mints twice, burn immediately after mint |
| Unlock | claim immediately before and after unlock boundary |
| Referral | self-referral, cyclic referral, deep referral chain, rounding across chain |

## How to use this file

1. For each instruction, copy the relevant invariants into a local test in `tests/`.
2. Record pass/fail and the exact accounts/inputs in `findings/`.
3. A single broken invariant with bounded, non-destructive reproduction is a candidate report.

## Invariant tracking table (fill per instruction)

| Instruction | Invariant | Test location | Result | Notes |
|-------------|-----------|---------------|--------|-------|
| | | | | |
