/**
 * Economic invariant simulator.
 *
 * Turns the invariant catalog in `docs/02-invariants.md` into executable checks.
 * Everything is exact integer (BigInt) math so we model on-chain `u64` behavior
 * faithfully: overflow, fee rounding direction, and value conservation.
 *
 * Pure functions only. No network, no transactions.
 */

export const U64_MAX = (1n << 64n) - 1n;
export const BPS_DENOMINATOR = 10_000n;

export type Rounding = "floor" | "ceil";

export interface InvariantIssue {
  severity: "high" | "medium" | "low" | "info";
  invariant: string;
  detail: string;
  recommendation: string;
}

export interface SimParams {
  /** Fee in basis points (e.g. 500 = 5%). */
  feeBps: bigint;
  /** Direction the program rounds fees. */
  feeRounding: Rounding;
  /** Optional max supply cap for mint-count checks. */
  supplyCap?: bigint;
  /** Representative HVT/value amounts to probe (base units). */
  amounts: bigint[];
}

export const DEFAULT_PARAMS: SimParams = {
  // docs/02 documents burn-to-recover value minus a 5% fee.
  feeBps: 500n,
  feeRounding: "floor",
  supplyCap: undefined,
  amounts: [0n, 1n, 2n, 19n, 99n, 100n, 1_000n, 1_000_000n, U64_MAX],
};

/** fee = value * bps / 10_000, with explicit rounding direction. */
export function computeFee(value: bigint, bps: bigint, rounding: Rounding): bigint {
  const numerator = value * bps;
  if (rounding === "ceil") {
    return (numerator + BPS_DENOMINATOR - 1n) / BPS_DENOMINATOR;
  }
  return numerator / BPS_DENOMINATOR;
}

/** burn refund = value - fee (must never be negative or exceed value). */
export function burnRefund(value: bigint, bps: bigint, rounding: Rounding): bigint {
  return value - computeFee(value, bps, rounding);
}

/** True when `a + b` would exceed u64. */
export function addOverflowsU64(a: bigint, b: bigint): boolean {
  return a + b > U64_MAX;
}

/** True when `a * b` would exceed u64. */
export function mulOverflowsU64(a: bigint, b: bigint): boolean {
  return a * b > U64_MAX;
}

export function simulateInvariants(params: SimParams): InvariantIssue[] {
  const issues: InvariantIssue[] = [];
  const { feeBps, feeRounding, amounts, supplyCap } = params;

  for (const value of amounts) {
    if (value < 0n || value > U64_MAX) {
      issues.push({
        severity: "info",
        invariant: "amount in u64 range",
        detail: `Probe amount ${value} is outside [0, u64::MAX]; skipping value-specific checks.`,
        recommendation: "Constrain probe amounts to the on-chain u64 domain.",
      });
      continue;
    }

    const fee = computeFee(value, feeBps, feeRounding);
    const refund = burnRefund(value, feeBps, feeRounding);

    // Fee rounds to zero: a non-zero balance is burned/recovered with no fee taken.
    if (value > 0n && feeBps > 0n && fee === 0n) {
      issues.push({
        severity: "medium",
        invariant: "fee = bps * value (non-zero for non-zero value)",
        detail:
          `value=${value}, bps=${feeBps} → fee rounds to 0. The protocol collects no fee ` +
          `on this burn/recover, and a griefer can repeat at the dust boundary.`,
        recommendation:
          "Enforce a minimum fee (or reject amounts below the fee-rounding threshold). " +
          "Confirm the exact rounding direction against source.",
      });
    }

    // Refund conservation: refund must be within [0, value].
    if (refund < 0n || refund > value) {
      issues.push({
        severity: "high",
        invariant: "0 <= burn_refund <= value",
        detail: `value=${value} → refund=${refund}, which violates the conservation bound.`,
        recommendation: "Refund math underflows/overflows; clamp and use checked arithmetic.",
      });
    }

    // Ceil rounding at the dust boundary can take more than the whole value.
    if (fee > value) {
      issues.push({
        severity: "high",
        invariant: "fee <= value",
        detail: `value=${value}, bps=${feeBps} → fee=${fee} exceeds the value being burned.`,
        recommendation: "Cap fee at `value`; reject or special-case dust amounts.",
      });
    }

    // u64 overflow seam: doubling a near-max balance (e.g. reward accrual) overflows.
    if (addOverflowsU64(value, value) && value > 0n) {
      issues.push({
        severity: "medium",
        invariant: "no u64 overflow on accumulation",
        detail:
          `value=${value}: value + value exceeds u64::MAX. Any unchecked accumulation ` +
          `(rewards, totals, vault balances) at this magnitude wraps.`,
        recommendation:
          "Use checked_add/checked_mul (or saturating with explicit handling) on all " +
          "balance/reward accumulators.",
      });
    }

    // Supply cap boundary.
    if (supplyCap !== undefined && value > supplyCap) {
      issues.push({
        severity: "low",
        invariant: "mint_count <= supply_cap",
        detail: `value=${value} exceeds configured supply cap ${supplyCap}.`,
        recommendation: "Enforce the supply cap with a checked comparison before minting.",
      });
    }
  }

  return issues;
}
