"""
Economic invariant simulator.

Port of soex-premiumcvt-audit/scripts/lib/invariants.ts.

Turns the invariant catalog into executable checks. Everything is exact integer
math so we model on-chain u64 behavior faithfully: overflow, fee rounding
direction, and value conservation. Uses Python int with explicit u64 masking.

Pure functions only. No network, no transactions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


U64_MAX: int = (1 << 64) - 1
BPS_DENOMINATOR: int = 10_000

Rounding = Literal["floor", "ceil"]


@dataclass
class InvariantIssue:
    severity: str
    invariant: str
    detail: str
    recommendation: str


@dataclass
class SimParams:
    fee_bps: int = 500
    fee_rounding: Rounding = "floor"
    supply_cap: int | None = None
    amounts: list[int] = field(
        default_factory=lambda: [0, 1, 2, 19, 99, 100, 1_000, 1_000_000, U64_MAX]
    )


@dataclass
class ReferralChainParams:
    reward_bps: int = 1_000
    rounding: Rounding = "floor"
    depth: int = 5
    base_amount: int = 1_000
    max_total_reward: int | None = None


@dataclass
class ReferralChainResult:
    per_level: list[int]
    total_paid: int
    issues: list[InvariantIssue]


@dataclass
class RoundTripResult:
    deposited: int
    fee: int
    refund: int
    recovered: int
    dust_lost: int
    issues: list[InvariantIssue]


DEFAULT_PARAMS = SimParams(
    fee_bps=500,
    fee_rounding="floor",
    supply_cap=None,
    amounts=[0, 1, 2, 19, 99, 100, 1_000, 1_000_000, U64_MAX],
)


def compute_fee(value: int, bps: int, rounding: Rounding) -> int:
    """Compute fee = value * bps / 10_000 with explicit rounding direction.

    Args:
        value: The base amount (u64).
        bps: Fee in basis points (e.g. 500 = 5%).
        rounding: "floor" or "ceil".

    Returns:
        Fee amount as a Python int (u64-range).
    """
    numerator = value * bps
    if rounding == "ceil":
        return (numerator + BPS_DENOMINATOR - 1) // BPS_DENOMINATOR
    return numerator // BPS_DENOMINATOR


def burn_refund(value: int, bps: int, rounding: Rounding) -> int:
    """Compute burn refund = value - fee.

    Args:
        value: The base amount (u64).
        bps: Fee in basis points.
        rounding: "floor" or "ceil".

    Returns:
        Refund amount.
    """
    return value - compute_fee(value, bps, rounding)


def add_overflows_u64(a: int, b: int) -> bool:
    """Check whether a + b would overflow u64.

    Args:
        a: First operand.
        b: Second operand.

    Returns:
        True if a + b > U64_MAX.
    """
    return a + b > U64_MAX


def mul_overflows_u64(a: int, b: int) -> bool:
    """Check whether a * b would overflow u64.

    Args:
        a: First operand.
        b: Second operand.

    Returns:
        True if a * b > U64_MAX.
    """
    return a * b > U64_MAX


def simulate_invariants(params: SimParams) -> list[InvariantIssue]:
    """Run the economic invariant simulator against the given parameters.

    Args:
        params: SimParams with fee, rounding, supply cap, and probe amounts.

    Returns:
        List of InvariantIssue instances found.
    """
    issues: list[InvariantIssue] = []
    fee_bps = params.fee_bps
    fee_rounding = params.fee_rounding
    amounts = params.amounts

    for value in amounts:
        if value < 0 or value > U64_MAX:
            issues.append(
                InvariantIssue(
                    severity="info",
                    invariant="amount in u64 range",
                    detail=(
                        f"Probe amount {value} is outside [0, u64::MAX]; "
                        "skipping value-specific checks."
                    ),
                    recommendation="Constrain probe amounts to the on-chain u64 domain.",
                )
            )
            continue

        fee = compute_fee(value, fee_bps, fee_rounding)
        refund = burn_refund(value, fee_bps, fee_rounding)

        # Fee rounds to zero: a non-zero balance is burned/recovered with no fee taken.
        if value > 0 and fee_bps > 0 and fee == 0:
            issues.append(
                InvariantIssue(
                    severity="medium",
                    invariant="fee > 0 when value > 0 and bps > 0",
                    detail=(
                        f"value={value}, bps={fee_bps} → fee rounds to 0 "
                        f"({fee_rounding}). Dust amounts can be burned/recovered "
                        f"fee-free, draining the protocol."
                    ),
                    recommendation=(
                        "Add a minimum fee (e.g. 1 lamport) or refuse amounts below "
                        "the dust threshold."
                    ),
                )
            )

        # Refund conservation: refund + fee must equal value exactly.
        if refund + fee != value:
            issues.append(
                InvariantIssue(
                    severity="high",
                    invariant="refund + fee == value",
                    detail=(
                        f"value={value}, bps={fee_bps} → fee={fee}, refund={refund}, "
                        f"sum={refund + fee} ≠ {value}. Refund math underflows/overflows."
                    ),
                    recommendation=(
                        "Refund math underflows/overflows; clamp and use checked arithmetic."
                    ),
                )
            )

        # Ceil rounding at the dust boundary can take more than the whole value.
        if fee > value:
            issues.append(
                InvariantIssue(
                    severity="high",
                    invariant="fee <= value",
                    detail=(
                        f"value={value}, bps={fee_bps} → fee={fee} exceeds the value "
                        "being burned."
                    ),
                    recommendation=(
                        "Cap fee at `value`; reject or special-case dust amounts."
                    ),
                )
            )

        # u64 overflow seam: doubling a near-max balance overflows.
        if add_overflows_u64(value, value) and value > 0:
            issues.append(
                InvariantIssue(
                    severity="medium",
                    invariant="no u64 overflow on accumulation",
                    detail=(
                        f"value={value}: adding it to itself overflows u64 "
                        f"(2×{value} > {U64_MAX}). Reward accrual or mint paths "
                        "that double a balance are overflow candidates."
                    ),
                    recommendation=(
                        "Use checked_add / saturating_add for all accumulation; "
                        "probe near-max inputs in tests."
                    ),
                )
            )

        # Supply cap: minting this amount would exceed the cap.
        if params.supply_cap is not None and value > params.supply_cap:
            issues.append(
                InvariantIssue(
                    severity="high",
                    invariant="value <= supply_cap",
                    detail=(
                        f"value={value} > supply_cap={params.supply_cap}. "
                        "A single mint call can violate the cap."
                    ),
                    recommendation=(
                        "Enforce `require!(amount <= supply_cap - current_supply)` before "
                        "every mint."
                    ),
                )
            )

    return issues


def simulate_referral_chain(params: ReferralChainParams) -> ReferralChainResult:
    """Model the referral tree as a payment graph and check two seams.

    Checks reward rounding-to-zero across a deep chain, and total referral
    reward exceeding the configured maximum.

    Args:
        params: ReferralChainParams with depth, reward bps, and base amount.

    Returns:
        ReferralChainResult with per-level rewards and issues found.
    """
    per_level: list[int] = []
    issues: list[InvariantIssue] = []
    total_paid = 0

    for _ in range(params.depth):
        reward = compute_fee(params.base_amount, params.reward_bps, params.rounding)
        per_level.append(reward)
        total_paid += reward

    if params.base_amount > 0 and params.reward_bps > 0 and any(r == 0 for r in per_level):
        issues.append(
            InvariantIssue(
                severity="medium",
                invariant="referral reward > 0 when base > 0 and bps > 0",
                detail=(
                    f"base_amount={params.base_amount}, reward_bps={params.reward_bps} → "
                    "reward rounds to 0 at every level. Attacker can create a deep chain "
                    "for free and collect zero-cost ancestry."
                ),
                recommendation=(
                    "Enforce a minimum reward or minimum base amount to prevent dust-chain abuse."
                ),
            )
        )

    if params.max_total_reward is not None and total_paid > params.max_total_reward:
        issues.append(
            InvariantIssue(
                severity="high",
                invariant="total_referral_reward <= max_total_reward",
                detail=(
                    f"Total referral payout {total_paid} exceeds max_total_reward "
                    f"{params.max_total_reward} across {params.depth} levels."
                ),
                recommendation=(
                    "Enforce the max cap before each payout, or cap depth so "
                    "total cannot exceed the limit."
                ),
            )
        )

    if add_overflows_u64(total_paid, 0):
        issues.append(
            InvariantIssue(
                severity="medium",
                invariant="no u64 overflow on referral accumulation",
                detail=f"Cumulative referral reward {total_paid} exceeds u64::MAX.",
                recommendation=(
                    "Use checked_add when accumulating referral payouts."
                ),
            )
        )

    return ReferralChainResult(per_level=per_level, total_paid=total_paid, issues=issues)


def simulate_round_trip(
    amount: int,
    fee_bps: int,
    rounding: Rounding = "floor",
) -> RoundTripResult:
    """Model a deposit → burn-to-recover round-trip and check conservation.

    Args:
        amount: The amount deposited.
        fee_bps: Fee in basis points.
        rounding: Fee rounding direction.

    Returns:
        RoundTripResult with dust_lost and issues.
    """
    issues: list[InvariantIssue] = []
    fee = compute_fee(amount, fee_bps, rounding)
    refund = burn_refund(amount, fee_bps, rounding)
    recovered = refund
    dust_lost = amount - recovered

    if dust_lost < 0:
        issues.append(
            InvariantIssue(
                severity="critical",
                invariant="recovered <= deposited",
                detail=(
                    f"recovered={recovered} > deposited={amount}: value was created, "
                    "not conserved."
                ),
                recommendation=(
                    "Check burn/refund math — recovered amount must never exceed deposit."
                ),
            )
        )
    elif dust_lost > amount:
        issues.append(
            InvariantIssue(
                severity="high",
                invariant="dust_lost <= deposited",
                detail=(
                    f"dust_lost={dust_lost} > deposited={amount}: entire principal lost."
                ),
                recommendation="Review fee computation — fee cannot exceed principal.",
            )
        )

    return RoundTripResult(
        deposited=amount,
        fee=fee,
        refund=refund,
        recovered=recovered,
        dust_lost=dust_lost,
        issues=issues,
    )


def check_fee_monotonicity(
    fee_bps: int, amounts: list[int], rounding: Rounding = "floor"
) -> list[InvariantIssue]:
    """Check that fee is monotonically non-decreasing as amount increases.

    Args:
        fee_bps: Fee in basis points.
        amounts: Sorted probe amounts.
        rounding: Fee rounding direction.

    Returns:
        List of issues if fee is not monotone.
    """
    issues: list[InvariantIssue] = []
    sorted_amounts = sorted(amounts)
    prev_fee = -1
    prev_value = -1
    for value in sorted_amounts:
        if value < 0 or value > U64_MAX:
            continue
        fee = compute_fee(value, fee_bps, rounding)
        if prev_fee >= 0 and fee < prev_fee:
            issues.append(
                InvariantIssue(
                    severity="high",
                    invariant="fee monotonically non-decreasing",
                    detail=(
                        f"fee({prev_value})={prev_fee} > fee({value})={fee}: "
                        "fee decreases as value increases (rounding artifact)."
                    ),
                    recommendation=(
                        "Use consistent rounding direction; ensure fee is never less than "
                        "the fee on a smaller amount."
                    ),
                )
            )
        prev_fee = fee
        prev_value = value
    return issues
