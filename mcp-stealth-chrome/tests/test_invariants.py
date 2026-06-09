"""
Unit tests for the invariant simulator engine.

Tests exact u64 integer math, fee rounding, overflow detection, referral chain,
and round-trip conservation. All tests are offline with no network and no secrets.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.invariants import (
    U64_MAX,
    BPS_DENOMINATOR,
    compute_fee,
    burn_refund,
    add_overflows_u64,
    mul_overflows_u64,
    simulate_invariants,
    simulate_referral_chain,
    simulate_round_trip,
    check_fee_monotonicity,
    SimParams,
    ReferralChainParams,
    DEFAULT_PARAMS,
)


# ── u64 helpers ───────────────────────────────────────────────────────────────

def test_u64_max_value():
    assert U64_MAX == 2**64 - 1


def test_add_overflows_u64_at_max():
    assert add_overflows_u64(U64_MAX, 1) is True


def test_add_not_overflows_below_max():
    assert add_overflows_u64(U64_MAX - 1, 1) is False


def test_mul_overflows_u64():
    assert mul_overflows_u64(U64_MAX, 2) is True


def test_mul_not_overflows():
    assert mul_overflows_u64(1, 1) is False


def test_add_overflow_boundary():
    # U64_MAX + U64_MAX overflows
    assert add_overflows_u64(U64_MAX, U64_MAX) is True
    # U64_MAX + 0 does not
    assert add_overflows_u64(U64_MAX, 0) is False


# ── compute_fee ───────────────────────────────────────────────────────────────

def test_compute_fee_floor_basic():
    # 1000 * 500 / 10000 = 50
    assert compute_fee(1000, 500, "floor") == 50


def test_compute_fee_ceil_basic():
    # 1001 * 500 / 10000 = 50.05 → ceil = 51
    assert compute_fee(1001, 500, "ceil") == 51


def test_compute_fee_dust_floor_rounds_to_zero():
    # 19 * 500 / 10000 = 0.95 → floor = 0
    assert compute_fee(19, 500, "floor") == 0


def test_compute_fee_dust_ceil_rounds_up():
    # 19 * 500 / 10000 = 0.95 → ceil = 1
    assert compute_fee(19, 500, "ceil") == 1


def test_compute_fee_zero_value():
    assert compute_fee(0, 500, "floor") == 0
    assert compute_fee(0, 500, "ceil") == 0


def test_compute_fee_zero_bps():
    assert compute_fee(1000, 0, "floor") == 0


def test_compute_fee_100_percent():
    # 10000 bps = 100%
    assert compute_fee(1000, 10000, "floor") == 1000


def test_compute_fee_200_percent_ceil_exceeds_value():
    # 1 * 20000 / 10000 = 2 > value=1
    fee = compute_fee(1, 20000, "ceil")
    assert fee == 2


# ── burn_refund ───────────────────────────────────────────────────────────────

def test_burn_refund_conservation():
    for value in [0, 1, 100, 1000, U64_MAX]:
        fee = compute_fee(value, 500, "floor")
        refund = burn_refund(value, 500, "floor")
        assert fee + refund == value


def test_burn_refund_zero():
    assert burn_refund(0, 500, "floor") == 0


# ── simulate_invariants ───────────────────────────────────────────────────────

def test_simulator_no_issues_with_clean_params():
    # Use amounts that don't trigger any edge cases
    params = SimParams(fee_bps=500, fee_rounding="floor", amounts=[100, 1000, 10000])
    issues = simulate_invariants(params)
    # Should be no issues for clean mid-range amounts
    assert all(i.invariant != "fee > 0 when value > 0 and bps > 0" for i in issues)


def test_simulator_surfaces_fee_rounds_to_zero_dust():
    params = SimParams(fee_bps=500, fee_rounding="floor", amounts=[19])
    issues = simulate_invariants(params)
    dust = next((i for i in issues if "rounds to 0" in i.detail), None)
    assert dust is not None, "Expected fee-rounds-to-zero issue for value=19 at 5%"
    assert dust.severity == "medium"


def test_simulator_surfaces_u64_overflow():
    params = SimParams(fee_bps=500, fee_rounding="floor", amounts=[U64_MAX])
    issues = simulate_invariants(params)
    overflow = next((i for i in issues if "overflow" in i.invariant), None)
    assert overflow is not None, "Expected overflow issue for U64_MAX"


def test_simulator_surfaces_ceil_fee_exceeds_value():
    # value=1, bps=20000 (200%) ceil → fee=2 > value=1
    params = SimParams(fee_bps=20000, fee_rounding="ceil", amounts=[1])
    issues = simulate_invariants(params)
    too_big = next((i for i in issues if "fee <= value" in i.invariant), None)
    assert too_big is not None


def test_simulator_supply_cap_issue():
    params = SimParams(fee_bps=500, fee_rounding="floor", supply_cap=100, amounts=[200])
    issues = simulate_invariants(params)
    cap = next((i for i in issues if "supply_cap" in i.invariant), None)
    assert cap is not None
    assert cap.severity == "high"


def test_simulator_out_of_range_amount():
    params = SimParams(fee_bps=500, fee_rounding="floor", amounts=[-1])
    issues = simulate_invariants(params)
    oor = next((i for i in issues if "u64 range" in i.invariant), None)
    assert oor is not None
    assert oor.severity == "info"


# ── simulate_referral_chain ───────────────────────────────────────────────────

def test_referral_chain_basic():
    params = ReferralChainParams(reward_bps=1000, rounding="floor", depth=3, base_amount=1000)
    result = simulate_referral_chain(params)
    assert result.per_level == [100, 100, 100]
    assert result.total_paid == 300
    assert result.issues == []


def test_referral_chain_dust_rounds_to_zero():
    params = ReferralChainParams(reward_bps=100, rounding="floor", depth=2, base_amount=50)
    result = simulate_referral_chain(params)
    # 50 * 100 / 10000 = 0.5 → floor = 0
    assert all(r == 0 for r in result.per_level)
    dust_issue = next((i for i in result.issues if "rounds to 0" in i.detail), None)
    assert dust_issue is not None


def test_referral_chain_max_total_exceeded():
    params = ReferralChainParams(
        reward_bps=1000, rounding="floor", depth=5, base_amount=1000, max_total_reward=400
    )
    result = simulate_referral_chain(params)
    # 5 * 100 = 500 > 400
    assert result.total_paid == 500
    cap_issue = next((i for i in result.issues if "max_total_reward" in i.invariant), None)
    assert cap_issue is not None
    assert cap_issue.severity == "high"


def test_referral_chain_zero_depth():
    params = ReferralChainParams(reward_bps=1000, rounding="floor", depth=0, base_amount=1000)
    result = simulate_referral_chain(params)
    assert result.per_level == []
    assert result.total_paid == 0
    assert result.issues == []


# ── simulate_round_trip ───────────────────────────────────────────────────────

def test_round_trip_basic_conservation():
    result = simulate_round_trip(1000, 500, "floor")
    assert result.deposited == 1000
    assert result.fee == 50
    assert result.refund == 950
    assert result.dust_lost == 50
    assert result.issues == []


def test_round_trip_zero_amount():
    result = simulate_round_trip(0, 500, "floor")
    assert result.deposited == 0
    assert result.fee == 0
    assert result.dust_lost == 0


def test_round_trip_dust_amount():
    # value=19, fee=0 (rounds to zero), dust_lost=0
    result = simulate_round_trip(19, 500, "floor")
    assert result.fee == 0
    assert result.dust_lost == 0


# ── check_fee_monotonicity ────────────────────────────────────────────────────

def test_fee_monotone_for_floor():
    amounts = [0, 1, 100, 1000, 10000, 100000]
    issues = check_fee_monotonicity(500, amounts, "floor")
    assert issues == [], f"Unexpected monotonicity issues: {issues}"


def test_fee_monotone_for_ceil():
    amounts = [0, 1, 100, 1000, 10000, 100000]
    issues = check_fee_monotonicity(500, amounts, "ceil")
    assert issues == []


def test_default_params_probe_amounts():
    # The default probe amounts should include the edge cases
    assert 0 in DEFAULT_PARAMS.amounts
    assert 1 in DEFAULT_PARAMS.amounts
    assert U64_MAX in DEFAULT_PARAMS.amounts


def test_simulator_with_default_params():
    issues = simulate_invariants(DEFAULT_PARAMS)
    # Should find at least dust issue (value=19) and overflow issue (U64_MAX)
    dust = next((i for i in issues if "rounds to 0" in i.detail), None)
    overflow = next((i for i in issues if "overflow" in i.invariant), None)
    assert dust is not None
    assert overflow is not None
