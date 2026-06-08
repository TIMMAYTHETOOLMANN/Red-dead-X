"""
Unit tests for the attack surface mapper and scope gate.

All tests are offline with no network and no secrets.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.bugrap import (
    BugRapProgram,
    ScopedContract,
    normalize_registry,
    program_by_key,
    check_scope,
    assert_in_scope,
)
from engine.attack_surface import (
    map_program_surface,
    map_ecosystem_surface,
    summarize_coverage,
    prioritize_cells,
)
from engine.chains import resolve_chain
from engine.taxonomy import payout_band, payout_midpoint, vuln_types_by_class


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_program(
    key="test-prog",
    chains=None,
    vuln_classes=None,
) -> BugRapProgram:
    return BugRapProgram(
        key=key,
        name=key,
        category="defi",
        chains=chains or ["solana"],
        vuln_classes=vuln_classes or ["smart-contract"],
        contracts=[],
        payout_bands=None,
        notes="",
    )


# ── taxonomy tests ────────────────────────────────────────────────────────────

def test_payout_band_default_critical():
    band = payout_band("critical")
    assert band.min_usd == 5000
    assert band.max_usd == 20000


def test_payout_band_default_info():
    band = payout_band("info")
    assert band.min_usd == 0
    assert band.max_usd == 0


def test_payout_midpoint_high():
    mid = payout_midpoint("high")
    assert mid == (2000 + 5000) // 2


def test_vuln_types_by_class_smart_contract():
    types = vuln_types_by_class("smart-contract")
    assert len(types) > 0
    assert all(t.vuln_class == "smart-contract" for t in types)


def test_vuln_types_by_class_unknown():
    types = vuln_types_by_class("nonexistent-class")
    assert types == []


# ── chains tests ──────────────────────────────────────────────────────────────

def test_resolve_chain_solana():
    chain = resolve_chain("solana")
    assert chain.vm == "svm"
    assert chain.key == "solana"


def test_resolve_chain_ethereum():
    chain = resolve_chain("ethereum")
    assert chain.vm == "evm"
    assert chain.chain_id == 1


def test_resolve_chain_by_id():
    chain = resolve_chain(56)
    assert chain.key == "bsc"


def test_resolve_chain_unknown_raises():
    with pytest.raises(ValueError, match="Unknown chain"):
        resolve_chain("nonexistent-chain-xyz")


# ── bugrap registry tests ─────────────────────────────────────────────────────

_VALID_REGISTRY = {
    "source": "https://example.com",
    "programs": [
        {
            "key": "test-prog",
            "name": "Test Program",
            "category": "defi",
            "chains": ["solana"],
            "vulnClasses": ["smart-contract"],
            "contracts": [],
            "notes": "Test program",
        }
    ],
}


def test_normalize_registry_valid():
    reg = normalize_registry(_VALID_REGISTRY)
    assert len(reg.programs) == 1
    assert reg.programs[0].key == "test-prog"


def test_normalize_registry_raises_on_non_dict():
    with pytest.raises(ValueError, match="not a JSON object"):
        normalize_registry([])


def test_normalize_registry_raises_on_duplicate_key():
    raw = {
        "programs": [
            {"key": "dup", "chains": ["solana"], "vulnClasses": ["smart-contract"]},
            {"key": "dup", "chains": ["ethereum"], "vulnClasses": ["smart-contract"]},
        ]
    }
    with pytest.raises(ValueError, match="Duplicate program key"):
        normalize_registry(raw)


def test_normalize_registry_raises_on_unknown_vuln_class():
    raw = {
        "programs": [
            {"key": "p", "chains": ["solana"], "vulnClasses": ["nonexistent-class"]}
        ]
    }
    with pytest.raises(ValueError, match="unknown vuln class"):
        normalize_registry(raw)


def test_program_by_key_found():
    reg = normalize_registry(_VALID_REGISTRY)
    prog = program_by_key(reg, "test-prog")
    assert prog is not None
    assert prog.key == "test-prog"


def test_program_by_key_not_found():
    reg = normalize_registry(_VALID_REGISTRY)
    assert program_by_key(reg, "missing") is None


def test_program_by_key_case_insensitive():
    reg = normalize_registry(_VALID_REGISTRY)
    prog = program_by_key(reg, "TEST-PROG")
    assert prog is not None


# ── scope check tests ─────────────────────────────────────────────────────────

def test_scope_check_in_scope():
    prog = _make_program(chains=["solana"], vuln_classes=["smart-contract"])
    decision = check_scope(prog, chain="solana", vuln_class="smart-contract")
    assert decision.in_scope is True
    assert decision.reasons == []


def test_scope_check_wrong_chain():
    prog = _make_program(chains=["solana"], vuln_classes=["smart-contract"])
    decision = check_scope(prog, chain="ethereum", vuln_class="smart-contract")
    assert decision.in_scope is False
    assert any("chain" in r for r in decision.reasons)


def test_scope_check_wrong_vuln_class():
    prog = _make_program(chains=["solana"], vuln_classes=["smart-contract"])
    decision = check_scope(prog, chain="solana", vuln_class="auth")
    assert decision.in_scope is False
    assert any("vuln class" in r for r in decision.reasons)


def test_scope_check_unpinned_address():
    prog = _make_program(chains=["solana"], vuln_classes=["smart-contract"])
    # No contracts pinned
    decision = check_scope(prog, address="SomeAddress111")
    assert decision.in_scope is False
    assert any("not among" in r for r in decision.reasons)


def test_scope_check_pinned_address_found():
    prog = BugRapProgram(
        key="p",
        name="P",
        category="defi",
        chains=["solana"],
        vuln_classes=["smart-contract"],
        contracts=[ScopedContract(chain="solana", address="KnownAddr", label="Vault")],
        payout_bands=None,
        notes="",
    )
    decision = check_scope(prog, address="KnownAddr")
    assert decision.in_scope is True


def test_assert_in_scope_raises_when_out_of_scope():
    prog = _make_program(chains=["solana"])
    with pytest.raises(ValueError, match="Out-of-scope"):
        assert_in_scope(prog, chain="ethereum")


# ── attack surface mapper tests ───────────────────────────────────────────────

def test_map_program_surface_single_program():
    prog = _make_program(chains=["solana", "ethereum"], vuln_classes=["smart-contract", "auth"])
    cells = map_program_surface(prog)
    # 2 chains × 2 classes = 4 cells
    assert len(cells) == 4
    assert all(c.program == "test-prog" for c in cells)


def test_map_program_surface_solana_has_svm_static():
    prog = _make_program(chains=["solana"], vuln_classes=["smart-contract"])
    cells = map_program_surface(prog)
    assert len(cells) == 1
    # svm-static engine should be present for solana + smart-contract
    assert "svm-static" in cells[0].engines


def test_map_program_surface_ethereum_has_evm_static():
    prog = _make_program(chains=["ethereum"], vuln_classes=["smart-contract"])
    cells = map_program_surface(prog)
    assert len(cells) == 1
    assert "evm-static" in cells[0].engines


def test_map_program_surface_automated_flag():
    prog = _make_program(chains=["solana"], vuln_classes=["smart-contract"])
    cells = map_program_surface(prog)
    assert cells[0].automated is True  # svm-static covers it


def test_map_program_surface_manual_only_for_auth_on_solana():
    prog = _make_program(chains=["solana"], vuln_classes=["auth"])
    cells = map_program_surface(prog)
    assert len(cells) == 1
    # auth has no svm/evm-static engine — only manual
    assert cells[0].automated is False


def test_summarize_coverage_totals():
    prog = _make_program(chains=["solana", "ethereum"], vuln_classes=["smart-contract"])
    cells = map_program_surface(prog)
    summary = summarize_coverage(cells)
    assert summary.total_cells == len(cells)
    assert summary.automated_cells + summary.manual_only_cells == summary.total_cells


def test_prioritize_cells_by_payout():
    prog1 = _make_program("defi", chains=["ethereum"], vuln_classes=["smart-contract"])
    prog2 = _make_program("wallet", chains=["solana"], vuln_classes=["auth"])
    cells = map_ecosystem_surface([prog1, prog2])
    prioritized = prioritize_cells(cells)
    # Higher payout cells should come first
    payouts = [c.payout_ceiling_usd for c in prioritized]
    assert payouts == sorted(payouts, reverse=True)


# ── bundled registry test ─────────────────────────────────────────────────────

def test_bundled_registry_loads():
    """The bundled bugrap-programs.json should load and validate cleanly."""
    data_path = Path(__file__).parent.parent / "data" / "bugrap-programs.json"
    assert data_path.exists(), f"Registry not found at {data_path}"
    from engine.bugrap import load_registry
    reg = load_registry(str(data_path))
    assert len(reg.programs) > 0
    # soex-premiumcvt should be present
    assert any(p.key == "soex-premiumcvt" for p in reg.programs)
