"""
Unit tests for the IDL analyzer engine.

Tests IDL normalization, fingerprinting, lane coverage, and ranking.
All tests are offline with no network and no secrets.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.idl import normalize_idl, NormalizedIdl
from engine.analyze import (
    analyze_idl,
    apply_baseline,
    fingerprint,
    risk_score,
    to_sarif,
    SEVERITY_ORDER,
)


# ── fixtures ──────────────────────────────────────────────────────────────────

_MINIMAL_IDL = {
    "name": "test_program",
    "instructions": [],
}

_PRIVILEGED_NO_SIGNER = {
    "name": "test_program",
    "instructions": [
        {
            "name": "initialize",
            "accounts": [
                {"name": "vault", "writable": True, "signer": False},
            ],
            "args": [],
        }
    ],
}

_AUTHORITY_UNBOUND = {
    "name": "test_program",
    "instructions": [
        {
            "name": "transfer",
            "accounts": [
                {"name": "authority", "writable": False, "signer": False},
                {"name": "vault", "writable": True, "signer": False},
            ],
            "args": [],
        }
    ],
}

_TOKEN_NO_SEEDS = {
    "name": "test_program",
    "instructions": [
        {
            "name": "deposit",
            "accounts": [
                {"name": "vaultTokenAccount", "writable": True, "signer": False},
                {"name": "owner", "writable": False, "signer": True},
            ],
            "args": [{"name": "amount", "type": "u64"}],
        }
    ],
}

_REFERRAL_WRITABLE = {
    "name": "test_program",
    "instructions": [
        {
            "name": "claim",
            "accounts": [
                {"name": "referrer", "writable": True, "signer": False},
            ],
            "args": [],
        }
    ],
}

_UPGRADE_NO_SIGNER = {
    "name": "test_program",
    "instructions": [
        {
            "name": "set_authority",
            "accounts": [
                {"name": "vault", "writable": True, "signer": False},
            ],
            "args": [],
        }
    ],
}

_CPI_UNPINNED = {
    "name": "test_program",
    "instructions": [
        {
            "name": "invoke_action",
            "accounts": [
                {"name": "cpiProgram", "writable": False, "signer": False},
            ],
            "args": [],
        }
    ],
}

_INIT_UNBOUND = {
    "name": "test_program",
    "instructions": [
        {
            "name": "initialize_vault",
            "accounts": [
                {"name": "vault", "writable": True, "signer": False},
                {"name": "payer", "writable": True, "signer": True},
            ],
            "args": [],
        }
    ],
}

_DOS_UNBOUNDED = {
    "name": "test_program",
    "instructions": [
        {
            "name": "store",
            "accounts": [],
            "args": [{"name": "data", "type": "bytes"}],
        }
    ],
}


# ── normalization tests ───────────────────────────────────────────────────────

def test_normalize_minimal_idl():
    idl = normalize_idl(_MINIMAL_IDL)
    assert idl.name == "test_program"
    assert idl.instructions == []
    assert idl.address is None


def test_normalize_idl_preserves_name_from_metadata():
    raw = {"metadata": {"name": "from_metadata"}, "instructions": []}
    idl = normalize_idl(raw)
    assert idl.name == "from_metadata"


def test_normalize_idl_legacy_mut_signer():
    raw = {
        "name": "prog",
        "instructions": [
            {
                "name": "ix",
                "accounts": [{"name": "acc", "isMut": True, "isSigner": True}],
                "args": [],
            }
        ],
    }
    idl = normalize_idl(raw)
    acc = idl.instructions[0].accounts[0]
    assert acc.writable is True
    assert acc.signer is True


def test_normalize_idl_raises_on_non_dict():
    with pytest.raises(ValueError, match="not a JSON object"):
        normalize_idl([])


# ── fingerprint tests ─────────────────────────────────────────────────────────

def test_fingerprint_stable_across_calls():
    id1 = fingerprint("A-authority", "initialize", None)
    id2 = fingerprint("A-authority", "initialize", None)
    assert id1 == id2


def test_fingerprint_differs_by_account():
    id1 = fingerprint("A-authority", "transfer", "vault")
    id2 = fingerprint("A-authority", "transfer", "authority")
    assert id1 != id2


def test_fingerprint_length_is_16():
    fp = fingerprint("X-correlation", "some_ix", "some_acc")
    assert len(fp) == 16


def test_fingerprint_hex_chars_only():
    fp = fingerprint("B-account-substitution", "ix", None)
    assert all(c in "0123456789abcdef" for c in fp)


# ── risk score tests ──────────────────────────────────────────────────────────

def test_risk_score_critical_firm_is_max():
    assert risk_score("critical", "firm") == 15  # 5 × 3


def test_risk_score_info_tentative_is_min():
    assert risk_score("info", "tentative") == 1  # 1 × 1


def test_risk_score_ordering():
    assert risk_score("critical", "firm") > risk_score("high", "firm")
    assert risk_score("high", "firm") > risk_score("high", "likely")


# ── lane detection tests ──────────────────────────────────────────────────────

def test_lane_A_privileged_no_signer():
    idl = normalize_idl(_PRIVILEGED_NO_SIGNER)
    result = analyze_idl(idl)
    lanes = {f.lane for f in result.findings}
    assert "A-authority" in lanes
    signer_finding = next(
        (f for f in result.findings if f.lane == "A-authority" and f.account is None), None
    )
    assert signer_finding is not None
    assert signer_finding.severity == "high"
    assert signer_finding.confidence == "firm"


def test_lane_A_authority_unbound():
    idl = normalize_idl(_AUTHORITY_UNBOUND)
    result = analyze_idl(idl)
    auth_findings = [f for f in result.findings if f.lane == "A-authority" and f.account == "authority"]
    assert auth_findings, "Expected A-authority finding for unbound authority account"
    assert auth_findings[0].severity == "medium"


def test_lane_C_token_no_seeds():
    idl = normalize_idl(_TOKEN_NO_SEEDS)
    result = analyze_idl(idl)
    c_findings = [f for f in result.findings if f.lane == "C-token-custody"]
    assert c_findings, "Expected C-token-custody finding"


def test_lane_E_referral_writable():
    idl = normalize_idl(_REFERRAL_WRITABLE)
    result = analyze_idl(idl)
    e_findings = [f for f in result.findings if f.lane == "E-referral"]
    assert e_findings


def test_lane_F_upgrade_no_signer():
    idl = normalize_idl(_UPGRADE_NO_SIGNER)
    result = analyze_idl(idl)
    f_findings = [f for f in result.findings if f.lane == "F-upgrade-admin"]
    assert f_findings
    assert f_findings[0].severity == "high"
    assert f_findings[0].confidence == "firm"


def test_lane_G_cpi_unpinned():
    idl = normalize_idl(_CPI_UNPINNED)
    result = analyze_idl(idl)
    g_findings = [f for f in result.findings if f.lane == "G-cpi-program"]
    assert g_findings


def test_lane_H_init_unbound():
    idl = normalize_idl(_INIT_UNBOUND)
    result = analyze_idl(idl)
    h_findings = [f for f in result.findings if f.lane == "H-init-safety"]
    assert h_findings
    assert h_findings[0].severity == "high"


def test_lane_I_dos_unbounded():
    idl = normalize_idl(_DOS_UNBOUNDED)
    result = analyze_idl(idl)
    i_findings = [f for f in result.findings if f.lane == "I-dos-compute"]
    assert i_findings


# ── ranking tests ─────────────────────────────────────────────────────────────

def test_findings_sorted_by_risk_descending():
    idl = normalize_idl(_PRIVILEGED_NO_SIGNER)
    result = analyze_idl(idl)
    risks = [f.risk for f in result.findings]
    assert risks == sorted(risks, reverse=True)


def test_severity_counts_sum_to_total_findings():
    idl = normalize_idl(_AUTHORITY_UNBOUND)
    result = analyze_idl(idl)
    total = sum(result.severity_counts.values())
    assert total == len(result.findings)


def test_lane_counts_sum_to_total_findings():
    idl = normalize_idl(_AUTHORITY_UNBOUND)
    result = analyze_idl(idl)
    total = sum(result.lane_counts.values())
    assert total == len(result.findings)


# ── baseline suppression ──────────────────────────────────────────────────────

def test_apply_baseline_suppresses_by_id():
    idl = normalize_idl(_PRIVILEGED_NO_SIGNER)
    result = analyze_idl(idl)
    assert result.findings
    all_ids = {f.id for f in result.findings}
    kept, suppressed = apply_baseline(result.findings, all_ids)
    assert kept == []
    assert suppressed == len(result.findings)


def test_apply_baseline_keeps_non_baseline():
    idl = normalize_idl(_PRIVILEGED_NO_SIGNER)
    result = analyze_idl(idl)
    kept, suppressed = apply_baseline(result.findings, set())
    assert len(kept) == len(result.findings)
    assert suppressed == 0


def test_apply_baseline_partial():
    idl = normalize_idl(_PRIVILEGED_NO_SIGNER)
    result = analyze_idl(idl)
    if len(result.findings) >= 2:
        to_suppress = {result.findings[0].id}
        kept, suppressed = apply_baseline(result.findings, to_suppress)
        assert suppressed == 1
        assert len(kept) == len(result.findings) - 1


# ── SARIF export ──────────────────────────────────────────────────────────────

def test_sarif_valid_schema():
    idl = normalize_idl(_PRIVILEGED_NO_SIGNER)
    result = analyze_idl(idl)
    sarif = to_sarif(result, "test.json")
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1


def test_sarif_results_count_matches_findings():
    idl = normalize_idl(_PRIVILEGED_NO_SIGNER)
    result = analyze_idl(idl)
    sarif = to_sarif(result, "test.json")
    assert len(sarif["runs"][0]["results"]) == len(result.findings)


def test_sarif_fingerprints_present():
    idl = normalize_idl(_PRIVILEGED_NO_SIGNER)
    result = analyze_idl(idl)
    sarif = to_sarif(result, "test.json")
    for r in sarif["runs"][0]["results"]:
        assert "idlAnalyzer" in r["partialFingerprints"]


# ── cross-instruction correlation ─────────────────────────────────────────────

def test_x_correlation_detected():
    """An account bound in one instruction but unbound+writable in another should trigger X-correlation."""
    raw = {
        "name": "prog",
        "instructions": [
            {
                "name": "safe_ix",
                "accounts": [
                    {
                        "name": "vault",
                        "writable": True,
                        "signer": False,
                        "pda": {"seeds": [{"kind": "const", "value": [118, 97, 117, 108, 116]}]},
                    }
                ],
                "args": [],
            },
            {
                "name": "risky_ix",
                "accounts": [
                    {"name": "vault", "writable": True, "signer": False}
                ],
                "args": [],
            },
        ],
    }
    idl = normalize_idl(raw)
    result = analyze_idl(idl)
    x_findings = [f for f in result.findings if f.lane == "X-correlation"]
    assert x_findings, "Expected X-correlation finding"
    assert any(f.account == "vault" for f in x_findings)


# ── empty IDL ─────────────────────────────────────────────────────────────────

def test_empty_idl_no_findings():
    idl = normalize_idl(_MINIMAL_IDL)
    result = analyze_idl(idl)
    assert result.findings == []
    assert result.max_risk == 0
    assert result.instruction_count == 0
