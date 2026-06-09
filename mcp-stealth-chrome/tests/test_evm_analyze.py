"""
Unit tests for the EVM ABI normalizer and analyzer.

All tests are offline with no network and no secrets.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.evm_abi import normalize_abi, AbiFunction
from engine.evm_analyze import analyze_abi, evm_to_sarif


# ── normalization ─────────────────────────────────────────────────────────────

def test_normalize_json_abi():
    raw = [
        {
            "type": "function",
            "name": "transfer",
            "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}],
            "outputs": [{"name": "", "type": "bool"}],
            "stateMutability": "nonpayable",
        }
    ]
    abi = normalize_abi(raw)
    assert len(abi.functions) == 1
    fn = abi.functions[0]
    assert fn.name == "transfer"
    assert fn.read_only is False
    assert fn.payable is False
    assert len(fn.inputs) == 2


def test_normalize_view_function():
    raw = [
        {"type": "function", "name": "balanceOf", "inputs": [], "outputs": [], "stateMutability": "view"}
    ]
    abi = normalize_abi(raw)
    assert abi.functions[0].read_only is True


def test_normalize_payable_function():
    raw = [
        {"type": "function", "name": "deposit", "inputs": [], "outputs": [], "stateMutability": "payable"}
    ]
    abi = normalize_abi(raw)
    assert abi.functions[0].payable is True


def test_normalize_human_readable_function():
    raw = ["function withdraw(uint256 amount) nonpayable"]
    abi = normalize_abi(raw)
    assert len(abi.functions) == 1
    fn = abi.functions[0]
    assert fn.name == "withdraw"
    assert fn.read_only is False
    assert any(i.type == "uint256" for i in fn.inputs)


def test_normalize_human_readable_view():
    raw = ["function balanceOf(address owner) view returns (uint256)"]
    abi = normalize_abi(raw)
    assert abi.functions[0].read_only is True


def test_normalize_event():
    raw = [{"type": "event", "name": "Transfer", "inputs": [], "anonymous": False}]
    abi = normalize_abi(raw)
    assert len(abi.events) == 1
    assert abi.events[0].name == "Transfer"


def test_normalize_error():
    raw = [{"type": "error", "name": "InsufficientBalance", "inputs": []}]
    abi = normalize_abi(raw)
    assert "InsufficientBalance" in abi.errors


def test_normalize_fallback_receive():
    raw = ["fallback", "receive"]
    abi = normalize_abi(raw)
    assert abi.has_fallback is True
    assert abi.has_receive is True


def test_normalize_raises_on_non_list():
    with pytest.raises(ValueError, match="must be an array"):
        normalize_abi({})


def test_normalize_legacy_constant():
    raw = [
        {"type": "function", "name": "getter", "inputs": [], "outputs": [], "constant": True}
    ]
    abi = normalize_abi(raw)
    assert abi.functions[0].read_only is True


# ── lane detection ────────────────────────────────────────────────────────────

def _make_fn(name: str, mutability: str = "nonpayable", inputs=None) -> dict:
    return {
        "type": "function",
        "name": name,
        "inputs": inputs or [],
        "outputs": [],
        "stateMutability": mutability,
    }


def test_lane_EA_access_control_privileged():
    raw = [_make_fn("setFee")]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    ea = [f for f in result.findings if f.lane == "EA-access-control"]
    assert ea, "Expected EA-access-control finding for setFee"


def test_lane_EA_skips_read_only():
    raw = [_make_fn("getFee", mutability="view")]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    ea = [f for f in result.findings if f.lane == "EA-access-control"]
    assert not ea


def test_lane_EB_upgradeability():
    raw = [_make_fn("upgradeTo", inputs=[{"name": "impl", "type": "address"}])]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    eb = [f for f in result.findings if f.lane == "EB-upgradeability"]
    assert eb
    assert eb[0].severity == "critical"
    assert eb[0].confidence == "likely"


def test_lane_EC_arbitrary_call():
    raw = [
        _make_fn(
            "execute",
            inputs=[{"name": "target", "type": "address"}, {"name": "data", "type": "bytes"}],
        )
    ]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    ec = [f for f in result.findings if f.lane == "EC-arbitrary-call"]
    assert ec
    assert ec[0].confidence == "likely"


def test_lane_ED_token_approval():
    raw = [_make_fn("approve", inputs=[{"name": "spender", "type": "address"}, {"name": "amount", "type": "uint256"}])]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    ed = [f for f in result.findings if f.lane == "ED-token-approval"]
    assert ed


def test_lane_EE_signature_replay_without_nonce():
    raw = [
        _make_fn(
            "claimWithSig",
            inputs=[
                {"name": "v", "type": "uint8"},
                {"name": "r", "type": "bytes32"},
                {"name": "s", "type": "bytes32"},
            ],
        )
    ]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    ee = [f for f in result.findings if f.lane == "EE-signature-replay"]
    assert ee
    assert ee[0].severity == "high"
    assert ee[0].confidence == "likely"


def test_lane_EE_signature_replay_with_deadline_lower_severity():
    raw = [
        _make_fn(
            "permit",
            inputs=[
                {"name": "deadline", "type": "uint256"},
                {"name": "v", "type": "uint8"},
                {"name": "r", "type": "bytes32"},
                {"name": "s", "type": "bytes32"},
            ],
        )
    ]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    ee = [f for f in result.findings if f.lane == "EE-signature-replay"]
    assert ee
    assert ee[0].severity == "medium"


def test_lane_EF_reentrancy_withdraw():
    raw = [_make_fn("withdraw", inputs=[{"name": "amount", "type": "uint256"}])]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    ef = [f for f in result.findings if f.lane == "EF-reentrancy"]
    assert ef


def test_lane_EF_reentrancy_payable():
    raw = [_make_fn("deposit", mutability="payable")]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    ef = [f for f in result.findings if f.lane == "EF-reentrancy"]
    assert ef


def test_lane_EG_economic_math():
    raw = [_make_fn("mint", inputs=[{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}])]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    eg = [f for f in result.findings if f.lane == "EG-economic-math"]
    assert eg


def test_lane_EH_self_destruct():
    raw = [_make_fn("selfdestruct")]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    eh = [f for f in result.findings if f.lane == "EH-self-destruct"]
    assert eh


def test_lane_EX_correlation_no_getter():
    # Multiple privileged setters but no owner()/hasRole getter
    raw = [
        _make_fn("setFee"),
        _make_fn("setTreasury", inputs=[{"name": "t", "type": "address"}]),
        _make_fn("pause"),
    ]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    ex = [f for f in result.findings if f.lane == "EX-correlation"]
    assert ex


def test_lane_EX_no_correlation_with_getter():
    raw = [
        _make_fn("setFee"),
        _make_fn("setTreasury"),
        _make_fn("owner", mutability="view"),
    ]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    ex = [f for f in result.findings if f.lane == "EX-correlation"]
    assert not ex, "Should not flag EX-correlation when owner() getter is present"


# ── ranking ───────────────────────────────────────────────────────────────────

def test_findings_sorted_by_payout_weight():
    raw = [
        _make_fn("upgradeTo", inputs=[{"name": "impl", "type": "address"}]),
        _make_fn("setFee"),
        _make_fn("withdraw", inputs=[{"name": "amount", "type": "uint256"}]),
    ]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    weights = [f.payout_weight for f in result.findings]
    assert weights == sorted(weights, reverse=True)


def test_severity_counts_sum():
    raw = [_make_fn("upgradeTo"), _make_fn("setFee"), _make_fn("withdraw")]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    total = sum(result.severity_counts.values())
    assert total == len(result.findings)


def test_empty_abi_no_findings():
    abi = normalize_abi([])
    result = analyze_abi(abi)
    assert result.findings == []
    assert result.max_risk == 0


# ── SARIF export ──────────────────────────────────────────────────────────────

def test_evm_sarif_valid():
    raw = [_make_fn("upgradeTo")]
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    sarif = evm_to_sarif(result)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == len(result.findings)


# ── sample ABI ───────────────────────────────────────────────────────────────

def test_sample_evm_abi_loads_and_produces_findings():
    """The bundled sample EVM ABI should load and produce findings."""
    sample_path = Path(__file__).parent.parent / "data" / "samples" / "sample_evm_abi.json"
    assert sample_path.exists()
    with open(sample_path) as f:
        raw = json.load(f)
    abi = normalize_abi(raw)
    result = analyze_abi(abi)
    assert result.function_count > 0
    assert len(result.findings) > 0
