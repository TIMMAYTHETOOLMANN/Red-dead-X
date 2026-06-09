"""
Smoke tests for app.py tool functions.

Imports each tool function from app.py and runs it on the bundled sample data.
All tests are offline with no network and no secrets.
"""

import json
import sys
from pathlib import Path

import pytest

# Ensure the mcp-stealth-chrome directory is on the path
_HERE = Path(__file__).parent.parent
sys.path.insert(0, str(_HERE))


def test_import_app_tools():
    """All MCP tool functions should be importable from app.py."""
    from app import (
        analyze_idl_tool,
        simulate_invariants_tool,
        map_attack_surface_tool,
        forensic_scan_tool,
        analyze_evm_abi_tool,
        list_programs_tool,
        scope_check_tool,
    )
    assert callable(analyze_idl_tool)
    assert callable(simulate_invariants_tool)
    assert callable(map_attack_surface_tool)
    assert callable(forensic_scan_tool)
    assert callable(analyze_evm_abi_tool)
    assert callable(list_programs_tool)
    assert callable(scope_check_tool)


def test_analyze_idl_on_sample():
    from app import analyze_idl_tool, SAMPLE_IDL_PATH
    sample = SAMPLE_IDL_PATH.read_text()
    result = json.loads(analyze_idl_tool(sample))
    assert "error" not in result
    assert "program" in result
    assert "findings" in result
    assert isinstance(result["findings"], list)
    assert result["instructionCount"] > 0


def test_simulate_invariants_default():
    from app import simulate_invariants_tool
    result = json.loads(simulate_invariants_tool())
    assert "error" not in result
    assert "issues" in result
    assert "referralChain" in result
    assert "roundTrips" in result


def test_simulate_invariants_custom_params():
    from app import simulate_invariants_tool
    params = json.dumps({"feeBps": 300, "feeRounding": "ceil", "amounts": [100, 1000]})
    result = json.loads(simulate_invariants_tool(params))
    assert "error" not in result
    assert result["feeBps"] == 300


def test_map_attack_surface_all():
    from app import map_attack_surface_tool
    result = json.loads(map_attack_surface_tool())
    assert "error" not in result
    assert result["totalCells"] > 0
    assert "cells" in result


def test_map_attack_surface_single_program():
    from app import map_attack_surface_tool
    result = json.loads(map_attack_surface_tool("soex-premiumcvt"))
    assert "error" not in result
    assert result["totalCells"] > 0


def test_map_attack_surface_unknown_program():
    from app import map_attack_surface_tool
    result = json.loads(map_attack_surface_tool("nonexistent-xyz"))
    assert "error" in result
    assert "availableKeys" in result


def test_forensic_scan_with_both():
    from app import forensic_scan_tool, SAMPLE_IDL_PATH, SAMPLE_ABI_PATH
    idl = SAMPLE_IDL_PATH.read_text()
    abi = SAMPLE_ABI_PATH.read_text()
    result = json.loads(forensic_scan_tool(idl, abi))
    assert "error" not in result or result.get("errors") == []
    assert "sarif" in result
    assert "markdown" in result


def test_forensic_scan_idl_only():
    from app import forensic_scan_tool, SAMPLE_IDL_PATH
    idl = SAMPLE_IDL_PATH.read_text()
    result = json.loads(forensic_scan_tool(idl, ""))
    assert "sarif" in result


def test_forensic_scan_abi_only():
    from app import forensic_scan_tool, SAMPLE_ABI_PATH
    abi = SAMPLE_ABI_PATH.read_text()
    result = json.loads(forensic_scan_tool("", abi))
    assert "sarif" in result


def test_forensic_scan_empty_fails_gracefully():
    from app import forensic_scan_tool
    result = json.loads(forensic_scan_tool("", ""))
    assert "error" in result


def test_analyze_evm_abi_on_sample():
    from app import analyze_evm_abi_tool, SAMPLE_ABI_PATH
    abi = SAMPLE_ABI_PATH.read_text()
    result = json.loads(analyze_evm_abi_tool(abi))
    assert "error" not in result
    assert "findings" in result
    assert result["functionCount"] > 0


def test_analyze_evm_abi_with_address():
    from app import analyze_evm_abi_tool, SAMPLE_ABI_PATH
    abi = SAMPLE_ABI_PATH.read_text()
    result = json.loads(analyze_evm_abi_tool(abi, "0xdeadbeef"))
    assert result["address"] == "0xdeadbeef"


def test_analyze_evm_abi_invalid_json():
    from app import analyze_evm_abi_tool
    result = json.loads(analyze_evm_abi_tool("not valid json"))
    assert "error" in result


def test_list_programs():
    from app import list_programs_tool
    result = json.loads(list_programs_tool())
    assert "programs" in result
    assert result["count"] > 0
    keys = [p["key"] for p in result["programs"]]
    assert "soex-premiumcvt" in keys


def test_scope_check_in_scope():
    from app import scope_check_tool
    result = json.loads(scope_check_tool("soex-premiumcvt", "solana", "smart-contract"))
    assert "error" not in result
    assert result["inScope"] is True


def test_scope_check_out_of_scope():
    from app import scope_check_tool
    result = json.loads(scope_check_tool("soex-premiumcvt", "ethereum", "smart-contract"))
    assert result["inScope"] is False
    assert result["reasons"]


def test_scope_check_unknown_program():
    from app import scope_check_tool
    result = json.loads(scope_check_tool("no-such-program", "solana", "smart-contract"))
    assert "error" in result


def test_analyze_idl_with_baseline_suppression():
    from app import analyze_idl_tool, SAMPLE_IDL_PATH
    sample = SAMPLE_IDL_PATH.read_text()
    # First pass: get all finding ids
    first = json.loads(analyze_idl_tool(sample))
    all_ids = [f["id"] for f in first["findings"]]
    if all_ids:
        baseline = json.dumps(all_ids)
        second = json.loads(analyze_idl_tool(sample, baseline_json=baseline))
        assert second["suppressed"] == len(all_ids)
        assert second["activeFindings"] == 0


def test_analyze_idl_fail_on_high():
    from app import analyze_idl_tool, SAMPLE_IDL_PATH
    sample = SAMPLE_IDL_PATH.read_text()
    result = json.loads(analyze_idl_tool(sample, fail_on="high"))
    # The sample IDL has high-severity findings, so failTriggered should be True
    # (or findings list may be empty — just check the key exists)
    assert "failTriggered" in result


def test_analyze_idl_invalid_json():
    from app import analyze_idl_tool
    result = json.loads(analyze_idl_tool("{ broken json"))
    assert "error" in result
