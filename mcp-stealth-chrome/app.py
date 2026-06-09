"""
MCP Stealth Chrome — Gradio + MCP forensic analysis app.

A self-contained Hugging Face Space that re-packages the offline blockchain
forensic tooling as a Gradio app that is also an MCP server, hosted over HTTPS.

MCP SSE endpoint:
    https://timmaythetoolmann-mcp-stealth-chrome.hf.space/gradio_api/mcp/sse

All operations are read-only by default. No mainnet sends. No required secrets.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import gradio as gr

# ── path setup ───────────────────────────────────────────────────────────────

HERE = Path(__file__).parent
DATA_DIR = HERE / "data"
SAMPLES_DIR = DATA_DIR / "samples"
REGISTRY_PATH = DATA_DIR / "bugrap-programs.json"
SAMPLE_IDL_PATH = SAMPLES_DIR / "sample_idl.json"
SAMPLE_ABI_PATH = SAMPLES_DIR / "sample_evm_abi.json"

sys.path.insert(0, str(HERE))

from engine.idl import normalize_idl
from engine.analyze import analyze_idl, apply_baseline, to_sarif, findings_to_markdown, matrix_to_markdown
from engine.invariants import (
    SimParams, ReferralChainParams, DEFAULT_PARAMS,
    simulate_invariants, simulate_referral_chain, simulate_round_trip,
    check_fee_monotonicity, U64_MAX,
)
from engine.bugrap import load_registry, program_by_key, check_scope, BugRapProgram
from engine.attack_surface import (
    map_program_surface, map_ecosystem_surface, summarize_coverage,
    prioritize_cells, surface_to_markdown,
)
from engine.evm_abi import normalize_abi
from engine.evm_analyze import analyze_abi, evm_findings_to_markdown, evm_to_sarif
from engine.forensic_report import build_forensic_report

# ── guardrails ───────────────────────────────────────────────────────────────

READ_ONLY = os.environ.get("READ_ONLY", "true").lower() not in ("false", "0", "no")
ALLOW_TX = os.environ.get("ALLOW_TX", "false").lower() in ("true", "1", "yes")
EVIDENCE_DIR = os.environ.get("EVIDENCE_DIR", tempfile.gettempdir())
BASELINE_PATH = os.environ.get("BASELINE_PATH", "").strip()
FAIL_ON = os.environ.get("FAIL_ON", "").strip().lower()

# ── registry (loaded once at startup) ────────────────────────────────────────

_REGISTRY = None


def _get_registry():
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = load_registry(str(REGISTRY_PATH))
    return _REGISTRY


# ── MCP tool functions ────────────────────────────────────────────────────────


def analyze_idl_tool(idl_json: str, baseline_json: str = "", fail_on: str = "") -> str:
    """Run the Solana IDL static analyzer on pasted IDL JSON.

    Walks every instruction through 10 hunting lanes (authority, account-
    substitution, token-custody, economic, referral, upgrade/admin,
    CPI/arbitrary-program, init-safety, DoS/compute, cross-instruction
    correlation), ranks candidates by composite risk, assigns stable
    fingerprints, and returns JSON + Markdown + SARIF.

    Args:
        idl_json: The Anchor IDL as a JSON string.
        baseline_json: Optional JSON string of baseline finding ids to suppress
            (list of id strings or {"ids": [...]} dict).
        fail_on: Optional severity gate; one of critical/high/medium/low/info.
            Returns a non-zero exit signal in the JSON when active findings at
            or above this severity are found.

    Returns:
        JSON string with keys: program, findings (ranked), sarif, markdown,
        severityCounts, laneCounts, maxRisk, suppressed, failTriggered.
    """
    try:
        raw = json.loads(idl_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid IDL JSON: {e}"})

    try:
        idl = normalize_idl(raw)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    result = analyze_idl(idl)

    # Baseline suppression
    suppressed = 0
    active_findings = result.findings
    if baseline_json.strip():
        try:
            bl_raw = json.loads(baseline_json)
            if isinstance(bl_raw, list):
                bl_ids = set(str(x) for x in bl_raw)
            elif isinstance(bl_raw, dict):
                bl_ids = set(str(x) for x in bl_raw.get("ids", []))
            else:
                bl_ids = set()
            active_findings, suppressed = apply_baseline(result.findings, bl_ids)
        except json.JSONDecodeError:
            pass

    # Fail-on gate
    _FAIL_GATE = FAIL_ON or fail_on.strip().lower()
    _SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
    fail_triggered = False
    if _FAIL_GATE and _FAIL_GATE in _SEVERITY_ORDER:
        gate_idx = _SEVERITY_ORDER.index(_FAIL_GATE)
        fail_triggered = any(
            _SEVERITY_ORDER.index(f.severity) <= gate_idx for f in active_findings
        )

    sarif = to_sarif(result, "idl.json")
    md = (
        f"# IDL Static Analysis — {result.program}\n\n"
        f"- Address: {result.address or '(none)'}\n"
        f"- Instructions: {result.instruction_count}\n"
        f"- Max risk: {result.max_risk}\n"
        f"- Severity counts: {json.dumps(result.severity_counts)}\n"
        f"- Active findings: {len(active_findings)}"
        + (f" (+{suppressed} suppressed)" if suppressed else "")
        + "\n\n## Findings\n\n"
        + findings_to_markdown(active_findings)
        + "\n## Instruction/Account Matrix\n\n"
        + matrix_to_markdown(result.matrix)
    )

    return json.dumps(
        {
            "program": result.program,
            "address": result.address,
            "instructionCount": result.instruction_count,
            "maxRisk": result.max_risk,
            "severityCounts": result.severity_counts,
            "laneCounts": result.lane_counts,
            "activeFindings": len(active_findings),
            "suppressed": suppressed,
            "failTriggered": fail_triggered,
            "findings": [
                {
                    "id": f.id,
                    "lane": f.lane,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "risk": f.risk,
                    "instruction": f.instruction,
                    "account": f.account,
                    "title": f.title,
                    "detail": f.detail,
                    "recommendation": f.recommendation,
                }
                for f in active_findings
            ],
            "sarif": sarif,
            "markdown": md,
        },
        indent=2,
    )


def simulate_invariants_tool(params_json: str = "") -> str:
    """Run the economic invariant simulator.

    Checks fee rounding, u64 overflow, value conservation, supply cap, and
    referral chain seams using exact Python integer arithmetic (matching
    on-chain u64 behavior).

    Args:
        params_json: Optional JSON string with simulation parameters. Keys:
            feeBps (int, default 500), feeRounding (floor|ceil, default floor),
            supplyCap (int|null), amounts (list[int]),
            referralDepth (int, default 5), referralRewardBps (int, default 1000),
            referralBaseAmount (int, default 1000).

    Returns:
        JSON string with invariant issues, referral chain results, and round-trip
        results for each probe amount.
    """
    params = DEFAULT_PARAMS
    ref_params = ReferralChainParams()

    if params_json.strip():
        try:
            raw = json.loads(params_json)
            params = SimParams(
                fee_bps=int(raw.get("feeBps", DEFAULT_PARAMS.fee_bps)),
                fee_rounding=raw.get("feeRounding", DEFAULT_PARAMS.fee_rounding),
                supply_cap=raw.get("supplyCap"),
                amounts=[int(x) for x in raw.get("amounts", DEFAULT_PARAMS.amounts)],
            )
            ref_params = ReferralChainParams(
                reward_bps=int(raw.get("referralRewardBps", 1000)),
                rounding=raw.get("feeRounding", "floor"),
                depth=int(raw.get("referralDepth", 5)),
                base_amount=int(raw.get("referralBaseAmount", 1000)),
                max_total_reward=raw.get("referralMaxTotal"),
            )
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            return json.dumps({"error": f"Invalid params JSON: {e}"})

    issues = simulate_invariants(params)
    ref_result = simulate_referral_chain(ref_params)
    round_trips = [
        simulate_round_trip(amt, params.fee_bps, params.fee_rounding)
        for amt in params.amounts
        if 0 <= amt <= U64_MAX
    ]
    monotonicity = check_fee_monotonicity(params.fee_bps, params.amounts, params.fee_rounding)

    md_lines = [
        "# Invariant Simulator Results\n",
        f"- Fee BPS: {params.fee_bps} ({params.fee_rounding} rounding)",
        f"- Supply cap: {params.supply_cap or 'none'}",
        f"- Probe amounts: {params.amounts[:8]}{'...' if len(params.amounts) > 8 else ''}",
        f"- Issues found: {len(issues)}",
        "",
        "## Invariant Issues\n",
    ]
    if issues:
        for i in issues:
            md_lines.append(f"- **[{i.severity}]** `{i.invariant}`: {i.detail}")
    else:
        md_lines.append("_No invariant issues found._")

    md_lines += [
        "",
        f"## Referral Chain (depth={ref_params.depth}, bps={ref_params.reward_bps})\n",
        f"- Per-level rewards: {ref_result.per_level}",
        f"- Total paid: {ref_result.total_paid}",
        f"- Issues: {len(ref_result.issues)}",
    ]
    for i in ref_result.issues:
        md_lines.append(f"  - **[{i.severity}]** {i.detail}")

    md_lines += ["", "## Fee Monotonicity\n"]
    if monotonicity:
        for i in monotonicity:
            md_lines.append(f"- **[{i.severity}]** {i.detail}")
    else:
        md_lines.append("_Fee is monotonically non-decreasing across probe amounts._")

    return json.dumps(
        {
            "feeBps": params.fee_bps,
            "feeRounding": params.fee_rounding,
            "issues": [
                {
                    "severity": i.severity,
                    "invariant": i.invariant,
                    "detail": i.detail,
                    "recommendation": i.recommendation,
                }
                for i in issues
            ],
            "referralChain": {
                "perLevel": ref_result.per_level,
                "totalPaid": ref_result.total_paid,
                "issues": [
                    {
                        "severity": i.severity,
                        "invariant": i.invariant,
                        "detail": i.detail,
                    }
                    for i in ref_result.issues
                ],
            },
            "roundTrips": [
                {
                    "deposited": rt.deposited,
                    "fee": rt.fee,
                    "refund": rt.refund,
                    "dustLost": rt.dust_lost,
                    "issues": [
                        {"severity": i.severity, "detail": i.detail}
                        for i in rt.issues
                    ],
                }
                for rt in round_trips
            ],
            "monotonicity": [
                {"severity": i.severity, "detail": i.detail} for i in monotonicity
            ],
            "markdown": "\n".join(md_lines),
        },
        indent=2,
    )


def map_attack_surface_tool(program_key: str = "") -> str:
    """Run the attack-surface mapper over the bundled BugRap registry.

    Enumerates every (program × chain × bounty-class) cell, prioritizes by
    expected payout, and returns the coverage matrix as JSON + Markdown,
    including a scope-compliance gate.

    Args:
        program_key: Optional program key (e.g. "soex-premiumcvt") to map a
            single program. When empty, maps the entire ecosystem.

    Returns:
        JSON string with prioritized cells, coverage summary, and Markdown.
    """
    registry = _get_registry()

    if program_key.strip():
        prog = program_by_key(registry, program_key.strip())
        if not prog:
            keys = [p.key for p in registry.programs]
            return json.dumps(
                {
                    "error": f'Program "{program_key}" not found.',
                    "availableKeys": keys,
                }
            )
        programs = [prog]
    else:
        programs = registry.programs

    cells = map_ecosystem_surface(programs)
    prioritized = prioritize_cells(cells)
    summary = summarize_coverage(cells)
    md = surface_to_markdown(prioritized, summary)

    return json.dumps(
        {
            "totalCells": summary.total_cells,
            "automatedCells": summary.automated_cells,
            "manualOnlyCells": summary.manual_only_cells,
            "chains": summary.chains,
            "byClass": summary.by_class,
            "cells": [
                {
                    "program": c.program,
                    "chain": c.chain,
                    "vm": c.vm,
                    "vulnClass": c.vuln_class,
                    "engines": c.engines,
                    "automated": c.automated,
                    "payoutCeilingUsd": c.payout_ceiling_usd,
                }
                for c in prioritized
            ],
            "markdown": md,
        },
        indent=2,
    )


def forensic_scan_tool(idl_json: str = "", abi_json: str = "") -> str:
    """Unified offline Solana-IDL + EVM-ABI forensic scan.

    Folds IDL and EVM-ABI findings into one combined SARIF + Markdown brief.
    Both inputs are optional; at least one must be provided.

    Args:
        idl_json: Optional Anchor IDL as a JSON string.
        abi_json: Optional EVM contract ABI as a JSON string (array of entries
            or human-readable signatures).

    Returns:
        JSON string with combined findings, merged SARIF, and Markdown brief.
    """
    solana_result = None
    evm_result = None
    errors: list[str] = []

    if idl_json.strip():
        try:
            raw = json.loads(idl_json)
            idl = normalize_idl(raw)
            solana_result = analyze_idl(idl)
        except (json.JSONDecodeError, ValueError) as e:
            errors.append(f"IDL error: {e}")

    if abi_json.strip():
        try:
            raw_abi = json.loads(abi_json)
            abi = normalize_abi(raw_abi)
            evm_result = analyze_abi(abi)
        except (json.JSONDecodeError, ValueError) as e:
            errors.append(f"ABI error: {e}")

    if not solana_result and not evm_result:
        return json.dumps(
            {
                "error": "No valid IDL or ABI provided.",
                "errors": errors,
            }
        )

    report = build_forensic_report(solana_result, evm_result)

    return json.dumps(
        {
            "errors": errors,
            "solanaFindings": len(solana_result.findings) if solana_result else 0,
            "evmFindings": len(evm_result.findings) if evm_result else 0,
            "sarif": report.sarif,
            "markdown": report.markdown,
        },
        indent=2,
    )


def analyze_evm_abi_tool(abi_json: str, address: str = "") -> str:
    """Offline EVM ABI hunting lanes analysis.

    Walks every external function through 9 EVM hunting lanes (access control,
    upgradeability, arbitrary external call, token approval, signature replay,
    reentrancy, economic math, self-destruct, cross-function correlation) and
    ranks candidates by expected bounty payout.

    Args:
        abi_json: The contract ABI as a JSON string (array of ABI entries or
            human-readable function signatures).
        address: Optional contract address (used only as metadata in output,
            no live RPC calls made).

    Returns:
        JSON string with ranked findings, SARIF, Markdown, severity/lane counts,
        and payout weight summary.
    """
    try:
        raw = json.loads(abi_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid ABI JSON: {e}"})

    try:
        abi = normalize_abi(raw)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    result = analyze_abi(abi)
    sarif = evm_to_sarif(result, abi_path=address or "abi.json")
    md = (
        f"# EVM ABI Analysis"
        + (f" — `{address}`" if address else "")
        + "\n\n"
        + f"- Functions analyzed: {result.function_count}\n"
        + f"- Max risk: {result.max_risk}\n"
        + f"- Total payout weight: ${result.total_payout_weight:,}\n"
        + f"- Severity counts: {json.dumps(result.severity_counts)}\n"
        + f"- Lane counts: {json.dumps(result.lane_counts)}\n\n"
        + "## Findings\n\n"
        + evm_findings_to_markdown(result.findings)
    )

    return json.dumps(
        {
            "address": address or None,
            "functionCount": result.function_count,
            "maxRisk": result.max_risk,
            "totalPayoutWeight": result.total_payout_weight,
            "severityCounts": result.severity_counts,
            "laneCounts": result.lane_counts,
            "findings": [
                {
                    "id": f.id,
                    "lane": f.lane,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "risk": f.risk,
                    "payoutWeight": f.payout_weight,
                    "vulnTypeId": f.vuln_type_id,
                    "function": f.function,
                    "title": f.title,
                    "detail": f.detail,
                    "recommendation": f.recommendation,
                }
                for f in result.findings
            ],
            "sarif": sarif,
            "markdown": md,
        },
        indent=2,
    )


def list_programs_tool() -> str:
    """List all in-scope BugRap programs from the bundled registry.

    Returns:
        JSON string with a list of programs (key, name, category, chains,
        vulnClasses, notes).
    """
    registry = _get_registry()
    programs = [
        {
            "key": p.key,
            "name": p.name,
            "category": p.category,
            "chains": p.chains,
            "vulnClasses": p.vuln_classes,
            "notes": p.notes,
            "contracts": [
                {"chain": c.chain, "address": c.address, "label": c.label}
                for c in p.contracts
            ],
        }
        for p in registry.programs
    ]
    md_lines = [
        "# BugRap Program Registry\n",
        f"Source: {registry.source}\n",
        f"Programs: {len(programs)}\n",
        "| Key | Name | Category | Chains | Vuln Classes |",
        "|-----|------|----------|--------|-------------|",
    ]
    for p in programs:
        chains = ", ".join(p["chains"])
        classes = ", ".join(p["vulnClasses"])
        md_lines.append(f"| {p['key']} | {p['name']} | {p['category']} | {chains} | {classes} |")
    return json.dumps(
        {"programs": programs, "count": len(programs), "markdown": "\n".join(md_lines)},
        indent=2,
    )


def scope_check_tool(program_key: str, chain: str, vuln_class: str) -> str:
    """Check whether a target (program × chain × vuln class) is in scope.

    This is the scope-compliance gate: returns whether the target is explicitly
    in scope for the named BugRap program. Mirrors the Solana guardrail
    philosophy — refuse anything the bounty has not opened.

    Args:
        program_key: The BugRap program key (e.g. "soex-premiumcvt").
        chain: The chain key (e.g. "solana", "ethereum").
        vuln_class: The vulnerability class (e.g. "smart-contract", "auth").

    Returns:
        JSON string with inScope boolean and reasons list.
    """
    registry = _get_registry()
    prog = program_by_key(registry, program_key.strip())
    if not prog:
        keys = [p.key for p in registry.programs]
        return json.dumps(
            {
                "error": f'Program "{program_key}" not found.',
                "availableKeys": keys,
            }
        )
    decision = check_scope(prog, chain=chain.strip(), vuln_class=vuln_class.strip())
    return json.dumps(
        {
            "program": program_key,
            "chain": chain,
            "vulnClass": vuln_class,
            "inScope": decision.in_scope,
            "reasons": decision.reasons,
            "verdict": (
                "✅ In scope."
                if decision.in_scope
                else "❌ Out of scope: " + "; ".join(decision.reasons)
            ),
        },
        indent=2,
    )


# ── chat router ──────────────────────────────────────────────────────────────

_SAMPLE_IDL = SAMPLE_IDL_PATH.read_text(encoding="utf-8") if SAMPLE_IDL_PATH.exists() else "{}"
_SAMPLE_ABI = SAMPLE_ABI_PATH.read_text(encoding="utf-8") if SAMPLE_ABI_PATH.exists() else "[]"


def _chat_respond(message: str, history: list[list[str]]) -> str:
    """Deterministic command router for the chat interface.

    Routes common forensic commands to the appropriate tool function.
    When OPENAI_API_KEY or HF_TOKEN is set, responses could be enhanced
    by an LLM, but the deterministic path is always available as a fallback.

    Args:
        message: The user message.
        history: Prior conversation history (unused in deterministic mode).

    Returns:
        A string response with the tool output or help text.
    """
    msg = message.strip().lower()

    # --- Command routing ---
    if any(k in msg for k in ("list programs", "list_programs", "programs", "registry")):
        result = json.loads(list_programs_tool())
        return result.get("markdown", "Error listing programs.")

    if any(k in msg for k in ("scope check", "scope_check", "in scope", "in-scope")):
        parts = message.split()
        prog = next(
            (parts[i + 1] for i, p in enumerate(parts) if p.lower() in ("check", "scope")),
            "soex-premiumcvt",
        )
        result = json.loads(scope_check_tool(prog, "solana", "smart-contract"))
        return result.get("verdict", json.dumps(result))

    if any(k in msg for k in ("attack surface", "surface_map", "map surface", "coverage")):
        prog = ""
        for kw in ["program:", "program="]:
            if kw in msg:
                prog = msg.split(kw)[1].split()[0].strip()
        result = json.loads(map_attack_surface_tool(prog))
        return result.get("markdown", json.dumps(result, indent=2))

    if any(k in msg for k in ("invariant", "simulate_invariants", "simulate invariants", "fee sim", "u64")):
        result = json.loads(simulate_invariants_tool())
        return result.get("markdown", json.dumps(result, indent=2))

    if any(k in msg for k in ("analyze idl", "analyze_idl", "idl analyze", "solana idl")):
        result = json.loads(analyze_idl_tool(_SAMPLE_IDL))
        md = result.get("markdown", "")
        return (
            "_(Running on bundled sample IDL — paste your own IDL in the Tools tab for real analysis.)_\n\n"
            + md
        )

    if any(k in msg for k in ("analyze evm", "analyze_evm_abi", "evm abi", "evm analyze")):
        result = json.loads(analyze_evm_abi_tool(_SAMPLE_ABI))
        md = result.get("markdown", "")
        return (
            "_(Running on bundled sample EVM ABI — paste your own ABI in the Tools tab.)_\n\n"
            + md
        )

    if any(k in msg for k in ("forensic scan", "forensic_scan", "full scan", "unified scan")):
        result = json.loads(forensic_scan_tool(_SAMPLE_IDL, _SAMPLE_ABI))
        return result.get("markdown", json.dumps(result, indent=2))

    if any(k in msg for k in ("help", "what can you do", "commands", "tools")):
        return (
            "## 🛰️ MCP Stealth Chrome — Available Commands\n\n"
            "| Command | Description |\n"
            "|---------|-------------|\n"
            "| `list programs` | List all in-scope BugRap programs |\n"
            "| `scope check <program>` | Check if a target is in scope |\n"
            "| `attack surface [program:<key>]` | Map coverage matrix |\n"
            "| `invariant simulate` | Run economic invariant simulator |\n"
            "| `analyze idl` | Run IDL static analyzer (sample data) |\n"
            "| `analyze evm` | Run EVM ABI analyzer (sample data) |\n"
            "| `forensic scan` | Unified Solana+EVM forensic report |\n\n"
            "**For real analysis:** paste your IDL/ABI JSON in the **Tools** tab.\n\n"
            "**MCP endpoint:** `https://timmaythetoolmann-mcp-stealth-chrome.hf.space/gradio_api/mcp/sse`"
        )

    # Default: help message
    return (
        "I can help you analyze Solana programs and EVM contracts for security vulnerabilities.\n\n"
        "Try: `help`, `list programs`, `attack surface`, `invariant simulate`, "
        "`analyze idl`, or `analyze evm`.\n\n"
        "For real analysis, use the **Tools** tab to paste your own IDL/ABI JSON."
    )


# ── Gradio UI ─────────────────────────────────────────────────────────────────

def _build_ui() -> gr.Blocks:
    with gr.Blocks(
        title="🛰️ MCP Stealth Chrome — Blockchain Forensics",
    ) as demo:
        gr.Markdown(
            "# 🛰️ MCP Stealth Chrome\n"
            "**Offline blockchain forensics + MCP server.** "
            "Analyze Solana IDLs and EVM ABIs for security vulnerabilities — "
            "no secrets required, no mainnet sends.\n\n"
            "> **MCP endpoint:** `https://timmaythetoolmann-mcp-stealth-chrome.hf.space/gradio_api/mcp/sse`"
        )

        with gr.Tabs():
            # ── Chat tab ──────────────────────────────────────────────────
            with gr.TabItem("💬 Chat"):
                gr.Markdown(
                    "Ask forensic questions conversationally. "
                    "Try: `help`, `list programs`, `attack surface`, `analyze idl`, `analyze evm`."
                )
                gr.ChatInterface(
                    fn=_chat_respond,
                    examples=[
                        "help",
                        "list programs",
                        "attack surface program:soex-premiumcvt",
                        "invariant simulate",
                        "analyze idl",
                        "analyze evm",
                        "forensic scan",
                        "scope check soex-premiumcvt",
                    ],
                )

            # ── Tools tab ─────────────────────────────────────────────────
            with gr.TabItem("🔧 Tools"):
                gr.Markdown("## Forensic Analysis Tools\n\nPaste your own data or use the sample inputs.")

                with gr.Accordion("📋 IDL Static Analyzer", open=True):
                    with gr.Row():
                        idl_input = gr.Textbox(
                            label="Anchor IDL (JSON)",
                            lines=12,
                            value=_SAMPLE_IDL,
                            placeholder='{"name": "my_program", "instructions": [...]}',
                        )
                    with gr.Row():
                        baseline_input = gr.Textbox(
                            label="Baseline IDs (optional JSON list)",
                            lines=2,
                            placeholder='["abc123", "def456"]',
                        )
                        fail_on_input = gr.Dropdown(
                            label="Fail-on severity",
                            choices=["", "critical", "high", "medium", "low", "info"],
                            value="",
                        )
                    idl_btn = gr.Button("🔍 Analyze IDL", variant="primary")
                    idl_output = gr.Textbox(label="Results (JSON + Markdown)", lines=20, max_lines=40)
                    idl_btn.click(
                        fn=analyze_idl_tool,
                        inputs=[idl_input, baseline_input, fail_on_input],
                        outputs=idl_output,
                    )

                with gr.Accordion("⚙️ Invariant Simulator", open=False):
                    inv_input = gr.Textbox(
                        label="Simulation params (optional JSON)",
                        lines=5,
                        placeholder=(
                            '{"feeBps": 500, "feeRounding": "floor", '
                            '"referralDepth": 5, "referralRewardBps": 1000}'
                        ),
                    )
                    inv_btn = gr.Button("▶ Simulate Invariants", variant="primary")
                    inv_output = gr.Textbox(label="Results", lines=20, max_lines=40)
                    inv_btn.click(fn=simulate_invariants_tool, inputs=inv_input, outputs=inv_output)

                with gr.Accordion("🗺️ Attack Surface Mapper", open=False):
                    surface_prog_input = gr.Textbox(
                        label="Program key (optional — leave empty for full ecosystem)",
                        placeholder="soex-premiumcvt",
                    )
                    surface_btn = gr.Button("🗺️ Map Attack Surface", variant="primary")
                    surface_output = gr.Textbox(label="Coverage Matrix", lines=20, max_lines=40)
                    surface_btn.click(
                        fn=map_attack_surface_tool,
                        inputs=surface_prog_input,
                        outputs=surface_output,
                    )

                with gr.Accordion("⛓️ EVM ABI Analyzer", open=False):
                    with gr.Row():
                        abi_input = gr.Textbox(
                            label="EVM ABI (JSON array)",
                            lines=12,
                            value=_SAMPLE_ABI,
                            placeholder='[{"type": "function", "name": "withdraw", ...}]',
                        )
                    evm_address_input = gr.Textbox(
                        label="Contract address (optional metadata only)",
                        placeholder="0x...",
                    )
                    evm_btn = gr.Button("🔍 Analyze EVM ABI", variant="primary")
                    evm_output = gr.Textbox(label="Results", lines=20, max_lines=40)
                    evm_btn.click(
                        fn=analyze_evm_abi_tool,
                        inputs=[abi_input, evm_address_input],
                        outputs=evm_output,
                    )

                with gr.Accordion("🔬 Unified Forensic Scan", open=False):
                    with gr.Row():
                        scan_idl = gr.Textbox(
                            label="Anchor IDL (JSON, optional)",
                            lines=8,
                            value=_SAMPLE_IDL,
                        )
                        scan_abi = gr.Textbox(
                            label="EVM ABI (JSON, optional)",
                            lines=8,
                            value=_SAMPLE_ABI,
                        )
                    scan_btn = gr.Button("🔬 Run Forensic Scan", variant="primary")
                    scan_output = gr.Textbox(label="Combined Report", lines=20, max_lines=40)
                    scan_btn.click(
                        fn=forensic_scan_tool,
                        inputs=[scan_idl, scan_abi],
                        outputs=scan_output,
                    )

                with gr.Accordion("📋 Program Registry", open=False):
                    list_btn = gr.Button("📋 List Programs")
                    list_output = gr.Textbox(label="Registry", lines=15, max_lines=30)
                    list_btn.click(fn=list_programs_tool, outputs=list_output)

                with gr.Accordion("🚦 Scope Check", open=False):
                    with gr.Row():
                        sc_prog = gr.Textbox(label="Program key", value="soex-premiumcvt")
                        sc_chain = gr.Textbox(label="Chain", value="solana")
                        sc_class = gr.Textbox(label="Vuln class", value="smart-contract")
                    sc_btn = gr.Button("🚦 Check Scope")
                    sc_output = gr.Textbox(label="Scope Decision", lines=8)
                    sc_btn.click(
                        fn=scope_check_tool,
                        inputs=[sc_prog, sc_chain, sc_class],
                        outputs=sc_output,
                    )

            # ── About tab ─────────────────────────────────────────────────
            with gr.TabItem("ℹ️ About"):
                gr.Markdown(
                    "## About MCP Stealth Chrome\n\n"
                    "A self-contained Hugging Face Gradio Space that re-packages the offline "
                    "blockchain forensic tooling from the Red-dead-X repository as a "
                    "**Gradio app that is also an MCP server**.\n\n"
                    "### MCP Connection\n\n"
                    "```\n"
                    "# SSE endpoint (direct URL for MCP clients):\n"
                    "https://timmaythetoolmann-mcp-stealth-chrome.hf.space/gradio_api/mcp/sse\n\n"
                    "# For stdio-only MCP clients (e.g. Claude Desktop), use the bridge:\n"
                    "npx mcp-remote https://timmaythetoolmann-mcp-stealth-chrome.hf.space/gradio_api/mcp/sse\n"
                    "```\n\n"
                    "### Guardrails\n\n"
                    "- `READ_ONLY=true` — no blockchain writes\n"
                    "- `ALLOW_TX=false` — no transaction broadcasting\n"
                    "- All analysis is offline (no live RPC calls required)\n"
                    "- No mainnet sends, ever\n\n"
                    "### Source\n\n"
                    "TypeScript source: `soex-premiumcvt-audit/` in [Red-dead-X](https://github.com/TIMMAYTHETOOLMANN/Red-dead-X)\n"
                )

    return demo


# ── entrypoint ───────────────────────────────────────────────────────────────

demo = _build_ui()

if __name__ == "__main__":
    mcp_enabled = os.environ.get("GRADIO_MCP_SERVER", "true").lower() not in ("false", "0", "no")
    demo.launch(
        mcp_server=mcp_enabled,
        server_name="0.0.0.0",
        server_port=int(os.environ.get("PORT", 7860)),
    )
