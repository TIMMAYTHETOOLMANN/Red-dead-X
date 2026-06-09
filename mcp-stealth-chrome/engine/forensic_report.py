"""
Unified forensic report — folds IDL + EVM-ABI findings into one combined
SARIF + Markdown brief.

Port of soex-premiumcvt-audit/scripts/lib/forensic_report.ts.

Pure functions. No network, no SDK calls.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .analyze import AnalysisResult, Finding, findings_to_markdown, to_sarif
from .evm_analyze import EvmAnalysisResult, EvmFinding, evm_findings_to_markdown, evm_to_sarif


@dataclass
class ForensicReport:
    solana_result: AnalysisResult | None
    evm_result: EvmAnalysisResult | None
    sarif: dict
    markdown: str


def merge_sarif(solana_sarif: dict | None, evm_sarif: dict | None) -> dict:
    """Merge Solana IDL and EVM ABI SARIF runs into one document.

    Args:
        solana_sarif: SARIF from the IDL analyzer, or None.
        evm_sarif: SARIF from the EVM analyzer, or None.

    Returns:
        A merged SARIF 2.1.0 dict.
    """
    runs: list[dict] = []
    if solana_sarif:
        runs.extend(solana_sarif.get("runs", []))
    if evm_sarif:
        runs.extend(evm_sarif.get("runs", []))
    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": runs,
    }


def build_forensic_report(
    solana_result: AnalysisResult | None,
    evm_result: EvmAnalysisResult | None,
    idl_path: str = "idl.json",
    abi_path: str = "abi.json",
) -> ForensicReport:
    """Build a unified forensic report from IDL and/or EVM-ABI analysis.

    Args:
        solana_result: IDL analysis result, or None if not run.
        evm_result: EVM ABI analysis result, or None if not run.
        idl_path: Source IDL path for SARIF artifact URIs.
        abi_path: Source ABI path for SARIF artifact URIs.

    Returns:
        A ForensicReport with merged SARIF and Markdown.
    """
    solana_sarif = to_sarif(solana_result, idl_path) if solana_result else None
    evm_sarif = evm_to_sarif(evm_result, abi_path) if evm_result else None
    merged = merge_sarif(solana_sarif, evm_sarif)

    parts: list[str] = ["# Unified Forensic Report\n"]

    if solana_result:
        solana_total = len(solana_result.findings)
        parts.append(
            f"## Solana IDL Analysis — `{solana_result.program}`\n\n"
            f"- Address: {solana_result.address or '(none)'}\n"
            f"- Instructions: {solana_result.instruction_count}\n"
            f"- Max risk: {solana_result.max_risk}\n"
            f"- Severity counts: {json.dumps(solana_result.severity_counts)}\n"
            f"- Lane counts: {json.dumps(solana_result.lane_counts)}\n"
            f"- Findings: {solana_total}\n\n"
        )
        parts.append("### IDL Findings\n\n")
        parts.append(findings_to_markdown(solana_result.findings))
    else:
        parts.append("## Solana IDL Analysis\n\n_No IDL provided._\n\n")

    if evm_result:
        evm_total = len(evm_result.findings)
        parts.append(
            f"## EVM ABI Analysis\n\n"
            f"- Functions analyzed: {evm_result.function_count}\n"
            f"- Max risk: {evm_result.max_risk}\n"
            f"- Total payout weight: ${evm_result.total_payout_weight:,}\n"
            f"- Severity counts: {json.dumps(evm_result.severity_counts)}\n"
            f"- Lane counts: {json.dumps(evm_result.lane_counts)}\n"
            f"- Findings: {evm_total}\n\n"
        )
        parts.append("### EVM Findings\n\n")
        parts.append(evm_findings_to_markdown(evm_result.findings))
    else:
        parts.append("## EVM ABI Analysis\n\n_No ABI provided._\n\n")

    # Combined summary
    total_findings = (
        (len(solana_result.findings) if solana_result else 0)
        + (len(evm_result.findings) if evm_result else 0)
    )
    parts.append(
        f"\n---\n\n"
        f"*Total candidate findings: {total_findings}. "
        "All findings are candidates — confirm by hand before reporting.*\n"
    )

    return ForensicReport(
        solana_result=solana_result,
        evm_result=evm_result,
        sarif=merged,
        markdown="".join(parts),
    )
