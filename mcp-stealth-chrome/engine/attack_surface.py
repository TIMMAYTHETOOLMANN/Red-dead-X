"""
Cross-chain attack-surface / coverage mapper.

Port of soex-premiumcvt-audit/scripts/lib/attack_surface.ts.

Pure functions. No network, no SDK calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .bugrap import BugRapProgram
from .chains import resolve_chain
from .taxonomy import payout_band, vuln_types_by_class


AUTOMATED_ENGINES = {"evm-static", "svm-static", "invariant-sim"}


@dataclass
class SurfaceCell:
    program: str
    chain: str
    vm: str
    vuln_class: str
    engines: list[str]
    automated: bool
    payout_ceiling_usd: int


@dataclass
class CoverageSummary:
    total_cells: int
    automated_cells: int
    manual_only_cells: int
    by_class: dict[str, dict[str, int]]
    chains: list[str]


def _engines_for_vm(vm: str, class_engines: list[str]) -> list[str]:
    """Filter engines to those applicable for a given VM.

    Args:
        vm: The VM family ("evm", "svm", etc.).
        class_engines: All engines the vuln class supports.

    Returns:
        Filtered list of applicable engines.
    """
    result = []
    for e in class_engines:
        if e == "evm-static" and vm == "evm":
            result.append(e)
        elif e == "svm-static" and vm == "svm":
            result.append(e)
        elif e == "invariant-sim":
            result.append(e)  # VM-independent pure math
        elif e == "manual":
            result.append(e)
    return result


def _engines_for_class(vuln_class: str) -> list[str]:
    engines: set[str] = set()
    for vt in vuln_types_by_class(vuln_class):
        engines.update(vt.engines)
    return list(engines)


def _class_payout_ceiling(program: BugRapProgram, vuln_class: str) -> int:
    max_usd = 0
    for vt in vuln_types_by_class(vuln_class):
        band = payout_band(vt.typical_severity, program.payout_bands)
        if band.max_usd > max_usd:
            max_usd = band.max_usd
    return max_usd


def map_program_surface(program: BugRapProgram) -> list[SurfaceCell]:
    """Enumerate every in-scope (chain × bounty-class) cell for a single program.

    Args:
        program: The BugRapProgram to map.

    Returns:
        List of SurfaceCell entries.
    """
    cells: list[SurfaceCell] = []
    for chain_key in program.chains:
        chain = resolve_chain(chain_key)
        for vuln_class in program.vuln_classes:
            class_engines = _engines_for_class(vuln_class)
            engines = _engines_for_vm(chain.vm, class_engines)
            automated = any(e in AUTOMATED_ENGINES for e in engines)
            cells.append(
                SurfaceCell(
                    program=program.key,
                    chain=chain.key,
                    vm=chain.vm,
                    vuln_class=vuln_class,
                    engines=engines,
                    automated=automated,
                    payout_ceiling_usd=_class_payout_ceiling(program, vuln_class),
                )
            )
    return cells


def map_ecosystem_surface(programs: list[BugRapProgram]) -> list[SurfaceCell]:
    """Map the surface for every program in the registry.

    Args:
        programs: List of BugRapProgram instances.

    Returns:
        Flat list of all SurfaceCell entries.
    """
    cells: list[SurfaceCell] = []
    for prog in programs:
        cells.extend(map_program_surface(prog))
    return cells


def summarize_coverage(cells: list[SurfaceCell]) -> CoverageSummary:
    """Summarise coverage across a set of cells.

    Args:
        cells: List of SurfaceCell entries.

    Returns:
        CoverageSummary with totals and breakdown.
    """
    by_class: dict[str, dict[str, int]] = {}
    chains: set[str] = set()
    automated_cells = 0
    for cell in cells:
        chains.add(cell.chain)
        entry = by_class.setdefault(cell.vuln_class, {"total": 0, "automated": 0})
        entry["total"] += 1
        if cell.automated:
            entry["automated"] += 1
            automated_cells += 1
    return CoverageSummary(
        total_cells=len(cells),
        automated_cells=automated_cells,
        manual_only_cells=len(cells) - automated_cells,
        by_class=by_class,
        chains=sorted(chains),
    )


def prioritize_cells(cells: list[SurfaceCell]) -> list[SurfaceCell]:
    """Prioritise cells by expected payout ceiling, then automated-first.

    Args:
        cells: List of SurfaceCell entries.

    Returns:
        Sorted list, highest-value/automated leads first.
    """
    return sorted(
        cells,
        key=lambda c: (
            -c.payout_ceiling_usd,
            0 if c.automated else 1,
            c.program,
            c.chain,
        ),
    )


def surface_to_markdown(cells: list[SurfaceCell], summary: CoverageSummary) -> str:
    """Render the coverage matrix as Markdown.

    Args:
        cells: Prioritized surface cells.
        summary: Coverage summary.

    Returns:
        Markdown string.
    """
    lines = [
        "# Attack Surface Coverage Matrix\n",
        f"- **Total cells:** {summary.total_cells}",
        f"- **Automated:** {summary.automated_cells}",
        f"- **Manual-only:** {summary.manual_only_cells}",
        f"- **Chains touched:** {', '.join(summary.chains)}",
        "",
        "## Prioritized Cells (highest expected payout first)\n",
        "| Program | Chain | VM | Vuln Class | Engines | Auto | Payout Ceiling USD |",
        "|---------|-------|----|-----------|---------|------|-------------------|",
    ]
    for cell in cells[:50]:  # cap for readability
        auto = "✓" if cell.automated else ""
        engines = ", ".join(cell.engines)
        lines.append(
            f"| {cell.program} | {cell.chain} | {cell.vm} | {cell.vuln_class} "
            f"| {engines} | {auto} | ${cell.payout_ceiling_usd:,} |"
        )
    return "\n".join(lines) + "\n"
