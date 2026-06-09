"""
BugRap program registry, scope model, and scope-compliance gate.

Port of soex-premiumcvt-audit/scripts/lib/bugrap.ts.

Pure data + validation. The on-disk registry lives at data/bugrap-programs.json.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .chains import resolve_chain
from .taxonomy import PayoutBand, all_vuln_classes


VALID_CLASSES = set(all_vuln_classes())


@dataclass
class ScopedContract:
    chain: str
    address: str
    label: str


@dataclass
class BugRapProgram:
    key: str
    name: str
    category: str
    chains: list[str]
    vuln_classes: list[str]
    contracts: list[ScopedContract]
    payout_bands: list[PayoutBand] | None
    notes: str


@dataclass
class BugRapRegistry:
    source: str
    programs: list[BugRapProgram]


@dataclass
class ScopeDecision:
    in_scope: bool
    reasons: list[str]


def _normalize_program(raw: dict[str, Any]) -> BugRapProgram:
    key = str(raw.get("key", "")).strip().lower()
    vuln_classes_raw = raw.get("vulnClasses", [])
    if not isinstance(vuln_classes_raw, list):
        vuln_classes_raw = []
    vuln_classes: list[str] = [str(c) for c in vuln_classes_raw]
    for c in vuln_classes:
        if c not in VALID_CLASSES:
            raise ValueError(
                f'Program "{key}" lists unknown vuln class "{c}". '
                f"Valid: {', '.join(sorted(VALID_CLASSES))}."
            )

    chains_raw = raw.get("chains", [])
    chains: list[str] = [str(c) for c in (chains_raw if isinstance(chains_raw, list) else [])]
    for ch in chains:
        resolve_chain(ch)  # validates — raises on unknown chain

    contracts_raw = raw.get("contracts", [])
    contracts: list[ScopedContract] = []
    for c in (contracts_raw if isinstance(contracts_raw, list) else []):
        if not isinstance(c, dict):
            continue
        chain = str(c.get("chain", "")).strip().lower()
        resolve_chain(chain)
        contracts.append(
            ScopedContract(
                chain=chain,
                address=str(c.get("address", "")).strip(),
                label=str(c.get("label", "")).strip(),
            )
        )

    payout_bands: list[PayoutBand] | None = None
    if isinstance(raw.get("payoutBands"), list):
        payout_bands = [
            PayoutBand(
                severity=str(b.get("severity", "")),
                min_usd=int(b.get("minUsd", 0)),
                max_usd=int(b.get("maxUsd", 0)),
            )
            for b in raw["payoutBands"]
            if isinstance(b, dict)
        ]

    return BugRapProgram(
        key=key,
        name=str(raw.get("name", key)),
        category=str(raw.get("category", "unknown")),
        chains=chains,
        vuln_classes=vuln_classes,
        contracts=contracts,
        payout_bands=payout_bands,
        notes=str(raw.get("notes", "")),
    )


def normalize_registry(raw: Any) -> BugRapRegistry:
    """Parse and validate a registry object (already JSON-parsed).

    Args:
        raw: The parsed JSON registry object.

    Returns:
        A validated BugRapRegistry instance.

    Raises:
        ValueError: If the registry is malformed.
    """
    if not isinstance(raw, dict):
        raise ValueError("Registry is not a JSON object.")
    programs_raw = raw.get("programs", [])
    if not isinstance(programs_raw, list):
        programs_raw = []
    programs = [_normalize_program(p) for p in programs_raw if isinstance(p, dict)]

    seen: set[str] = set()
    for p in programs:
        if p.key in seen:
            raise ValueError(f'Duplicate program key "{p.key}" in registry.')
        seen.add(p.key)

    return BugRapRegistry(source=str(raw.get("source", "")), programs=programs)


def load_registry(path: str) -> BugRapRegistry:
    """Load and validate the on-disk registry.

    Args:
        path: Path to the bugrap-programs.json file.

    Returns:
        A validated BugRapRegistry instance.
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return normalize_registry(raw)


def program_by_key(registry: BugRapRegistry, key: str) -> BugRapProgram | None:
    """Find a program by key.

    Args:
        registry: The loaded registry.
        key: The program key to look up.

    Returns:
        The BugRapProgram, or None.
    """
    k = key.strip().lower()
    return next((p for p in registry.programs if p.key == k), None)


def check_scope(
    program: BugRapProgram,
    chain: str | None = None,
    vuln_class: str | None = None,
    address: str | None = None,
) -> ScopeDecision:
    """Scope-compliance gate: decide whether a target is in scope.

    Args:
        program: The BugRapProgram to check against.
        chain: Optional chain key to verify is in scope.
        vuln_class: Optional vuln class to verify is accepted.
        address: Optional address to verify is in the pinned contracts list.

    Returns:
        ScopeDecision with in_scope bool and reasons list.
    """
    reasons: list[str] = []
    if chain:
        ch = chain.strip().lower()
        if ch not in program.chains:
            reasons.append(
                f'chain "{ch}" is not in {program.key} scope '
                f"({', '.join(program.chains) or 'none'})"
            )
    if vuln_class and vuln_class not in program.vuln_classes:
        reasons.append(
            f'vuln class "{vuln_class}" is not accepted by {program.key} '
            f"({', '.join(program.vuln_classes) or 'none'})"
        )
    if address:
        addr = address.strip().lower()
        known = any(c.address.strip().lower() == addr for c in program.contracts)
        if not known:
            reasons.append(
                f'address "{address}" is not among {program.key}\'s pinned contracts — '
                "confirm it from the official program scope before any active step"
            )
    return ScopeDecision(in_scope=len(reasons) == 0, reasons=reasons)


def assert_in_scope(
    program: BugRapProgram,
    chain: str | None = None,
    vuln_class: str | None = None,
    address: str | None = None,
) -> None:
    """Hard assertion form of check_scope.

    Args:
        program: The BugRapProgram to check against.
        chain: Optional chain key.
        vuln_class: Optional vuln class.
        address: Optional address.

    Raises:
        ValueError: If the target is out of scope.
    """
    decision = check_scope(program, chain=chain, vuln_class=vuln_class, address=address)
    if not decision.in_scope:
        raise ValueError(
            f'Out-of-scope target for program "{program.key}": '
            + "; ".join(decision.reasons)
            + "."
        )
