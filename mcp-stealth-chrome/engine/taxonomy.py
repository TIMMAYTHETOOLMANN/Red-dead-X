"""
BugRap vulnerability taxonomy.

Port of soex-premiumcvt-audit/scripts/lib/taxonomy.ts.

Pure data + lookups. No network, no SDK.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


Severity = Literal["critical", "high", "medium", "low", "info"]

VulnClass = Literal[
    "smart-contract",
    "auth",
    "input-validation",
    "info-leak",
    "network-config",
    "business-logic",
    "wallet",
]

Engine = Literal["evm-static", "svm-static", "invariant-sim", "manual"]


@dataclass
class VulnType:
    id: str
    vuln_class: str
    title: str
    typical_severity: str
    engines: list[str]
    examples: list[str]


@dataclass
class PayoutBand:
    severity: str
    min_usd: int
    max_usd: int


DEFAULT_PAYOUT_BANDS: list[PayoutBand] = [
    PayoutBand(severity="critical", min_usd=5000, max_usd=20000),
    PayoutBand(severity="high", min_usd=2000, max_usd=5000),
    PayoutBand(severity="medium", min_usd=200, max_usd=1000),
    PayoutBand(severity="low", min_usd=10, max_usd=200),
    PayoutBand(severity="info", min_usd=0, max_usd=0),
]

VULN_TYPES: list[VulnType] = [
    VulnType(
        id="smart-contract/reentrancy",
        vuln_class="smart-contract",
        title="Reentrancy (cross-function / read-only)",
        typical_severity="critical",
        engines=["evm-static", "manual"],
        examples=[
            "state write after external call",
            "ERC-777/ERC-721 hook reentry",
            "read-only reentrancy of a price/share oracle",
        ],
    ),
    VulnType(
        id="smart-contract/overflow",
        vuln_class="smart-contract",
        title="Integer overflow / underflow / precision loss",
        typical_severity="high",
        engines=["evm-static", "svm-static", "invariant-sim"],
        examples=["unchecked u64/uint256 math", "fee rounds to zero", "share inflation"],
    ),
    VulnType(
        id="smart-contract/access-control",
        vuln_class="smart-contract",
        title="Missing / broken on-chain access control",
        typical_severity="critical",
        engines=["evm-static", "svm-static"],
        examples=["missing onlyOwner", "unprotected initializer", "public mint/withdraw"],
    ),
    VulnType(
        id="smart-contract/arbitrary-call",
        vuln_class="smart-contract",
        title="Arbitrary external call / delegatecall / CPI substitution",
        typical_severity="critical",
        engines=["evm-static", "svm-static"],
        examples=[
            "delegatecall to user input",
            "unpinned CPI program",
            "approve+transferFrom relay",
        ],
    ),
    VulnType(
        id="smart-contract/logic",
        vuln_class="smart-contract",
        title="Smart-contract logic / race condition",
        typical_severity="high",
        engines=["evm-static", "svm-static", "invariant-sim"],
        examples=["accounting invariant break", "front-runnable state", "signature replay"],
    ),
    VulnType(
        id="auth/authentication",
        vuln_class="auth",
        title="Authentication / authorization flaw",
        typical_severity="high",
        engines=["manual"],
        examples=["JWT/session bypass", "IDOR", "privilege escalation"],
    ),
    VulnType(
        id="input-validation/injection",
        vuln_class="input-validation",
        title="Input validation / injection (XSS, SQLi, RCE)",
        typical_severity="critical",
        engines=["manual"],
        examples=["stored XSS", "SQL injection", "remote code execution"],
    ),
    VulnType(
        id="info-leak/sensitive-data",
        vuln_class="info-leak",
        title="Sensitive information leakage",
        typical_severity="high",
        engines=["manual"],
        examples=["unencrypted transmission", "key/secret exposure", "improper storage"],
    ),
    VulnType(
        id="network-config/misconfiguration",
        vuln_class="network-config",
        title="Network / security configuration error",
        typical_severity="medium",
        engines=["manual"],
        examples=["open admin RPC", "weak TLS", "exposed management port"],
    ),
    VulnType(
        id="business-logic/flaw",
        vuln_class="business-logic",
        title="Business-logic vulnerability",
        typical_severity="high",
        engines=["invariant-sim", "manual"],
        examples=["reward double-spend", "referral abuse", "fee/limit bypass"],
    ),
    VulnType(
        id="wallet/mobile-extension",
        vuln_class="wallet",
        title="Mobile app / browser-extension wallet bug",
        typical_severity="high",
        engines=["manual"],
        examples=[
            "deep-link phishing",
            "insecure key storage",
            "approval blind-signing",
        ],
    ),
]

_BY_ID: dict[str, VulnType] = {v.id: v for v in VULN_TYPES}
_PAYOUT_BY_SEVERITY: dict[str, PayoutBand] = {b.severity: b for b in DEFAULT_PAYOUT_BANDS}


def vuln_type_by_id(id: str) -> VulnType | None:
    """Look up a vuln type by id.

    Args:
        id: The stable vuln type id (e.g. "smart-contract/reentrancy").

    Returns:
        The VulnType, or None if not found.
    """
    return _BY_ID.get(id)


def vuln_types_by_class(vuln_class: str) -> list[VulnType]:
    """All vuln types in a given class.

    Args:
        vuln_class: The vulnerability class (e.g. "smart-contract").

    Returns:
        List of VulnType in that class.
    """
    return [v for v in VULN_TYPES if v.vuln_class == vuln_class]


def vuln_types_for_engine(engine: str) -> list[VulnType]:
    """Vuln types an engine can produce candidate findings for.

    Args:
        engine: Engine name (e.g. "evm-static").

    Returns:
        List of VulnType covered by that engine.
    """
    return [v for v in VULN_TYPES if engine in v.engines]


def payout_band(severity: str, override: list[PayoutBand] | None = None) -> PayoutBand:
    """Default payout band for a severity.

    Args:
        severity: Severity level.
        override: Optional per-program payout band overrides.

    Returns:
        PayoutBand for that severity.
    """
    if override:
        found = next((b for b in override if b.severity == severity), None)
        if found:
            return found
    return _PAYOUT_BY_SEVERITY.get(severity, PayoutBand(severity=severity, min_usd=0, max_usd=0))


def payout_midpoint(severity: str, override: list[PayoutBand] | None = None) -> int:
    """Midpoint of a severity's payout band.

    Args:
        severity: Severity level.
        override: Optional per-program payout band overrides.

    Returns:
        Integer midpoint of the payout band in USD.
    """
    band = payout_band(severity, override)
    return (band.min_usd + band.max_usd) // 2


def all_vuln_classes() -> list[str]:
    """Every distinct bounty class.

    Returns:
        List of all vuln class strings.
    """
    return [
        "smart-contract",
        "auth",
        "input-validation",
        "info-leak",
        "network-config",
        "business-logic",
        "wallet",
    ]
