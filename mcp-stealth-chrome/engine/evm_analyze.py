"""
Deep static analysis of an EVM contract ABI.

Port of soex-premiumcvt-audit/scripts/lib/evm_analyze.ts.

Walks every external function through EVM-specific hunting lanes and ranks
candidates by composite risk and expected bounty payout.

Like the Solana analyzer, the output is candidate leads to confirm by hand —
never a verdict.

Pure functions only. No network, no SDK calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .analyze import fingerprint, risk_score, SEVERITY_ORDER
from .evm_abi import AbiFunction, NormalizedAbi
from .taxonomy import PayoutBand, payout_midpoint


EvmLane = str  # e.g. "EA-access-control", "EB-upgradeability", etc.


@dataclass
class EvmFinding:
    id: str
    lane: str
    severity: str
    confidence: str
    risk: int
    payout_weight: int
    vuln_type_id: str
    function: str
    title: str
    detail: str
    recommendation: str


@dataclass
class EvmAnalysisResult:
    function_count: int
    findings: list[EvmFinding]
    severity_counts: dict[str, int]
    lane_counts: dict[str, int]
    max_risk: int
    total_payout_weight: int


# ── naming heuristics ────────────────────────────────────────────────────────

_PRIVILEGED_RE = re.compile(
    r"(mint|burn|withdraw|setowner|setadmin|set_|setconfig|configure|pause|unpause|upgrade|"
    r"migrate|initialize|^init$|rescue|sweep|drain|seize|setfee|setprice|whitelist|blacklist|"
    r"grantrole|revokerole|addminter|removeminter|setminter|settreasury|setvault)",
    re.IGNORECASE,
)
_UPGRADE_RE = re.compile(
    r"(upgradeto|upgradetoandcall|setimplementation|changeadmin|transferownership|"
    r"renounceownership|_setimplementation|_upgradeto)",
    re.IGNORECASE,
)
_ARBITRARY_CALL_RE = re.compile(
    r"(^execute$|^call$|multicall|functioncall|delegatecall|aggregate|^batch|forward|relay)",
    re.IGNORECASE,
)
_APPROVAL_RE = re.compile(
    r"(^approve$|increaseallowance|setapprovalforall|^permit$)", re.IGNORECASE
)
_SIGNATURE_RE = re.compile(
    r"(permit|withsig|metatx|executemeta|verifysignature|claimwithsig)", re.IGNORECASE
)
_VALUE_OUT_RE = re.compile(
    r"(withdraw|claim|redeem|unstake|transfer|send|payout|distribute|harvest|collect)",
    re.IGNORECASE,
)
_SELFDESTRUCT_RE = re.compile(
    r"(selfdestruct|destroy|^kill$|terminate)", re.IGNORECASE
)
_AMOUNT_TYPE_RE = re.compile(r"^(u?int(8|16|32|64|128|256)?)$")
_ADMIN_GETTER_RE = re.compile(r"^(owner|admin|getowner|hasrole|getroleadmin)$", re.IGNORECASE)


def _is_uint_type(t: str) -> bool:
    return bool(_AMOUNT_TYPE_RE.match(t))


def _has_address_bytes_pair(fn: AbiFunction) -> bool:
    has_addr = any(i.type == "address" for i in fn.inputs)
    has_bytes = any(i.type == "bytes" or i.type.startswith("bytes") for i in fn.inputs)
    return has_addr and has_bytes


def _has_signature_shape(fn: AbiFunction) -> bool:
    if _SIGNATURE_RE.search(fn.name):
        return True
    has_v = any(i.type == "uint8" and re.match(r"^v$", i.name, re.IGNORECASE) for i in fn.inputs)
    has_r = any(i.type == "bytes32" and re.match(r"^r$", i.name, re.IGNORECASE) for i in fn.inputs)
    has_s = any(i.type == "bytes32" and re.match(r"^s$", i.name, re.IGNORECASE) for i in fn.inputs)
    has_sig = any(
        (i.type == "bytes" or i.type == "bytes32")
        and re.search(r"sig|signature", i.name, re.IGNORECASE)
        for i in fn.inputs
    )
    return (has_v and has_r and has_s) or has_sig


def _has_nonce_or_deadline(fn: AbiFunction) -> bool:
    return any(
        re.search(r"nonce|deadline|expiry|validuntil", i.name, re.IGNORECASE)
        for i in fn.inputs
    )


# ── lane logic ───────────────────────────────────────────────────────────────

def _lane_access_control(fn: AbiFunction) -> list[dict]:
    if fn.read_only:
        return []
    if not _PRIVILEGED_RE.search(fn.name):
        return []
    return [
        dict(
            lane="EA-access-control",
            severity="high",
            confidence="tentative",
            vuln_type_id="smart-contract/access-control",
            function=fn.name,
            title="Privileged function — verify access control",
            detail=(
                f"`{fn.name}` is a state-mutating, privileged-looking function. The ABI cannot "
                "prove an `onlyOwner`/role modifier exists. If it is unprotected, anyone can call it."
            ),
            recommendation=(
                "Confirm the modifier in source (Ownable/AccessControl). Reproduce by calling from "
                "an unrelated EOA on a fork and checking it does not revert."
            ),
        )
    ]


def _lane_upgradeability(fn: AbiFunction) -> list[dict]:
    if not _UPGRADE_RE.search(fn.name):
        return []
    return [
        dict(
            lane="EB-upgradeability",
            severity="critical",
            confidence="likely",
            vuln_type_id="smart-contract/access-control",
            function=fn.name,
            title="Upgrade / ownership-authority function",
            detail=(
                f"`{fn.name}` changes implementation, admin, or ownership. If the *current* "
                "admin/owner is not strictly required (and the function is not behind a timelock), "
                "an attacker who reaches it can seize the contract or point it at malicious code."
            ),
            recommendation=(
                "Verify the caller must be the current admin/owner, confirm a timelock/multisig "
                "guards upgrades, and check the proxy's storage layout compatibility."
            ),
        )
    ]


def _lane_arbitrary_call(fn: AbiFunction) -> list[dict]:
    if fn.read_only:
        return []
    name_hit = bool(_ARBITRARY_CALL_RE.search(fn.name))
    shape_hit = _has_address_bytes_pair(fn)
    if not name_hit and not shape_hit:
        return []
    confidence = "likely" if (name_hit and shape_hit) else "tentative"
    return [
        dict(
            lane="EC-arbitrary-call",
            severity="critical",
            confidence=confidence,
            vuln_type_id="smart-contract/arbitrary-call",
            function=fn.name,
            title="Arbitrary external call / delegatecall seam",
            detail=(
                f"`{fn.name}` looks like it forwards a call to a caller-supplied target/calldata "
                "(address+bytes). If it uses `call`/`delegatecall` without strict target "
                "allow-listing, an attacker can execute arbitrary code or drain approvals "
                "routed through the contract."
            ),
            recommendation=(
                "Confirm the target is allow-listed and that delegatecall (if any) cannot reach "
                "attacker code. Check for approval-draining via routed transferFrom."
            ),
        )
    ]


def _lane_token_approval(fn: AbiFunction) -> list[dict]:
    if not _APPROVAL_RE.search(fn.name):
        return []
    return [
        dict(
            lane="ED-token-approval",
            severity="medium",
            confidence="tentative",
            vuln_type_id="smart-contract/logic",
            function=fn.name,
            title="Approval surface — verify allowance handling",
            detail=(
                f"`{fn.name}` manages token approvals. Approval race conditions, infinite "
                "approvals, and permit replay are classic relay/phishing seams across "
                "DeFi/exchange programs."
            ),
            recommendation=(
                "Check for the approve race (require zero-first or increase/decrease), and that "
                "any permit path is nonce- and deadline-bound."
            ),
        )
    ]


def _lane_signature_replay(fn: AbiFunction) -> list[dict]:
    if fn.read_only:
        return []
    if not _has_signature_shape(fn):
        return []
    unguarded = not _has_nonce_or_deadline(fn)
    return [
        dict(
            lane="EE-signature-replay",
            severity="high" if unguarded else "medium",
            confidence="likely" if unguarded else "tentative",
            vuln_type_id="smart-contract/logic",
            function=fn.name,
            title=(
                "Signature-verifying function without a visible nonce/deadline"
                if unguarded
                else "Signature-verifying function (verify domain separation)"
            ),
            detail=(
                f"`{fn.name}` consumes a signature. "
                + (
                    "No nonce/deadline parameter is visible, so the signature may be replayable "
                    "across transactions or chains."
                    if unguarded
                    else "Confirm EIP-712 domain separation binds chainId and contract so it "
                    "cannot be replayed."
                )
            ),
            recommendation=(
                "Confirm per-signer nonces, a deadline, and an EIP-712 domain (name, version, "
                "chainId, verifyingContract). Attempt a replay on a fork to confirm."
            ),
        )
    ]


def _lane_reentrancy(fn: AbiFunction) -> list[dict]:
    if fn.read_only:
        return []
    value_out = bool(_VALUE_OUT_RE.search(fn.name))
    if not value_out and not fn.payable:
        return []
    return [
        dict(
            lane="EF-reentrancy",
            severity="high",
            confidence="tentative",
            vuln_type_id="smart-contract/reentrancy",
            function=fn.name,
            title="Value-moving function — verify reentrancy guard / CEI",
            detail=(
                f"`{fn.name}` moves value ({'payable' if fn.payable else 'value-out'}). If it "
                "makes an external call before updating state (violating checks-effects-"
                "interactions) and lacks `nonReentrant`, it is a reentrancy candidate."
            ),
            recommendation=(
                "Confirm CEI ordering and a reentrancy guard. Test with a malicious receiver/hook "
                "that re-enters during the external call."
            ),
        )
    ]


def _lane_economic_math(fn: AbiFunction) -> list[dict]:
    if fn.read_only:
        return []
    numeric = [i for i in fn.inputs if _is_uint_type(i.type)]
    valueish = bool(
        re.search(
            r"(mint|burn|deposit|withdraw|swap|stake|unstake|borrow|repay|redeem|price|fee|"
            r"reward|share)",
            fn.name,
            re.IGNORECASE,
        )
    )
    if not numeric or not valueish:
        return []
    args_desc = ", ".join(f"{i.name or '_'}:{i.type}" for i in numeric)
    return [
        dict(
            lane="EG-economic-math",
            severity="medium",
            confidence="tentative",
            vuln_type_id="smart-contract/overflow",
            function=fn.name,
            title="Value-moving math — probe overflow / rounding / share inflation",
            detail=(
                f"`{fn.name}` takes numeric amount(s) [{args_desc}] and touches value. "
                "Rounding-to-zero, precision loss, first-depositor share inflation, and "
                "(pre-0.8 / unchecked) overflow are the seams here."
            ),
            recommendation=(
                "Run the invariant simulator on the fee/share math and probe 0, 1, and near-max "
                "boundaries. Check rounding direction always favours the protocol."
            ),
        )
    ]


def _lane_self_destruct(fn: AbiFunction) -> list[dict]:
    if not _SELFDESTRUCT_RE.search(fn.name):
        return []
    return [
        dict(
            lane="EH-self-destruct",
            severity="high",
            confidence="tentative",
            vuln_type_id="smart-contract/access-control",
            function=fn.name,
            title="Self-destruct / terminate function",
            detail=(
                f"`{fn.name}` may destroy the contract or its logic. Behind a proxy this can "
                "brick the system or strand funds. Verify it is unreachable by untrusted callers."
            ),
            recommendation=(
                "Confirm strict access control and that no delegatecall path can reach a "
                "selfdestruct in the implementation."
            ),
        )
    ]


_LANES = [
    _lane_access_control,
    _lane_upgradeability,
    _lane_arbitrary_call,
    _lane_token_approval,
    _lane_signature_replay,
    _lane_reentrancy,
    _lane_economic_math,
    _lane_self_destruct,
]


def _correlate(abi: NormalizedAbi) -> list[dict]:
    """Cross-function correlation: privileged setters without ownership getter.

    Args:
        abi: The normalized ABI to analyze.

    Returns:
        List of raw finding dicts for EX-correlation lane.
    """
    privileged_setters = [
        f for f in abi.functions
        if not f.read_only and _PRIVILEGED_RE.search(f.name) and not _UPGRADE_RE.search(f.name)
    ]
    has_admin_getter = any(_ADMIN_GETTER_RE.match(f.name) for f in abi.functions)
    if len(privileged_setters) >= 2 and not has_admin_getter:
        examples = ", ".join(f"`{f.name}`" for f in privileged_setters[:3])
        return [
            dict(
                lane="EX-correlation",
                severity="high",
                confidence="likely",
                vuln_type_id="smart-contract/access-control",
                function=privileged_setters[0].name,
                title="Privileged setters with no standard ownership/role getter",
                detail=(
                    f"The contract exposes {len(privileged_setters)} privileged setters "
                    f"(e.g. {examples}) but no `owner()`/`hasRole` getter. The access model may "
                    "be ad-hoc or missing — a high-signal seam for an access-control takeover."
                ),
                recommendation=(
                    "Map every privileged function to a concrete authority check in source; prefer "
                    "a standard Ownable/AccessControl with events and a getter."
                ),
            )
        ]
    return []


def _finalize(raw: dict, payout_bands: list[PayoutBand] | None = None) -> EvmFinding:
    confidence = raw.get("confidence") or "likely"
    severity = raw["severity"]
    return EvmFinding(
        id=fingerprint(raw["lane"], raw["function"], None),
        lane=raw["lane"],
        severity=severity,
        confidence=confidence,
        risk=risk_score(severity, confidence),
        payout_weight=payout_midpoint(severity, payout_bands),
        vuln_type_id=raw["vuln_type_id"],
        function=raw["function"],
        title=raw["title"],
        detail=raw["detail"],
        recommendation=raw["recommendation"],
    )


def analyze_abi(
    abi: NormalizedAbi, payout_bands: list[PayoutBand] | None = None
) -> EvmAnalysisResult:
    """Analyze a normalized EVM ABI through all hunting lanes.

    Args:
        abi: The normalized ABI to analyze.
        payout_bands: Optional per-program payout band overrides.

    Returns:
        EvmAnalysisResult with ranked findings and severity/lane counts.
    """
    per_fn = [
        raw
        for fn in abi.functions
        for lane_fn in _LANES
        for raw in lane_fn(fn)
    ]
    correlated = _correlate(abi)
    findings = [_finalize(r, payout_bands) for r in per_fn + correlated]

    severity_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    lane_counts: dict[str, int] = {
        "EA-access-control": 0,
        "EB-upgradeability": 0,
        "EC-arbitrary-call": 0,
        "ED-token-approval": 0,
        "EE-signature-replay": 0,
        "EF-reentrancy": 0,
        "EG-economic-math": 0,
        "EH-self-destruct": 0,
        "EX-correlation": 0,
    }
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        lane_counts[f.lane] = lane_counts.get(f.lane, 0) + 1

    # Rank by payout weight first, then composite risk, then function name.
    sorted_findings = sorted(
        findings,
        key=lambda f: (-f.payout_weight, -f.risk, f.function),
    )

    max_risk = max((f.risk for f in findings), default=0)
    total_payout_weight = sum(f.payout_weight for f in findings)

    return EvmAnalysisResult(
        function_count=len(abi.functions),
        findings=sorted_findings,
        severity_counts=severity_counts,
        lane_counts=lane_counts,
        max_risk=max_risk,
        total_payout_weight=total_payout_weight,
    )


def evm_findings_to_markdown(findings: list[EvmFinding]) -> str:
    """Render EVM findings as a Markdown table.

    Args:
        findings: List of EvmFinding instances.

    Returns:
        Markdown string.
    """
    if not findings:
        return "_No findings._\n"
    lines = [
        "| Payout | Risk | Severity | Confidence | Lane | Function | Title |",
        "|--------|------|----------|------------|------|----------|-------|",
    ]
    for f in findings:
        lines.append(
            f"| ${f.payout_weight:,} | {f.risk} | {f.severity} | {f.confidence} "
            f"| {f.lane} | {f.function} | {f.title} |"
        )
    return "\n".join(lines) + "\n"


def evm_to_sarif(result: EvmAnalysisResult, abi_path: str = "abi.json") -> dict:
    """Export EVM analysis result as SARIF 2.1.0.

    Args:
        result: The EvmAnalysisResult to export.
        abi_path: The source ABI path (used as artifact URI).

    Returns:
        A SARIF 2.1.0 dict.
    """
    _SARIF_LEVEL = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "warning",
        "info": "note",
    }
    _SEC_SEVERITY = {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.5",
        "low": "3.0",
        "info": "1.0",
    }
    rule_index: dict[str, int] = {}
    rules: list[dict] = []
    for f in result.findings:
        rid = f"{f.lane}/{f.title}".replace(" ", "-").lower()
        if rid in rule_index:
            continue
        rule_index[rid] = len(rules)
        rules.append(
            {
                "id": rid,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "note")},
                "properties": {
                    "lane": f.lane,
                    "security-severity": _SEC_SEVERITY.get(f.severity, "1.0"),
                },
            }
        )

    sarif_results = []
    for f in result.findings:
        rid = f"{f.lane}/{f.title}".replace(" ", "-").lower()
        sarif_results.append(
            {
                "ruleId": rid,
                "ruleIndex": rule_index.get(rid, 0),
                "level": _SARIF_LEVEL.get(f.severity, "note"),
                "message": {
                    "text": (
                        f"[{f.severity}/{f.confidence}] {f.detail} "
                        f"Recommendation: {f.recommendation}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": abi_path},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [
                            {
                                "name": f.function,
                                "fullyQualifiedName": f.function,
                                "kind": "function",
                            }
                        ],
                    }
                ],
                "partialFingerprints": {"evmAnalyzer": f.id},
                "properties": {
                    "function": f.function,
                    "confidence": f.confidence,
                    "risk": f.risk,
                    "payoutWeight": f.payout_weight,
                },
            }
        )

    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "evm-abi-analyzer",
                        "version": "1.0.0",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
