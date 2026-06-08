"""
Deep, multi-layer static analysis of an Anchor IDL.

Port of soex-premiumcvt-audit/scripts/lib/analyze.ts.

This is a *static* pass: it reasons about the structure the IDL exposes
(signers, PDA seeds, writability, fixed addresses, relations) and walks every
instruction through the ten hunting lanes.

The output is a list of candidate findings to confirm by hand — never a verdict.

Pure functions only. No network, no transactions, no filesystem.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Literal

from .idl import NormalizedAccount, NormalizedIdl, NormalizedInstruction

# ── types ──────────────────────────────────────────────────────────────────

Severity = Literal["critical", "high", "medium", "low", "info"]
Lane = Literal[
    "A-authority",
    "B-account-substitution",
    "C-token-custody",
    "D-economic",
    "E-referral",
    "F-upgrade-admin",
    "G-cpi-program",
    "H-init-safety",
    "I-dos-compute",
    "X-correlation",
]
Confidence = Literal["firm", "likely", "tentative"]

SEVERITY_ORDER: list[Severity] = ["critical", "high", "medium", "low", "info"]

SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

CONFIDENCE_WEIGHT: dict[str, int] = {
    "firm": 3,
    "likely": 2,
    "tentative": 1,
}


@dataclass
class Finding:
    id: str
    lane: str
    severity: str
    confidence: str
    risk: int
    instruction: str
    account: str | None
    title: str
    detail: str
    recommendation: str


@dataclass
class MatrixRow:
    instruction: str
    account: str
    signer: bool
    writable: bool
    seeds: str
    pinned_address: bool
    relations: str


@dataclass
class AnalysisResult:
    program: str
    address: str | None
    instruction_count: int
    findings: list[Finding]
    matrix: list[MatrixRow]
    severity_counts: dict[str, int]
    lane_counts: dict[str, int]
    max_risk: int


# ── helpers ─────────────────────────────────────────────────────────────────

def fingerprint(lane: str, instruction: str, account: str | None) -> str:
    """Stable content-addressed id for a finding.

    Args:
        lane: The analysis lane identifier.
        instruction: The instruction name.
        account: The account name, or None for instruction-level findings.

    Returns:
        A 16-character hex string.
    """
    data = f"{lane}\x00{instruction}\x00{account or ''}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def risk_score(severity: str, confidence: str) -> int:
    """Composite rank: severity weight × confidence weight.

    Args:
        severity: One of critical/high/medium/low/info.
        confidence: One of firm/likely/tentative.

    Returns:
        Integer risk score (higher = hunt first).
    """
    return SEVERITY_WEIGHT.get(severity, 1) * CONFIDENCE_WEIGHT.get(confidence, 1)


def _finalize(raw: dict) -> Finding:
    confidence = raw.get("confidence") or "likely"
    return Finding(
        id=fingerprint(raw["lane"], raw["instruction"], raw.get("account")),
        lane=raw["lane"],
        severity=raw["severity"],
        confidence=confidence,
        risk=risk_score(raw["severity"], confidence),
        instruction=raw["instruction"],
        account=raw.get("account"),
        title=raw["title"],
        detail=raw["detail"],
        recommendation=raw["recommendation"],
    )


# ── naming heuristics ────────────────────────────────────────────────────────

_PRIVILEGED_RE = re.compile(
    r"(init|initialize|config|configure|set_|update|admin|owner|authority|"
    r"withdraw|mint|burn|claim|close|upgrade|migrate|pause|unpause|freeze|thaw|"
    r"govern|treasury|fee|price|whitelist|blacklist)",
    re.IGNORECASE,
)
_AUTHORITY_RE = re.compile(
    r"(authority|admin|owner|governance|treasury|signer|payer|delegate|manager|operator)",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(r"(token|vault|ata|mint|escrow|pool|reserve|treasury)", re.IGNORECASE)
_REFERRAL_RE = re.compile(
    r"(referr|referer|parent|sponsor|upline|downline|invite|inviter)", re.IGNORECASE
)
_UPGRADE_RE = re.compile(
    r"(upgrade|migrate|set_authority|transfer_authority|set_admin|set_owner|set_upgrade)",
    re.IGNORECASE,
)
_NUMERIC_ARG_RE = re.compile(r"(u8|u16|u32|u64|u128|i8|i16|i32|i64|i128)")
_PROGRAM_RE = re.compile(r"(_program$|^program$|_prog$|invoke|cpi)", re.IGNORECASE)
_INIT_RE = re.compile(r"(init|initialize|create|open|register|new_)", re.IGNORECASE)
_UNBOUNDED_ARG_RE = re.compile(r"^(vec<|bytes$|string$)", re.IGNORECASE)


def _is_program_like(acc: NormalizedAccount) -> bool:
    return acc.has_address or bool(re.search(r"program|sysvar|rent|clock", acc.name, re.IGNORECASE))


def _has_seeds(acc: NormalizedAccount) -> bool:
    return len(acc.seeds) > 0


def _seed_summary(acc: NormalizedAccount) -> str:
    if not acc.seeds:
        return ""
    return " + ".join(f"{s.kind}:{s.value}" for s in acc.seeds)


# ── lane logic ───────────────────────────────────────────────────────────────

def _lane_authority(ix: NormalizedInstruction) -> list[dict]:
    findings: list[dict] = []
    privileged = bool(_PRIVILEGED_RE.search(ix.name))
    any_signer = any(a.signer for a in ix.accounts)

    if privileged and ix.accounts and not any_signer:
        findings.append(
            dict(
                lane="A-authority",
                severity="high",
                confidence="firm",
                instruction=ix.name,
                account=None,
                title="Privileged instruction has no signer",
                detail=(
                    f"Instruction `{ix.name}` looks state-mutating/privileged but declares no "
                    f"signer account. If no signer is enforced, anyone can invoke it."
                ),
                recommendation=(
                    "Confirm in source: require a `Signer<'info>` (or `has_one` against a stored "
                    "authority that must sign). Reproduce by invoking with an unrelated keypair."
                ),
            )
        )

    for acc in ix.accounts:
        if not _AUTHORITY_RE.search(acc.name):
            continue
        if _is_program_like(acc):
            continue
        if not acc.signer and not acc.relations and not _has_seeds(acc) and not acc.has_address:
            findings.append(
                dict(
                    lane="A-authority",
                    severity="medium",
                    confidence="likely",
                    instruction=ix.name,
                    account=acc.name,
                    title="Authority-like account is not a signer and is unbound",
                    detail=(
                        f"Account `{acc.name}` in `{ix.name}` reads like an authority but is not a "
                        f"signer and has no PDA seeds, pinned address, or `relations`/`has_one` "
                        f"binding. An attacker may be able to pass an arbitrary account here."
                    ),
                    recommendation=(
                        "Verify the authority is compared to a signer (e.g. `has_one = authority` "
                        "plus `Signer`). Test by substituting an attacker-controlled account."
                    ),
                )
            )
    return findings


def _lane_account_substitution(ix: NormalizedInstruction) -> list[dict]:
    findings: list[dict] = []
    for acc in ix.accounts:
        if _is_program_like(acc):
            continue
        if acc.signer:
            continue
        if (
            acc.writable
            and not _has_seeds(acc)
            and not acc.has_address
            and not acc.relations
            and not re.search(r"payer|funder", acc.name, re.IGNORECASE)
        ):
            findings.append(
                dict(
                    lane="B-account-substitution",
                    severity="medium",
                    confidence="likely",
                    instruction=ix.name,
                    account=acc.name,
                    title="Writable account has no PDA-seed or relation binding",
                    detail=(
                        f"Writable account `{acc.name}` in `{ix.name}` has no declared PDA seeds, "
                        f"pinned address, or `relations`. If the program does not re-derive/verify "
                        f"it, a substituted account could redirect writes (state or funds)."
                    ),
                    recommendation=(
                        "Confirm the account is a checked PDA (`seeds`+`bump`) or constrained via "
                        "`has_one`/`address`. Try the wrong-account substitution from lane B."
                    ),
                )
            )
        arg_seed = next((s for s in acc.seeds if s.kind == "arg"), None)
        if arg_seed:
            findings.append(
                dict(
                    lane="B-account-substitution",
                    severity="low",
                    confidence="tentative",
                    instruction=ix.name,
                    account=acc.name,
                    title="PDA seed is derived from a caller-supplied argument",
                    detail=(
                        f"PDA `{acc.name}` in `{ix.name}` uses a caller-supplied arg "
                        f"(`{arg_seed.value}`) as a seed. Caller-steered seeds can let an attacker "
                        f"target or collide PDAs they should not control."
                    ),
                    recommendation=(
                        "Confirm the arg-derived seed is additionally bound to the signer/owner so "
                        "it cannot address another user's PDA."
                    ),
                )
            )
    return findings


def _lane_token_custody(ix: NormalizedInstruction) -> list[dict]:
    findings: list[dict] = []
    for acc in ix.accounts:
        if not _TOKEN_RE.search(acc.name):
            continue
        if _is_program_like(acc):
            continue
        if acc.signer:
            continue
        if acc.writable and not _has_seeds(acc) and not acc.relations:
            findings.append(
                dict(
                    lane="C-token-custody",
                    severity="medium",
                    confidence="likely",
                    instruction=ix.name,
                    account=acc.name,
                    title="Token/vault account is not bound by seeds or relations",
                    detail=(
                        f"Token-custody account `{acc.name}` in `{ix.name}` is writable but has "
                        f"no PDA seeds or `relations`. The IDL cannot prove its mint/owner/"
                        f"token-program are constrained, so a wrong-mint or wrong-owner token "
                        f"account may be accepted."
                    ),
                    recommendation=(
                        "Confirm `token::mint`, `token::authority`/owner, and `token_program` "
                        "constraints in source. Test with a wrong-mint and wrong-owner token account."
                    ),
                )
            )
    return findings


def _lane_economic(ix: NormalizedInstruction) -> list[dict]:
    numeric_args = [a for a in ix.args if _NUMERIC_ARG_RE.search(a.type)]
    touches_value = any(
        _TOKEN_RE.search(a.name) and a.writable and not _is_program_like(a)
        for a in ix.accounts
    )
    if numeric_args and touches_value:
        args_desc = ", ".join(f"{a.name}:{a.type}" for a in numeric_args)
        return [
            dict(
                lane="D-economic",
                severity="low",
                confidence="tentative",
                instruction=ix.name,
                account=None,
                title="Value-moving instruction takes numeric amounts",
                detail=(
                    f"Instruction `{ix.name}` takes numeric arg(s) [{args_desc}] and writes a "
                    f"token/vault account. Amount math here is a prime seam for overflow, fee "
                    f"rounding-to-zero, and value-conservation breaks."
                ),
                recommendation=(
                    "Run the invariant simulator against this instruction's fee/mint/burn math and "
                    "probe 0, 1, and near-u64-max boundaries."
                ),
            )
        ]
    return []


def _lane_referral(ix: NormalizedInstruction) -> list[dict]:
    findings: list[dict] = []
    for acc in ix.accounts:
        if not _REFERRAL_RE.search(acc.name):
            continue
        writable_unbound = (
            acc.writable and not acc.signer and not _has_seeds(acc) and not acc.relations
        )
        findings.append(
            dict(
                lane="E-referral",
                severity="medium" if writable_unbound else "info",
                confidence="likely" if writable_unbound else "tentative",
                instruction=ix.name,
                account=acc.name,
                title=(
                    "Referral/parent account is writable and unbound"
                    if writable_unbound
                    else "Referral/parent account participates in this instruction"
                ),
                detail=(
                    f"Account `{acc.name}` in `{ix.name}` is part of the referral graph. "
                    + (
                        "It is writable, non-signing, and unbound, which enables parent injection."
                        if writable_unbound
                        else "Model the referral graph as a payment graph, not a profile feature."
                    )
                ),
                recommendation=(
                    "Check self-referral, A↔B cycles, parent changes after accrual, "
                    "duplicate-parent injection, deep-chain rounding, and compute exhaustion."
                ),
            )
        )
    return findings


def _lane_upgrade_admin(ix: NormalizedInstruction) -> list[dict]:
    if not _UPGRADE_RE.search(ix.name):
        return []
    any_signer = any(a.signer for a in ix.accounts)
    return [
        dict(
            lane="F-upgrade-admin",
            severity="medium" if any_signer else "high",
            confidence="likely" if any_signer else "firm",
            instruction=ix.name,
            account=None,
            title=(
                "Authority/upgrade change instruction (verify the current authority must sign)"
                if any_signer
                else "Authority/upgrade change instruction with no signer"
            ),
            detail=(
                f"Instruction `{ix.name}` changes admin/upgrade authority. "
                + (
                    "Confirm the *current* authority (not just any signer) is required."
                    if any_signer
                    else "No signer is declared — an unintended caller may seize authority."
                )
            ),
            recommendation=(
                "Verify the current authority is enforced via `has_one`+`Signer`. "
                "Cross-check the on-chain upgrade authority."
            ),
        )
    ]


def _lane_cpi_program(ix: NormalizedInstruction) -> list[dict]:
    findings: list[dict] = []
    for acc in ix.accounts:
        if not _PROGRAM_RE.search(acc.name):
            continue
        if acc.has_address:
            continue
        if re.search(r"sysvar|rent|clock", acc.name, re.IGNORECASE):
            continue
        if acc.signer or _has_seeds(acc):
            continue
        findings.append(
            dict(
                lane="G-cpi-program",
                severity="high",
                confidence="likely" if not acc.relations else "tentative",
                instruction=ix.name,
                account=acc.name,
                title="CPI target program is not pinned to a fixed address",
                detail=(
                    f"Program account `{acc.name}` in `{ix.name}` is used like a CPI target but "
                    f"declares no fixed `address`. If the program id is not checked, an attacker "
                    f"can pass a malicious program and execute arbitrary code under the "
                    f"instruction's trust."
                ),
                recommendation=(
                    "Pin the program id (`address = <known program>`), or compare it in source "
                    "against the expected constant before any `invoke`/`invoke_signed`."
                ),
            )
        )
    return findings


def _lane_init_safety(ix: NormalizedInstruction) -> list[dict]:
    if not _INIT_RE.search(ix.name):
        return []
    findings: list[dict] = []
    for acc in ix.accounts:
        if not acc.writable:
            continue
        if _is_program_like(acc):
            continue
        if acc.signer:
            continue
        if re.search(r"payer|funder", acc.name, re.IGNORECASE):
            continue
        if _has_seeds(acc) or acc.has_address or acc.relations:
            continue
        findings.append(
            dict(
                lane="H-init-safety",
                severity="high",
                confidence="likely",
                instruction=ix.name,
                account=acc.name,
                title="Initialized account is not a checked PDA (re-init / overwrite risk)",
                detail=(
                    f"Init-style instruction `{ix.name}` writes `{acc.name}`, which has no PDA "
                    f"seeds, pinned address, or relation binding. Without an `init` constraint on "
                    f"a derived PDA, the account can be re-initialized or substituted."
                ),
                recommendation=(
                    "Use `#[account(init, seeds = [...], bump)]` so the address is derived and "
                    "cannot be re-initialized."
                ),
            )
        )
    return findings


def _lane_dos_compute(ix: NormalizedInstruction) -> list[dict]:
    findings: list[dict] = []
    for arg in ix.args:
        if _UNBOUNDED_ARG_RE.search(arg.type):
            findings.append(
                dict(
                    lane="I-dos-compute",
                    severity="low",
                    confidence="tentative",
                    instruction=ix.name,
                    account=None,
                    title="Instruction takes a caller-sized unbounded argument",
                    detail=(
                        f"Instruction `{ix.name}` accepts `{arg.name}: {arg.type}`, whose length "
                        f"the caller controls. Without an explicit length cap, large inputs can "
                        f"exhaust the compute budget or grow state unboundedly."
                    ),
                    recommendation=(
                        "Enforce a maximum length on the input and a bounded account size; reject "
                        "oversized payloads before processing."
                    ),
                )
            )
    writable_count = sum(
        1 for a in ix.accounts if a.writable and not _is_program_like(a)
    )
    if writable_count >= 8:
        findings.append(
            dict(
                lane="I-dos-compute",
                severity="info",
                confidence="tentative",
                instruction=ix.name,
                account=None,
                title="High writable-account fan-out",
                detail=(
                    f"Instruction `{ix.name}` writes {writable_count} non-program accounts. "
                    f"Wide fan-out often implies per-account loops that can hit the compute "
                    f"budget at scale."
                ),
                recommendation=(
                    "Confirm per-account work is bounded and cannot be amplified by an attacker."
                ),
            )
        )
    return findings


_LANES = [
    _lane_authority,
    _lane_account_substitution,
    _lane_token_custody,
    _lane_economic,
    _lane_referral,
    _lane_upgrade_admin,
    _lane_cpi_program,
    _lane_init_safety,
    _lane_dos_compute,
]


def _correlate_accounts(idl: NormalizedIdl) -> list[dict]:
    """Cross-instruction correlation pass.

    Args:
        idl: The normalized IDL to analyze.

    Returns:
        List of raw finding dicts for X-correlation lane.
    """
    from collections import defaultdict

    by_name: dict[str, list[dict]] = defaultdict(list)
    for ix in idl.instructions:
        for acc in ix.accounts:
            if _is_program_like(acc):
                continue
            bound = _has_seeds(acc) or acc.has_address or bool(acc.relations)
            by_name[acc.name].append(
                {"instruction": ix.name, "bound": bound, "writable": acc.writable}
            )

    findings: list[dict] = []
    for name, sites in by_name.items():
        bound_sites = [s for s in sites if s["bound"]]
        unbound_writable = [s for s in sites if not s["bound"] and s["writable"]]
        if bound_sites and unbound_writable:
            bound_instr = ", ".join(f"`{s['instruction']}`" for s in bound_sites)
            for site in unbound_writable:
                findings.append(
                    dict(
                        lane="X-correlation",
                        severity="high",
                        confidence="likely",
                        instruction=site["instruction"],
                        account=name,
                        title="Account is PDA/relation-bound elsewhere but unbound here",
                        detail=(
                            f"Account `{name}` is constrained (PDA seeds / pinned address / "
                            f"relations) in [{bound_instr}] but is a writable, unbound account "
                            f"in `{site['instruction']}`. The inconsistent constraint strongly "
                            f"suggests a missing check at the unbound site."
                        ),
                        recommendation=(
                            "Apply the same binding used in the constrained instructions "
                            "(seeds+bump or `has_one`/`address`) to this site, then test "
                            "wrong-account substitution."
                        ),
                    )
                )
    return findings


def _build_matrix(idl: NormalizedIdl) -> list[MatrixRow]:
    rows: list[MatrixRow] = []
    for ix in idl.instructions:
        for acc in ix.accounts:
            rows.append(
                MatrixRow(
                    instruction=ix.name,
                    account=acc.name,
                    signer=acc.signer,
                    writable=acc.writable,
                    seeds=_seed_summary(acc),
                    pinned_address=acc.has_address,
                    relations=", ".join(acc.relations),
                )
            )
    return rows


def analyze_idl(idl: NormalizedIdl) -> AnalysisResult:
    """Walk every instruction through all analysis lanes and rank findings.

    Args:
        idl: The normalized IDL to analyze.

    Returns:
        An AnalysisResult with ranked findings and coverage matrix.
    """
    per_instruction = [
        _finalize(raw)
        for ix in idl.instructions
        for lane_fn in _LANES
        for raw in lane_fn(ix)
    ]
    correlated = [_finalize(raw) for raw in _correlate_accounts(idl)]
    findings = per_instruction + correlated

    severity_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    lane_counts: dict[str, int] = {
        "A-authority": 0,
        "B-account-substitution": 0,
        "C-token-custody": 0,
        "D-economic": 0,
        "E-referral": 0,
        "F-upgrade-admin": 0,
        "G-cpi-program": 0,
        "H-init-safety": 0,
        "I-dos-compute": 0,
        "X-correlation": 0,
    }
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        lane_counts[f.lane] = lane_counts.get(f.lane, 0) + 1

    sorted_findings = sorted(
        findings,
        key=lambda f: (
            -f.risk,
            SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 99,
            f.instruction,
        ),
    )

    max_risk = max((f.risk for f in findings), default=0)

    return AnalysisResult(
        program=idl.name,
        address=idl.address,
        instruction_count=len(idl.instructions),
        findings=sorted_findings,
        matrix=_build_matrix(idl),
        severity_counts=severity_counts,
        lane_counts=lane_counts,
        max_risk=max_risk,
    )


def apply_baseline(
    findings: list[Finding], baseline_ids: set[str]
) -> tuple[list[Finding], int]:
    """Suppress findings whose stable id appears in baseline_ids.

    Args:
        findings: All findings from analyze_idl.
        baseline_ids: Set of stable finding ids to suppress.

    Returns:
        Tuple of (kept findings, suppressed count).
    """
    kept = [f for f in findings if f.id not in baseline_ids]
    return kept, len(findings) - len(kept)


def to_sarif(result: AnalysisResult, idl_path: str) -> dict:
    """Export analysis result as SARIF 2.1.0.

    Args:
        result: The AnalysisResult to export.
        idl_path: The source IDL path (used as artifact URI).

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
                "fullDescription": {"text": f"{f.lane}: {f.title}"},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "note")},
                "properties": {
                    "lane": f.lane,
                    "security-severity": _SEC_SEVERITY.get(f.severity, "1.0"),
                    "tags": ["security", "solana", "anchor", f.lane],
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
                            "artifactLocation": {"uri": idl_path},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [
                            {
                                "name": f.account or f.instruction,
                                "fullyQualifiedName": (
                                    f"{f.instruction}.{f.account}"
                                    if f.account
                                    else f.instruction
                                ),
                                "kind": "member" if f.account else "function",
                            }
                        ],
                    }
                ],
                "partialFingerprints": {"idlAnalyzer": f.id},
                "properties": {
                    "instruction": f.instruction,
                    "account": f.account,
                    "confidence": f.confidence,
                    "risk": f.risk,
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
                        "name": "soex-premiumcvt-idl-analyzer",
                        "version": "1.0.0",
                        "informationUri": (
                            "https://github.com/TIMMAYTHETOOLMANN/Red-dead-X/blob/main/"
                            "soex-premiumcvt-audit/docs/05-deep-analysis.md"
                        ),
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def findings_to_markdown(findings: list[Finding]) -> str:
    """Render findings as a Markdown table.

    Args:
        findings: List of findings to render.

    Returns:
        Markdown string with a findings table.
    """
    if not findings:
        return "_No findings._\n"
    lines = [
        "| Risk | Severity | Confidence | Lane | Instruction | Account | Title |",
        "|------|----------|------------|------|-------------|---------|-------|",
    ]
    for f in findings:
        acct = f.account or ""
        lines.append(
            f"| {f.risk} | {f.severity} | {f.confidence} | {f.lane} "
            f"| {f.instruction} | {acct} | {f.title} |"
        )
    return "\n".join(lines) + "\n"


def matrix_to_markdown(matrix: list[MatrixRow]) -> str:
    """Render the instruction/account matrix as Markdown.

    Args:
        matrix: List of MatrixRow entries.

    Returns:
        Markdown string with the matrix table.
    """
    if not matrix:
        return "_No accounts._\n"
    lines = [
        "| Instruction | Account | Signer | Writable | Seeds | Pinned | Relations |",
        "|-------------|---------|--------|----------|-------|--------|-----------|",
    ]
    for r in matrix:
        lines.append(
            f"| {r.instruction} | {r.account} | {'✓' if r.signer else ''} "
            f"| {'✓' if r.writable else ''} | {r.seeds} | {'✓' if r.pinned_address else ''} "
            f"| {r.relations} |"
        )
    return "\n".join(lines) + "\n"
