"""
Minimal, normalized Anchor IDL model.

Port of soex-premiumcvt-audit/scripts/lib/idl.ts.

Anchor changed its IDL shape between releases (pre-0.30 used isMut/isSigner,
0.30+ uses writable/signer and a richer pda object). The analyzers should not
care which compiler produced the file, so we normalize both shapes into the
structures below before doing any analysis.

Everything here is pure data parsing. No network access, no transactions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class NormalizedSeed:
    kind: Literal["const", "account", "arg", "unknown"]
    value: str


@dataclass
class NormalizedAccount:
    name: str
    writable: bool
    signer: bool
    optional: bool
    seeds: list[NormalizedSeed]
    has_address: bool
    relations: list[str]


@dataclass
class NormalizedArg:
    name: str
    type: str


@dataclass
class NormalizedInstruction:
    name: str
    accounts: list[NormalizedAccount]
    args: list[NormalizedArg]


@dataclass
class NormalizedIdl:
    name: str
    address: str | None
    instructions: list[NormalizedInstruction]


def _type_to_string(t: Any) -> str:
    if t is None:
        return "unknown"
    if isinstance(t, str):
        return t.lower()
    if isinstance(t, dict):
        if isinstance(t.get("defined"), str):
            return t["defined"].lower()
        if isinstance(t.get("defined"), dict):
            name = t["defined"].get("name")
            if isinstance(name, str):
                return name.lower()
        if "option" in t:
            return f"option<{_type_to_string(t['option'])}>"
        if "vec" in t:
            return f"vec<{_type_to_string(t['vec'])}>"
        if "array" in t:
            arr = t["array"]
            if isinstance(arr, list) and arr:
                return f"array<{_type_to_string(arr[0])}>"
        keys = list(t.keys())
        if keys:
            return keys[0].lower()
    return "unknown"


def _normalize_seed(seed: Any) -> NormalizedSeed:
    if not isinstance(seed, dict):
        return NormalizedSeed(kind="unknown", value=str(seed or ""))
    kind = seed.get("kind", "")
    if kind == "const":
        value = seed.get("value")
        if isinstance(value, list):
            bytes_list = [b for b in value if isinstance(b, int)]
            if all(32 <= b < 127 for b in bytes_list):
                rendered = bytes(bytes_list).decode("utf-8", errors="replace")
            else:
                rendered = f"bytes[{len(bytes_list)}]"
            return NormalizedSeed(kind="const", value=rendered)
        return NormalizedSeed(kind="const", value=str(value or ""))
    if kind == "account":
        path = seed.get("path") or seed.get("account", "")
        return NormalizedSeed(kind="account", value=str(path))
    if kind == "arg":
        path = seed.get("path") or seed.get("arg", "")
        return NormalizedSeed(kind="arg", value=str(path))
    return NormalizedSeed(kind="unknown", value=json.dumps(seed))


def _normalize_account(raw: dict[str, Any]) -> NormalizedAccount:
    writable = bool(raw.get("writable") or raw.get("isMut") or False)
    signer = bool(raw.get("signer") or raw.get("isSigner") or False)
    optional = bool(raw.get("optional") or raw.get("isOptional") or False)
    has_address = isinstance(raw.get("address"), str) and len(raw["address"]) > 0

    seeds: list[NormalizedSeed] = []
    pda = raw.get("pda")
    if isinstance(pda, dict):
        raw_seeds = pda.get("seeds")
        if isinstance(raw_seeds, list):
            seeds = [_normalize_seed(s) for s in raw_seeds]
        else:
            seeds = [NormalizedSeed(kind="unknown", value="pda")]

    relations = [str(r) for r in raw.get("relations", []) if raw.get("relations")]

    return NormalizedAccount(
        name=str(raw.get("name", "unknown")),
        writable=writable,
        signer=signer,
        optional=optional,
        seeds=seeds,
        has_address=has_address,
        relations=relations,
    )


def _flatten_accounts(raw: list[Any]) -> list[NormalizedAccount]:
    out: list[NormalizedAccount] = []
    for entry in raw:
        if isinstance(entry, dict):
            if isinstance(entry.get("accounts"), list):
                out.extend(_flatten_accounts(entry["accounts"]))
            else:
                out.append(_normalize_account(entry))
    return out


def _normalize_instruction(ix: dict[str, Any]) -> NormalizedInstruction:
    accounts = _flatten_accounts(ix.get("accounts", []))
    args = [
        NormalizedArg(name=str(a.get("name", "unknown")), type=_type_to_string(a.get("type")))
        for a in ix.get("args", [])
        if isinstance(a, dict)
    ]
    return NormalizedInstruction(
        name=str(ix.get("name", "unknown")),
        accounts=accounts,
        args=args,
    )


def normalize_idl(raw: Any) -> NormalizedIdl:
    """Normalize a raw parsed IDL object into a NormalizedIdl.

    Args:
        raw: The parsed JSON IDL object (dict).

    Returns:
        A NormalizedIdl instance.

    Raises:
        ValueError: If raw is not a dict.
    """
    if not isinstance(raw, dict):
        raise ValueError("IDL is not a JSON object.")

    metadata = raw.get("metadata") or {}
    name = (
        (metadata.get("name") if isinstance(metadata.get("name"), str) else None)
        or (raw.get("name") if isinstance(raw.get("name"), str) else None)
        or "unknown-program"
    )
    address = (
        (raw.get("address") if isinstance(raw.get("address"), str) else None)
        or (metadata.get("address") if isinstance(metadata.get("address"), str) else None)
    )

    instructions = [
        _normalize_instruction(ix)
        for ix in raw.get("instructions", [])
        if isinstance(ix, dict)
    ]

    return NormalizedIdl(name=name, address=address or None, instructions=instructions)


def load_idl(path: str) -> NormalizedIdl:
    """Load and normalize an Anchor IDL from a JSON file.

    Args:
        path: Path to the IDL JSON file.

    Returns:
        A NormalizedIdl instance.
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return normalize_idl(raw)
