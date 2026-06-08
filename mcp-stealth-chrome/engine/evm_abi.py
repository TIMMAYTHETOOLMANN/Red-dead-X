"""
Normalized EVM ABI model.

Port of soex-premiumcvt-audit/scripts/lib/evm_abi.ts.

Supports both JSON-object ABI (array of entries) and human-readable
ABI signatures. Pure data parsing. No network, no SDK calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

StateMutability = Literal["pure", "view", "nonpayable", "payable"]


@dataclass
class AbiParam:
    name: str
    type: str
    indexed: bool = False


@dataclass
class AbiFunction:
    name: str
    state_mutability: str
    inputs: list[AbiParam]
    outputs: list[AbiParam]
    payable: bool
    read_only: bool


@dataclass
class AbiEvent:
    name: str
    inputs: list[AbiParam]
    anonymous: bool


@dataclass
class NormalizedAbi:
    functions: list[AbiFunction]
    events: list[AbiEvent]
    errors: list[str]
    has_fallback: bool
    has_receive: bool


def _normalize_param(raw: object) -> AbiParam:
    obj = raw if isinstance(raw, dict) else {}
    return AbiParam(
        name=str(obj.get("name", "")),
        type=str(obj.get("type", "unknown")).lower(),
        indexed=bool(obj.get("indexed", False)),
    )


def _derive_mutability(obj: dict) -> str:
    sm = obj.get("stateMutability", "")
    if sm in ("pure", "view", "payable", "nonpayable"):
        return sm
    if obj.get("payable") is True:
        return "payable"
    if obj.get("constant") is True:
        return "view"
    return "nonpayable"


def _normalize_function_object(obj: dict) -> AbiFunction:
    sm = _derive_mutability(obj)
    inputs = [_normalize_param(p) for p in obj.get("inputs", [])]
    outputs = [_normalize_param(p) for p in obj.get("outputs", [])]
    return AbiFunction(
        name=str(obj.get("name", "unknown")),
        state_mutability=sm,
        inputs=inputs,
        outputs=outputs,
        payable=sm == "payable",
        read_only=sm in ("view", "pure"),
    )


_FUNC_RE = re.compile(r"^\s*function\s+([A-Za-z0-9_$]+)\s*\(([^)]*)\)(.*)$")
_EVENT_RE = re.compile(r"^\s*event\s+([A-Za-z0-9_$]+)\s*\(([^)]*)\)")
_ERROR_RE = re.compile(r"^\s*error\s+([A-Za-z0-9_$]+)")


def _parse_human_function(line: str) -> AbiFunction | None:
    m = _FUNC_RE.match(line)
    if not m:
        return None
    name = m.group(1)
    inputs_raw = m.group(2).strip()
    tail = m.group(3) or ""

    inputs: list[AbiParam] = []
    if inputs_raw:
        for part in inputs_raw.split(","):
            parts = part.strip().split()
            t = (parts[0] if parts else "unknown").lower()
            n = parts[-1] if len(parts) > 1 else ""
            inputs.append(AbiParam(name=n, type=t, indexed=False))

    sm: str = "nonpayable"
    if re.search(r"\bview\b", tail):
        sm = "view"
    elif re.search(r"\bpure\b", tail):
        sm = "pure"
    elif re.search(r"\bpayable\b", tail):
        sm = "payable"

    outputs: list[AbiParam] = []
    ret_m = re.search(r"returns\s*\(([^)]*)\)", tail)
    if ret_m and ret_m.group(1).strip():
        for part in ret_m.group(1).split(","):
            parts = part.strip().split()
            outputs.append(
                AbiParam(
                    name=parts[-1] if len(parts) > 1 else "",
                    type=(parts[0] if parts else "unknown").lower(),
                    indexed=False,
                )
            )

    return AbiFunction(
        name=name,
        state_mutability=sm,
        inputs=inputs,
        outputs=outputs,
        payable=sm == "payable",
        read_only=sm in ("view", "pure"),
    )


def _parse_human_event(line: str) -> AbiEvent | None:
    m = _EVENT_RE.match(line)
    if not m:
        return None
    inputs: list[AbiParam] = []
    if m.group(2).strip():
        for part in m.group(2).split(","):
            parts = part.strip().split()
            t = (parts[0] if parts else "unknown").lower()
            indexed = "indexed" in part
            n = parts[-1] if len(parts) > 1 else ""
            inputs.append(AbiParam(name=n, type=t, indexed=indexed))
    return AbiEvent(name=m.group(1), inputs=inputs, anonymous=False)


def normalize_abi(raw: object) -> NormalizedAbi:
    """Normalize an ABI in JSON-object or human-readable form.

    Args:
        raw: An array of ABI entries (dicts) or human-readable signature strings.

    Returns:
        A NormalizedAbi instance.

    Raises:
        ValueError: If raw is not a list.
    """
    if not isinstance(raw, list):
        raise ValueError("ABI must be an array (JSON ABI entries or human-readable signatures).")

    functions: list[AbiFunction] = []
    events: list[AbiEvent] = []
    errors: list[str] = []
    has_fallback = False
    has_receive = False

    for entry in raw:
        if isinstance(entry, str):
            fn = _parse_human_function(entry)
            if fn:
                functions.append(fn)
                continue
            ev = _parse_human_event(entry)
            if ev:
                events.append(ev)
                continue
            err_m = _ERROR_RE.match(entry)
            if err_m:
                errors.append(err_m.group(1))
            elif re.match(r"^\s*fallback\b", entry):
                has_fallback = True
            elif re.match(r"^\s*receive\b", entry):
                has_receive = True
            continue

        if isinstance(entry, dict):
            etype = str(entry.get("type", "function"))
            if etype == "function":
                functions.append(_normalize_function_object(entry))
            elif etype == "event":
                events.append(
                    AbiEvent(
                        name=str(entry.get("name", "unknown")),
                        inputs=[_normalize_param(p) for p in entry.get("inputs", [])],
                        anonymous=bool(entry.get("anonymous", False)),
                    )
                )
            elif etype == "error":
                errors.append(str(entry.get("name", "unknown")))
            elif etype == "fallback":
                has_fallback = True
            elif etype == "receive":
                has_receive = True
            elif etype == "constructor":
                pass  # constructors don't need analysis

    return NormalizedAbi(
        functions=functions,
        events=events,
        errors=errors,
        has_fallback=has_fallback,
        has_receive=has_receive,
    )
