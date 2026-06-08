/**
 * Normalized EVM ABI model.
 *
 * The thirdweb v5 SDK resolves a contract's ABI (via `resolveContractAbi`) as a
 * standard JSON ABI; some sources publish the human-readable form instead
 * (`function transfer(address,uint256) returns (bool)`). The EVM analyzer should
 * not care which shape it got, so we normalize both into the structures below —
 * the EVM analog of `lib/idl.ts` for Solana.
 *
 * Pure data parsing. No network, no SDK calls.
 */

export type StateMutability = "pure" | "view" | "nonpayable" | "payable";

export interface AbiParam {
  name: string;
  /** Solidity type string, lower-cased (e.g. "address", "uint256", "bytes"). */
  type: string;
  /** True for indexed event params. */
  indexed: boolean;
}

export interface AbiFunction {
  name: string;
  stateMutability: StateMutability;
  inputs: AbiParam[];
  outputs: AbiParam[];
  /** Convenience flags derived from stateMutability. */
  payable: boolean;
  readOnly: boolean;
}

export interface AbiEvent {
  name: string;
  inputs: AbiParam[];
  anonymous: boolean;
}

export interface NormalizedAbi {
  functions: AbiFunction[];
  events: AbiEvent[];
  errors: string[];
  hasFallback: boolean;
  hasReceive: boolean;
}

function normalizeParam(raw: unknown): AbiParam {
  const obj = (raw ?? {}) as Record<string, unknown>;
  return {
    name: String(obj.name ?? ""),
    type: String(obj.type ?? "unknown").toLowerCase(),
    indexed: Boolean(obj.indexed ?? false),
  };
}

function deriveMutability(obj: Record<string, unknown>): StateMutability {
  const sm = typeof obj.stateMutability === "string" ? obj.stateMutability : "";
  if (sm === "pure" || sm === "view" || sm === "payable" || sm === "nonpayable") {
    return sm;
  }
  // Fall back to the legacy `constant`/`payable` booleans.
  if (obj.payable === true) return "payable";
  if (obj.constant === true) return "view";
  return "nonpayable";
}

function normalizeFunctionObject(obj: Record<string, unknown>): AbiFunction {
  const stateMutability = deriveMutability(obj);
  const inputs = Array.isArray(obj.inputs) ? obj.inputs.map(normalizeParam) : [];
  const outputs = Array.isArray(obj.outputs) ? obj.outputs.map(normalizeParam) : [];
  return {
    name: String(obj.name ?? "unknown"),
    stateMutability,
    inputs,
    outputs,
    payable: stateMutability === "payable",
    readOnly: stateMutability === "view" || stateMutability === "pure",
  };
}

/**
 * Parse one human-readable ABI signature line into a function. Best-effort:
 * supports `function name(type a, type b) [view|payable] [returns (...)]`.
 * Returns null for non-function lines (events/errors handled separately).
 */
function parseHumanFunction(line: string): AbiFunction | null {
  const m = /^\s*function\s+([A-Za-z0-9_$]+)\s*\(([^)]*)\)(.*)$/.exec(line);
  if (!m) return null;
  const name = m[1];
  const inputsRaw = m[2].trim();
  const tail = m[3] ?? "";

  const inputs: AbiParam[] = inputsRaw
    ? inputsRaw.split(",").map((p) => {
        const parts = p.trim().split(/\s+/);
        const type = (parts[0] ?? "unknown").toLowerCase();
        const nm = parts.length > 1 ? parts[parts.length - 1] : "";
        return { name: nm, type, indexed: false };
      })
    : [];

  let stateMutability: StateMutability = "nonpayable";
  if (/\bview\b/.test(tail)) stateMutability = "view";
  else if (/\bpure\b/.test(tail)) stateMutability = "pure";
  else if (/\bpayable\b/.test(tail)) stateMutability = "payable";

  const outputs: AbiParam[] = [];
  const ret = /returns\s*\(([^)]*)\)/.exec(tail);
  if (ret && ret[1].trim()) {
    for (const p of ret[1].split(",")) {
      const parts = p.trim().split(/\s+/);
      outputs.push({
        name: parts.length > 1 ? parts[parts.length - 1] : "",
        type: (parts[0] ?? "unknown").toLowerCase(),
        indexed: false,
      });
    }
  }

  return {
    name,
    stateMutability,
    inputs,
    outputs,
    payable: stateMutability === "payable",
    readOnly: stateMutability === "view" || stateMutability === "pure",
  };
}

function parseHumanEvent(line: string): AbiEvent | null {
  const m = /^\s*event\s+([A-Za-z0-9_$]+)\s*\(([^)]*)\)/.exec(line);
  if (!m) return null;
  const inputs: AbiParam[] = m[2].trim()
    ? m[2].split(",").map((p) => {
        const parts = p.trim().split(/\s+/);
        const type = (parts[0] ?? "unknown").toLowerCase();
        const indexed = /\bindexed\b/.test(p);
        const nm = parts.length > 1 ? parts[parts.length - 1] : "";
        return { name: nm, type, indexed };
      })
    : [];
  return { name: m[1], inputs, anonymous: false };
}

/**
 * Normalize an ABI in either JSON-object form (array of ABI entries) or
 * human-readable string form (array of signature strings).
 */
export function normalizeAbi(raw: unknown): NormalizedAbi {
  const functions: AbiFunction[] = [];
  const events: AbiEvent[] = [];
  const errors: string[] = [];
  let hasFallback = false;
  let hasReceive = false;

  if (!Array.isArray(raw)) {
    throw new Error("ABI must be an array (JSON ABI entries or human-readable signatures).");
  }

  for (const entry of raw) {
    if (typeof entry === "string") {
      const fn = parseHumanFunction(entry);
      if (fn) {
        functions.push(fn);
        continue;
      }
      const ev = parseHumanEvent(entry);
      if (ev) {
        events.push(ev);
        continue;
      }
      if (/^\s*error\s+([A-Za-z0-9_$]+)/.test(entry)) {
        errors.push(/^\s*error\s+([A-Za-z0-9_$]+)/.exec(entry)![1]);
      } else if (/^\s*fallback\b/.test(entry)) hasFallback = true;
      else if (/^\s*receive\b/.test(entry)) hasReceive = true;
      continue;
    }

    if (entry && typeof entry === "object") {
      const obj = entry as Record<string, unknown>;
      const type = String(obj.type ?? "function");
      switch (type) {
        case "function":
          functions.push(normalizeFunctionObject(obj));
          break;
        case "event":
          events.push({
            name: String(obj.name ?? "unknown"),
            inputs: Array.isArray(obj.inputs) ? obj.inputs.map(normalizeParam) : [],
            anonymous: Boolean(obj.anonymous ?? false),
          });
          break;
        case "error":
          errors.push(String(obj.name ?? "unknown"));
          break;
        case "fallback":
          hasFallback = true;
          break;
        case "receive":
          hasReceive = true;
          break;
        // constructor: ignored for surface analysis.
        default:
          break;
      }
    }
  }

  return { functions, events, errors, hasFallback, hasReceive };
}
