/**
 * EVM bytecode → compiler fingerprint + compiler-specific vulnerability lane.
 *
 * Many abandoned or breached contracts are *unverified* — there is no source to
 * read — yet the deployed bytecode still carries a signature of the toolchain
 * that produced it. The Solidity compiler appends a CBOR-encoded metadata
 * trailer to runtime bytecode that embeds the exact `solc` version; recent Vyper
 * builds embed a similar marker. This module lifts that fingerprint out of raw
 * bytecode and matches it against a curated database of compiler-version bugs
 * (e.g. pre-0.8.0 unchecked integer overflow), emitting candidate findings into
 * the same unified pipeline the ABI/IDL lanes use.
 *
 * It is the minimal first step of the plan's "Universal Ecosystem Adapters →
 * Compiler-Specific Vulnerability Signatures": no decompilation yet, just a
 * lightweight, fully-offline fingerprint + signature match.
 *
 * Pure functions only. No network, no SDK calls.
 */

import {
  Confidence,
  Severity,
  fingerprint,
  riskScore,
} from "./analyze";
import { PayoutBand, payoutMidpoint } from "./taxonomy";

/** Toolchain family inferred from the bytecode metadata trailer. */
export type CompilerKind = "solc" | "vyper" | "unknown";

export interface CompilerFingerprint {
  kind: CompilerKind;
  /** Semver string (e.g. "0.6.12") when decodable, else null. */
  version: string | null;
  /** Whether a recognisable metadata trailer was present at all. */
  hasMetadata: boolean;
}

export type BytecodeLane = "BC-compiler-fingerprint" | "BC-known-compiler-bug";

export interface BytecodeFinding {
  id: string;
  lane: BytecodeLane;
  severity: Severity;
  confidence: Confidence;
  /** Composite rank = severity weight × confidence weight. */
  risk: number;
  /** Expected payout weight (USD midpoint of the severity band). */
  payoutWeight: number;
  vulnTypeId: string;
  /** Locator: the inferred compiler + version (e.g. "solc 0.6.12"). */
  locator: string;
  title: string;
  detail: string;
  recommendation: string;
}

export interface BytecodeAnalysisResult {
  fingerprint: CompilerFingerprint;
  findings: BytecodeFinding[];
}

type RawBytecodeFinding = Omit<
  BytecodeFinding,
  "id" | "risk" | "payoutWeight"
>;

// --- hex helpers -----------------------------------------------------------

/** Strip an optional 0x prefix and lower-case. Returns "" for empty/no-code. */
function normalizeHex(bytecode: string): string {
  const hex = bytecode.trim().toLowerCase().replace(/^0x/, "");
  // An EOA / self-destructed contract returns "0x" (empty) — nothing to read.
  return /^[0-9a-f]*$/.test(hex) ? hex : "";
}

// --- compiler fingerprinting ----------------------------------------------

/**
 * The Solidity metadata CBOR encodes the version under a 4-char text key
 * "solc" as a 3-byte value (major, minor, patch). In hex that is the literal
 * marker `64 736f6c63 43` (text-string(4) "solc" + byte-string(3)) followed by
 * the three version bytes. Searching for this marker is robust to where the
 * metadata sits and to the surrounding CBOR map shape.
 */
const SOLC_MARKER = "64736f6c6343"; // 'd' 's''o''l''c' 'C'

/**
 * Vyper (>= ~0.3.4) embeds a CBOR marker keyed by the 5-char text "vyper"
 * (`65 7679706572`) followed by a 3-byte version (`43` + 3 bytes).
 */
const VYPER_MARKER = "657679706572"; // text-string(5) "vyper"

function readThreeByteVersionAt(hex: string, byteStart: number): string | null {
  // byteStart is the hex index where the 3 version bytes begin.
  if (byteStart + 6 > hex.length) return null;
  const major = parseInt(hex.slice(byteStart, byteStart + 2), 16);
  const minor = parseInt(hex.slice(byteStart + 2, byteStart + 4), 16);
  const patch = parseInt(hex.slice(byteStart + 4, byteStart + 6), 16);
  if ([major, minor, patch].some((n) => Number.isNaN(n))) return null;
  return `${major}.${minor}.${patch}`;
}

/**
 * Lift the compiler fingerprint out of deployed/runtime bytecode. Returns a
 * best-effort {kind, version}; unknown/unverifiable bytecode yields
 * `{kind: "unknown", version: null, hasMetadata: false}` rather than throwing.
 */
export function fingerprintBytecode(bytecode: string): CompilerFingerprint {
  const hex = normalizeHex(bytecode);
  if (hex.length === 0) {
    return { kind: "unknown", version: null, hasMetadata: false };
  }

  const solcIdx = hex.lastIndexOf(SOLC_MARKER);
  if (solcIdx !== -1) {
    const version = readThreeByteVersionAt(hex, solcIdx + SOLC_MARKER.length);
    return { kind: "solc", version, hasMetadata: true };
  }

  const vyperIdx = hex.lastIndexOf(VYPER_MARKER);
  if (vyperIdx !== -1) {
    // The value after the "vyper" key is `43` (byte-string(3)) + 3 bytes.
    const afterKey = vyperIdx + VYPER_MARKER.length;
    const isByteString3 = hex.slice(afterKey, afterKey + 2) === "43";
    const version = isByteString3
      ? readThreeByteVersionAt(hex, afterKey + 2)
      : null;
    return { kind: "vyper", version, hasMetadata: true };
  }

  // A CBOR metadata trailer commonly ends with the ipfs/bzzr hash + 2-byte
  // length; if any recognisable solc-era marker is absent the contract was
  // likely compiled with metadata stripped or by another toolchain.
  return { kind: "unknown", version: null, hasMetadata: false };
}

// --- semver-lite comparison ------------------------------------------------

function parseVersion(v: string): [number, number, number] | null {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(v.trim());
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

/** -1 if a<b, 0 if equal, 1 if a>b. */
function cmpVersion(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return 0;
  for (let i = 0; i < 3; i++) {
    if (pa[i] < pb[i]) return -1;
    if (pa[i] > pb[i]) return 1;
  }
  return 0;
}

/** True when `lo <= v < hi` (hi exclusive). Either bound may be omitted. */
function inRange(v: string, lo: string | null, hi: string | null): boolean {
  if (lo && cmpVersion(v, lo) < 0) return false;
  if (hi && cmpVersion(v, hi) >= 0) return false;
  return true;
}

// --- compiler-bug signature database ---------------------------------------

interface CompilerSignature {
  kind: CompilerKind;
  /** Inclusive lower bound (null ⇒ unbounded below). */
  introduced: string | null;
  /** Exclusive upper bound — the version that fixed it (null ⇒ still open). */
  fixed: string | null;
  severity: Severity;
  confidence: Confidence;
  vulnTypeId: string;
  title: string;
  detail: string;
  recommendation: string;
}

/**
 * Curated, version-ranged compiler-bug signatures. Kept deliberately small and
 * high-signal; each entry maps to a real, well-documented compiler issue and a
 * taxonomy id. Extend as new compiler CVEs are catalogued.
 */
export const COMPILER_SIGNATURES: CompilerSignature[] = [
  {
    kind: "solc",
    introduced: null,
    fixed: "0.8.0",
    severity: "high",
    confidence: "likely",
    vulnTypeId: "smart-contract/overflow",
    title: "Pre-0.8.0 Solidity: arithmetic is unchecked by default",
    detail:
      "Solidity before 0.8.0 does not insert overflow/underflow checks on +, -, *. " +
      "Unless the contract uses SafeMath everywhere, value-moving math can wrap, " +
      "enabling balance/share inflation or underflow drains.",
    recommendation:
      "Confirm SafeMath (or equivalent guarded math) wraps every arithmetic on " +
      "value/balances. Re-test boundary inputs (0, 1, near-max) with invariant-sim.",
  },
  {
    kind: "solc",
    introduced: "0.5.8",
    fixed: "0.8.16",
    severity: "medium",
    confidence: "tentative",
    vulnTypeId: "smart-contract/logic",
    title: "solc 0.5.8–0.8.15: calldata tuple ABI-reencoding head-overflow bug",
    detail:
      "A compiler bug in ABI re-encoding of calldata tuples (fixed in 0.8.16) can " +
      "corrupt re-encoded data when a function passes calldata structs/arrays " +
      "straight to an external call or abi.encode.",
    recommendation:
      "If the contract re-encodes calldata tuples/arrays to external calls, " +
      "recompile with >=0.8.16 and diff behaviour; review affected call paths.",
  },
  {
    kind: "solc",
    introduced: "0.8.13",
    fixed: "0.8.15",
    severity: "medium",
    confidence: "tentative",
    vulnTypeId: "smart-contract/logic",
    title: "solc 0.8.13–0.8.14: optimizer drops inline-assembly memory writes",
    detail:
      "Under the IR optimizer, memory side-effects of certain inline-assembly " +
      "blocks could be incorrectly removed (fixed in 0.8.15), silently changing " +
      "behaviour of assembly-heavy code.",
    recommendation:
      "If the contract uses inline assembly with the IR pipeline, recompile with " +
      ">=0.8.15 and verify the assembly paths behave identically.",
  },
];

// --- lane logic ------------------------------------------------------------

function finalize(
  raw: RawBytecodeFinding,
  payoutBands?: PayoutBand[],
): BytecodeFinding {
  return {
    ...raw,
    id: fingerprint(raw.lane, raw.locator, null),
    risk: riskScore(raw.severity, raw.confidence),
    payoutWeight: payoutMidpoint(raw.severity, payoutBands),
  };
}

/**
 * Fingerprint deployed bytecode and emit compiler-version candidate findings.
 * Always emits an informational fingerprint finding (so the report records the
 * inferred toolchain) plus one finding per matched compiler-bug signature.
 */
export function analyzeBytecode(
  bytecode: string,
  payoutBands?: PayoutBand[],
): BytecodeAnalysisResult {
  const fp = fingerprintBytecode(bytecode);
  const raws: RawBytecodeFinding[] = [];

  const locator =
    fp.version !== null ? `${fp.kind} ${fp.version}` : `${fp.kind} (version unknown)`;

  raws.push({
    lane: "BC-compiler-fingerprint",
    severity: "info",
    confidence: fp.version !== null ? "likely" : "tentative",
    vulnTypeId: "smart-contract/logic",
    locator,
    title:
      fp.version !== null
        ? `Compiler fingerprint: ${locator}`
        : "Compiler fingerprint: not recoverable from bytecode",
    detail:
      fp.version !== null
        ? `The deployed bytecode embeds a ${fp.kind} ${fp.version} metadata trailer. ` +
          "Use this to scope compiler-specific bug classes and to confirm any " +
          "unverified source you recover matches the on-chain artifact."
        : "No decodable solc/vyper metadata trailer was found (metadata may be " +
          "stripped or the toolchain is unrecognised). Compiler-specific signature " +
          "matching is skipped for this target.",
    recommendation:
      fp.version !== null
        ? "Cross-check against the program's declared toolchain; flag a mismatch."
        : "Treat as unverified; prefer bytecode-level (decompilation) review.",
  });

  if (fp.version !== null) {
    for (const sig of COMPILER_SIGNATURES) {
      if (sig.kind !== fp.kind) continue;
      if (!inRange(fp.version, sig.introduced, sig.fixed)) continue;
      raws.push({
        lane: "BC-known-compiler-bug",
        severity: sig.severity,
        confidence: sig.confidence,
        vulnTypeId: sig.vulnTypeId,
        locator,
        title: sig.title,
        detail: sig.detail,
        recommendation: sig.recommendation,
      });
    }
  }

  return { fingerprint: fp, findings: raws.map((r) => finalize(r, payoutBands)) };
}
