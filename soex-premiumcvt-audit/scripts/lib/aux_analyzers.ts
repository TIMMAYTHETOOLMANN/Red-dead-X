/**
 * Auxiliary static analyzers, wired into the unified forensic pipeline.
 *
 * The encoding, data-state, admin/authority, and economic-invariant tools used
 * to live as `console.log`-only scripts driven by hard-coded mock inputs. This
 * module turns each into a pure function that takes a *real* input and emits
 * `UnifiedFinding`s, so their results land in the same SARIF + Markdown brief as
 * the Solana IDL and EVM ABI engines instead of being analysis islands.
 *
 * Pure functions only: no network, no filesystem. Severity/confidence are mapped
 * conservatively (these are *candidate* leads to confirm by hand, per
 * docs/03-triage-rubric.md) and composite `risk` is computed with the same
 * `riskScore` the core engines use.
 */

import { Confidence, Severity, fingerprint, riskScore } from "./analyze";
import {
  AuthorityClassification,
  scanAuthorities,
  scanPrivilegeActions,
} from "./admin";
import { decodeCandidate } from "./encoding";
import { checkUuidCollisions, diffJson, scanWithRegex } from "./data";
import { INVARIANT_SIM_CONFIG, SimulationEngine } from "./invariant";
import { ForensicEntry, ForensicTarget, UnifiedFinding } from "./forensic_report";

function mkFinding(args: {
  engine: UnifiedFinding["engine"];
  lane: string;
  severity: Severity;
  confidence: Confidence;
  vulnTypeId: string | null;
  locator: string;
  subLocator?: string | null;
  title: string;
  detail: string;
  recommendation: string;
}): UnifiedFinding {
  const subLocator = args.subLocator ?? null;
  return {
    id: fingerprint(`${args.engine}/${args.lane}`, args.locator, subLocator),
    engine: args.engine,
    lane: args.lane,
    severity: args.severity,
    confidence: args.confidence,
    risk: riskScore(args.severity, args.confidence),
    payoutWeight: 0,
    vulnTypeId: args.vulnTypeId,
    locator: args.locator,
    subLocator,
    title: args.title,
    detail: args.detail,
    recommendation: args.recommendation,
  };
}

// --- admin / authority -----------------------------------------------------

const ADMIN_RISK_TO_SEVERITY: Record<string, Severity> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
};

export interface AdminInput {
  /** Contract / program label. */
  contract: string;
  /** Authority state (e.g. `{ upgradeAuthority: "0x..", owner: "0x.." }`). */
  state?: Record<string, unknown>;
  /** Function surface for privileged-action / ACL scanning. */
  abi?: { name: string; modifiers?: string[] }[];
  /** Operator-supplied facts that override the EOA-detection placeholder. */
  classification?: AuthorityClassification;
}

/** Admin/authority lane → unified findings. */
export function analyzeAdmin(input: AdminInput): UnifiedFinding[] {
  const findings: UnifiedFinding[] = [];
  const classification = input.classification ?? {};
  const hasFacts =
    (classification.knownMultisigs?.length ?? 0) +
      (classification.knownContracts?.length ?? 0) +
      (classification.knownEoas?.length ?? 0) >
    0;

  if (input.state) {
    for (const a of scanAuthorities(input.contract, input.state, classification)) {
      // EOA classification leans on a heuristic unless the operator supplied
      // real facts — reflect that in confidence so it ranks below firm signals.
      const confidence: Confidence = a.isEOA && !hasFacts ? "tentative" : "likely";
      findings.push(
        mkFinding({
          engine: "admin-static",
          lane: "admin-authority",
          severity: ADMIN_RISK_TO_SEVERITY[a.riskLevel] ?? "low",
          confidence,
          vulnTypeId: "auth/privileged-authority",
          locator: a.contract,
          subLocator: a.field,
          title: a.isEOA ? "Privileged authority is single-sig/EOA" : "Privileged authority",
          detail: a.description,
          recommendation:
            "Confirm the authority's on-chain type (getCode / multisig threshold) and " +
            "move single-sig upgrade/mint authority behind a timelocked multisig.",
        }),
      );
    }
  }

  if (input.abi) {
    for (const p of scanPrivilegeActions(input.contract, input.abi)) {
      const unguarded = p.roleRequired === "NONE";
      findings.push(
        mkFinding({
          engine: "admin-static",
          lane: "admin-privilege",
          severity: unguarded ? "high" : "info",
          confidence: unguarded ? "likely" : "tentative",
          vulnTypeId: "auth/access-control",
          locator: p.contract,
          subLocator: p.action,
          title: unguarded
            ? "Privileged action lacks a visible role modifier"
            : "Privileged action (guarded)",
          detail: p.description,
          recommendation: unguarded
            ? "Add an `onlyOwner`/role check (or PDA/signer binding) and test calling it as a non-admin."
            : "Verify the modifier actually enforces the intended role/threshold.",
        }),
      );
    }
  }

  return findings;
}

// --- encoding --------------------------------------------------------------

export interface EncodingInput {
  /** Fields to decode/inspect (name + the encoded value seen on-chain/in calldata). */
  fields: { name: string; value: string }[];
}

/** Encoding/decoding lane → unified findings (flags obfuscated privileged terms). */
export function analyzeEncoding(input: EncodingInput): UnifiedFinding[] {
  const findings: UnifiedFinding[] = [];
  for (const field of input.fields) {
    for (const decoded of decodeCandidate(field.value)) {
      if (!decoded.suspicious) continue;
      findings.push(
        mkFinding({
          engine: "encoding-static",
          lane: "encoding-obfuscation",
          severity: "medium",
          confidence: "tentative",
          vulnTypeId: "input-validation/encoding",
          locator: field.name,
          subLocator: decoded.format,
          title: "Field decodes to a privileged-looking term",
          detail:
            `Field \`${field.name}\` value \`${field.value}\` decodes via ${decoded.format} to ` +
            `"${decoded.decodedValue.replace(/\x00/g, "\\x00")}", which contains a privileged term. ` +
            `Possible parameter smuggling / obfuscated privilege escalation.`,
          recommendation:
            "Decode and validate this field server/contract-side; reject privileged tokens supplied " +
            "as user input and test the decoded value against the access-control path.",
        }),
      );
    }
  }
  return findings;
}

// --- data state ------------------------------------------------------------

const AUTHORITY_KEY_RE = /(authority|owner|admin|upgrad|pauser|governance|manager)/i;
const PRIVILEGED_VALUE_RE = /(admin|upgrad|owner|root|sudo|secret|priv)/i;

export interface DataInput {
  /** Pre-change state snapshot (e.g. before an upgrade). */
  pre?: Record<string, unknown>;
  /** Post-change state snapshot. */
  post?: Record<string, unknown>;
  /** Identifiers to check for collisions (e.g. account UUIDs). */
  uuids?: string[];
  /** Extra regex patterns to scan the post state with. */
  regexPatterns?: RegExp[];
}

/** Data-manipulation lane → unified findings (authority drift, role injection, collisions). */
export function analyzeData(input: DataInput): UnifiedFinding[] {
  const findings: UnifiedFinding[] = [];

  if (input.pre && input.post) {
    for (const d of diffJson(input.pre, input.post) as Array<{
      key: string;
      type: "added" | "removed" | "changed";
      pre?: unknown;
      post?: unknown;
    }>) {
      const authorityKey = AUTHORITY_KEY_RE.test(d.key);
      if (d.type === "changed" && authorityKey) {
        findings.push(
          mkFinding({
            engine: "data-static",
            lane: "data-authority-drift",
            severity: "high",
            confidence: "likely",
            vulnTypeId: "business-logic/state-drift",
            locator: d.key,
            title: "Authority field changed between snapshots",
            detail:
              `Authority-bearing field \`${d.key}\` changed from ` +
              `\`${JSON.stringify(d.pre)}\` to \`${JSON.stringify(d.post)}\`. Confirm the change ` +
              `was an authorized, expected transfer and not an unguarded takeover.`,
            recommendation:
              "Trace which instruction/function mutated this field and verify it enforces the " +
              "current authority before allowing the change.",
          }),
        );
      } else if (d.type === "added") {
        const addedStr = JSON.stringify(d.post);
        if (PRIVILEGED_VALUE_RE.test(addedStr) || authorityKey) {
          findings.push(
            mkFinding({
              engine: "data-static",
              lane: "data-role-injection",
              severity: "medium",
              confidence: "tentative",
              vulnTypeId: "business-logic/role-injection",
              locator: d.key,
              title: "Privileged-looking entry added between snapshots",
              detail:
                `New entry \`${d.key}\` = \`${addedStr}\` appeared in the post state and looks ` +
                `privileged. Confirm whether an attacker can inject such a role/value.`,
              recommendation:
                "Validate that role/authority lists can only be extended through an authorized path.",
            }),
          );
        }
      }
    }
  }

  if (input.uuids && input.uuids.length > 0) {
    const collisions = checkUuidCollisions(input.uuids);
    for (const id of collisions) {
      findings.push(
        mkFinding({
          engine: "data-static",
          lane: "data-id-collision",
          severity: "medium",
          confidence: "likely",
          vulnTypeId: "business-logic/id-collision",
          locator: id,
          title: "Duplicate identifier detected",
          detail:
            `Identifier \`${id}\` appears more than once. Colliding ids can cause state confusion, ` +
            `balance merges, or authorization bound to the wrong record.`,
          recommendation:
            "Enforce uniqueness on this identifier at creation and test record-substitution flows.",
        }),
      );
    }
  }

  if (input.post && input.regexPatterns && input.regexPatterns.length > 0) {
    const hits = scanWithRegex(JSON.stringify(input.post), input.regexPatterns);
    for (const hit of hits) {
      findings.push(
        mkFinding({
          engine: "data-static",
          lane: "data-pattern-match",
          severity: "low",
          confidence: "tentative",
          vulnTypeId: "info-leak/pattern",
          locator: hit,
          title: "Sensitive pattern present in state",
          detail: `State contains a value matching a sensitive pattern: \`${hit}\`.`,
          recommendation: "Confirm whether this value should be exposed in the inspected surface.",
        }),
      );
    }
  }

  return findings;
}

// --- economic invariants ---------------------------------------------------

export interface EconomicInput {
  /** Fee rate (basis points) used for the swap/dust probe. Default 100 (1%). */
  feeRateBps?: number;
  /** Swap probe amounts (decimal strings). Default exercises a dust boundary. */
  swapAmounts?: string[];
  /** When true, also exercise the deliberately-vulnerable (unchecked) mint path. */
  probeVulnerableMint?: boolean;
}

/** Economic-invariant lane → unified findings (overflow, dust drain). */
export function analyzeEconomic(input: EconomicInput = {}): UnifiedFinding[] {
  const findings: UnifiedFinding[] = [];
  const engine = new SimulationEngine();
  const feeRateBps = BigInt(input.feeRateBps ?? 100);
  const swapAmounts = input.swapAmounts ?? ["1", "50", "1000"];

  if (input.probeVulnerableMint) {
    const max = INVARIANT_SIM_CONFIG.safetyBounds.supplyMax;
    // Seed a non-zero supply first so minting near the ceiling actually wraps
    // (minting `max` into an empty supply lands exactly at `max` and would not).
    engine.simulateMint("1", false);
    const r = engine.simulateMint(max, true);
    if (!r.invariantPassed) {
      findings.push(
        mkFinding({
          engine: "invariant-sim",
          lane: "economic-overflow",
          severity: "high",
          confidence: "likely",
          vulnTypeId: "smart-contract/economic-overflow",
          locator: r.action,
          title: "Mint can wrap/decrease supply (overflow)",
          detail:
            `${r.failureReason ?? "Overflow"} (category: ${r.vulnCategory ?? "overflow/underflow"}). ` +
            `Minting near the supply ceiling without a bounds check wraps the total supply.`,
          recommendation:
            "Use checked arithmetic and reject mints that would exceed the supply cap; re-run `invariant-sim`.",
        }),
      );
    }
  }

  for (const amount of swapAmounts) {
    const r = engine.simulateSwapFee(amount, feeRateBps);
    if (!r.invariantPassed) {
      findings.push(
        mkFinding({
          engine: "invariant-sim",
          lane: "economic-dust",
          severity: "medium",
          confidence: "likely",
          vulnTypeId: "business-logic/dust-drain",
          locator: `swap(${amount})`,
          title: "Fee rounds to zero (dust drain)",
          detail:
            `${r.failureReason ?? "Fee rounded to zero"} at amount ${amount} with feeRateBps ` +
            `${feeRateBps}. Repeated tiny swaps can move value while paying no fee.`,
          recommendation:
            "Enforce a minimum fee (or round fees up) and reject swaps whose fee would be zero.",
        }),
      );
    }
  }

  return findings;
}

// --- entry assembly --------------------------------------------------------

/** Wrap a pre-computed set of unified findings as a forensic entry. */
export function entryFromFindings(
  target: ForensicTarget,
  findings: UnifiedFinding[],
): ForensicEntry {
  return { target, findings };
}
