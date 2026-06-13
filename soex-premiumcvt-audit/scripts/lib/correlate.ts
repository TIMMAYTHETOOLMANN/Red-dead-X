/**
 * Depth pass: cross-chain de-duplication and cross-function/instruction
 * exploit-chain correlation over the unified finding stream.
 *
 * The per-engine lanes rank findings independently and per (chain × contract).
 * Two structural blind spots remain, and this module closes them:
 *
 *   1. Cross-chain dedup — the same contract deployed on N chains yields N
 *      identical findings. `collapseCrossChain` merges them into one seam tagged
 *      with the chains it spans ("same seam, N chains") so the matrix isn't
 *      inflated and the operator sees the shared root once.
 *
 *   2. Exploit-chain modeling — an access-control gap that *enables* a
 *      high-impact primitive (arbitrary call, approval drain, economic overflow,
 *      self-destruct) is far more valuable than either finding alone.
 *      `correlateExploitChains` links an enabler to each amplifier in the same
 *      target and emits a composite, severity-escalated `correlation` finding.
 *
 * Pure functions only.
 */

import { Confidence, Severity, fingerprint, riskScore } from "./analyze";
import { ForensicEntry, UnifiedFinding } from "./forensic_report";

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

function severityIndex(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/** Bump a severity up one rung, capped at critical. */
function escalate(s: Severity): Severity {
  return SEVERITY_ORDER[Math.min(severityIndex(s) + 1, SEVERITY_ORDER.length - 1)];
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return severityIndex(a) >= severityIndex(b) ? a : b;
}

// --- cross-chain de-duplication --------------------------------------------

/** Stable seam identity for cross-chain merging — excludes the chain. */
function seamKey(target: { program: string; address?: string | null }, f: UnifiedFinding): string {
  const addr = (target.address ?? "").trim().toLowerCase() || `program:${target.program}`;
  const sub = f.subLocator ?? "";
  return [addr, f.engine, f.lane, f.locator, sub, f.title].join("\u0000");
}

export interface CrossChainResult {
  /** De-duplicated findings; multi-chain seams carry a populated `chains`. */
  findings: UnifiedFinding[];
  /** How many duplicate findings were merged away. */
  merged: number;
  /** How many resulting seams span more than one chain. */
  multiChainSeams: number;
}

/**
 * Collapse identical seams observed on the same program+address across multiple
 * chains into a single finding annotated with every chain it appears on.
 */
export function collapseCrossChain(entries: ForensicEntry[]): CrossChainResult {
  const groups = new Map<string, { finding: UnifiedFinding; chains: Set<string> }>();
  let total = 0;

  for (const entry of entries) {
    for (const f of entry.findings) {
      total += 1;
      const key = seamKey(entry.target, f);
      const existing = groups.get(key);
      if (existing) {
        existing.chains.add(entry.target.chain);
      } else {
        groups.set(key, { finding: f, chains: new Set([entry.target.chain]) });
      }
    }
  }

  let multiChainSeams = 0;
  const findings: UnifiedFinding[] = [];
  for (const { finding, chains } of groups.values()) {
    if (chains.size > 1) {
      multiChainSeams += 1;
      findings.push({ ...finding, chains: [...chains].sort() });
    } else {
      findings.push(finding);
    }
  }

  return { findings, merged: total - groups.size, multiChainSeams };
}

// --- exploit-chain correlation ---------------------------------------------

/**
 * Lanes representing an access-control / authority *gap* that can enable another
 * primitive. Spans both EVM and SVM engines plus the admin analyzer.
 */
const ENABLER_LANES = new Set<string>([
  "EA-access-control",
  "EX-correlation",
  "A-authority",
  "X-correlation",
  "admin-authority",
  "admin-privilege",
]);

/** Lanes representing a high-impact primitive an enabler can amplify. */
const AMPLIFIER_LANES = new Set<string>([
  "EC-arbitrary-call",
  "ED-token-approval",
  "EG-economic-math",
  "EH-self-destruct",
  "C-token-custody",
  "D-economic",
  "economic-overflow",
]);

function isEnabler(f: UnifiedFinding): boolean {
  // An access-control finding only "enables" when the control is actually weak.
  if (f.lane === "admin-privilege" || f.lane === "EA-access-control") {
    return severityIndex(f.severity) >= severityIndex("high");
  }
  return ENABLER_LANES.has(f.lane);
}

/**
 * Link an access-control enabler to each high-impact amplifier in the same
 * target and emit composite, severity-escalated correlation findings.
 *
 * The composite is intentionally conservative: it only fires when both an
 * enabler and an amplifier are present, and de-duplicates by enabler→amplifier
 * locator pair so a target produces a bounded set of chains.
 */
export function correlateExploitChains(findings: UnifiedFinding[]): UnifiedFinding[] {
  const enablers = findings.filter(isEnabler);
  const amplifiers = findings.filter((f) => AMPLIFIER_LANES.has(f.lane));
  if (enablers.length === 0 || amplifiers.length === 0) return [];

  const composites: UnifiedFinding[] = [];
  const seen = new Set<string>();

  for (const amp of amplifiers) {
    // Pair each amplifier with the strongest enabler at a *different* locator —
    // an exploit chain links two distinct functions/instructions (a same-locator
    // gap+primitive is already captured by the per-lane findings).
    const enabler = [...enablers]
      .filter((e) => e.locator !== amp.locator && e.id !== amp.id)
      .sort((a, b) => b.risk - a.risk)[0];
    if (!enabler) continue;
    const pairKey = `${enabler.locator}\u0000${amp.locator}`;
    if (seen.has(pairKey)) continue;
    seen.add(pairKey);

    const severity = maxSeverity(escalate(amp.severity), enabler.severity);
    const confidence: Confidence = "tentative"; // a hypothesized chain, confirm by hand
    composites.push({
      id: fingerprint("correlation/exploit-chain", enabler.locator, amp.locator),
      engine: "correlation",
      lane: "exploit-chain",
      severity,
      confidence,
      risk: riskScore(severity, confidence),
      payoutWeight: Math.max(enabler.payoutWeight, amp.payoutWeight),
      vulnTypeId: amp.vulnTypeId,
      locator: `${enabler.locator} → ${amp.locator}`,
      subLocator: null,
      title: "Exploit chain: access-control gap enables high-impact primitive",
      detail:
        `Enabler \`${enabler.locator}\` (${enabler.lane}: ${enabler.title}) can unlock amplifier ` +
        `\`${amp.locator}\` (${amp.lane}: ${amp.title}). Chained, the access-control gap turns the ` +
        `primitive into a higher-severity path than either finding scored alone.`,
      recommendation:
        "Close the access-control gap first (it gates the chain), then re-test the amplifier in " +
        "isolation to confirm the composite impact.",
      components: [enabler.id, amp.id],
    });
  }

  return composites;
}

/**
 * Run exploit-chain correlation per entry and return a new entry list with the
 * composite findings appended to each target they were derived from.
 */
export function annotateExploitChains(entries: ForensicEntry[]): ForensicEntry[] {
  return entries.map((entry) => {
    const composites = correlateExploitChains(entry.findings);
    if (composites.length === 0) return entry;
    return { ...entry, findings: [...entry.findings, ...composites] };
  });
}
