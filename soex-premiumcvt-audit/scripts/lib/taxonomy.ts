/**
 * BugRap vulnerability taxonomy — every bounty type, every severity, every band.
 *
 * The original scaffold only modelled Solana/Anchor smart-contract seams. BugRap
 * programs accept a far wider surface: smart-contract bugs, auth/authz flaws,
 * input-validation/injection, sensitive-information leakage, network/config
 * errors, business-logic flaws, and mobile/extension-wallet bugs — each paid out
 * across Critical/High/Medium/Low severity bands.
 *
 * This module turns that into a typed catalog so the forensic system can:
 *   - enumerate *every* bounty type when mapping an attack surface (so nothing
 *     is skipped), and
 *   - weight findings by the bounty payout band, not just severity.
 *
 * Pure data + lookups. No network, no SDK.
 */

import { Severity } from "./analyze";

/** The bounty/vulnerability classes BugRap programs reward. */
export type VulnClass =
  | "smart-contract"
  | "auth"
  | "input-validation"
  | "info-leak"
  | "network-config"
  | "business-logic"
  | "wallet";

/** Which analyzer engine has coverage for a given vuln class. */
export type Engine = "evm-static" | "svm-static" | "invariant-sim" | "manual";

export interface VulnType {
  /** Stable id, e.g. "smart-contract/reentrancy". */
  id: string;
  vulnClass: VulnClass;
  /** Short human-readable label. */
  title: string;
  /** Typical severity ceiling for this type (impact-if-true upper bound). */
  typicalSeverity: Severity;
  /** Engines that produce candidate findings for this type. */
  engines: Engine[];
  /** Example concrete bugs in this type (for coverage notes). */
  examples: string[];
}

/**
 * Approximate USDC payout bands per severity, modelled from BugRap's published
 * ranges. These are *defaults* — a specific program can override them in the
 * registry (`targets/bugrap-programs.json`). Used to payout-weight findings so
 * the highest expected-value leads float up.
 */
export interface PayoutBand {
  severity: Severity;
  minUsd: number;
  maxUsd: number;
}

export const DEFAULT_PAYOUT_BANDS: PayoutBand[] = [
  { severity: "critical", minUsd: 5000, maxUsd: 20000 },
  { severity: "high", minUsd: 2000, maxUsd: 5000 },
  { severity: "medium", minUsd: 200, maxUsd: 1000 },
  { severity: "low", minUsd: 10, maxUsd: 200 },
  { severity: "info", minUsd: 0, maxUsd: 0 },
];

/** The full taxonomy of accepted bounty types across BugRap programs. */
export const VULN_TYPES: VulnType[] = [
  {
    id: "smart-contract/reentrancy",
    vulnClass: "smart-contract",
    title: "Reentrancy (cross-function / read-only)",
    typicalSeverity: "critical",
    engines: ["evm-static", "manual"],
    examples: [
      "state write after external call",
      "ERC-777/ERC-721 hook reentry",
      "read-only reentrancy of a price/share oracle",
    ],
  },
  {
    id: "smart-contract/overflow",
    vulnClass: "smart-contract",
    title: "Integer overflow / underflow / precision loss",
    typicalSeverity: "high",
    engines: ["evm-static", "svm-static", "invariant-sim"],
    examples: ["unchecked u64/uint256 math", "fee rounds to zero", "share inflation"],
  },
  {
    id: "smart-contract/access-control",
    vulnClass: "smart-contract",
    title: "Missing / broken on-chain access control",
    typicalSeverity: "critical",
    engines: ["evm-static", "svm-static"],
    examples: ["missing onlyOwner", "unprotected initializer", "public mint/withdraw"],
  },
  {
    id: "smart-contract/arbitrary-call",
    vulnClass: "smart-contract",
    title: "Arbitrary external call / delegatecall / CPI substitution",
    typicalSeverity: "critical",
    engines: ["evm-static", "svm-static"],
    examples: ["delegatecall to user input", "unpinned CPI program", "approve+transferFrom relay"],
  },
  {
    id: "smart-contract/logic",
    vulnClass: "smart-contract",
    title: "Smart-contract logic / race condition",
    typicalSeverity: "high",
    engines: ["evm-static", "svm-static", "invariant-sim"],
    examples: ["accounting invariant break", "front-runnable state", "signature replay"],
  },
  {
    id: "auth/authentication",
    vulnClass: "auth",
    title: "Authentication / authorization flaw",
    typicalSeverity: "high",
    engines: ["manual"],
    examples: ["JWT/session bypass", "IDOR", "privilege escalation"],
  },
  {
    id: "input-validation/injection",
    vulnClass: "input-validation",
    title: "Input validation / injection (XSS, SQLi, RCE)",
    typicalSeverity: "critical",
    engines: ["manual"],
    examples: ["stored XSS", "SQL injection", "remote code execution"],
  },
  {
    id: "info-leak/sensitive-data",
    vulnClass: "info-leak",
    title: "Sensitive information leakage",
    typicalSeverity: "high",
    engines: ["manual"],
    examples: ["unencrypted transmission", "key/secret exposure", "improper storage"],
  },
  {
    id: "network-config/misconfiguration",
    vulnClass: "network-config",
    title: "Network / security configuration error",
    typicalSeverity: "medium",
    engines: ["manual"],
    examples: ["open admin RPC", "weak TLS", "exposed management port"],
  },
  {
    id: "business-logic/flaw",
    vulnClass: "business-logic",
    title: "Business-logic vulnerability",
    typicalSeverity: "high",
    engines: ["invariant-sim", "manual"],
    examples: ["reward double-spend", "referral abuse", "fee/limit bypass"],
  },
  {
    id: "wallet/mobile-extension",
    vulnClass: "wallet",
    title: "Mobile app / browser-extension wallet bug",
    typicalSeverity: "high",
    engines: ["manual"],
    examples: ["deep-link phishing", "insecure key storage", "approval blind-signing"],
  },
];

const BY_ID = new Map<string, VulnType>(VULN_TYPES.map((v) => [v.id, v]));
const PAYOUT_BY_SEVERITY = new Map<Severity, PayoutBand>(
  DEFAULT_PAYOUT_BANDS.map((b) => [b.severity, b]),
);

/** Look up a vuln type by id. */
export function vulnTypeById(id: string): VulnType | undefined {
  return BY_ID.get(id);
}

/** All vuln types in a given class (e.g. all "smart-contract" types). */
export function vulnTypesByClass(vulnClass: VulnClass): VulnType[] {
  return VULN_TYPES.filter((v) => v.vulnClass === vulnClass);
}

/** Vuln types an engine can produce candidate findings for. */
export function vulnTypesForEngine(engine: Engine): VulnType[] {
  return VULN_TYPES.filter((v) => v.engines.includes(engine));
}

/** Default payout band for a severity (program registry may override). */
export function payoutBand(
  severity: Severity,
  override?: PayoutBand[],
): PayoutBand {
  if (override) {
    const found = override.find((b) => b.severity === severity);
    if (found) return found;
  }
  return PAYOUT_BY_SEVERITY.get(severity) ?? { severity, minUsd: 0, maxUsd: 0 };
}

/**
 * Midpoint of a severity's payout band, used as the expected-value weight when
 * ranking findings by bounty payout rather than raw severity.
 */
export function payoutMidpoint(severity: Severity, override?: PayoutBand[]): number {
  const band = payoutBand(severity, override);
  return Math.round((band.minUsd + band.maxUsd) / 2);
}

/** Every distinct bounty class — used to assert full-surface coverage. */
export function allVulnClasses(): VulnClass[] {
  return [
    "smart-contract",
    "auth",
    "input-validation",
    "info-leak",
    "network-config",
    "business-logic",
    "wallet",
  ];
}
