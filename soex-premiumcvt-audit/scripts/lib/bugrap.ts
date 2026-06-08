/**
 * BugRap program registry, scope model, and scope-compliance gate.
 *
 * BugRap hosts many programs (exchanges, wallets, custody, L2s, DeFi, privacy
 * chains). Each program has its own in-scope chains, asset types, accepted
 * bounty classes, and payout schedule. The original scaffold hard-coded a single
 * SOEX/PremiumCVT scope; this generalises it so the forensic system can reason
 * about *every* program — and refuse out-of-scope targets the same way the
 * Solana guardrails refuse mainnet writes.
 *
 * Pure data + validation. The on-disk registry lives at
 * `targets/bugrap-programs.json`; this module loads and validates it against the
 * chain catalog and vulnerability taxonomy.
 */

import fs from "fs";
import { Severity } from "./analyze";
import { ChainInfo, resolveChain } from "./chains";
import { PayoutBand, VulnClass, allVulnClasses } from "./taxonomy";

/** A concrete on-chain target inside a program's scope. */
export interface ScopedContract {
  /** Chain key from the catalog (e.g. "ethereum", "solana"). */
  chain: string;
  /** EVM address or Solana program id. Empty string = "to be pinned". */
  address: string;
  /** Short label (e.g. "Vault", "Router", "PremiumCVT program"). */
  label: string;
}

export interface BugRapProgram {
  /** Stable lower-case key (e.g. "soex-premiumcvt", "bitget"). */
  key: string;
  /** Display name. */
  name: string;
  /** Asset / product category (exchange, wallet, custody, defi, l2, privacy...). */
  category: string;
  /** In-scope chain keys (must exist in the chain catalog). */
  chains: string[];
  /** Accepted bounty classes for this program (subset of the taxonomy). */
  vulnClasses: VulnClass[];
  /** Concrete in-scope contracts/programs, when published. */
  contracts: ScopedContract[];
  /** Optional payout-band override (USD); falls back to taxonomy defaults. */
  payoutBands?: PayoutBand[];
  /** Free-form scope notes / rules-of-engagement pointers. */
  notes: string;
}

export interface BugRapRegistry {
  source: string;
  programs: BugRapProgram[];
}

function asString(v: unknown, field: string): string {
  if (typeof v !== "string") throw new Error(`Registry field "${field}" must be a string.`);
  return v;
}

function asStringArray(v: unknown, field: string): string[] {
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    throw new Error(`Registry field "${field}" must be a string array.`);
  }
  return v as string[];
}

const VALID_CLASSES = new Set<string>(allVulnClasses());

function normalizeProgram(raw: Record<string, unknown>): BugRapProgram {
  const key = asString(raw.key, "key").trim().toLowerCase();
  const vulnClasses = asStringArray(raw.vulnClasses ?? [], "vulnClasses");
  for (const c of vulnClasses) {
    if (!VALID_CLASSES.has(c)) {
      throw new Error(
        `Program "${key}" lists unknown vuln class "${c}". Valid: ${[...VALID_CLASSES].join(", ")}.`,
      );
    }
  }
  const chains = asStringArray(raw.chains ?? [], "chains");
  // Validate each chain resolves — fail loudly on typos rather than mis-routing.
  for (const ch of chains) resolveChain(ch);

  const contractsRaw = Array.isArray(raw.contracts) ? raw.contracts : [];
  const contracts: ScopedContract[] = contractsRaw.map((c) => {
    const obj = c as Record<string, unknown>;
    const chain = asString(obj.chain, "contracts[].chain").trim().toLowerCase();
    resolveChain(chain);
    return {
      chain,
      address: String(obj.address ?? "").trim(),
      label: String(obj.label ?? "").trim(),
    };
  });

  let payoutBands: PayoutBand[] | undefined;
  if (Array.isArray(raw.payoutBands)) {
    payoutBands = raw.payoutBands.map((b) => {
      const obj = b as Record<string, unknown>;
      return {
        severity: String(obj.severity) as Severity,
        minUsd: Number(obj.minUsd ?? 0),
        maxUsd: Number(obj.maxUsd ?? 0),
      };
    });
  }

  return {
    key,
    name: asString(raw.name ?? key, "name"),
    category: String(raw.category ?? "unknown"),
    chains,
    vulnClasses: vulnClasses as VulnClass[],
    contracts,
    payoutBands,
    notes: String(raw.notes ?? ""),
  };
}

/** Parse and validate a registry object (already JSON-parsed). */
export function normalizeRegistry(raw: unknown): BugRapRegistry {
  if (!raw || typeof raw !== "object") {
    throw new Error("Registry is not a JSON object.");
  }
  const obj = raw as Record<string, unknown>;
  const programsRaw = Array.isArray(obj.programs) ? obj.programs : [];
  const programs = programsRaw.map((p) => normalizeProgram(p as Record<string, unknown>));

  // Keys must be unique so scope lookups are unambiguous.
  const seen = new Set<string>();
  for (const p of programs) {
    if (seen.has(p.key)) throw new Error(`Duplicate program key "${p.key}" in registry.`);
    seen.add(p.key);
  }

  return { source: String(obj.source ?? ""), programs };
}

/** Load + validate the on-disk registry. */
export function loadRegistry(path: string): BugRapRegistry {
  const raw = fs.readFileSync(path, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Failed to parse registry JSON at ${path}: ${(err as Error).message}`);
  }
  return normalizeRegistry(parsed);
}

/** Find a program by key. */
export function programByKey(
  registry: BugRapRegistry,
  key: string,
): BugRapProgram | undefined {
  const k = key.trim().toLowerCase();
  return registry.programs.find((p) => p.key === k);
}

/** Resolve a program's in-scope chains to full ChainInfo records. */
export function programChains(program: BugRapProgram): ChainInfo[] {
  return program.chains.map((c) => resolveChain(c));
}

export interface ScopeDecision {
  inScope: boolean;
  reasons: string[];
}

/**
 * Scope-compliance gate: decide whether a (chain, vulnClass) target is in scope
 * for a program. Mirrors the Solana guardrail philosophy — refuse anything the
 * bounty has not explicitly opened. Active steps (recon, PoC) must call this
 * first and abort when `inScope` is false.
 */
export function checkScope(
  program: BugRapProgram,
  target: { chain?: string; vulnClass?: VulnClass; address?: string },
): ScopeDecision {
  const reasons: string[] = [];
  if (target.chain) {
    const chain = target.chain.trim().toLowerCase();
    if (!program.chains.includes(chain)) {
      reasons.push(
        `chain "${chain}" is not in ${program.key} scope (${program.chains.join(", ") || "none"})`,
      );
    }
  }
  if (target.vulnClass && !program.vulnClasses.includes(target.vulnClass)) {
    reasons.push(
      `vuln class "${target.vulnClass}" is not accepted by ${program.key} ` +
        `(${program.vulnClasses.join(", ") || "none"})`,
    );
  }
  if (target.address) {
    const addr = target.address.trim().toLowerCase();
    const known = program.contracts.some(
      (c) => c.address.trim().toLowerCase() === addr,
    );
    // An unpinned target is not necessarily out of scope, but it is flagged so
    // the operator pins it from the official program page before acting.
    if (!known) {
      reasons.push(
        `address "${target.address}" is not among ${program.key}'s pinned contracts — ` +
          `confirm it from the official program scope before any active step`,
      );
    }
  }
  return { inScope: reasons.length === 0, reasons };
}

/**
 * Hard assertion form of `checkScope` for use at the top of active collectors.
 * Throws with the accumulated reasons when the target is out of scope.
 */
export function assertInScope(
  program: BugRapProgram,
  target: { chain?: string; vulnClass?: VulnClass; address?: string },
): void {
  const decision = checkScope(program, target);
  if (!decision.inScope) {
    throw new Error(
      `Out-of-scope target for program "${program.key}": ${decision.reasons.join("; ")}.`,
    );
  }
}
