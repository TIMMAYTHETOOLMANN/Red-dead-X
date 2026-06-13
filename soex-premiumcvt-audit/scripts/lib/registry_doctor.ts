/**
 * Registry doctor — armed vs shell readiness report (pure, offline).
 *
 * The coverage mapper (`attack_surface.ts`) happily enumerates every
 * (chain × bounty-class) cell even when a program has no pinned contract
 * addresses. That makes a *shell* registry look as "covered" as a fully armed
 * one. This module measures how much of the registry is actually actionable so
 * coverage numbers aren't misleading:
 *
 *   - "armed"   — every listed contract has a pinned (non-empty) address.
 *   - "partial" — some, but not all, listed contracts are pinned.
 *   - "shell"   — no pinned contracts (nothing concrete to act on yet).
 *
 * Pure functions only: this reads the already-loaded registry, performs no
 * network/SDK calls, and never resolves an IDL/ABI live. Address resolution and
 * IDL/ABI reachability are deliberately left to the live recon paths.
 */

import { BugRapProgram, BugRapRegistry } from "./bugrap";

export type ArmedState = "armed" | "partial" | "shell";

export interface ProgramReadiness {
  key: string;
  name: string;
  /** In-scope chain keys for the program. */
  chains: string[];
  /** Total contracts listed in the registry for this program. */
  contractsTotal: number;
  /** Contracts with a pinned (non-empty) address. */
  contractsPinned: number;
  /** Contracts still awaiting a pinned address. */
  contractsUnpinned: number;
  /** Readiness classification (see module docs). */
  state: ArmedState;
}

export interface RegistryReadiness {
  total: number;
  armed: number;
  partial: number;
  shell: number;
  programs: ProgramReadiness[];
}

/** A contract is "pinned" when it carries a non-empty address. */
function isPinned(address: string): boolean {
  return address.trim().length > 0;
}

/** Classify a single program's readiness from its pinned-contract counts. */
export function programReadiness(program: BugRapProgram): ProgramReadiness {
  const contractsTotal = program.contracts.length;
  const contractsPinned = program.contracts.filter((c) => isPinned(c.address)).length;
  const contractsUnpinned = contractsTotal - contractsPinned;

  let state: ArmedState;
  if (contractsPinned === 0) {
    // No concrete address yet (covers both empty contract lists and
    // placeholder-only entries) — the engine is gated on data it lacks.
    state = "shell";
  } else if (contractsPinned === contractsTotal) {
    state = "armed";
  } else {
    state = "partial";
  }

  return {
    key: program.key,
    name: program.name,
    chains: [...program.chains],
    contractsTotal,
    contractsPinned,
    contractsUnpinned,
    state,
  };
}

/** Build the armed/partial/shell readiness report for the whole registry. */
export function assessRegistry(registry: BugRapRegistry): RegistryReadiness {
  const programs = registry.programs.map(programReadiness);
  const tally = (s: ArmedState) => programs.filter((p) => p.state === s).length;
  return {
    total: programs.length,
    armed: tally("armed"),
    partial: tally("partial"),
    shell: tally("shell"),
    programs,
  };
}
