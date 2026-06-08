/**
 * Cross-chain attack-surface / coverage mapper.
 *
 * "Every nook and cranny": this ties the program registry, the chain catalog,
 * and the vulnerability taxonomy together into a single coverage matrix. For a
 * program it enumerates every in-scope (chain × bounty-class) cell, records
 * which forensic engine covers it, and flags the cells that are manual-only — so
 * an operator can see at a glance that no network, asset type, or bounty class
 * was skipped, and where automated tooling stops and human review must begin.
 *
 * Pure functions. No network, no SDK calls.
 */

import { resolveChain, Vm } from "./chains";
import {
  Engine,
  VulnClass,
  payoutBand,
  vulnTypesByClass,
} from "./taxonomy";
import { BugRapProgram } from "./bugrap";

export interface SurfaceCell {
  program: string;
  chain: string;
  vm: Vm;
  vulnClass: VulnClass;
  /** Engines that apply to this cell given the chain's VM. */
  engines: Engine[];
  /** True when at least one *automated* engine covers the cell. */
  automated: boolean;
  /** Max expected payout (USD) for this class on this program. */
  payoutCeilingUsd: number;
}

export interface CoverageSummary {
  totalCells: number;
  automatedCells: number;
  manualOnlyCells: number;
  /** Per-bounty-class breakdown of automated vs manual cells. */
  byClass: Record<string, { total: number; automated: number }>;
  /** Chains touched across the surface. */
  chains: string[];
}

const AUTOMATED_ENGINES = new Set<Engine>(["evm-static", "svm-static", "invariant-sim"]);

/** Which engines actually run on a given VM (manual always remains available). */
function enginesForVm(vm: Vm, classEngines: Engine[]): Engine[] {
  return classEngines.filter((e) => {
    if (e === "evm-static") return vm === "evm";
    if (e === "svm-static") return vm === "svm";
    if (e === "invariant-sim") return true; // pure math, VM-independent
    return e === "manual"; // manual review applies everywhere
  });
}

/** The set of engines the taxonomy associates with a whole bounty class. */
function enginesForClass(vulnClass: VulnClass): Engine[] {
  const set = new Set<Engine>();
  for (const t of vulnTypesByClass(vulnClass)) {
    for (const e of t.engines) set.add(e);
  }
  return [...set];
}

/** Highest severity-band ceiling (USD) seen across a class's vuln types. */
function classPayoutCeiling(program: BugRapProgram, vulnClass: VulnClass): number {
  let max = 0;
  for (const t of vulnTypesByClass(vulnClass)) {
    const band = payoutBand(t.typicalSeverity, program.payoutBands);
    if (band.maxUsd > max) max = band.maxUsd;
  }
  return max;
}

/**
 * Enumerate every in-scope (chain × bounty-class) cell for a single program.
 * This is the per-program "no stone unturned" matrix.
 */
export function mapProgramSurface(program: BugRapProgram): SurfaceCell[] {
  const cells: SurfaceCell[] = [];
  for (const chainKey of program.chains) {
    const chain = resolveChain(chainKey);
    for (const vulnClass of program.vulnClasses) {
      const classEngines = enginesForClass(vulnClass);
      const engines = enginesForVm(chain.vm, classEngines);
      const automated = engines.some((e) => AUTOMATED_ENGINES.has(e));
      cells.push({
        program: program.key,
        chain: chain.key,
        vm: chain.vm,
        vulnClass,
        engines,
        automated,
        payoutCeilingUsd: classPayoutCeiling(program, vulnClass),
      });
    }
  }
  return cells;
}

/** Map the surface for every program in the registry. */
export function mapEcosystemSurface(programs: BugRapProgram[]): SurfaceCell[] {
  return programs.flatMap(mapProgramSurface);
}

/** Summarise coverage across a set of cells. */
export function summarizeCoverage(cells: SurfaceCell[]): CoverageSummary {
  const byClass: Record<string, { total: number; automated: number }> = {};
  const chains = new Set<string>();
  let automatedCells = 0;
  for (const cell of cells) {
    chains.add(cell.chain);
    const entry = byClass[cell.vulnClass] ?? { total: 0, automated: 0 };
    entry.total += 1;
    if (cell.automated) {
      entry.automated += 1;
      automatedCells += 1;
    }
    byClass[cell.vulnClass] = entry;
  }
  return {
    totalCells: cells.length,
    automatedCells,
    manualOnlyCells: cells.length - automatedCells,
    byClass,
    chains: [...chains].sort(),
  };
}

/**
 * Prioritise cells by expected payout ceiling (then by automated-first so
 * tooling-backed leads are actioned before pure-manual ones). Drives where a
 * hunter points effort across the whole ecosystem.
 */
export function prioritizeCells(cells: SurfaceCell[]): SurfaceCell[] {
  return [...cells].sort(
    (a, b) =>
      b.payoutCeilingUsd - a.payoutCeilingUsd ||
      Number(b.automated) - Number(a.automated) ||
      a.program.localeCompare(b.program) ||
      a.chain.localeCompare(b.chain),
  );
}
