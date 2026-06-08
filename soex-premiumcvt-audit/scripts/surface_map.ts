import "dotenv/config";
import fs from "fs";
import { loadRegistry, programByKey } from "./lib/bugrap";
import {
  SurfaceCell,
  mapEcosystemSurface,
  mapProgramSurface,
  prioritizeCells,
  summarizeCoverage,
} from "./lib/attack_surface";

/**
 * Attack-surface / coverage mapper CLI (read-only, pure).
 *
 * Enumerates every in-scope (chain × bounty-class) cell across the BugRap
 * ecosystem — or a single program when BUGRAP_PROGRAM is set — so nothing is
 * skipped: every network, every asset, every bounty type. Emits a prioritized
 * coverage matrix (highest expected payout first) plus a JSON + Markdown
 * evidence bundle showing where automated engines cover the surface and where
 * manual review must take over.
 *
 * Env:
 *   REGISTRY_PATH    registry file (default ./targets/bugrap-programs.json)
 *   BUGRAP_PROGRAM   optional single program key to scope the map
 *   EVIDENCE_DIR     output dir (default ./evidence)
 */

function cellsToMarkdown(cells: SurfaceCell[]): string {
  const lines = [
    "| Program | Chain | VM | Bounty class | Automated | Engines | Payout ceiling |",
    "|---------|-------|----|--------------|-----------|---------|----------------|",
  ];
  for (const c of cells) {
    lines.push(
      `| ${c.program} | ${c.chain} | ${c.vm} | ${c.vulnClass} | ${
        c.automated ? "yes" : "manual"
      } | ${c.engines.join(", ")} | $${c.payoutCeilingUsd} |`,
    );
  }
  return lines.join("\n") + "\n";
}

function main() {
  const registryPath =
    (process.env.REGISTRY_PATH ?? "").trim() || "./targets/bugrap-programs.json";
  const registry = loadRegistry(registryPath);

  const programKey = (process.env.BUGRAP_PROGRAM ?? "").trim();
  let cells: SurfaceCell[];
  let scope: string;
  if (programKey) {
    const program = programByKey(registry, programKey);
    if (!program) throw new Error(`Program "${programKey}" not found in ${registryPath}.`);
    cells = mapProgramSurface(program);
    scope = program.key;
  } else {
    cells = mapEcosystemSurface(registry.programs);
    scope = "all-programs";
  }

  const prioritized = prioritizeCells(cells);
  const summary = summarizeCoverage(cells);

  const evidenceDir = process.env.EVIDENCE_DIR ?? "./evidence";
  fs.mkdirSync(evidenceDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const base = `${evidenceDir}/attack-surface-${scope}-${stamp}`;

  fs.writeFileSync(
    `${base}.json`,
    JSON.stringify(
      { scope, generatedAt: new Date().toISOString(), summary, cells: prioritized },
      null,
      2,
    ),
  );

  const md =
    `# Attack-surface coverage — ${scope}\n\n` +
    `- Generated: ${new Date().toISOString()}\n` +
    `- Cells: ${summary.totalCells} (automated ${summary.automatedCells}, ` +
    `manual-only ${summary.manualOnlyCells})\n` +
    `- Chains: ${summary.chains.join(", ")}\n\n` +
    `## By bounty class\n\n` +
    `| Class | Cells | Automated |\n|-------|-------|-----------|\n` +
    Object.entries(summary.byClass)
      .map(([k, v]) => `| ${k} | ${v.total} | ${v.automated} |`)
      .join("\n") +
    `\n\n## Prioritized cells (highest expected payout first)\n\n` +
    cellsToMarkdown(prioritized);
  fs.writeFileSync(`${base}.md`, md);

  console.log(`Wrote ${base}.json / .md`);
  console.log(
    `Scope: ${scope}  Cells: ${summary.totalCells}  ` +
      `Automated: ${summary.automatedCells}  Manual-only: ${summary.manualOnlyCells}`,
  );
  console.table(
    prioritized.slice(0, 20).map((c) => ({
      program: c.program,
      chain: c.chain,
      class: c.vulnClass,
      automated: c.automated,
      payoutCeiling: c.payoutCeilingUsd,
    })),
  );
}

main();
