import "dotenv/config";
import { loadRegistry } from "./lib/bugrap";
import { assessRegistry, ProgramReadiness } from "./lib/registry_doctor";

/**
 * Registry doctor CLI (read-only, pure).
 *
 * Reports which BugRap programs are "armed" (every listed contract has a pinned
 * address), "partial" (some pinned), or "shell" (no pinned contracts yet), so
 * the attack-surface coverage numbers aren't read as more complete than the data
 * behind them actually is. Performs no network/SDK calls.
 *
 * Env:
 *   REGISTRY_PATH   registry file (default ./targets/bugrap-programs.json)
 *   FAIL_ON_SHELL   when "true", exit non-zero if any program is still a shell
 *                   (useful as a CI gate once addresses are expected to be pinned)
 */

function stateLabel(p: ProgramReadiness): string {
  return `${p.contractsPinned}/${p.contractsTotal} pinned`;
}

function main() {
  const registryPath =
    (process.env.REGISTRY_PATH ?? "").trim() || "./targets/bugrap-programs.json";
  const registry = loadRegistry(registryPath);
  const report = assessRegistry(registry);

  console.log(`Registry: ${registryPath}`);
  console.log(
    `Programs: ${report.total}  Armed: ${report.armed}  ` +
      `Partial: ${report.partial}  Shell: ${report.shell}`,
  );
  console.table(
    report.programs.map((p) => ({
      program: p.key,
      state: p.state,
      contracts: stateLabel(p),
      chains: p.chains.join(", "),
    })),
  );

  const failOnShell = (process.env.FAIL_ON_SHELL ?? "").trim().toLowerCase() === "true";
  if (failOnShell && report.shell > 0) {
    console.error(
      `FAIL_ON_SHELL=true: ${report.shell} program(s) still have no pinned contract address.`,
    );
    process.exit(1);
  }
}

main();
