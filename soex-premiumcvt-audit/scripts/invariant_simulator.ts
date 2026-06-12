import "dotenv/config";
import { EconomicInput, analyzeEconomic, entryFromFindings } from "./lib/aux_analyzers";
import { readJsonInput, writeUnifiedReport } from "./aux_io";

/**
 * Economic / invariant simulation analyzer (read-only, pure logic + file I/O).
 *
 * Runs the exact-arithmetic invariant probes against real parameters (fee rate,
 * swap amounts, optional vulnerable-mint probe) and folds overflow / dust-drain
 * findings into the unified SARIF + Markdown brief.
 *
 * Env:
 *   ECONOMIC_INPUT_PATH   JSON input (default targets/samples/economic-input.json)
 *   BUGRAP_PROGRAM        program label for the report target (default "soex-premiumcvt")
 *   EVM_CHAIN             chain label for the report target (default "ethereum")
 *   EVIDENCE_DIR          output dir (default ./evidence)
 */

function main() {
  const input = readJsonInput<EconomicInput>(
    "ECONOMIC_INPUT_PATH",
    "targets/samples/economic-input.json",
  );
  const findings = analyzeEconomic(input);
  const entry = entryFromFindings(
    {
      program: (process.env.BUGRAP_PROGRAM ?? "soex-premiumcvt").trim(),
      chain: (process.env.EVM_CHAIN ?? "ethereum").trim(),
      vm: "evm",
      address: null,
      label: "economic invariants",
    },
    findings,
  );
  writeUnifiedReport("economic-analyze", entry);
}

main();
