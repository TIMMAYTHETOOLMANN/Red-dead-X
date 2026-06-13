import "dotenv/config";
import { DataInput, analyzeData, entryFromFindings } from "./lib/aux_analyzers";
import { DATA_MANIPULATION_CONFIG } from "./lib/data";
import { readJsonInput, writeUnifiedReport } from "./aux_io";

/**
 * Data-manipulation forensic analyzer (read-only, pure logic + file I/O).
 *
 * Reads pre/post state snapshots (and optional identifier lists) and folds
 * authority-drift / role-injection / id-collision findings into the unified
 * SARIF + Markdown brief.
 *
 * Env:
 *   DATA_INPUT_PATH   JSON input (default targets/samples/data-input.json)
 *   BUGRAP_PROGRAM    program label for the report target (default "soex-premiumcvt")
 *   EVM_CHAIN         chain label for the report target (default "ethereum")
 *   EVIDENCE_DIR      output dir (default ./evidence)
 */

function main() {
  const input = readJsonInput<DataInput>("DATA_INPUT_PATH", "targets/samples/data-input.json");
  // Always scan the post state with the standard sensitive-pattern set.
  const findings = analyzeData({ ...input, regexPatterns: DATA_MANIPULATION_CONFIG.regexPatterns });
  const entry = entryFromFindings(
    {
      program: (process.env.BUGRAP_PROGRAM ?? "soex-premiumcvt").trim(),
      chain: (process.env.EVM_CHAIN ?? "ethereum").trim(),
      vm: "evm",
      address: null,
      label: "state snapshots",
    },
    findings,
  );
  writeUnifiedReport("data-analyze", entry);
}

main();
