import "dotenv/config";
import { AdminInput, analyzeAdmin, entryFromFindings } from "./lib/aux_analyzers";
import { readJsonInput, writeUnifiedReport } from "./aux_io";

/**
 * Admin / authority forensic analyzer (read-only, pure logic + file I/O).
 *
 * Reads a real authority-state / ABI input and folds its findings into the
 * unified SARIF + Markdown brief (instead of the previous console-only mock).
 *
 * Env:
 *   ADMIN_INPUT_PATH   JSON input (default targets/samples/admin-input.json)
 *   BUGRAP_PROGRAM     program label for the report target (default "soex-premiumcvt")
 *   EVM_CHAIN          chain label for the report target (default "ethereum")
 *   EVIDENCE_DIR       output dir (default ./evidence)
 */

function main() {
  const input = readJsonInput<AdminInput>(
    "ADMIN_INPUT_PATH",
    "targets/samples/admin-input.json",
  );
  const findings = analyzeAdmin(input);
  const entry = entryFromFindings(
    {
      program: (process.env.BUGRAP_PROGRAM ?? "soex-premiumcvt").trim(),
      chain: (process.env.EVM_CHAIN ?? "ethereum").trim(),
      vm: "evm",
      address: null,
      label: input.contract,
    },
    findings,
  );
  writeUnifiedReport("admin-analyze", entry);
}

main();
