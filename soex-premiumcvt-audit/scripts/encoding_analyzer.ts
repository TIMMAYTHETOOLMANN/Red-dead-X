import "dotenv/config";
import { EncodingInput, analyzeEncoding, entryFromFindings } from "./lib/aux_analyzers";
import { readJsonInput, writeUnifiedReport } from "./aux_io";

/**
 * Encoding / decoding forensic analyzer (read-only, pure logic + file I/O).
 *
 * Reads real field values (e.g. calldata/config fields) and folds decode-based
 * findings into the unified SARIF + Markdown brief.
 *
 * Env:
 *   ENCODING_INPUT_PATH   JSON input (default targets/samples/encoding-input.json)
 *   BUGRAP_PROGRAM        program label for the report target (default "soex-premiumcvt")
 *   EVM_CHAIN             chain label for the report target (default "ethereum")
 *   EVIDENCE_DIR          output dir (default ./evidence)
 */

function main() {
  const input = readJsonInput<EncodingInput>(
    "ENCODING_INPUT_PATH",
    "targets/samples/encoding-input.json",
  );
  const findings = analyzeEncoding(input);
  const entry = entryFromFindings(
    {
      program: (process.env.BUGRAP_PROGRAM ?? "soex-premiumcvt").trim(),
      chain: (process.env.EVM_CHAIN ?? "ethereum").trim(),
      vm: "evm",
      address: null,
      label: "encoding fields",
    },
    findings,
  );
  writeUnifiedReport("encoding-analyze", entry);
}

main();
