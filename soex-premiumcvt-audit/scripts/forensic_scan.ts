import "dotenv/config";
import fs from "fs";
import { loadIdl } from "./lib/idl";
import { analyzeIdl } from "./lib/analyze";
import { normalizeAbi } from "./lib/evm_abi";
import { analyzeAbi } from "./lib/evm_analyze";
import { resolveChain } from "./lib/chains";
import { loadRegistry, programByKey } from "./lib/bugrap";
import {
  AdminInput,
  DataInput,
  EconomicInput,
  EncodingInput,
  analyzeAdmin,
  analyzeData,
  analyzeEconomic,
  analyzeEncoding,
} from "./lib/aux_analyzers";
import { annotateExploitChains, collapseCrossChain } from "./lib/correlate";
import {
  ForensicEntry,
  UnifiedFinding,
  assembleReport,
  entryFromEvm,
  entryFromSolana,
  toMarkdown,
  toSarif,
} from "./lib/forensic_report";

/**
 * Offline forensic-scan orchestrator (read-only, no network).
 *
 * Folds the local engines into one unified, multi-chain forensic report:
 *   - Solana IDL static analysis  (IDL_PATH, when set)
 *   - EVM ABI static analysis     (EVM_ABI_PATH, a published/exported ABI)
 *   - Auxiliary analyzers         (AUX_INPUT_PATH: admin/encoding/data/economic)
 *
 * It then runs the depth pass: exploit-chain correlation (links an access-control
 * gap to the high-impact primitive it enables) and cross-chain de-duplication
 * (collapses the same seam seen on multiple chains into one "same seam, N chains").
 *
 * This is the no-network sibling of `evm_recon.ts` (which resolves ABIs live via
 * thirdweb). Use it to analyze ABIs/IDLs you already hold and to assemble a
 * combined SARIF + Markdown brief keyed by program, chain, and bounty type.
 *
 * Env:
 *   BUGRAP_PROGRAM   program key (default "soex-premiumcvt") for payout weighting
 *   REGISTRY_PATH    registry file (default ./targets/bugrap-programs.json)
 *   IDL_PATH         Solana IDL to analyze (optional)
 *   EVM_ABI_PATH     EVM ABI JSON (or human-readable) to analyze (optional)
 *   EVM_CHAIN        chain key/id for the EVM ABI target (default "ethereum")
 *   EVM_ADDRESS      address label for the EVM ABI target (optional)
 *   AUX_INPUT_PATH   JSON with optional { admin, encoding, data, economic } inputs
 *   EVIDENCE_DIR     output dir (default ./evidence)
 */

interface AuxBundle {
  admin?: AdminInput;
  encoding?: EncodingInput;
  data?: DataInput;
  economic?: EconomicInput;
}

function main() {
  const registryPath =
    (process.env.REGISTRY_PATH ?? "").trim() || "./targets/bugrap-programs.json";
  const programKey = (process.env.BUGRAP_PROGRAM ?? "soex-premiumcvt").trim();
  const registry = loadRegistry(registryPath);
  const program = programByKey(registry, programKey);
  const payoutBands = program?.payoutBands;

  const entries: ForensicEntry[] = [];

  const idlPath = (process.env.IDL_PATH ?? "").trim();
  if (idlPath && fs.existsSync(idlPath)) {
    const result = analyzeIdl(loadIdl(idlPath));
    entries.push(
      entryFromSolana(
        { program: programKey, chain: "solana", vm: "svm", address: result.address, label: result.program },
        result,
      ),
    );
  }

  const abiPath = (process.env.EVM_ABI_PATH ?? "").trim();
  if (abiPath && fs.existsSync(abiPath)) {
    const chainRef = (process.env.EVM_CHAIN ?? "ethereum").trim();
    const chain = resolveChain(/^\d+$/.test(chainRef) ? Number(chainRef) : chainRef);
    const abi = normalizeAbi(JSON.parse(fs.readFileSync(abiPath, "utf8")));
    const result = analyzeAbi(abi, payoutBands);
    entries.push(
      entryFromEvm(
        {
          program: programKey,
          chain: chain.key,
          vm: "evm",
          address: (process.env.EVM_ADDRESS ?? "").trim() || null,
          label: "ABI file",
        },
        result,
      ),
    );
  }

  const auxPath = (process.env.AUX_INPUT_PATH ?? "").trim();
  if (auxPath && fs.existsSync(auxPath)) {
    const aux = JSON.parse(fs.readFileSync(auxPath, "utf8")) as AuxBundle;
    const auxChain = (process.env.EVM_CHAIN ?? "ethereum").trim();
    const auxFindings: UnifiedFinding[] = [
      ...(aux.admin ? analyzeAdmin(aux.admin) : []),
      ...(aux.encoding ? analyzeEncoding(aux.encoding) : []),
      ...(aux.data ? analyzeData(aux.data) : []),
      ...(aux.economic ? analyzeEconomic(aux.economic) : []),
    ];
    if (auxFindings.length > 0) {
      entries.push({
        target: {
          program: programKey,
          chain: auxChain,
          vm: "evm",
          address: (process.env.EVM_ADDRESS ?? "").trim() || null,
          label: "auxiliary analyzers",
        },
        findings: auxFindings,
      });
    }
  }

  if (entries.length === 0) {
    throw new Error(
      "Nothing to analyze. Set IDL_PATH, EVM_ABI_PATH and/or AUX_INPUT_PATH to a Solana IDL / EVM ABI / auxiliary input file.",
    );
  }

  // Depth pass: link access-control gaps to the primitives they enable, then
  // collapse identical seams seen across multiple chains.
  const correlated = annotateExploitChains(entries);
  const crossChain = collapseCrossChain(correlated);

  const report = assembleReport(correlated);
  const evidenceDir = process.env.EVIDENCE_DIR ?? "./evidence";
  fs.mkdirSync(evidenceDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const base = `${evidenceDir}/forensic-scan-${programKey}-${stamp}`;

  fs.writeFileSync(`${base}.json`, JSON.stringify(report, null, 2));
  fs.writeFileSync(`${base}.sarif`, JSON.stringify(toSarif(report), null, 2));
  fs.writeFileSync(`${base}.md`, toMarkdown(report));

  const total = correlated.reduce((s, e) => s + e.findings.length, 0);
  console.log(`Wrote ${base}.json / .sarif / .md`);
  console.log(`Program: ${programKey}  Targets: ${correlated.length}  Candidate findings: ${total}`);
  for (const e of correlated) {
    console.log(`- ${e.target.chain} (${e.target.vm}): ${e.findings.length} findings`);
  }
  console.log(
    `Cross-chain: ${crossChain.multiChainSeams} seam(s) span >1 chain ` +
      `(${crossChain.merged} duplicate finding(s) collapsed).`,
  );
}

main();
