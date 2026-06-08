import "dotenv/config";
import fs from "fs";
import { loadIdl } from "./lib/idl";
import { analyzeIdl } from "./lib/analyze";
import { normalizeAbi } from "./lib/evm_abi";
import { analyzeAbi } from "./lib/evm_analyze";
import { resolveChain } from "./lib/chains";
import { loadRegistry, programByKey } from "./lib/bugrap";
import {
  ForensicEntry,
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
 *   EVIDENCE_DIR     output dir (default ./evidence)
 */

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

  if (entries.length === 0) {
    throw new Error(
      "Nothing to analyze. Set IDL_PATH and/or EVM_ABI_PATH to a Solana IDL / EVM ABI file.",
    );
  }

  const report = assembleReport(entries);
  const evidenceDir = process.env.EVIDENCE_DIR ?? "./evidence";
  fs.mkdirSync(evidenceDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const base = `${evidenceDir}/forensic-scan-${programKey}-${stamp}`;

  fs.writeFileSync(`${base}.json`, JSON.stringify(report, null, 2));
  fs.writeFileSync(`${base}.sarif`, JSON.stringify(toSarif(report), null, 2));
  fs.writeFileSync(`${base}.md`, toMarkdown(report));

  const total = entries.reduce((s, e) => s + e.findings.length, 0);
  console.log(`Wrote ${base}.json / .sarif / .md`);
  console.log(`Program: ${programKey}  Targets: ${entries.length}  Candidate findings: ${total}`);
  for (const e of entries) {
    console.log(`- ${e.target.chain} (${e.target.vm}): ${e.findings.length} findings`);
  }
}

main();
