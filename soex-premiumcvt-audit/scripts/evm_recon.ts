import "dotenv/config";
import fs from "fs";
import { createThirdwebClient, defineChain, getContract } from "thirdweb";
import { resolveContractAbi, getBytecode } from "thirdweb/contract";
import { resolveImplementation } from "thirdweb/utils";
import { normalizeAbi } from "./lib/evm_abi";
import { analyzeAbi } from "./lib/evm_analyze";
import { analyzeBytecode } from "./lib/bytecode_fingerprint";
import { resolveChain, isEvm } from "./lib/chains";
import {
  assertInScope,
  loadRegistry,
  programByKey,
} from "./lib/bugrap";
import {
  assembleReport,
  entryFromEvm,
  fromBytecodeFinding,
  toMarkdown,
  toSarif,
} from "./lib/forensic_report";

/**
 * thirdweb v5 (TypeScript) read-only EVM forensic recon collector — the
 * multi-chain analog of `program_info.ts`.
 *
 * It dynamically leverages the thirdweb SDK to pull a live EVM contract's attack
 * surface — its ABI (every external function), proxy/implementation target, and
 * deployed bytecode — for any EVM chain in the catalog, then runs the static EVM
 * analyzer over the resolved ABI and writes an evidence bundle plus a unified
 * forensic report (SARIF + Markdown).
 *
 * Guardrails (mirrors the rest of the scaffold):
 *   - READ_ONLY must stay true. This tool only *reads* (ABI/impl/bytecode) and
 *     never builds, signs, or sends a transaction.
 *   - When BUGRAP_PROGRAM is set, the target chain/address is checked against the
 *     program's published scope and refused if out of scope.
 *
 * Required env:
 *   THIRDWEB_SECRET_KEY  (server-side) or THIRDWEB_CLIENT_ID
 *   EVM_CHAIN            chain key ("ethereum") or numeric id ("1")
 *   EVM_ADDRESS          0x-address of the contract to analyze
 * Optional env:
 *   BUGRAP_PROGRAM       program key to scope-check against the registry
 *   REGISTRY_PATH        registry file (default ./targets/bugrap-programs.json)
 *   EVIDENCE_DIR         output dir (default ./evidence)
 */

function requireEnv(name: string): string {
  const v = (process.env[name] ?? "").trim();
  if (!v) throw new Error(`${name} is empty. Set it in .env (see scripts/evm_recon.ts header).`);
  return v;
}

function buildClient() {
  const secretKey = (process.env.THIRDWEB_SECRET_KEY ?? "").trim();
  const clientId = (process.env.THIRDWEB_CLIENT_ID ?? "").trim();
  if (secretKey) return createThirdwebClient({ secretKey });
  if (clientId) return createThirdwebClient({ clientId });
  throw new Error(
    "Provide THIRDWEB_SECRET_KEY (server) or THIRDWEB_CLIENT_ID. Get one at " +
      "https://thirdweb.com/create-api-key.",
  );
}

function writeEvidence(name: string, payload: unknown): string {
  const evidenceDir = process.env.EVIDENCE_DIR ?? "./evidence";
  fs.mkdirSync(evidenceDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const out = `${evidenceDir}/${name}-${stamp}`;
  fs.writeFileSync(`${out}.json`, JSON.stringify(payload, null, 2));
  return out;
}

async function main() {
  const readOnly = process.env.READ_ONLY !== "false";
  if (!readOnly) {
    throw new Error("READ_ONLY must stay true — evm_recon only reads, never sends.");
  }

  const chainRef = requireEnv("EVM_CHAIN");
  const address = requireEnv("EVM_ADDRESS");
  const chain = resolveChain(/^\d+$/.test(chainRef) ? Number(chainRef) : chainRef);
  if (!isEvm(chain) || chain.thirdwebChainId === null) {
    throw new Error(
      `Chain "${chain.key}" is not EVM; use the Solana path (npm run analyze-idl) instead.`,
    );
  }

  // Scope-compliance gate (refuses out-of-scope targets, like the SVM guardrails).
  const programKey = (process.env.BUGRAP_PROGRAM ?? "").trim();
  let payoutBands;
  if (programKey) {
    const registryPath =
      (process.env.REGISTRY_PATH ?? "").trim() || "./targets/bugrap-programs.json";
    const registry = loadRegistry(registryPath);
    const program = programByKey(registry, programKey);
    if (!program) throw new Error(`Program "${programKey}" not found in ${registryPath}.`);
    assertInScope(program, { chain: chain.key, vulnClass: "smart-contract", address });
    payoutBands = program.payoutBands;
  }

  const client = buildClient();
  const twChain = defineChain(chain.thirdwebChainId);
  const contract = getContract({ client, chain: twChain, address });

  // --- read-only surface resolution via thirdweb ---------------------------
  const abiRaw = await resolveContractAbi(contract);

  let implementation: { address: string; isProxy: boolean } = {
    address,
    isProxy: false,
  };
  try {
    const impl = await resolveImplementation(contract);
    if (impl.address && impl.address.toLowerCase() !== address.toLowerCase()) {
      implementation = { address: impl.address, isProxy: true };
    }
  } catch {
    // Not a recognised proxy pattern — analyze the contract as-is.
  }

  const abi = normalizeAbi(abiRaw as unknown[]);
  const analysis = analyzeAbi(abi, payoutBands);

  // --- compiler fingerprint over the deployed bytecode ---------------------
  // Read the runtime bytecode of the *implementation* (proxies hold no logic of
  // their own) and lift its compiler fingerprint, matching it against the
  // known-compiler-bug signature DB. Read-only: getBytecode is eth_getCode.
  const bytecodeTarget = implementation.isProxy ? implementation.address : address;
  let bytecodeAnalysis;
  try {
    const codeContract = implementation.isProxy
      ? getContract({ client, chain: twChain, address: implementation.address })
      : contract;
    const bytecode = await getBytecode(codeContract);
    bytecodeAnalysis = analyzeBytecode(bytecode, payoutBands);
  } catch {
    // Bytecode unavailable (e.g. node rejected eth_getCode) — skip the lane.
    bytecodeAnalysis = undefined;
  }

  const target = {
    program: programKey || "(unscoped)",
    chain: chain.key,
    vm: "evm" as const,
    address,
    label: implementation.isProxy ? `proxy → ${implementation.address}` : "contract",
  };
  const entry = entryFromEvm(target, analysis);
  if (bytecodeAnalysis) {
    entry.findings.push(...bytecodeAnalysis.findings.map(fromBytecodeFinding));
  }
  const report = assembleReport([entry]);

  const base = writeEvidence("evm-recon", {
    collectedAt: new Date().toISOString(),
    readOnly: true,
    chain: chain.key,
    chainId: chain.chainId,
    address,
    implementation,
    compiler: bytecodeAnalysis
      ? { target: bytecodeTarget, ...bytecodeAnalysis.fingerprint }
      : null,
    functionCount: analysis.functionCount,
    severityCounts: analysis.severityCounts,
    laneCounts: analysis.laneCounts,
    maxRisk: analysis.maxRisk,
    totalPayoutWeight: analysis.totalPayoutWeight,
    findings: analysis.findings,
    compilerFindings: bytecodeAnalysis?.findings ?? [],
  });
  fs.writeFileSync(`${base}.sarif`, JSON.stringify(toSarif(report), null, 2));
  fs.writeFileSync(`${base}.md`, toMarkdown(report));

  console.log(`Wrote ${base}.json / .sarif / .md`);
  console.log(
    `Chain ${chain.key} (${chain.chainId})  Contract ${address}  ` +
      `Functions: ${analysis.functionCount}  Findings: ${analysis.findings.length}  ` +
      `Proxy: ${implementation.isProxy ? implementation.address : "no"}`,
  );
  console.log("Severity:", analysis.severityCounts);
  if (bytecodeAnalysis) {
    const fp = bytecodeAnalysis.fingerprint;
    console.log(
      `Compiler: ${fp.kind}${fp.version ? ` ${fp.version}` : " (version unknown)"}  ` +
        `Compiler findings: ${bytecodeAnalysis.findings.length}`,
    );
  }
  if (analysis.findings.length > 0) {
    console.table(
      analysis.findings.map((f) => ({
        risk: f.risk,
        payout: f.payoutWeight,
        severity: f.severity,
        lane: f.lane,
        function: f.function,
        title: f.title,
      })),
    );
  }
}

void main();
