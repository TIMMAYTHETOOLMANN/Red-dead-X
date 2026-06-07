import "dotenv/config";
import fs from "fs";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

/**
 * Guardrailed PoC harness — the system's "hands".
 *
 * Lets a hunter actually *exercise* an instruction to prove a bug, instead of
 * only reading chain state. It is deliberately constrained to stay
 * bounty-compliant (see docs/00-scope-and-rules.md):
 *
 *   1. SIMULATE BY DEFAULT. It calls `simulateTransaction` and never sends
 *      unless explicitly told to.
 *   2. To actually send a transaction ALL of the following must hold:
 *        - EXECUTE=true            (explicit opt-in for this run)
 *        - ALLOW_TX=true           (the scaffold-wide write guard is lifted)
 *        - CLUSTER in {localnet, devnet}   (never mainnet)
 *      Any mainnet/mainnet-beta cluster is refused for sends, no exceptions.
 *   3. Signing keypairs come from git-ignored `*.keypair.json` files.
 *
 * PoC plan format (JSON, path via POC_PLAN):
 * {
 *   "feePayer": "<keypair path>",
 *   "signers": ["<keypair path>", ...],     // optional extra signers
 *   "instructions": [
 *     {
 *       "programId": "<base58>",
 *       "keys": [{ "pubkey": "<base58>", "isSigner": false, "isWritable": true }],
 *       "dataBase64": "<base64>"            // or "dataHex": "0x..." or omit for empty
 *     }
 *   ]
 * }
 */

interface PlanKey {
  pubkey: string;
  isSigner?: boolean;
  isWritable?: boolean;
}

interface PlanInstruction {
  programId: string;
  keys?: PlanKey[];
  dataBase64?: string;
  dataHex?: string;
}

interface PocPlan {
  feePayer: string;
  signers?: string[];
  instructions: PlanInstruction[];
}

const SAFE_CLUSTERS = new Set(["localnet", "devnet"]);

const RPC_BY_CLUSTER: Record<string, string> = {
  localnet: "http://127.0.0.1:8899",
  devnet: "https://api.devnet.solana.com",
};

function clusterRpc(cluster: string): string {
  if (process.env.RPC_URL && process.env.RPC_URL.trim() !== "") {
    return process.env.RPC_URL.trim();
  }
  return RPC_BY_CLUSTER[cluster] ?? RPC_BY_CLUSTER.devnet;
}

function loadKeypair(path: string): Keypair {
  const raw = fs.readFileSync(path, "utf8");
  const secret = Uint8Array.from(JSON.parse(raw) as number[]);
  return Keypair.fromSecretKey(secret);
}

function decodeData(ix: PlanInstruction): Buffer {
  if (ix.dataBase64) return Buffer.from(ix.dataBase64, "base64");
  if (ix.dataHex) return Buffer.from(ix.dataHex.replace(/^0x/, ""), "hex");
  return Buffer.alloc(0);
}

function buildInstruction(ix: PlanInstruction): TransactionInstruction {
  return new TransactionInstruction({
    programId: new PublicKey(ix.programId),
    keys: (ix.keys ?? []).map((k) => ({
      pubkey: new PublicKey(k.pubkey),
      isSigner: Boolean(k.isSigner),
      isWritable: Boolean(k.isWritable),
    })),
    data: decodeData(ix),
  });
}

function writeEvidence(name: string, payload: unknown): string {
  const evidenceDir = process.env.EVIDENCE_DIR ?? "./evidence";
  fs.mkdirSync(evidenceDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const out = `${evidenceDir}/${name}-${stamp}.json`;
  fs.writeFileSync(out, JSON.stringify(payload, null, 2));
  console.log(`Wrote ${out}`);
  return out;
}

async function main() {
  const planPath = (process.env.POC_PLAN ?? "").trim();
  if (!planPath) {
    throw new Error(
      "POC_PLAN is empty. Point it at a PoC plan JSON (see scripts/poc_harness.ts header).",
    );
  }
  if (!fs.existsSync(planPath)) {
    throw new Error(`PoC plan not found at ${planPath}.`);
  }

  const cluster = (process.env.CLUSTER ?? "devnet").trim();
  const execute = process.env.EXECUTE === "true";
  const allowTx = process.env.ALLOW_TX === "true";

  const plan = JSON.parse(fs.readFileSync(planPath, "utf8")) as PocPlan;
  if (!Array.isArray(plan.instructions) || plan.instructions.length === 0) {
    throw new Error("PoC plan has no instructions.");
  }

  const feePayer = loadKeypair(plan.feePayer);
  const extraSigners = (plan.signers ?? []).map(loadKeypair);
  const connection = new Connection(clusterRpc(cluster), "confirmed");

  // --- Decide simulate vs. send under the guardrails BEFORE any network I/O.
  const wantsSend = execute;
  const sendAllowed = wantsSend && allowTx && SAFE_CLUSTERS.has(cluster);

  if (wantsSend && !sendAllowed) {
    const reasons: string[] = [];
    if (!allowTx) reasons.push("ALLOW_TX is not true");
    if (!SAFE_CLUSTERS.has(cluster))
      reasons.push(`cluster "${cluster}" is not in {localnet, devnet}`);
    console.error(
      `Refusing to send: ${reasons.join("; ")}. Falling back to simulation only.`,
    );
  }

  const tx = new Transaction();
  for (const ix of plan.instructions) tx.add(buildInstruction(ix));
  tx.feePayer = feePayer.publicKey;
  const { blockhash } = await connection.getLatestBlockhash();
  tx.recentBlockhash = blockhash;

  if (!sendAllowed) {
    // Simulation path — signs locally for a realistic sim but never broadcasts.
    tx.sign(feePayer, ...extraSigners);
    const sim = await connection.simulateTransaction(tx);
    const out = writeEvidence("poc-simulate", {
      mode: "simulate",
      cluster,
      planPath,
      feePayer: feePayer.publicKey.toBase58(),
      err: sim.value.err ?? null,
      unitsConsumed: sim.value.unitsConsumed ?? null,
      logs: sim.value.logs ?? [],
      collectedAt: new Date().toISOString(),
    });
    console.log(
      `Simulated on ${cluster}. err=${JSON.stringify(sim.value.err)} ` +
        `units=${sim.value.unitsConsumed ?? "n/a"}`,
    );
    console.log(`Logs and result saved to ${out}.`);
    return;
  }

  // --- Send path (localnet/devnet only, all guards satisfied) --------------
  console.log(
    `Executing on ${cluster} (ALLOW_TX=true, EXECUTE=true). This broadcasts a transaction.`,
  );
  const signature = await sendAndConfirmTransaction(connection, tx, [
    feePayer,
    ...extraSigners,
  ]);
  const out = writeEvidence("poc-execute", {
    mode: "execute",
    cluster,
    planPath,
    feePayer: feePayer.publicKey.toBase58(),
    signature,
    collectedAt: new Date().toISOString(),
  });
  console.log(`Confirmed signature: ${signature}`);
  console.log(`Evidence saved to ${out}.`);
}

void main();
