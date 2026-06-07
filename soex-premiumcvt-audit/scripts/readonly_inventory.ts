import "dotenv/config";
import fs from "fs";
import crypto from "crypto";
import { Connection, PublicKey } from "@solana/web3.js";

const rpcUrl = process.env.RPC_URL ?? "https://api.devnet.solana.com";
const accountsPath = process.env.KNOWN_ACCOUNTS ?? "./targets/accounts.txt";
const evidenceDir = process.env.EVIDENCE_DIR ?? "./evidence";
const readOnly = process.env.READ_ONLY !== "false";

if (!readOnly) {
  throw new Error("READ_ONLY must stay true for inventory collection.");
}

fs.mkdirSync(evidenceDir, { recursive: true });

const raw = fs
  .readFileSync(accountsPath, "utf8")
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith("#"));

const maxAccounts = Number(process.env.MAX_ACCOUNTS ?? 50);
const keys = raw.slice(0, maxAccounts).map((k) => new PublicKey(k));

async function main() {
  const infos =
    keys.length === 0
      ? []
      : await new Connection(rpcUrl, "confirmed").getMultipleAccountsInfo(keys);

  const rows = infos.map((info, i) => {
    if (!info) {
      return {
        pubkey: keys[i].toBase58(),
        exists: false,
      };
    }

    const dataHash = crypto.createHash("sha256").update(info.data).digest("hex");

    return {
      pubkey: keys[i].toBase58(),
      exists: true,
      owner: info.owner.toBase58(),
      executable: info.executable,
      lamports: info.lamports,
      dataLength: info.data.length,
      rentEpoch: String(info.rentEpoch),
      dataSha256: dataHash,
    };
  });

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const out = `${evidenceDir}/inventory-${stamp}.json`;
  fs.writeFileSync(
    out,
    JSON.stringify(
      {
        rpcUrl,
        collectedAt: new Date().toISOString(),
        readOnly: true,
        rows,
      },
      null,
      2,
    ),
  );

  console.log(`Wrote ${out}`);
  console.table(rows);
}

void main();
