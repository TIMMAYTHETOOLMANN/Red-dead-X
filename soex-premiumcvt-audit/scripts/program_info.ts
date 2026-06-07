import "dotenv/config";
import fs from "fs";
import { Connection, PublicKey } from "@solana/web3.js";

/**
 * Read-only collector for program + upgrade-authority metadata.
 *
 * Mirrors `solana program show <id>` but emits a JSON evidence file. Performs no transactions.
 * Requires TARGET_PROGRAM_ID to be pinned in .env (never guess it).
 */

const rpcUrl = process.env.RPC_URL ?? "https://api.devnet.solana.com";
const evidenceDir = process.env.EVIDENCE_DIR ?? "./evidence";
const programIdRaw = (process.env.TARGET_PROGRAM_ID ?? "").trim();
const readOnly = process.env.READ_ONLY !== "false";

if (!readOnly) {
  throw new Error("READ_ONLY must stay true for metadata collection.");
}

if (!programIdRaw) {
  throw new Error(
    "TARGET_PROGRAM_ID is empty. Pin it from the official bounty portal/source in .env before running.",
  );
}

// BPF upgradeable loader; programdata is a PDA derived from the program id.
const BPF_UPGRADEABLE_LOADER = new PublicKey(
  "BPFLoaderUpgradeab1e11111111111111111111111",
);

function parseUpgradeableProgramData(data: Buffer) {
  // ProgramData account layout:
  //   [0..4]   u32 enum tag (3 = ProgramData)
  //   [4..12]  u64 slot (last deploy slot)
  //   [12]     Option<Pubkey> discriminant (1 = Some)
  //   [13..45] Pubkey upgrade authority (present only when discriminant == 1)
  if (data.length < 13) {
    return { parsed: false as const };
  }
  const slot = data.readBigUInt64LE(4);
  const hasAuthority = data[12] === 1;
  const upgradeAuthority = hasAuthority
    ? new PublicKey(data.subarray(13, 45)).toBase58()
    : null;
  return {
    parsed: true as const,
    lastDeploySlot: slot.toString(),
    upgradeAuthority,
    upgradeable: hasAuthority,
  };
}

async function main() {
  const programId = new PublicKey(programIdRaw);
  const conn = new Connection(rpcUrl, "confirmed");

  fs.mkdirSync(evidenceDir, { recursive: true });

  const programInfo = await conn.getAccountInfo(programId);
  const result: Record<string, unknown> = {
    rpcUrl,
    collectedAt: new Date().toISOString(),
    readOnly: true,
    programId: programId.toBase58(),
  };

  if (!programInfo) {
    result.exists = false;
    writeOut(result);
    console.log("Program account not found on this cluster.");
    return;
  }

  result.exists = true;
  result.owner = programInfo.owner.toBase58();
  result.executable = programInfo.executable;
  result.lamports = programInfo.lamports;
  result.isUpgradeableLoader = programInfo.owner.equals(BPF_UPGRADEABLE_LOADER);

  // For upgradeable programs, the program account stores the programdata address.
  if (result.isUpgradeableLoader && programInfo.data.length >= 36) {
    const programDataAddress = new PublicKey(programInfo.data.subarray(4, 36));
    result.programDataAddress = programDataAddress.toBase58();
    const programData = await conn.getAccountInfo(programDataAddress);
    if (programData) {
      result.programData = parseUpgradeableProgramData(programData.data);
    } else {
      result.programData = { parsed: false, note: "programdata account missing" };
    }
  }

  writeOut(result);
  console.log(JSON.stringify(result, null, 2));
}

function writeOut(result: Record<string, unknown>) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const out = `${evidenceDir}/program-info-${stamp}.json`;
  fs.writeFileSync(out, JSON.stringify(result, null, 2));
  console.log(`Wrote ${out}`);
}

void main();
