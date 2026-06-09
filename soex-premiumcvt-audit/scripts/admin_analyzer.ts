import { ADMIN_ANALYSIS_CONFIG, scanAuthorities, scanPrivilegeActions } from "./lib/admin.js";

async function main() {
  console.log("=== ADMINISTRATOR & AUTHORITY FORENSICS ===");
  console.log("Stage 4 Analysis\n");

  const mockContractState = {
    upgradeAuthority: "0xEOA1234567890abcdef1234567890abcdef12345", // Mock EOA
    owner: "0xMULTI0000000000000000000000000000000000",        // Mock Multisig
    pauser: "0xEOA99999999999999999999999999999999999",          // Mock EOA
    feeRate: 500
  };

  const mockAbi = [
    { name: "transfer", modifiers: [] },
    { name: "upgradeTo", modifiers: ["onlyUpgradeAuthority"] },
    { name: "pause", modifiers: ["onlyPauser"] },
    { name: "emergencyWithdraw", modifiers: [] }, // Missing modifiers!
    { name: "mint", modifiers: ["onlyOwner"] }
  ];

  console.log("--- 1. Authority Scanning ---");
  const authFindings = scanAuthorities("VaultContract", mockContractState);
  authFindings.forEach(f => {
    console.log(`[${f.riskLevel}] Field: ${f.field} = ${f.value}`);
    console.log(`    => ${f.description}`);
  });

  console.log("\n--- 2. Privilege Action & ACL Scanning ---");
  const privFindings = scanPrivilegeActions("VaultContract", mockAbi);
  privFindings.forEach(f => {
    if (f.roleRequired === "NONE") {
      console.log(`[CRITICAL] Action: ${f.action}()`);
      console.log(`    => ${f.description}`);
    } else {
      console.log(`[INFO] Action: ${f.action}()`);
      console.log(`    => ${f.description}`);
    }
  });

  console.log("\n===========================================");
}

main().catch(console.error);
