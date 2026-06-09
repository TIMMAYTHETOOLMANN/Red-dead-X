import { 
  DATA_MANIPULATION_CONFIG, 
  diffJson, 
  extractPaths, 
  scanWithRegex, 
  checkUuidCollisions, 
  escapeLogData 
} from "./lib/data.js";

async function main() {
  console.log("=== DATA MANIPULATION & FORENSICS ===");
  console.log("Stage 2 Analysis\n");

  const statePreUpgrade = {
    upgradeAuthority: "0x1234567890123456789012345678901234567890",
    roles: ["admin", "minter"],
    accounts: [
      { id: "550e8400-e29b-41d4-a716-446655440000", balance: 100 },
      { id: "550e8400-e29b-41d4-a716-446655440000", balance: 50 }, // Intentional collision
      { id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8", balance: 200 }
    ],
    metadata: "Normal\nLog\nData"
  };

  const statePostUpgrade = {
    upgradeAuthority: "0x9999999999999999999999999999999999999999", // Drift
    roles: ["admin", "minter", "upgrader_secret_role"],
    accounts: [
      { id: "550e8400-e29b-41d4-a716-446655440000", balance: 100 },
      { id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8", balance: 200 }
    ],
    metadata: "Normal\nLog\nData<script>alert(1)</script>"
  };

  console.log("--- 1. Extraction (JSON Path Mock) ---");
  const extracted = extractPaths(statePostUpgrade, DATA_MANIPULATION_CONFIG.fields);
  for (const [path, values] of Object.entries(extracted)) {
    console.log(`Path [${path}]: ${JSON.stringify(values)}`);
  }

  console.log("\n--- 2. Regex Scanning ---");
  const stringifiedState = JSON.stringify(statePostUpgrade);
  const regexHits = scanWithRegex(stringifiedState, DATA_MANIPULATION_CONFIG.regexPatterns);
  console.log("Regex Hits Found:");
  regexHits.forEach(hit => console.log(`  - ${hit}`));

  console.log("\n--- 3. Diffing (Pre vs Post Upgrade) ---");
  const differences = diffJson(statePreUpgrade, statePostUpgrade);
  differences.forEach(diff => {
    if (diff.type === 'changed') {
      console.log(`[CHANGED] ${diff.key}: ${JSON.stringify(diff.pre)} -> ${JSON.stringify(diff.post)}`);
    } else if (diff.type === 'added') {
      console.log(`[ADDED] ${diff.key}: ${JSON.stringify(diff.post)}`);
    } else if (diff.type === 'removed') {
      console.log(`[REMOVED] ${diff.key}`);
    }
  });

  console.log("\n--- 4. UUID Collision Check ---");
  const allIds = [
    ...(statePreUpgrade.accounts.map(a => a.id)),
    ...(statePostUpgrade.accounts.map(a => a.id))
  ];
  const collisions = checkUuidCollisions(allIds);
  if (collisions.length > 0) {
    console.log(`[!] UUID Collisions Detected: ${collisions.join(", ")}`);
  } else {
    console.log("No UUID collisions detected.");
  }

  console.log("\n--- 5. Log Escaping ---");
  const rawLog = statePostUpgrade.metadata;
  console.log(`Raw: ${rawLog}`);
  DATA_MANIPULATION_CONFIG.escapers.forEach(escaper => {
    console.log(`Escaped (${escaper}): ${escapeLogData(rawLog, escaper as any)}`);
  });

  console.log("\n=====================================");
}

main().catch(console.error);
