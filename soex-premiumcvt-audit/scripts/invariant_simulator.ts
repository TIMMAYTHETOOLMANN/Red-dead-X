import { INVARIANT_SIM_CONFIG, SimulationEngine, SimResult } from "./lib/invariant.js";

function printResult(res: SimResult) {
  const status = res.invariantPassed ? "[PASS]" : "[FAIL]";
  console.log(`${status} Action: ${res.action}`);
  console.log(`       Inputs: ${JSON.stringify(res.inputs)}`);
  
  if (!res.invariantPassed && res.failureReason) {
    console.log(`       => REASON: ${res.failureReason}`);
    if (res.vulnCategory) console.log(`       => CATEGORY: ${res.vulnCategory}`);
  }
}

async function main() {
  console.log("=== ECONOMIC & INVARIANT SIMULATION ===");
  console.log("Stage 3 Analysis\n");

  const engine = new SimulationEngine();

  console.log("--- 1. Testing Overflow / Supply Cap ---");
  console.log("Pre-state Supply:", engine.supply.toString());
  
  // Test safe mint
  const r1 = engine.simulateMint("1000", false);
  printResult(r1);

  // Test overflow on vulnerable mint
  // 2**256 - 1
  const maxUint = INVARIANT_SIM_CONFIG.safetyBounds.supplyMax;
  const r2 = engine.simulateMint(maxUint, true); // Should trigger wraparound
  printResult(r2);
  console.log(`       Post-state Supply (Wrapped): ${engine.supply.toString()}`);

  console.log("\n--- 2. Testing Dust Drain & Monotonic Fees ---");
  // reset state for isolation
  engine.treasury = 1000n;
  console.log("Pre-state Treasury:", engine.treasury.toString());

  // Normal Swap (fee 100 bps = 1%)
  const r3 = engine.simulateSwapFee("1000", 100n);
  printResult(r3);
  
  // Dust Swap (fee 100 bps = 1%, input 1 unit -> fee is 0 due to rounding)
  const r4 = engine.simulateSwapFee("1", 100n);
  printResult(r4);

  // Medium swap vs large swap fee check
  const r5 = engine.simulateSwapFee("50", 100n);
  printResult(r5);

  console.log("\n--- 3. Loaded Configurations ---");
  console.log(`Invariants Tracked: ${INVARIANT_SIM_CONFIG.invariants.length}`);
  console.log(`Safety Bounds Loaded:`);
  console.log(` - Min Fee: ${INVARIANT_SIM_CONFIG.safetyBounds.minFee}`);
  console.log(` - Max Supply: ${INVARIANT_SIM_CONFIG.safetyBounds.supplyMax}`);

  console.log("\n=======================================");
}

main().catch(console.error);
