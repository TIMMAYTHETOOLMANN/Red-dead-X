/**
 * Economic & Invariant Simulation Configuration & Tooling
 * 
 * Provides automated math simulations, bounds checking, and overflow/dust detection.
 */

export const INVARIANT_SIM_CONFIG = {
  invariants: [
    "fee monotonicity", // Fee never decreases as volume increases
    "overflow/underflow", // No uint wraparounds; rejects excess supply
    "supply conservation", // No value lost/created contrary to intended logic
    "mint == burn round-trip", // Value that’s minted must be burnable for same result
    "dust drain detection", // No persistent <1 unit leakage
    "edge-case math (0, 1, uint_max)",
    "referral/reward monotonicity", 
  ],
  functions: [
    "mint", "burn", "swap", "withdraw", "deposit", "claim", "transfer", "reward"
  ],
  fuzzInputs: [
    { method: "mint", amount: "0" },
    { method: "mint", amount: "1" },
    { method: "mint", amount: "2**256 - 1" },
    { method: "swap", inAmount: "1", outAmount: "MAX" },
    { method: "burn", amount: "full supply" },
    { method: "withdraw", amount: "MAX" },
    { method: "claim", ref: "MAX" },
  ],
  economicChecks: [
    "totalIn == totalOut + totalFees",
    "contractBalance >= 0",
    "userBalance change matches action",
    "no persistent dust",
    "fees always >= minFee",
    "reward per user <= input",
  ],
  safetyBounds: {
    supplyMax: "115792089237316195423570985008687907853269984665640564039457584007913129639935", // 2**256 - 1
    minFee: "1",
    zero: "0",
  },
};

export interface SimResult {
  action: string;
  inputs: Record<string, string>;
  preState: Record<string, bigint>;
  postState: Record<string, bigint>;
  invariantPassed: boolean;
  failureReason?: string | undefined;
  vulnCategory?: string | undefined;
}

// Very basic mocking engine for financial operations
export class SimulationEngine {
  supply: bigint = 0n;
  treasury: bigint = 1000n; // Mock existing treasury

  /**
   * Mocks a mint function which fails properly on overflow, but we can simulate a vulnerable variant.
   */
  simulateMint(amountStr: string, isVulnerable: boolean = false): SimResult {
    let amount: bigint;
    try {
      amount = BigInt(amountStr);
    } catch {
      return this.failResult("mint", { amount: amountStr }, "Invalid BigInt");
    }

    const preState = { supply: this.supply };
    const max = BigInt(INVARIANT_SIM_CONFIG.safetyBounds.supplyMax);

    if (isVulnerable) {
      // Intentional overflow logic: doesn't check bounds properly
      // We simulate wrapping by modulo
      const newSupply = (this.supply + amount) % (max + 1n);
      this.supply = newSupply;

      const invariantPassed = (newSupply >= preState.supply);
      return {
        action: "mint (vulnerable)",
        inputs: { amount: amountStr },
        preState,
        postState: { supply: this.supply },
        invariantPassed,
        failureReason: invariantPassed ? undefined : "Supply wrapped/decreased after mint",
        vulnCategory: invariantPassed ? undefined : "overflow/underflow"
      };
    } else {
      // Safe logic
      if (this.supply + amount > max) {
         return this.failResult("mint (safe)", { amount: amountStr }, "Transaction Reverted: Exceeds Max Supply");
      }
      this.supply += amount;
      return {
        action: "mint (safe)",
        inputs: { amount: amountStr },
        preState,
        postState: { supply: this.supply },
        invariantPassed: true,
      };
    }
  }

  /**
   * Mocks a swap to check for monotonic fees
   */
  simulateSwapFee(amountStr: string, feeRateBps: bigint): SimResult {
    let amount: bigint;
    try {
      amount = BigInt(amountStr);
    } catch {
      return this.failResult("swap", { amount: amountStr }, "Invalid BigInt");
    }

    const preState = { treasury: this.treasury };
    // fee = (amount * feeRateBps) / 10000
    // Vulnerable edge case: small amounts (like 1) * feeRate / 10000 = 0 (Dust leak!)
    const fee = (amount * feeRateBps) / 10000n;

    const outAmount = amount - fee;
    this.treasury += fee;

    const invariantPassed = fee >= BigInt(INVARIANT_SIM_CONFIG.safetyBounds.minFee) || amount === 0n;
    return {
      action: "swap",
      inputs: { amount: amountStr, feeRateBps: feeRateBps.toString() },
      preState,
      postState: { treasury: this.treasury, outAmount, feePaid: fee },
      invariantPassed,
      failureReason: invariantPassed ? undefined : `Fee evaluated to ${fee}, expected >= ${INVARIANT_SIM_CONFIG.safetyBounds.minFee}. Dust draining possible.`,
      vulnCategory: invariantPassed ? undefined : "dust drain detection"
    };
  }

  private failResult(action: string, inputs: Record<string, string>, reason: string): SimResult {
    return {
      action,
      inputs,
      preState: { supply: this.supply, treasury: this.treasury },
      postState: { supply: this.supply, treasury: this.treasury },
      invariantPassed: false,
      failureReason: reason
    };
  }
}
