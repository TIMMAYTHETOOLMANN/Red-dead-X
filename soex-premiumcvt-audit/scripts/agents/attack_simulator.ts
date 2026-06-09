export function generateAttackPlan(cell: any, findings: any[]) {
  const encodings = ["Base64", "Base32", "Hex", "URL", "ASCII"];
  const plan = {
    target: cell.address,
    chain: cell.chain,
    privilege: cell.privilege,
    tests: [] as string[],
  };

  if (findings.some(f => f.lane === "admin" && f.status === "FAIL")) {
    plan.tests.push("Attempt privilege bypass with encodings: " + encodings.join(", "));
    plan.tests.push("Fuzz admin role fields with overlong and numeric edge cases.");
  }
  
  if (findings.some(f => f.lane === "economic")) {
    plan.tests.push("Simulate mint with MAX_UINT (2^256-1) and check for overflow wrap.");
    plan.tests.push("Simulate flash loan sandwich attacks on exposed liquidity functions.");
  }

  plan.tests.push("Record raw calldata, block diffs, and evidence hashes for all txs.");

  return plan;
}
