# Stage 3: Economic & Invariant Simulation

This stage provides an agent-ready config, methods, research workload, and reporting model for automated and manual economic invariant testing across DeFi and contract systems.

## 1. Economic Simulation Tool Inventory & Attack Surface

| Tool/Approach | Usage/Mode | Economic Pitfall / Attack Vector |
|---|---|---|
| BigNumber Math Lib | High-precision math, uint256 simulations | Overflows, underflows, rounding errors, dust draining |
| Invariant Sim Engine | Simulates contract ops, fee logic | Breaks in value conservation; non-monotonic fees; infinite mint |
| Fuzz Engine | Systematic random/max-edge case input | Rare states: underflow, 0/1-unit, max supply, empty/overflow |
| Scenario Runner | Batch run mint/burn/swap/withdraw ops | Time-based, recursive, cross-period or sandwich attack flows |
| Action Table | List all value-moving functions | Forgotten action, asymmetric logic, ignored/hidden burn/mint |
| Unit Test Bed | Boolean checks/assertions on economic proofs | Fails expected invariants = clear vulnerability |

## 2. Core Agent Configuration

See `scripts/lib/invariant.ts` for the implementation of `INVARIANT_SIM_CONFIG`.

## 3. Agent Steps – Stage 3 Forensic Simulation

1. **Enumerate All Value-Moving Functions:** Scrape ABI, identify all ops: mint, burn, transfer, swap, withdraw/reward.
2. **Edge-Case Fuzzing & Simulation:** For every function: simulate with `[0, 1, MAX_UINT, supply max, fee=0, fee=max]`.
3. **Invariant Proofs:** Validate key assertions: supply conservation, recipient balance, contract balance after, fees accumulated, “no dust” on repeat runs.
4. **Rounding & Overflow/Underflow Tests:** Every output is checked for rounding in attacker's favor.
5. **Math/Logic Assertions:** Compare with invariant: values never negative, total input/output matches allowance and overall supply/balance down to last digit/wei.
6. **SARIF/Markdown Reporting:** Store every test vector, attack scenario, and output by action taken, inputs used, expected vs actual balances, explicit delta, and failure reason.

## 4. Attack Vector, Failure, and Edge-Case Table

| Method | Fuzz Input | Vulnerability/Attack | Example Output/State Change |
|---|---|---|---|
| mint | amount: 0 | Minting 0 tokens (should revert) | supply unchanged; if not: 💥 logic error |
| mint | amount: MAX | Overflow on supply/cap | supply wraps/zeroes; attacker can infinitely mint |
| swap | in: 1, fee: 0 | Dust draining, fee regression | contract leaks value on repeat |
| burn | amount: >supply | Underflow; should fail | supply becomes negative/huge; attacker drains pool |
| withdraw | amount: MAX | Exceeding treasury balance | negative balance or error vs safe revert |
| claim (ref) | ref: MAX | Referrer reward > user input | rewards “create money from nowhere” |
