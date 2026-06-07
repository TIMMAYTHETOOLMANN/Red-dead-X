import "dotenv/config";
import fs from "fs";
import {
  DEFAULT_PARAMS,
  InvariantIssue,
  SimParams,
  U64_MAX,
  simulateInvariants,
} from "./lib/invariants";

/**
 * Economic invariant simulator CLI (read-only, pure math).
 *
 * Runs the invariant battery from docs/02 against configurable fee/supply
 * parameters and writes the surfaced issues to `evidence/`. Pin the real fee
 * basis points and supply cap from source before trusting the output.
 */

const evidenceDir = process.env.EVIDENCE_DIR ?? "./evidence";

function parseBigIntEnv(name: string): bigint | undefined {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return undefined;
  try {
    return BigInt(raw.trim());
  } catch {
    throw new Error(`Env ${name}="${raw}" is not a valid integer.`);
  }
}

function buildParams(): SimParams {
  const feeBps = parseBigIntEnv("FEE_BPS") ?? DEFAULT_PARAMS.feeBps;
  const supplyCap = parseBigIntEnv("SUPPLY_CAP");
  const roundingRaw = (process.env.FEE_ROUNDING ?? DEFAULT_PARAMS.feeRounding).trim();
  if (roundingRaw !== "floor" && roundingRaw !== "ceil") {
    throw new Error(`FEE_ROUNDING must be "floor" or "ceil", got "${roundingRaw}".`);
  }

  // Optional comma-separated custom probe amounts.
  const amountsRaw = (process.env.PROBE_AMOUNTS ?? "").trim();
  const amounts =
    amountsRaw === ""
      ? DEFAULT_PARAMS.amounts
      : amountsRaw.split(",").map((a) => {
          const t = a.trim();
          return t.toLowerCase() === "u64max" ? U64_MAX : BigInt(t);
        });

  return { feeBps, feeRounding: roundingRaw, supplyCap, amounts };
}

function main() {
  const params = buildParams();
  const issues = simulateInvariants(params);

  fs.mkdirSync(evidenceDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const out = `${evidenceDir}/invariant-sim-${stamp}.json`;

  const serializable = {
    simulatedAt: new Date().toISOString(),
    readOnly: true,
    params: {
      feeBps: params.feeBps.toString(),
      feeRounding: params.feeRounding,
      supplyCap: params.supplyCap?.toString() ?? null,
      amounts: params.amounts.map((a) => a.toString()),
    },
    issueCount: issues.length,
    issues,
  };

  fs.writeFileSync(out, JSON.stringify(serializable, null, 2));
  console.log(`Wrote ${out}`);
  console.log(
    `feeBps=${params.feeBps} rounding=${params.feeRounding} ` +
      `supplyCap=${params.supplyCap ?? "(none)"} issues=${issues.length}`,
  );
  if (issues.length > 0) {
    console.table(
      issues.map((i: InvariantIssue) => ({
        severity: i.severity,
        invariant: i.invariant,
        detail: i.detail,
      })),
    );
  }
}

main();
