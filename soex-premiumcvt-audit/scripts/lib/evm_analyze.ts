/**
 * Deep static analysis of an EVM contract ABI.
 *
 * The EVM analog of `lib/analyze.ts`. Given a normalized ABI (resolved live by
 * the thirdweb v5 SDK, or loaded from a published ABI), it walks every external
 * function through EVM-specific hunting lanes — access control, upgradeability,
 * arbitrary external call / delegatecall, token-approval relay, signature
 * replay, reentrancy seams, value-moving math, and self-destruct — and ranks
 * candidates by composite risk *and* by expected bounty payout.
 *
 * Like the Solana analyzer, the output is a list of **candidate** leads to
 * confirm by hand (the ABI cannot prove a modifier exists), never a verdict.
 *
 * Pure functions only. No network, no SDK calls.
 */

import {
  Confidence,
  Severity,
  fingerprint,
  riskScore,
  SEVERITY_ORDER,
} from "./analyze";
import { AbiFunction, NormalizedAbi } from "./evm_abi";
import { PayoutBand, payoutMidpoint } from "./taxonomy";

export type EvmLane =
  | "EA-access-control"
  | "EB-upgradeability"
  | "EC-arbitrary-call"
  | "ED-token-approval"
  | "EE-signature-replay"
  | "EF-reentrancy"
  | "EG-economic-math"
  | "EH-self-destruct"
  | "EX-correlation";

export interface EvmFinding {
  id: string;
  lane: EvmLane;
  severity: Severity;
  confidence: Confidence;
  /** Composite rank = severity weight × confidence weight. */
  risk: number;
  /** Expected payout weight (USD midpoint of the severity band). */
  payoutWeight: number;
  /** Taxonomy id this candidate maps to (e.g. "smart-contract/access-control"). */
  vulnTypeId: string;
  function: string;
  title: string;
  detail: string;
  recommendation: string;
}

export interface EvmAnalysisResult {
  functionCount: number;
  findings: EvmFinding[];
  severityCounts: Record<Severity, number>;
  laneCounts: Record<EvmLane, number>;
  maxRisk: number;
  /** Sum of payout weights across findings — total expected bounty surface. */
  totalPayoutWeight: number;
}

export type RawEvmFinding = Omit<
  EvmFinding,
  "id" | "risk" | "confidence" | "payoutWeight"
> & {
  confidence?: Confidence;
};

// --- naming heuristics -----------------------------------------------------

const PRIVILEGED_RE =
  /(mint|burn|withdraw|setowner|setadmin|set_|setconfig|configure|pause|unpause|upgrade|migrate|initialize|^init$|rescue|sweep|drain|seize|setfee|setprice|whitelist|blacklist|grantrole|revokerole|addminter|removeminter|setminter|settreasury|setvault)/i;
const UPGRADE_RE =
  /(upgradeto|upgradetoandcall|setimplementation|changeadmin|transferownership|renounceownership|_setimplementation|_upgradeto)/i;
const ARBITRARY_CALL_RE =
  /(^execute$|^call$|multicall|functioncall|delegatecall|aggregate|^batch|forward|relay)/i;
const APPROVAL_RE = /(^approve$|increaseallowance|setapprovalforall|^permit$)/i;
const SIGNATURE_RE = /(permit|withsig|metatx|executemeta|verifysignature|claimwithsig)/i;
const VALUE_OUT_RE =
  /(withdraw|claim|redeem|unstake|transfer|send|payout|distribute|harvest|collect)/i;
const SELFDESTRUCT_RE = /(selfdestruct|destroy|^kill$|terminate)/i;
const AMOUNT_TYPE_RE = /^(u?int(8|16|32|64|128|256)?)$/;
const ADMIN_GETTER_RE = /^(owner|admin|getowner|hasrole|getroleadmin)$/i;

function isUintType(type: string): boolean {
  return AMOUNT_TYPE_RE.test(type);
}

function hasAddressBytesPair(fn: AbiFunction): boolean {
  const hasAddress = fn.inputs.some((i) => i.type === "address");
  const hasBytes = fn.inputs.some((i) => i.type === "bytes" || i.type.startsWith("bytes"));
  return hasAddress && hasBytes;
}

function hasSignatureShape(fn: AbiFunction): boolean {
  if (SIGNATURE_RE.test(fn.name)) return true;
  const hasV = fn.inputs.some((i) => i.type === "uint8" && /^v$/i.test(i.name));
  const hasR = fn.inputs.some((i) => i.type === "bytes32" && /^r$/i.test(i.name));
  const hasS = fn.inputs.some((i) => i.type === "bytes32" && /^s$/i.test(i.name));
  const hasSigBytes = fn.inputs.some(
    (i) => (i.type === "bytes" || i.type === "bytes32") && /sig|signature/i.test(i.name),
  );
  return (hasV && hasR && hasS) || hasSigBytes;
}

function hasNonceOrDeadline(fn: AbiFunction): boolean {
  return fn.inputs.some((i) => /nonce|deadline|expiry|validuntil/i.test(i.name));
}

// --- lane logic ------------------------------------------------------------

function laneAccessControl(fn: AbiFunction): RawEvmFinding[] {
  if (fn.readOnly) return [];
  if (!PRIVILEGED_RE.test(fn.name)) return [];
  return [
    {
      lane: "EA-access-control",
      severity: "high",
      confidence: "tentative",
      vulnTypeId: "smart-contract/access-control",
      function: fn.name,
      title: "Privileged function — verify access control",
      detail:
        `\`${fn.name}\` is a state-mutating, privileged-looking function. The ABI cannot ` +
        `prove an \`onlyOwner\`/role modifier exists. If it is unprotected, anyone can call it.`,
      recommendation:
        "Confirm the modifier in source (Ownable/AccessControl). Reproduce by calling from " +
        "an unrelated EOA on a fork and checking it does not revert.",
    },
  ];
}

function laneUpgradeability(fn: AbiFunction): RawEvmFinding[] {
  if (!UPGRADE_RE.test(fn.name)) return [];
  return [
    {
      lane: "EB-upgradeability",
      severity: "critical",
      confidence: "likely",
      vulnTypeId: "smart-contract/access-control",
      function: fn.name,
      title: "Upgrade / ownership-authority function",
      detail:
        `\`${fn.name}\` changes implementation, admin, or ownership. If the *current* admin/owner ` +
        `is not strictly required (and the function is not behind a timelock), an attacker who ` +
        `reaches it can seize the contract or point it at malicious code.`,
      recommendation:
        "Verify the caller must be the current admin/owner, confirm a timelock/multisig guards " +
        "upgrades, and check the proxy's storage layout compatibility.",
    },
  ];
}

function laneArbitraryCall(fn: AbiFunction): RawEvmFinding[] {
  if (fn.readOnly) return [];
  const nameHit = ARBITRARY_CALL_RE.test(fn.name);
  const shapeHit = hasAddressBytesPair(fn);
  if (!nameHit && !shapeHit) return [];
  return [
    {
      lane: "EC-arbitrary-call",
      severity: "critical",
      confidence: nameHit && shapeHit ? "likely" : "tentative",
      vulnTypeId: "smart-contract/arbitrary-call",
      function: fn.name,
      title: "Arbitrary external call / delegatecall seam",
      detail:
        `\`${fn.name}\` looks like it forwards a call to a caller-supplied target/calldata ` +
        `(address+bytes). If it uses \`call\`/\`delegatecall\` without strict target allow-listing, ` +
        `an attacker can execute arbitrary code or drain approvals routed through the contract.`,
      recommendation:
        "Confirm the target is allow-listed and that delegatecall (if any) cannot reach " +
        "attacker code. Check for approval-draining via routed transferFrom.",
    },
  ];
}

function laneTokenApproval(fn: AbiFunction): RawEvmFinding[] {
  if (!APPROVAL_RE.test(fn.name)) return [];
  return [
    {
      lane: "ED-token-approval",
      severity: "medium",
      confidence: "tentative",
      vulnTypeId: "smart-contract/logic",
      function: fn.name,
      title: "Approval surface — verify allowance handling",
      detail:
        `\`${fn.name}\` manages token approvals. Approval race conditions, infinite approvals, ` +
        `and permit replay are classic relay/phishing seams across DeFi/exchange programs.`,
      recommendation:
        "Check for the approve race (require zero-first or increase/decrease), and that any " +
        "permit path is nonce- and deadline-bound.",
    },
  ];
}

function laneSignatureReplay(fn: AbiFunction): RawEvmFinding[] {
  if (fn.readOnly) return [];
  if (!hasSignatureShape(fn)) return [];
  const unguarded = !hasNonceOrDeadline(fn);
  return [
    {
      lane: "EE-signature-replay",
      severity: unguarded ? "high" : "medium",
      confidence: unguarded ? "likely" : "tentative",
      vulnTypeId: "smart-contract/logic",
      function: fn.name,
      title: unguarded
        ? "Signature-verifying function without a visible nonce/deadline"
        : "Signature-verifying function (verify domain separation)",
      detail:
        `\`${fn.name}\` consumes a signature. ` +
        (unguarded
          ? "No nonce/deadline parameter is visible, so the signature may be replayable across " +
            "transactions or chains."
          : "Confirm EIP-712 domain separation binds chainId and contract so it cannot be replayed."),
      recommendation:
        "Confirm per-signer nonces, a deadline, and an EIP-712 domain (name, version, chainId, " +
        "verifyingContract). Attempt a replay on a fork to confirm.",
    },
  ];
}

function laneReentrancy(fn: AbiFunction): RawEvmFinding[] {
  if (fn.readOnly) return [];
  const valueOut = VALUE_OUT_RE.test(fn.name);
  if (!valueOut && !fn.payable) return [];
  return [
    {
      lane: "EF-reentrancy",
      severity: "high",
      confidence: "tentative",
      vulnTypeId: "smart-contract/reentrancy",
      function: fn.name,
      title: "Value-moving function — verify reentrancy guard / CEI",
      detail:
        `\`${fn.name}\` moves value (${fn.payable ? "payable" : "value-out"}). If it makes an ` +
        `external call before updating state (violating checks-effects-interactions) and lacks ` +
        `\`nonReentrant\`, it is a reentrancy candidate — including read-only reentrancy of any ` +
        `share/price view it exposes.`,
      recommendation:
        "Confirm CEI ordering and a reentrancy guard. Test with a malicious receiver/hook that " +
        "re-enters during the external call.",
    },
  ];
}

function laneEconomicMath(fn: AbiFunction): RawEvmFinding[] {
  if (fn.readOnly) return [];
  const numeric = fn.inputs.filter((i) => isUintType(i.type));
  const valueish =
    /(mint|burn|deposit|withdraw|swap|stake|unstake|borrow|repay|redeem|price|fee|reward|share)/i.test(
      fn.name,
    );
  if (numeric.length === 0 || !valueish) return [];
  return [
    {
      lane: "EG-economic-math",
      severity: "medium",
      confidence: "tentative",
      vulnTypeId: "smart-contract/overflow",
      function: fn.name,
      title: "Value-moving math — probe overflow / rounding / share inflation",
      detail:
        `\`${fn.name}\` takes numeric amount(s) [${numeric
          .map((i) => `${i.name || "_"}:${i.type}`)
          .join(", ")}] and touches value. Rounding-to-zero, precision loss, first-depositor ` +
        `share inflation, and (pre-0.8 / unchecked) overflow are the seams here.`,
      recommendation:
        "Run `npm run invariant-sim` on the fee/share math and probe 0, 1, and near-max " +
        "boundaries. Check rounding direction always favours the protocol.",
    },
  ];
}

function laneSelfDestruct(fn: AbiFunction): RawEvmFinding[] {
  if (!SELFDESTRUCT_RE.test(fn.name)) return [];
  return [
    {
      lane: "EH-self-destruct",
      severity: "high",
      confidence: "tentative",
      vulnTypeId: "smart-contract/access-control",
      function: fn.name,
      title: "Self-destruct / terminate function",
      detail:
        `\`${fn.name}\` may destroy the contract or its logic. Behind a proxy this can brick the ` +
        `system or strand funds. Verify it is unreachable by untrusted callers.`,
      recommendation:
        "Confirm strict access control and that no delegatecall path can reach a selfdestruct " +
        "in the implementation.",
    },
  ];
}

const LANES: ((fn: AbiFunction) => RawEvmFinding[])[] = [
  laneAccessControl,
  laneUpgradeability,
  laneArbitraryCall,
  laneTokenApproval,
  laneSignatureReplay,
  laneReentrancy,
  laneEconomicMath,
  laneSelfDestruct,
];

/**
 * Cross-function correlation: privileged setters exist but the contract exposes
 * no ownership/role getter (`owner()`/`hasRole`). That inconsistency is a strong
 * signal the access model is ad-hoc (or missing) rather than a standard
 * Ownable/AccessControl — worth a focused manual check.
 */
function correlate(abi: NormalizedAbi): RawEvmFinding[] {
  const privilegedSetters = abi.functions.filter(
    (f) => !f.readOnly && PRIVILEGED_RE.test(f.name) && !UPGRADE_RE.test(f.name),
  );
  const hasAdminGetter = abi.functions.some((f) => ADMIN_GETTER_RE.test(f.name));
  if (privilegedSetters.length >= 2 && !hasAdminGetter) {
    return [
      {
        lane: "EX-correlation",
        severity: "high",
        confidence: "likely",
        vulnTypeId: "smart-contract/access-control",
        function: privilegedSetters[0].name,
        title: "Privileged setters with no standard ownership/role getter",
        detail:
          `The contract exposes ${privilegedSetters.length} privileged setters ` +
          `(e.g. \`${privilegedSetters
            .slice(0, 3)
            .map((f) => f.name)
            .join("`, `")}\`) but no \`owner()\`/\`hasRole\` getter. The access model may be ad-hoc ` +
          `or missing — a high-signal seam for an access-control takeover.`,
        recommendation:
          "Map every privileged function to a concrete authority check in source; prefer a " +
          "standard Ownable/AccessControl with events and a getter.",
      },
    ];
  }
  return [];
}

function finalize(raw: RawEvmFinding, payoutBands?: PayoutBand[]): EvmFinding {
  const confidence = raw.confidence ?? "likely";
  return {
    ...raw,
    confidence,
    id: fingerprint(raw.lane, raw.function, null),
    risk: riskScore(raw.severity, confidence),
    payoutWeight: payoutMidpoint(raw.severity, payoutBands),
  };
}

function emptyLaneCounts(): Record<EvmLane, number> {
  return {
    "EA-access-control": 0,
    "EB-upgradeability": 0,
    "EC-arbitrary-call": 0,
    "ED-token-approval": 0,
    "EE-signature-replay": 0,
    "EF-reentrancy": 0,
    "EG-economic-math": 0,
    "EH-self-destruct": 0,
    "EX-correlation": 0,
  };
}

/**
 * Analyze a normalized ABI. `payoutBands` (from a program's registry entry) tunes
 * the expected-payout weighting; omitting it uses the taxonomy defaults.
 */
export function analyzeAbi(
  abi: NormalizedAbi,
  payoutBands?: PayoutBand[],
): EvmAnalysisResult {
  const perFn = abi.functions.flatMap((fn) => LANES.flatMap((lane) => lane(fn)));
  const correlated = correlate(abi);
  const findings = [...perFn, ...correlated].map((f) => finalize(f, payoutBands));

  const severityCounts = SEVERITY_ORDER.reduce(
    (acc, s) => ({ ...acc, [s]: 0 }),
    {} as Record<Severity, number>,
  );
  const laneCounts = emptyLaneCounts();
  for (const f of findings) {
    severityCounts[f.severity] += 1;
    laneCounts[f.lane] += 1;
  }

  // Rank by payout weight first (highest expected bounty), then composite risk,
  // then function name for a stable order.
  const sorted = [...findings].sort(
    (a, b) =>
      b.payoutWeight - a.payoutWeight ||
      b.risk - a.risk ||
      a.function.localeCompare(b.function),
  );

  const maxRisk = findings.reduce((m, f) => Math.max(m, f.risk), 0);
  const totalPayoutWeight = findings.reduce((s, f) => s + f.payoutWeight, 0);

  return {
    functionCount: abi.functions.length,
    findings: sorted,
    severityCounts,
    laneCounts,
    maxRisk,
    totalPayoutWeight,
  };
}
