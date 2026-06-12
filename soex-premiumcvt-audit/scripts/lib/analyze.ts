import crypto from "crypto";
import { logger } from "./logger";
import {
  NormalizedAccount,
  NormalizedIdl,
  NormalizedInstruction,
} from "./idl";

/**
 * Deep, multi-layer static analysis of an Anchor IDL.
 *
 * This is a *static* pass: it reasons about the structure the IDL exposes
 * (signers, PDA seeds, writability, fixed addresses, relations) and walks every
 * instruction through the six hunting lanes from `docs/01-hunting-lanes.md`.
 *
 * The output is a list of **candidate** findings to confirm by hand — never a
 * verdict. The triage rubric (`docs/03-triage-rubric.md`) still applies: do not
 * report "the tool said so". The value here is coverage and ranking: it makes
 * sure no instruction/account pair is skipped and surfaces the deep seams
 * (account substitution, missing signer binding, unbound token custody,
 * attacker-influenced PDA seeds) that surface-level scanners miss.
 *
 * Pure functions only. No network, no transactions, no filesystem.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Lane =
  | "A-authority"
  | "B-account-substitution"
  | "C-token-custody"
  | "D-economic"
  | "E-referral"
  | "F-upgrade-admin"
  | "G-cpi-program"
  | "H-init-safety"
  | "I-dos-compute"
  | "X-correlation";

/**
 * Confidence that a candidate finding reflects a real, exploitable seam — as
 * opposed to a benign-but-flag-worthy pattern. This is *separate* from severity
 * (impact-if-true). Composite `risk` = severity weight × confidence weight, and
 * is what we rank by so the highest-impact, highest-confidence leads float up.
 */
export type Confidence = "firm" | "likely" | "tentative";

export interface Finding {
  /** Stable fingerprint (see `fingerprint`) — survives across runs for baselining. */
  id: string;
  lane: Lane;
  severity: Severity;
  /** Likelihood the candidate is a real seam (distinct from severity/impact). */
  confidence: Confidence;
  /** Composite rank = severity weight × confidence weight (higher = hunt first). */
  risk: number;
  instruction: string;
  account: string | null;
  title: string;
  detail: string;
  recommendation: string;
}

export interface MatrixRow {
  instruction: string;
  account: string;
  signer: boolean;
  writable: boolean;
  seeds: string;
  pinnedAddress: boolean;
  relations: string;
}

export interface AnalysisResult {
  program: string;
  address: string | null;
  instructionCount: number;
  findings: Finding[];
  matrix: MatrixRow[];
  severityCounts: Record<Severity, number>;
  laneCounts: Record<Lane, number>;
  /** Highest composite risk present (0 when there are no findings). */
  maxRisk: number;
}

/**
 * What a lane emits before scoring. `confidence` is optional at the lane site
 * (defaults to "likely"); `id` and `risk` are derived centrally so every lane
 * stays focused on detection logic, not bookkeeping.
 */
export type RawFinding = Omit<Finding, "id" | "risk" | "confidence"> & {
  confidence?: Confidence;
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_INDEX: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const CONFIDENCE_WEIGHT: Record<Confidence, number> = {
  firm: 3,
  likely: 2,
  tentative: 1,
};

/**
 * Stable, content-addressed id for a finding so the same seam keeps the same id
 * across runs. Deliberately excludes prose (title/detail) so wording tweaks do
 * not churn baselines — identity is (lane, instruction, account).
 */
const fingerprintCache = new Map<string, string>();

export function fingerprint(
  lane: Lane | string,
  instruction: string,
  account: string | null,
): string {
  const key = `${lane}\u0000${instruction}\u0000${account ?? ""}`;
  if (fingerprintCache.has(key)) {
    return fingerprintCache.get(key)!;
  }
  const hash = crypto
    .createHash("sha256")
    .update(key)
    .digest("hex")
    .slice(0, 16);
  fingerprintCache.set(key, hash);
  return hash;
}

/** Composite rank used for ordering: impact-if-true × likelihood-it-is-real. */
export function riskScore(severity: Severity, confidence: Confidence): number {
  return SEVERITY_WEIGHT[severity] * CONFIDENCE_WEIGHT[confidence];
}

function finalize(raw: RawFinding): Finding {
  const confidence = raw.confidence ?? "likely";
  return {
    ...raw,
    confidence,
    id: fingerprint(raw.lane, raw.instruction, raw.account),
    risk: riskScore(raw.severity, confidence),
  };
}

// --- naming heuristics -----------------------------------------------------

/** Instructions whose names imply a privileged state mutation. */
const PRIVILEGED_RE =
  /(init|initialize|config|configure|set_|update|admin|owner|authority|withdraw|mint|burn|claim|close|upgrade|migrate|pause|unpause|freeze|thaw|govern|treasury|fee|price|whitelist|blacklist)/i;

/** Account names that imply an authority/role that should be enforced. */
const AUTHORITY_RE =
  /(authority|admin|owner|governance|treasury|signer|payer|delegate|manager|operator)/i;

/**
 * A *protocol* authority/role — deliberately excludes beneficiary-class names
 * (`payer`, `owner`, `user`, `funder`) so we can tell "a privileged op is gated
 * by a distinct admin/authority" apart from "a privileged op is gated only by
 * whoever happens to call it".
 */
const PROTOCOL_AUTHORITY_RE = /(authority|admin|governance|manager|operator|delegate)/i;

/** Instruction names that create/move value and therefore demand authorization. */
const VALUE_OP_RE =
  /(mint|burn|withdraw|redeem|claim|payout|distribute|deposit|transfer|swap)/i;

/** The subset of value ops whose abuse is directly fund-creating/extracting. */
const HIGH_VALUE_OP_RE = /(mint|burn|withdraw|redeem|transfer|swap)/i;

/** The upgradeable-loader ProgramData account: writable *state* (holds the
 * upgrade authority), NOT a CPI program target — must not be treated as a pinned
 * program account. */
const PROGRAM_DATA_RE = /program[_-]?data/i;

/** An account that receives an authority/role (e.g. `new_authority`, `new_admin`). */
const AUTHORITY_RECIPIENT_RE = /(new_?|next_?|pending_?).*(authority|admin|owner)/i;

/** Account names that imply token custody. The `ata` (associated-token-account)
 * token is matched with delimiters so it does not spuriously fire inside words
 * like "data"/"metadata". */
const TOKEN_RE =
  /(token|vault|mint|escrow|pool|reserve|treasury|(?:^|_|-)ata(?:$|_|-))/i;

/** Account names that imply referral-graph participation. */
const REFERRAL_RE = /(referr|referer|parent|sponsor|upline|downline|invite|inviter)/i;

/** Instruction names that imply upgrade/admin-authority changes. */
const UPGRADE_RE =
  /(upgrade|migrate|set_authority|transfer_authority|set_admin|set_owner|set_upgrade)/i;

/** Numeric argument types worth simulating for overflow/rounding. */
const NUMERIC_ARG_RE = /(u8|u16|u32|u64|u128|i8|i16|i32|i64|i128)/;

/** Account names that imply a program account (a CPI target). */
const PROGRAM_RE = /(_program$|^program$|_prog$|invoke|cpi)/i;

/** Instruction names that create/initialize an account. */
const INIT_RE = /(init|initialize|create|open|register|new_)/i;

/** Arg types whose size the caller controls (unbounded → compute/DoS seam). */
const UNBOUNDED_ARG_RE = /^(vec<|bytes$|string$)/i;

const programLikeCache = new WeakMap<NormalizedAccount, boolean>();
function isProgramLike(account: NormalizedAccount): boolean {
  if (programLikeCache.has(account)) return programLikeCache.get(account)!;
  // System/sysvar/token programs are typically pinned by a fixed address.
  // Exception: the upgradeable-loader `program_data` account merely *contains*
  // "program" in its name but is writable state (it holds the upgrade authority),
  // so it must remain analyzable — never silently skipped as a pinned program.
  const res =
    account.hasAddress ||
    (/program|sysvar|rent|clock/i.test(account.name) && !PROGRAM_DATA_RE.test(account.name));
  programLikeCache.set(account, res);
  return res;
}

const seedsCache = new WeakMap<NormalizedAccount, boolean>();
function hasSeeds(account: NormalizedAccount): boolean {
  if (seedsCache.has(account)) return seedsCache.get(account)!;
  const res = account.seeds.length > 0;
  seedsCache.set(account, res);
  return res;
}

function seedSummary(account: NormalizedAccount): string {
  if (account.seeds.length === 0) return "";
  return account.seeds.map((s) => `${s.kind}:${s.value}`).join(" + ");
}

// --- lane logic ------------------------------------------------------------

function laneAuthority(ix: NormalizedInstruction): RawFinding[] {
  const findings: RawFinding[] = [];
  const privileged = PRIVILEGED_RE.test(ix.name);
  const anySigner = ix.accounts.some((a) => a.signer);

  if (privileged && ix.accounts.length > 0 && !anySigner) {
    findings.push({
      lane: "A-authority",
      severity: "high",
      confidence: "firm",
      instruction: ix.name,
      account: null,
      title: "Privileged instruction has no signer",
      detail:
        `Instruction \`${ix.name}\` looks state-mutating/privileged but declares no signer ` +
        `account. If no signer is enforced, anyone can invoke it.`,
      recommendation:
        "Confirm in source: require a `Signer<'info>` (or `has_one` against a stored " +
        "authority that must sign). Reproduce by invoking with an unrelated keypair.",
    });
  }

  // Self-authorized value operation: a fund-creating/-moving instruction that
  // *does* have a signer, but whose signer set contains no **distinct protocol
  // authority** (admin/authority/governance/...). The only thing standing
  // between a caller and minting/withdrawing is the caller's own signature, so
  // the privileged action is effectively self-authorized. Lane A's no-signer
  // rule above structurally cannot see this (a signer is present).
  if (VALUE_OP_RE.test(ix.name) && anySigner) {
    const writesNonProgram = ix.accounts.some((a) => a.writable && !isProgramLike(a));
    const hasProtocolAuthority = ix.accounts.some((a) => PROTOCOL_AUTHORITY_RE.test(a.name));
    if (writesNonProgram && !hasProtocolAuthority) {
      const severity: Severity = HIGH_VALUE_OP_RE.test(ix.name) ? "high" : "medium";
      findings.push({
        lane: "A-authority",
        severity,
        confidence: "likely",
        instruction: ix.name,
        account: null,
        title: "Value-moving instruction has no distinct protocol authority",
        detail:
          `Instruction \`${ix.name}\` creates or moves value and writes a non-program account, ` +
          `but no admin/authority/governance account participates — the only authorization is ` +
          `the caller's own signature. If a privileged authority is not separately required, ` +
          `any caller can self-authorize this operation (e.g. unauthorized mint/withdraw/claim).`,
        recommendation:
          "Require a distinct, stored protocol authority to sign (e.g. `has_one = authority` + " +
          "`Signer`) for this operation, separate from the payer/beneficiary. Test by invoking " +
          "with a fresh keypair that is not the configured authority.",
      });
    }
  }

  for (const acc of ix.accounts) {
    if (!AUTHORITY_RE.test(acc.name)) continue;
    if (isProgramLike(acc)) continue;
    // Payers usually sign; an authority-ish account that neither signs nor is
    // bound by relations/seeds is the classic "authority stored but never compared".
    if (!acc.signer && acc.relations.length === 0 && !hasSeeds(acc) && !acc.hasAddress) {
      findings.push({
        lane: "A-authority",
        severity: "medium",
        confidence: "likely",
        instruction: ix.name,
        account: acc.name,
        title: "Authority-like account is not a signer and is unbound",
        detail:
          `Account \`${acc.name}\` in \`${ix.name}\` reads like an authority but is not a ` +
          `signer and has no PDA seeds, pinned address, or \`relations\`/\`has_one\` binding. ` +
          `An attacker may be able to pass an arbitrary account here.`,
        recommendation:
          "Verify the authority is compared to a signer (e.g. `has_one = authority` plus " +
          "`Signer`). Test by substituting an attacker-controlled account.",
      });
    }
  }
  return findings;
}

function laneAccountSubstitution(ix: NormalizedInstruction): RawFinding[] {
  const findings: RawFinding[] = [];
  for (const acc of ix.accounts) {
    if (isProgramLike(acc)) continue;
    if (acc.signer) continue; // a signer cannot be silently substituted

    // Writable, non-signer, no seed binding, no pinned address, no relations:
    // the program is trusting an account it cannot verify by derivation.
    if (
      acc.writable &&
      !hasSeeds(acc) &&
      !acc.hasAddress &&
      acc.relations.length === 0 &&
      !/payer|funder/i.test(acc.name)
    ) {
      findings.push({
        lane: "B-account-substitution",
        severity: "medium",
        confidence: "likely",
        instruction: ix.name,
        account: acc.name,
        title: "Writable account has no PDA-seed or relation binding",
        detail:
          `Writable account \`${acc.name}\` in \`${ix.name}\` has no declared PDA seeds, ` +
          `pinned address, or \`relations\`. If the program does not re-derive/verify it, ` +
          `a substituted account could redirect writes (state or funds).`,
        recommendation:
          "Confirm the account is a checked PDA (`seeds`+`bump`) or constrained via " +
          "`has_one`/`address`. Try the wrong-account substitution from lane B.",
      });
    }

    // Attacker-influenced PDA seed (`arg`) — the caller can steer which PDA is hit.
    const argSeed = acc.seeds.find((s) => s.kind === "arg");
    if (argSeed) {
      // If the PDA is *also* seeded by an account (e.g. the signer/owner pubkey),
      // the caller can only steer within their own namespace. If there is no
      // account-kind seed at all, the arg is the only thing selecting the PDA, so
      // a caller can address another user's PDA outright (cross-user theft /
      // collision) — a materially stronger seam, so rank it higher.
      const accountBoundSeed = acc.seeds.some((s) => s.kind === "account");
      findings.push({
        lane: "B-account-substitution",
        severity: accountBoundSeed ? "low" : "medium",
        confidence: accountBoundSeed ? "tentative" : "likely",
        instruction: ix.name,
        account: acc.name,
        title: "PDA seed is derived from a caller-supplied argument",
        detail:
          `PDA \`${acc.name}\` in \`${ix.name}\` uses a caller-supplied arg (\`${argSeed.value}\`) ` +
          `as a seed. Caller-steered seeds can let an attacker target or collide PDAs they ` +
          `should not control.` +
          (accountBoundSeed
            ? ""
            : ` No account-kind seed (e.g. the signer/owner pubkey) binds this PDA, so the ` +
              `caller can address *another user's* PDA by supplying their value.`),
        recommendation:
          "Confirm the arg-derived seed is additionally bound to the signer/owner so it " +
          "cannot address another user's PDA.",
      });
    }
  }
  return findings;
}

function laneTokenCustody(ix: NormalizedInstruction): RawFinding[] {
  const findings: RawFinding[] = [];
  for (const acc of ix.accounts) {
    if (!TOKEN_RE.test(acc.name)) continue;
    if (isProgramLike(acc)) continue;
    if (acc.signer) continue;

    // Token/vault account that is writable but not seed-bound or relation-bound:
    // mint/owner constraints cannot be confirmed from the IDL, so flag for review.
    if (acc.writable && !hasSeeds(acc) && acc.relations.length === 0) {
      findings.push({
        lane: "C-token-custody",
        severity: "medium",
        confidence: "likely",
        instruction: ix.name,
        account: acc.name,
        title: "Token/vault account is not bound by seeds or relations",
        detail:
          `Token-custody account \`${acc.name}\` in \`${ix.name}\` is writable but has no PDA ` +
          `seeds or \`relations\`. The IDL cannot prove its mint/owner/token-program are ` +
          `constrained, so a wrong-mint or wrong-owner token account may be accepted.`,
        recommendation:
          "Confirm `token::mint`, `token::authority`/owner, and `token_program` constraints " +
          "in source. Test with a wrong-mint and wrong-owner token account.",
      });
    }
  }
  return findings;
}

function laneEconomic(ix: NormalizedInstruction): RawFinding[] {
  const findings: RawFinding[] = [];
  const numericArgs = ix.args.filter((a) => NUMERIC_ARG_RE.test(a.type));
  const touchesValue = ix.accounts.some(
    (a) => TOKEN_RE.test(a.name) && a.writable && !isProgramLike(a),
  );
  if (numericArgs.length > 0 && touchesValue) {
    findings.push({
      lane: "D-economic",
      severity: "low",
      confidence: "tentative",
      instruction: ix.name,
      account: null,
      title: "Value-moving instruction takes numeric amounts",
      detail:
        `Instruction \`${ix.name}\` takes numeric arg(s) ` +
        `[${numericArgs.map((a) => `${a.name}:${a.type}`).join(", ")}] and writes a ` +
        `token/vault account. Amount math here is a prime seam for overflow, fee ` +
        `rounding-to-zero, and value-conservation breaks.`,
      recommendation:
        "Run `npm run invariant-sim` against this instruction's fee/mint/burn math and " +
        "probe 0, 1, and near-u64-max boundaries (see docs/02-invariants.md).",
    });
  }
  return findings;
}

function laneReferral(ix: NormalizedInstruction): RawFinding[] {
  const findings: RawFinding[] = [];
  for (const acc of ix.accounts) {
    if (!REFERRAL_RE.test(acc.name)) continue;
    const writableUnbound =
      acc.writable && !acc.signer && !hasSeeds(acc) && acc.relations.length === 0;
    findings.push({
      lane: "E-referral",
      severity: writableUnbound ? "medium" : "info",
      confidence: writableUnbound ? "likely" : "tentative",
      instruction: ix.name,
      account: acc.name,
      title: writableUnbound
        ? "Referral/parent account is writable and unbound"
        : "Referral/parent account participates in this instruction",
      detail:
        `Account \`${acc.name}\` in \`${ix.name}\` is part of the referral graph. ` +
        (writableUnbound
          ? "It is writable, non-signing, and unbound, which enables parent injection."
          : "Model the referral graph as a payment graph, not a profile feature."),
      recommendation:
        "Check self-referral, A↔B cycles, parent changes after accrual, duplicate-parent " +
        "injection, deep-chain rounding, and compute exhaustion (lane D).",
    });
  }
  return findings;
}

function laneUpgradeAdmin(ix: NormalizedInstruction): RawFinding[] {
  const findings: RawFinding[] = [];
  if (!UPGRADE_RE.test(ix.name)) return findings;
  const anySigner = ix.accounts.some((a) => a.signer);
  findings.push({
    lane: "F-upgrade-admin",
    severity: anySigner ? "medium" : "high",
    confidence: anySigner ? "likely" : "firm",
    instruction: ix.name,
    account: null,
    title: anySigner
      ? "Authority/upgrade change instruction (verify the current authority must sign)"
      : "Authority/upgrade change instruction with no signer",
    detail:
      `Instruction \`${ix.name}\` changes admin/upgrade authority. ` +
      (anySigner
        ? "Confirm the *current* authority (not just any signer) is required."
        : "No signer is declared — an unintended caller may seize authority."),
    recommendation:
      "Verify the current authority is enforced via `has_one`+`Signer`. Cross-check the " +
      "on-chain upgrade authority with `npm run program-info`.",
  });

  // One-step authority hand-off: the new authority is named/handed in but never
  // signs and is otherwise unbound. A direct (non-two-step) transfer to an
  // address that does not have to accept the role risks handing control to a
  // typo'd or attacker-supplied account with no recovery.
  for (const acc of ix.accounts) {
    if (!AUTHORITY_RECIPIENT_RE.test(acc.name)) continue;
    if (acc.signer || isProgramLike(acc)) continue;
    findings.push({
      lane: "F-upgrade-admin",
      severity: "medium",
      confidence: "likely",
      instruction: ix.name,
      account: acc.name,
      title: "Authority handed to a non-signing account (no two-step acceptance)",
      detail:
        `Instruction \`${ix.name}\` assigns authority to \`${acc.name}\`, which does not sign ` +
        `and is unbound. A one-step transfer to an account that never has to accept the role ` +
        `means a wrong/attacker-supplied address takes control immediately, with no recovery.`,
      recommendation:
        "Adopt a two-step transfer: store a `pending_authority`, then require the new authority " +
        "to sign an explicit `accept_authority` before it takes effect.",
    });
  }
  return findings;
}

// --- new deep lanes (G, H, I) ---------------------------------------------

/**
 * Lane G — CPI / arbitrary-program substitution.
 *
 * Solana programs that invoke another program (CPI) must pin that program's id.
 * A program-like account that is NOT pinned by a fixed address (and is not a
 * known sysvar) lets an attacker pass a malicious program of their own, turning
 * a "trusted" CPI into attacker-controlled code (fake token program, fake
 * metadata program, etc.).
 */
function laneCpiProgram(ix: NormalizedInstruction): RawFinding[] {
  const findings: RawFinding[] = [];
  for (const acc of ix.accounts) {
    const looksLikeProgram = PROGRAM_RE.test(acc.name);
    if (!looksLikeProgram) continue;
    // A sysvar/rent/clock or a pinned address is fine — it cannot be substituted.
    if (acc.hasAddress) continue;
    if (/sysvar|rent|clock/i.test(acc.name)) continue;
    // A program account that is also a signer/PDA is unusual but bound; skip.
    if (acc.signer || hasSeeds(acc)) continue;

    findings.push({
      lane: "G-cpi-program",
      severity: "high",
      confidence: acc.relations.length === 0 ? "likely" : "tentative",
      instruction: ix.name,
      account: acc.name,
      title: "CPI target program is not pinned to a fixed address",
      detail:
        `Program account \`${acc.name}\` in \`${ix.name}\` is used like a CPI target but ` +
        `declares no fixed \`address\`. If the program id is not checked, an attacker can ` +
        `pass a malicious program (fake token/metadata program) and execute arbitrary code ` +
        `under the instruction's trust.`,
      recommendation:
        "Pin the program id (`address = <known program>`), or compare it in source against " +
        "the expected constant before any `invoke`/`invoke_signed`.",
    });
  }
  return findings;
}

/**
 * Lane H — re-initialization / init safety.
 *
 * An `init`-style instruction whose target state account is not a checked PDA
 * (no seeds, no pinned address, not a signer) can often be re-initialized or
 * pointed at an arbitrary account, overwriting existing state (config takeover,
 * reward-account reset, escrow reset).
 */
function laneInitSafety(ix: NormalizedInstruction): RawFinding[] {
  if (!INIT_RE.test(ix.name)) return [];
  const findings: RawFinding[] = [];
  for (const acc of ix.accounts) {
    if (!acc.writable) continue;
    if (isProgramLike(acc)) continue;
    if (acc.signer) continue;
    if (/payer|funder/i.test(acc.name)) continue;
    // A PDA (seeds) or relation-bound or pinned account is the safe shape.
    if (hasSeeds(acc) || acc.hasAddress || acc.relations.length > 0) continue;

    findings.push({
      lane: "H-init-safety",
      severity: "high",
      confidence: "likely",
      instruction: ix.name,
      account: acc.name,
      title: "Initialized account is not a checked PDA (re-init / overwrite risk)",
      detail:
        `Init-style instruction \`${ix.name}\` writes \`${acc.name}\`, which has no PDA seeds, ` +
        `pinned address, or relation binding. Without an \`init\` (not \`init_if_needed\`) ` +
        `constraint on a derived PDA, the account can be re-initialized or substituted, ` +
        `overwriting live state.`,
      recommendation:
        "Use `#[account(init, seeds = [...], bump)]` so the address is derived and cannot be " +
        "re-initialized; avoid `init_if_needed` unless the reset path is explicitly safe.",
    });
  }
  return findings;
}

/**
 * Lane I — DoS / compute exhaustion (local-only impact, per docs/01 lane F).
 *
 * Flags caller-controlled unbounded inputs (`vec<_>`, `bytes`, `string`) and
 * unusually high account fan-out, both of which can blow the compute budget or
 * trap funds via state that cannot be processed/resized.
 */
function laneDosCompute(ix: NormalizedInstruction): RawFinding[] {
  const findings: RawFinding[] = [];
  for (const arg of ix.args) {
    if (UNBOUNDED_ARG_RE.test(arg.type)) {
      findings.push({
        lane: "I-dos-compute",
        severity: "low",
        confidence: "tentative",
        instruction: ix.name,
        account: null,
        title: "Instruction takes a caller-sized unbounded argument",
        detail:
          `Instruction \`${ix.name}\` accepts \`${arg.name}: ${arg.type}\`, whose length the ` +
          `caller controls. Without an explicit length cap, large inputs can exhaust the ` +
          `compute budget or grow state unboundedly (local-only DoS, docs/01 lane F).`,
        recommendation:
          "Enforce a maximum length on the input and a bounded account size; reject oversized " +
          "payloads before processing.",
      });
    }
  }
  // Account fan-out heuristic: many writable accounts loop = compute pressure.
  const writableCount = ix.accounts.filter(
    (a) => a.writable && !isProgramLike(a),
  ).length;
  if (writableCount >= 8) {
    findings.push({
      lane: "I-dos-compute",
      severity: "info",
      confidence: "tentative",
      instruction: ix.name,
      account: null,
      title: "High writable-account fan-out",
      detail:
        `Instruction \`${ix.name}\` writes ${writableCount} non-program accounts. Wide fan-out ` +
        `often implies per-account loops that can hit the compute budget at scale.`,
      recommendation:
        "Confirm per-account work is bounded and cannot be amplified by an attacker.",
    });
  }
  return findings;
}

const LANES: ((ix: NormalizedInstruction) => RawFinding[])[] = [
  laneAuthority,
  laneAccountSubstitution,
  laneTokenCustody,
  laneEconomic,
  laneReferral,
  laneUpgradeAdmin,
  laneCpiProgram,
  laneInitSafety,
  laneDosCompute,
];

/**
 * Cross-instruction correlation (whole-IDL pass).
 *
 * Per-instruction lanes cannot see that the *same* account name is a checked PDA
 * in one instruction but an unbound writable in another. That inconsistency is a
 * strong, low-noise signal: the developer clearly knows how to bind the account,
 * so the unbound site is likely the real bug (account substitution / state
 * confusion). This catches seams the per-instruction view structurally misses.
 */
function correlateAccounts(idl: NormalizedIdl): RawFinding[] {
  interface Site {
    instruction: string;
    bound: boolean;
    writable: boolean;
  }
  const byName = new Map<string, Site[]>();
  for (const ix of idl.instructions) {
    for (const acc of ix.accounts) {
      if (isProgramLike(acc)) continue;
      const bound = hasSeeds(acc) || acc.hasAddress || acc.relations.length > 0;
      const sites = byName.get(acc.name) ?? [];
      sites.push({ instruction: ix.name, bound, writable: acc.writable });
      byName.set(acc.name, sites);
    }
  }

  const findings: RawFinding[] = [];
  for (const [name, sites] of byName) {
    const boundSites = sites.filter((s) => s.bound);
    const unboundWritable = sites.filter((s) => !s.bound && s.writable);
    if (boundSites.length > 0 && unboundWritable.length > 0) {
      for (const site of unboundWritable) {
        findings.push({
          lane: "X-correlation",
          severity: "high",
          confidence: "likely",
          instruction: site.instruction,
          account: name,
          title: "Account is PDA/relation-bound elsewhere but unbound here",
          detail:
            `Account \`${name}\` is constrained (PDA seeds / pinned address / relations) in ` +
            `[${boundSites.map((s) => `\`${s.instruction}\``).join(", ")}] but is a writable, ` +
            `unbound account in \`${site.instruction}\`. The inconsistent constraint strongly ` +
            `suggests a missing check at the unbound site.`,
          recommendation:
            "Apply the same binding used in the constrained instructions (seeds+bump or " +
            "`has_one`/`address`) to this site, then test wrong-account substitution.",
        });
      }
    }
  }
  return findings;
}

export function analyzeInstruction(ix: NormalizedInstruction): Finding[] {
  return LANES.flatMap((lane) => lane(ix)).map(finalize);
}

function buildMatrix(idl: NormalizedIdl): MatrixRow[] {
  const rows: MatrixRow[] = [];
  for (const ix of idl.instructions) {
    for (const acc of ix.accounts) {
      rows.push({
        instruction: ix.name,
        account: acc.name,
        signer: acc.signer,
        writable: acc.writable,
        seeds: seedSummary(acc),
        pinnedAddress: acc.hasAddress,
        relations: acc.relations.join(", "),
      });
    }
  }
  return rows;
}

function emptyLaneCounts(): Record<Lane, number> {
  return {
    "A-authority": 0,
    "B-account-substitution": 0,
    "C-token-custody": 0,
    "D-economic": 0,
    "E-referral": 0,
    "F-upgrade-admin": 0,
    "G-cpi-program": 0,
    "H-init-safety": 0,
    "I-dos-compute": 0,
    "X-correlation": 0,
  };
}

export function analyzeIdl(idl: NormalizedIdl): AnalysisResult {
  logger.info(`Starting deep static IDL analysis for program: ${idl.name}`);
  const startTime = Date.now();
  
  const perInstruction = idl.instructions.flatMap(analyzeInstruction);
  const correlated = correlateAccounts(idl).map(finalize);
  const findings = [...perInstruction, ...correlated];

  const severityCounts = SEVERITY_ORDER.reduce(
    (acc, s) => ({ ...acc, [s]: 0 }),
    {} as Record<Severity, number>,
  );
  const laneCounts = emptyLaneCounts();
  for (const f of findings) {
    severityCounts[f.severity] += 1;
    laneCounts[f.lane] += 1;
  }

  // Rank by composite risk (severity × confidence) first, then severity, then
  // instruction name for a stable, readable order.
  const sorted = [...findings].sort(
    (a, b) =>
      b.risk - a.risk ||
      SEVERITY_INDEX[a.severity] - SEVERITY_INDEX[b.severity] ||
      a.instruction.localeCompare(b.instruction),
  );

  const maxRisk = findings.reduce((m, f) => Math.max(m, f.risk), 0);

  const duration = Date.now() - startTime;
  logger.info(`Completed IDL analysis for ${idl.name} in ${duration}ms. Findings: ${findings.length}`);

  return {
    program: idl.name,
    address: idl.address,
    instructionCount: idl.instructions.length,
    findings: sorted,
    matrix: buildMatrix(idl),
    severityCounts,
    laneCounts,
    maxRisk,
  };
}

/**
 * Baseline suppression: drop findings whose stable id appears in `baselineIds`.
 * Lets a team accept reviewed-but-not-yet-fixed candidates so CI only surfaces
 * *new* seams on subsequent runs. Returns the kept findings plus how many were
 * suppressed.
 */
export function applyBaseline(
  findings: Finding[],
  baselineIds: Iterable<string>,
): { kept: Finding[]; suppressed: number } {
  const baseline = new Set(baselineIds);
  const kept = findings.filter((f) => !baseline.has(f.id));
  return { kept, suppressed: findings.length - kept.length };
}

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(severity);
}

export { SEVERITY_ORDER, SEVERITY_WEIGHT, CONFIDENCE_WEIGHT };
