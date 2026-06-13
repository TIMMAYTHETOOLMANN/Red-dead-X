/**
 * Administrator/Authority Lane Configuration & Tooling
 */

export const ADMIN_ANALYSIS_CONFIG = {
  authorityFields: ["upgradeAuthority", "owner", "admin", "pauser", "manager", "governance"],
  privilegeActions: ["upgrade", "mint", "pause", "emergencyWithdraw", "blacklist", "setFee"],
  requiredChecks: ["immutability", "multi-sig"],
};

export interface AuthorityFinding {
  contract: string;
  field: string;
  value: string;
  isEOA: boolean; // True if it's an externally owned account / single sig
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
}

export interface PrivilegeFinding {
  contract: string;
  action: string;
  roleRequired: string;
  description: string;
}

/**
 * Classifies an address as an EOA (single-sig / externally-owned account) vs a
 * contract/multisig.
 *
 * PLACEHOLDER HEURISTIC: with no chain access this can only guess from the
 * address label (the substrings "eoa"/"multi"). It is **not** an on-chain
 * `getCode`/threshold check and must not be trusted as evidence. Provide real
 * data via {@link AuthorityClassification} (`knownMultisigs`/`knownContracts`)
 * to override the guess; live recon (thirdweb `getCode`) should supply those
 * sets. When nothing is known it defaults to EOA so the worst case is surfaced
 * for manual confirmation rather than silently cleared.
 */
export function isLikelyEOA(address: string, opts: AuthorityClassification = {}): boolean {
  const addr = address.trim().toLowerCase();
  const known = (list?: string[]) => (list ?? []).map((a) => a.trim().toLowerCase());
  // Real, operator-supplied facts win over the heuristic.
  if (known(opts.knownMultisigs).includes(addr)) return false;
  if (known(opts.knownContracts).includes(addr)) return false;
  if (known(opts.knownEoas).includes(addr)) return true;
  // Heuristic fallback (placeholder only — see doc comment).
  if (addr.includes("eoa")) return true;
  if (addr.includes("multi")) return false;
  // Default to EOA for worst-case scanning.
  return true;
}

/**
 * Backwards-compatible alias for {@link isLikelyEOA}. Retained so existing
 * callers keep working; prefer `isLikelyEOA` (and pass real classification data).
 * @deprecated Use {@link isLikelyEOA} with a {@link AuthorityClassification}.
 */
export function isEOAMock(address: string): boolean {
  return isLikelyEOA(address);
}

/** Operator-supplied authority classification facts (override the heuristic). */
export interface AuthorityClassification {
  /** Addresses known to be multisigs (treated as not-EOA). */
  knownMultisigs?: string[];
  /** Addresses known to be contracts (treated as not-EOA). */
  knownContracts?: string[];
  /** Addresses known to be single-sig EOAs (treated as EOA). */
  knownEoas?: string[];
}

/**
 * Scans an object (representing contract state/config) for known authority fields.
 */
export function scanAuthorities(
  contractName: string,
  state: Record<string, any>,
  opts: AuthorityClassification = {},
): AuthorityFinding[] {
  const findings: AuthorityFinding[] = [];

  for (const field of ADMIN_ANALYSIS_CONFIG.authorityFields) {
    if (state[field]) {
      const value = state[field].toString();
      const isEOA = isLikelyEOA(value, opts);
      
      let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
      let description = `Authority field '${field}' found.`;

      if (isEOA) {
        riskLevel = field.toLowerCase().includes('upgrade') ? 'CRITICAL' : 'HIGH';
        description = `Authority field '${field}' is controlled by a single-sig/EOA (${value}). Risk of rug/compromise.`;
      } else {
        description = `Authority field '${field}' is controlled by a multisig/contract (${value}).`;
      }

      findings.push({
        contract: contractName,
        field,
        value,
        isEOA,
        riskLevel,
        description
      });
    }
  }

  return findings;
}

/**
 * Checks an ABI for privileged actions and what roles they map to
 */
export function scanPrivilegeActions(contractName: string, abiFunctions: { name: string, modifiers?: string[] }[]): PrivilegeFinding[] {
  const findings: PrivilegeFinding[] = [];

  for (const func of abiFunctions) {
    const isPrivileged = ADMIN_ANALYSIS_CONFIG.privilegeActions.some(action => func.name.toLowerCase().includes(action.toLowerCase()));
    
    if (isPrivileged) {
      const modifiers = func.modifiers || [];
      const hasAuthModifier = modifiers.some(m => m.toLowerCase().includes('only') || m.toLowerCase().includes('require'));
      
      findings.push({
        contract: contractName,
        action: func.name,
        roleRequired: hasAuthModifier ? modifiers.join(", ") : "NONE",
        description: hasAuthModifier 
          ? `Privileged action '${func.name}' is guarded by: ${modifiers.join(", ")}`
          : `CRITICAL: Privileged action '${func.name}' appears to lack role modifiers!`
      });
    }
  }

  return findings;
}
