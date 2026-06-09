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
 * Mocks identifying if an address is an EOA vs Multisig/Contract.
 * In production, this would query the chain (e.g. eth_getCode == '0x').
 */
export function isEOAMock(address: string): boolean {
  // Mock logic: 0xEOA... -> true, 0xMULTI... -> false
  if (address.toLowerCase().includes('eoa')) return true;
  if (address.toLowerCase().includes('multi')) return false;
  // Default to EOA for worst-case scanning
  return true;
}

/**
 * Scans an object (representing contract state/config) for known authority fields.
 */
export function scanAuthorities(contractName: string, state: Record<string, any>): AuthorityFinding[] {
  const findings: AuthorityFinding[] = [];

  for (const field of ADMIN_ANALYSIS_CONFIG.authorityFields) {
    if (state[field]) {
      const value = state[field].toString();
      const isEOA = isEOAMock(value);
      
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
