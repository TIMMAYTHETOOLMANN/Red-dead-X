# Stage 4: Administrator/Authority Lane

This stage focuses on extracting and auditing administrative configurations, permissions, and upgradeability patterns to identify central points of failure, rug-pull risks, or overlooked legacy privileges.

## 1. Structured Tool Inventory

| Tool | Typical Use Case | Attack Surface Pitfall |
|---|---|---|
| Authority scanner | Identify admin/owner fields | Single-sig wallets holding upgrade keys |
| Upgrade-priv detection | Map upgradeability patterns | Silent upgrade capability allowing logic subversion |
| ACL mapping | Matrix of roles vs actions | Missing roles, overlap, legacy deployer access |

## 2. Core Configuration

See `scripts/lib/admin.ts` for the implementation:
- `authorityFields`: Known fields like `upgradeAuthority`, `owner`, `admin`, `pauser`.
- `privilegeActions`: Actions mapped against roles (`upgrade`, `mint`, `pause`, `emergencyWithdraw`).
- `requiredChecks`: Policies to enforce (e.g. `immutability`, `multi-sig`).

## 3. Agent Execution Method

- **Extract:** Extract all upgrader, admin, and critical authority fields from state or ABI.
- **Analyze:** Check if roles are hardcoded or upgradeable. Enumerate downstream risks if a role is compromised.
- **Flag:** Flag any single-sig (EOA) authority on high-value contracts. 

### Examples of Risks:
- An ERC20 token where `upgradeAuthority` is set to an EOA instead of a multisig/timelock.
- A deployer address that retains the `pause()` capability after supposedly handing off control to governance.
