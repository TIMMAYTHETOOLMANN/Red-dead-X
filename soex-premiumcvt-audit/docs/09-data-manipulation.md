# Stage 2: Data Manipulation & Forensic Data Transformation

This stage expands the system's forensic reach by embedding structured data tools (diff, schema, normalization, regex, and ID validation) into the inventory and analysis flow.

## 1. Structured Tool Inventory for Data Forensics

| Tool | Typical Use Case | Attack Surface Pitfall |
|---|---|---|
| CSV/JSON Escaper | Normalize event/ABI output | Malformed fields, double-encoding, log injection |
| JSON Path | Deep-scan contract/tx outputs | Overlooked roles/privilege, config drift |
| JSON Schema | Validate on-chain/state objects | Type confusion, missing/extra fields, overbroad mutability |
| Diff/Text Diff | Compare config/ABI/metadata | Undetected upgrade, role drift, infinite-supply flips |
| Sorting/Filter | Normalize inventories | Set overlap or order-based privilege errors |
| Regex | Extract secrets/roles/IDs | Credential/role leaks, non-unique IDs |
| UUID/ULID/ID Tools | ID lineage, uniqueness checks | ID collision, mistaken trust links |

## 2. Agent Configuration & Checklist

- **Normalize all contract and event outputs:** Strip encodings, catch log injection or mishandling with escapers.
- **Schema-validate each object (state, ABI, event):** Flag missing fields or type errors.
- **Path extraction:** Use JSON Path to pull authorities, roles, token lists, upgrades from any structured data.
- **Diff configs:** Compare contract fields/roles/pre/post-upgrade and flag drift.
- **Regex:** Grep for patterns like `/admin|owner|priv|secret|upgrad|0x[0-9a-f]{40}/i`, or GUIDs.
- **Sort:** Sort each output set for easier set comparison and SARIF/MD reporting.

## 3. Implementation

See `scripts/lib/data.ts` and `scripts/data_analyzer.ts` for the implementation.
