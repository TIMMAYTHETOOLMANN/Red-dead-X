SHELL := /bin/bash

.PHONY: verify safe-config inventory program-info analyze-idl invariant-sim poc test typecheck validator notes evm-recon surface-map registry-doctor forensic-scan encoding-analyze data-analyze admin-analyze economic-analyze dotnet-build

verify:
	rustc --version
	solana --version
	anchor --version
	node --version
	yarn --version

safe-config:
	solana config set --url devnet
	solana config get

inventory:
	npm run inventory

program-info:
	npm run program-info

analyze-idl:
	npm run analyze-idl

invariant-sim:
	npm run invariant-sim

# Guardrailed PoC harness. Simulates by default; sending requires
# EXECUTE=true ALLOW_TX=true and CLUSTER in {localnet,devnet}.
# Usage: make poc POC_PLAN=path/to/plan.json
poc:
	npm run poc

test:
	npm test

# --- Multi-chain forensics (BugRap ecosystem) ------------------------------

# Map every in-scope (chain x bounty-class) cell. Set BUGRAP_PROGRAM to scope.
surface-map:
	npm run surface-map

# Registry readiness: report armed (addresses pinned) vs shell (placeholders) programs.
registry-doctor:
	npm run registry-doctor

# Offline unified forensic report from local IDL_PATH and/or EVM_ABI_PATH.
# Optionally fold encoding/data/admin/economic evidence in via AUX_INPUT_PATH.
forensic-scan:
	npm run forensic-scan

# Stage 1/2/3/4 analyzers. Each reads a real *_INPUT_PATH JSON file (or a
# sample fixture when unset) and writes a unified JSON+SARIF+Markdown brief.
encoding-analyze:
	npm run encoding-analyze

data-analyze:
	npm run data-analyze

admin-analyze:
	npm run admin-analyze

economic-analyze:
	npm run economic-analyze

# thirdweb v5 read-only EVM recon. Requires THIRDWEB_SECRET_KEY/CLIENT_ID,
# EVM_CHAIN, EVM_ADDRESS. Read-only — never sends a transaction.
evm-recon:
	npm run evm-recon

# Build the thirdweb .NET read-only recon tool.
dotnet-build:
	cd dotnet/ThirdwebForensics && dotnet build -c Release

typecheck:
	npm run typecheck

validator:
	solana-test-validator --reset

notes:
	mkdir -p notes findings evidence reports tests targets
	date -u +"%Y-%m-%dT%H:%M:%SZ" > notes/session-start.txt
