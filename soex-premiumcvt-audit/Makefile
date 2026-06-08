SHELL := /bin/bash

.PHONY: verify safe-config inventory program-info analyze-idl invariant-sim poc test typecheck validator notes evm-recon surface-map forensic-scan dotnet-build

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

# Offline unified forensic report from local IDL_PATH and/or EVM_ABI_PATH.
forensic-scan:
	npm run forensic-scan

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
