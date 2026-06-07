SHELL := /bin/bash

.PHONY: verify safe-config inventory program-info analyze-idl invariant-sim poc test typecheck validator notes

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

typecheck:
	npm run typecheck

validator:
	solana-test-validator --reset

notes:
	mkdir -p notes findings evidence reports tests targets
	date -u +"%Y-%m-%dT%H:%M:%SZ" > notes/session-start.txt
