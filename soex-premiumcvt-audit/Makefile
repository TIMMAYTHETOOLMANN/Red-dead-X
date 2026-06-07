SHELL := /bin/bash

.PHONY: verify safe-config inventory validator notes

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

validator:
	solana-test-validator --reset

notes:
	mkdir -p notes findings evidence reports tests targets
	date -u +"%Y-%m-%dT%H:%M:%SZ" > notes/session-start.txt
