SHELL := /bin/bash

.PHONY: verify safe-config inventory program-info validator notes

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

validator:
	solana-test-validator --reset

notes:
	mkdir -p notes findings evidence reports tests targets
	date -u +"%Y-%m-%dT%H:%M:%SZ" > notes/session-start.txt
