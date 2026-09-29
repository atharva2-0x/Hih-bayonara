# DOUBLE-BLIND: common tasks.  `make help`
PY ?= .venv/bin/python
-include .env
export

.PHONY: help setup test demo serve bench policy env certs wheels build up drill docker-trial down logs verify tamper

help:
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[1m%-13s\033[0m %s\n", $$1, $$2}'

setup: ## create .venv and install dependencies
	python3 -m venv .venv && $(PY) -m pip install -q -r requirements.txt pytest

test: ## run the test suite
	$(PY) -m pytest -q

demo: ## terminal demo: standard, canary and contamination scenarios + verify + tamper
	$(PY) -m doubleblind demo --fresh --replay

serve: ## local simulation: site at http://127.0.0.1:8100, War Room at /warroom
	$(PY) -m doubleblind serve

bench: ## leakage / overhead / KV-cache benchmarks -> docs/results
	$(PY) -m doubleblind bench

policy: ## exhaustively check the policy invariants
	$(PY) -m doubleblind policy

env: ## detect Docker capabilities (gVisor, seccomp, CPUs) -> .env
	$(PY) scripts/gen_env.py

certs: ## generate the per-zone PKI -> infra/certs/out
	$(PY) -m doubleblind certs --out infra/certs/out

wheels: ## download dependency wheels for an offline, reproducible image build
	$(PY) -m pip download -q -r requirements.txt -d wheelhouse

build: wheels ## build the doubleblind:local image
	docker build --build-arg BASE_IMAGE=$${DB_BASE_IMAGE:-python:3.11-slim} -t doubleblind:local .

up: ## start authority, enclave, model and observability zones
	docker compose up -d arbiter enclave model obs

drill: ## run the breach-drill agent inside every zone
	for z in red blue enclave model observability; do docker compose --profile drill run --rm drill-$$z; done

docker-trial: ## full blinded trial through the isolated zones, then verify
	bash scripts/docker_trial.sh

down: ## stop everything and delete volumes
	docker compose --profile tenants --profile drill --profile llm down -v

logs:
	docker compose logs --tail=50

verify: ## verify an export: make verify EXPORT=exports/t-xxxx.json
	$(PY) -m doubleblind verify $(EXPORT) --replay stub

tamper: ## tamper with an export copy and show the verifier catching it
	$(PY) -m doubleblind tamper $(EXPORT) && $(PY) -m doubleblind verify $(EXPORT:.json=.tampered.json)
