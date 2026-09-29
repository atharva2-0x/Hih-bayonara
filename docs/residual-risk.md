# Residual risk

What DOUBLE-BLIND does **not** protect against, when its guarantees fail, and what would close each gap.
Likelihood 1–3 × impact 1–4 (the War Room radar plots the same numbers).

## Register

| # | Residual risk | L | I | Why it remains | Mitigation path |
|---|---|---|---|---|---|
| RR1 | Microarchitectural side channels (cache, SMT) between zones on shared physical cores | 1 | 3 | cpusets pin vCPUs, but on a cloud VM two vCPUs may share a physical core | Dedicated hosts, SMT off, core scheduling |
| RR2 | Host kernel or gVisor vulnerability | 1 | 4 | Every sandbox has a trusted computing base | MicroVMs (Firecracker / Kata) per zone, patch SLAs, NVD feed monitoring |
| RR3 | Malicious platform operator with root | 2 | 4 | The Arbiter sees plaintext by design; its keys are on the host | Confidential VMs (SEV-SNP / TDX) with remote attestation; split-key custody for the KEK |
| RR4 | Covert channels below bucket resolution | 1 | 2 | Buckets reduce leakage to what we measure as chance, but cannot prove zero for every channel | Coarser buckets, randomized scheduling, per-trial query budgets |
| RR5 | Statistical inference of blue's logic across many trials | 2 | 2 | Red must learn answered vs refused to function | Query budgets, defense rotation, privacy-preserving aggregate reporting |
| RR6 | Judge error | 2 | 2 | The PoC judge is a transparent refusal heuristic | Classifier ensemble + human review queue |
| RR7 | Signing key theft | 1 | 3 | Key file on the Authority volume | HSM/KMS-held key; public anchoring (Sigstore Rekor) so a stolen key cannot rewrite anchored history |
| RR8 | GPU memory residue between tenants | 2 | 3 | The PoC is CPU-only, so this is not exercised | MIG partitioning, memory scrubbing between trials |

## Found while building (not hypothetical)

| Finding | Status |
|---|---|
| The response body's `case_no` field has variable width, which leaked a byte of size | **Fixed**: the Equalizer now pads the whole body; the e2e test asserts identical refusal sizes |
| An empty directory from the shared image looked like a foreign mount to the drill | **Fixed**: the drill checks mount points, not paths |
| gVisor is not installable on the development host | **Recorded**: `process.gvisor_sandbox` fails in every zone, is an explicit accepted risk, and appears in the ledger and the verifier output |
| Ledger event timestamps are precise | **Accepted**: tenants cannot read the ledger before REVEAL (`D03`, invariant `I3`); auditors can |
| The overhead benchmark first compared different workloads (bare call without the system prompt) | **Fixed**: all setups now use the identical bundle |
| Trial state (not the ledger) lives in Arbiter memory: restarting the Arbiter loses in-flight trials, while the ledger and its signed checkpoints persist and keep verifying | **Open**: persist trial state (sealed) alongside the ledger |

## Guarantee break conditions

The guarantees **do not hold** if any of these is true:

- the host kernel, gVisor or the container runtime is compromised (RR2)
- the platform operator is malicious (RR3)
- the Authority signing key or KEK leaks (RR7)
- zones share physical cores with SMT on a hostile host (RR1)
- `bucket_ms` is set below the model's latency tail, so slow answers spill into later buckets and the spill itself becomes a signal (the Equalizer reports `spilled` per case)
- someone edits `docker-compose.yml` to attach a zone to another zone's network, and **also** skips the breach drill (arming refuses a failed or stale drill report)
- the trial runs in `local-sim` profile (the verifier warns: isolation is not enforced)
- red uses **adaptive** mode: the committed-set membership check is skipped by design (red commits to a strategy, not a fixed set)

## Not built (plan items deferred)

| Plan item | Status |
|---|---|
| Kubernetes profile (kind + Cilium + RuntimeClass gVisor), H7 | not built; the flow matrix and drill are runtime-agnostic |
| Sigstore Rekor anchoring, C6 | not built; the checkpoint format is ready to anchor |
| Rootless Docker/Podman setup, A10 | not built; documented as a deployment choice |
| Role-scoped War Room views for tenants, G8 | tenants use their report endpoints instead |
| Falco rules | written (`infra/falco/`) but Falco was not available to validate them here |
| Real llama.cpp model | backend implemented and tested against a fake llama.cpp API; not run against a real model here (no model download available) |
