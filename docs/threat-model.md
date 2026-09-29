# Threat model

Scope: a shared cloud host running Bayora's red team, blue team and client LLM at the same time.
Each control below links to the code that implements it and the test or drill check that demonstrates it.

## Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| Red payload sets | Seen early by blue → defenses overfit to the test | Red vault (tenant key), sealed records (trial DEK) |
| Blue defense bundles, classifier config | Inferred by red → attacks tailored to one filter | Blue state, sealed in Authority, loaded into the enclave |
| Model weights and state | Contamination makes later results meaningless | Model zone (digest-pinned, read-only) |
| Trial results | The deliverable | Sealed records → revealed at REVEAL |
| Ledger signing key, KEK, token secret | Forge history / read sealed data | Authority volume only |

## Adversaries

| ID | Adversary | Assumed capability |
|---|---|---|
| A1 | Malicious or curious **red** tenant | Full control of its own container; any input; measures timing and size of every response |
| A2 | Malicious or curious **blue** tenant | Full control of its workbench; authors the enclave bundle (which sees red inputs) |
| A3 | **Contaminating input** | Test cases crafted to leave state in the model environment |
| A4 | **Log tamperer** | Write access to ledger storage or an export, but not the signing key |
| A5 | **Platform operator** | Root on the host. Out of scope for full protection (see residual risk RR3) |

## Trust boundaries

Six zones: red, blue, Trial Authority, sealed enclave, model clean room, observability. Each has its own
internal Docker network, its own CA, its own cpuset and its own volumes. The Arbiter is the only component
attached to more than one zone, and each of its listeners binds to a single network and trusts a single CA.
The allowed-flow matrix in [`ARCHITECTURE.md`](../ARCHITECTURE.md) is the contract; `drill/flow_matrix.json`
is its machine-readable form, and the breach drill tests every cell.

## STRIDE with evidence

| Threat | Example | Control | Evidence |
|---|---|---|---|
| **S**poofing | Blue presents itself at the red door | Per-zone CAs; each listener pins exactly one client CA | `tests/test_mtls.py::test_blue_cert_is_rejected_by_red_listener`; drill `mtls.allow.*`, `mtls.deny.model-admin` |
| **S**poofing | A tenant claims another role in the request body | Role comes from the listener, never the request; red's app has no bundle route, blue's has no case route | `tests/test_e2e.py::test_role_separation_and_state_policy` |
| **T**ampering | Edit a verdict after the fact | Hash chain + Ed25519-signed Merkle checkpoints | `test_ledger_detects_modified_event`, `test_verifier_catches_tampering_everywhere`, tamper demo |
| **T**ampering | Swap the defense bundle mid-trial | Blue commitment + enclave reports the loaded bundle hash at ARM; reveal checks it | `authority/service.py::arm`, `reveal` |
| **R**epudiation | "We never submitted that bundle" | Commitments in the ledger before anything runs | verifier `commitment opens (blue)` |
| **R**epudiation | Red adds cases mid-trial and denies it | Static mode: every submitted case must be in the committed set | `test_cases_outside_committed_set_invalidate` |
| **I**nfo disclosure (direct) | Blue reads red's cases while RUNNING | Network isolation; ABAC deny `D01`; sealed records; exhaustive invariant `I1` | `test_policy_invariants_hold_exhaustively`, drill `net.deny.*` |
| **I**nfo disclosure (audit channel) | Blue hashes public AdvBench prompts and looks them up in the ledger | Ledger stores **per-trial salted** hashes; salt sealed until REVEAL; tenants cannot read the ledger before REVEAL (`D03`) | `common/crypto.py::salted_hash`; `test_full_trial_happy_path` asserts no plaintext in the ledger |
| **I**nfo disclosure (monitoring channel) | Observability stream carries payloads | Telemetry schema is closed: enums, bounded numbers and digests only; unknown fields rejected | `test_telemetry_schema_rejects_plaintext`, drill `logical.telemetry_no_plaintext` |
| **I**nfo disclosure (side channel) | Red infers which layer refused from latency or size | Equalizer: canonical refusal, size buckets over the *entire* body, time buckets | `bench/leakage.py`: 100% → 50.0% (CI 44.6–55.4%); e2e asserts identical refusal sizes |
| **I**nfo disclosure (prompt leak) | Model echoes blue's system prompt to red | Blue's canary lives in the system prompt; outbound DLP withholds the response (`LEAK_CONTAINED`) | e2e `leaks_contained >= 1` |
| **I**nfo disclosure (enclave exfil) | Blue's bundle tries to send what it sees back to blue | Bundles are declarative data (no code); fixed output schema; reason codes whitelisted and pattern-bound; enclave has no route to blue | `zones/enclave/bundle.py`, `test_bundle_validation_rejects` |
| **I**nfo disclosure (isolation already broken) | Red holds blue's secret | Blue canary arriving *from* red → critical alert → INVALIDATED | `test_real_foreign_canary_from_red_invalidates`, canary drill |
| **D**enial / fairness | One tenant starves the model | cpusets, memory, pids limits; per-trial case budget; rate anomaly alerts | `docker-compose.yml`, `AnomalyDetector` |
| **E**levation | Container escape | gVisor (default), seccomp allowlist minus 37 syscalls, cap_drop ALL, no-new-privileges, read-only rootfs, non-root, no runtime socket | drill `process.*` checks |

## LLM-native threats

| Threat | Control | Evidence |
|---|---|---|
| Shared KV / prefix-cache timing across sessions | Cache scoped per trial and session; llama.cpp backend runs with `cache_prompt=false`; reset per trial | `bench/kvcache.py`: 100% → 45%; `test_stub_is_deterministic_and_cache_is_session_scoped` |
| Prompt-context leakage across sessions | Stateless sessions namespaced `trial/role.session`; fresh sessions for purity probes | `zones/model/app.py` |
| Cross-session contamination | Purity fingerprint F_pre/F_post; drift → INVALIDATED | `test_purity_drift_invalidates`, contamination scenario |
| Model-output isolation | Output reaches only the Arbiter; red gets the equalized view; blue gets nothing until REVEAL | `authority/service.py::submit_case` |
| Inference-time exfiltration | Model and enclave zones have no egress; tools disabled; outbound canary DLP | drill `net.deny.internet`, `net.deny.cloud-metadata` |
| Swapped or poisoned weights | Digest pinned at registration, re-checked at ARM, verified on replay | `DigestMismatch`, verifier `model digest pinned` |
| Judge manipulation | Judge runs in the Authority; red never self-grades | `authority/judge.py` |
