# DOUBLE-BLIND: Project Plan
### Hack in Hills '26 · Track 04 · *Securing Adversarial AI Safety Testing Infrastructure (Bayora)*

> **One-liner:** Other teams will put walls around containers. We run each red-team/blue-team evaluation as a
> **double-blind clinical trial**: pre-registered with cryptographic commitments, blinded by construction,
> watched by canaries, and replayable by anyone from a tamper-evident ledger.

Diagrams are in [`ARCHITECTURE.md`](./ARCHITECTURE.md).

![DOUBLE-BLIND architecture](docs/architecture.svg)

> ### Implementation status (2026-09-29)
> The PoC is built: every P0 and nearly every P1 in §11 is done. Status is marked per task below.
> **Verified** in real Docker zones on a standard VM: breach drill 113/118 with 8/8 positive controls (the 5
> failures are "no gVisor on this host", explicitly accepted and recorded), a blinded trial ATTESTED and
> verified offline with 34/34 bit-for-bit replay, and a canary drill invalidating its trial over the
> observability → Arbiter mTLS path.
> **Measured:** side-channel attacker 100% → 50.0% (chance), KV-cache observer 100% → 45% (chance), isolation
> +3.6 ms p50. See [`README.md`](./README.md), [`docs/results/`](docs/results/README.md) and
> [`docs/residual-risk.md`](docs/residual-risk.md) (including what is *not* built).

---

## 0. Table of contents
1. [Problem analysis](#1-problem-analysis)
2. [Our concept: why "double-blind"](#2-our-concept-why-double-blind)
3. [The wow factors (differentiators)](#3-the-wow-factors-differentiators)
4. [Architecture summary](#4-architecture-summary)
5. [Tech stack](#5-tech-stack)
6. [Coverage of judging objectives and verticals](#6-coverage-of-judging-objectives-and-verticals)
7. [Threat model and residual risk](#7-threat-model-and-residual-risk)
8. [Metrics we will show judges](#8-metrics-we-will-show-judges)
9. [Repository layout](#9-repository-layout)
10. [Team roles](#10-team-roles)
11. [Task breakdown (the backlog)](#11-task-breakdown-the-backlog)
12. [Timeline](#12-timeline)
13. [Demo script](#13-demo-script)
14. [Pitch deck outline](#14-pitch-deck-outline)
15. [Execution risks and cut lines](#15-execution-risks-and-cut-lines)
16. [Stretch goals](#16-stretch-goals)
17. [Pre-hackathon checklist](#17-pre-hackathon-checklist)

---

## 1. Problem analysis

### 1.1 What Bayora has today
- A red team runs adversarial test suites (jailbreak, prompt-injection and misuse benchmarks) against a client LLM.
- A blue team builds countermeasures such as input/output filters, classifiers and policies.
- **All three run in one shared Docker sandbox.**

### 1.2 Why that breaks the science
A safety finding is only valid if the experiment was **blind**:

| If this happens… | …then the finding is invalid because |
|---|---|
| Blue sees red payloads before the test ends | Blue can overfit defenses to the test ("teaching to the exam") |
| Red infers blue logic (from code, timing or response shape) | Red can tailor attacks to one filter, so results don't generalise |
| The client LLM keeps state between runs (cache, context, files) | Later results are contaminated by earlier ones |
| Noisy neighbours distort latency or resources | Timing becomes a side channel and benchmarks become noise |
| Logs can be edited | Nobody can independently trust or reproduce a finding |

### 1.3 The four hard requirements (from the brief)
1. **R1:** Red payloads are not observable by blue **before the test concludes**.
2. **R2:** Blue defensive logic is not exposed or **inferable** by red tooling.
3. **R3:** The client LLM stays **clean and uncontaminated**.
4. **R4:** Findings are **not invalidated** by leakage or cross-tenant interference.

### 1.4 Hidden insights most teams will miss
- **"Before a test concludes" means visibility depends on time and state.** A static ACL can't express it.
  You need a trial state machine plus policy that unlocks access at **REVEAL**.
- **"Inferable" goes beyond access control; it is about side channels.** Response latency and length can tell
  red whether a filter or the model refused. That has to be **equalized** and **measured**.
- **The blue defense has to see red inputs** to filter them, which looks like it contradicts R1. It doesn't if
  the defense runs inside a **sealed, platform-operated enclave** that blue *authors* but cannot *observe*.
- **"Monitoring without becoming a leakage channel"** means the observability plane handles metadata only
  (hashes, sizes, timings, verdict codes) and never plaintext.
- **"Independently reconstructed"** needs more than logs. It needs **deterministic replay** from pinned
  artifacts, checked by a verifier that does not trust the platform.

---

## 2. Our concept: why "double-blind"

We borrow the protocol medicine uses to make trial results trustworthy and map each piece to infrastructure:

| Clinical trial practice | DOUBLE-BLIND mechanism |
|---|---|
| **Pre-registration** of hypothesis and method | Red and blue submit **cryptographic commitments** `H(artifact ‖ nonce)` before the trial starts |
| **Blinding** of patients and investigators | **Zone isolation + Sealed Defense Enclave + Equalizer**: neither side can see or infer the other |
| **Sealed envelopes** | Artifacts are encrypted with per-tenant keys. Policy releases them only at **REVEAL** |
| **Clean control group** | **Ephemeral model clean room** with a **purity fingerprint** before and after |
| **Independent data monitoring committee** | **Observability zone + Canary Watcher**, able to **invalidate** a trial |
| **Public trial registry** | **Tamper-evident ledger** with signed Merkle checkpoints (optionally anchored publicly) |
| **Reproducibility / replication** | **Verifier CLI** replays the trial deterministically and checks every proof |

This framing gives judges an intuitive story and gives us a **principled checklist** in place of an ad-hoc pile of hardening.

---

## 3. The wow factors (differentiators)

Each is tagged by **visual impact** (for the demo) and **build effort**.

| # | Feature | What it does | Why it's different | Impact | Effort |
|---|---|---|---|---|---|
| W1 | **Commit-Reveal Pre-registration** | Red and blue commit hashes of payload sets and defense bundles. The Arbiter verifies them at reveal. | Gives *cryptographic proof* that neither side adapted to the other. Most teams only have ACLs. | ★★★ | Low |
| W2 | **Sealed Defense Enclave** | Blue's defense runs in a gVisor sandbox with no egress, read-only, and no logs back to blue. | Resolves the "defense must see inputs, blue must not" paradox | ★★ | Med |
| W3 | **Equalizer + Side-Channel Leakage Score** | Responses are released on fixed time and size buckets, and refusals are canonicalised. We *measure* leakage with an attacker classifier, before and after. | We **quantify** a side channel and show it drop to about chance level (≈50%) | ★★★ | Med |
| W4 | **Model Purity Fingerprint** | Deterministic golden-probe hash of model behaviour before and after each trial, plus a weight digest check | Proves R3 empirically, where others just assert it | ★★★ | Low |
| W5 | **Leakage Canaries** | Unique honeytokens sit in each tenant's vault. DLP at every boundary flags them, and a hit **auto-invalidates** the trial. | Isolation is *tested continuously*, not just claimed | ★★★ | Low |
| W6 | **Breach Drill → Isolation Certificate** | Automated negative tests for every forbidden cell in the flow matrix run before each trial. The result is hashed into the ledger. | Every finding carries a **certificate of isolation** | ★★ | Med |
| W7 | **Tamper-evident Ledger + Verifier CLI** | Hash-chained events, signed Merkle checkpoints and offline replay. We flip one byte on stage and it gets caught. | Independent reconstruction that is **live and visual** | ★★★ | Med |
| W8 | **War Room Dashboard** | Three live lanes (red, blue, model), a ledger ticker, canary lights, the isolation certificate and a residual-risk radar | Makes invisible security **visible** in a 5-minute demo | ★★★ | Med |
| W9 | **Residual Risk Register** | Scored threats, "guarantee break conditions" and a roadmap | Directly answers Objective 06, which most teams will treat lightly | ★★ | Low |

> **Safety-by-design bonus:** the War Room and all reports show **only IDs and hashes** of adversarial
> payloads, never plaintext. That is a leakage control, and it also keeps harmful text off the projector.

---

## 4. Architecture summary

*(Diagrams: [`ARCHITECTURE.md`](./ARCHITECTURE.md))*

| Zone | Components | Isolation mechanisms |
|---|---|---|
| **Trial Authority** (control plane) | Arbiter (state machine + sole broker), Equalizer, Policy Engine, Key Broker, Judge, Ledger | Only multi-homed service. mTLS. Signing key never leaves this zone. |
| **Red Zone** | Red Runner, Red Vault | `net-red` internal, gVisor, cpuset 2–3, encrypted vault (K_red), trial-scoped token |
| **Blue Zone** | Blue Workbench, Blue Vault | `net-blue` internal, cpuset 4–5, encrypted vault (K_blue), no data-plane access during RUNNING |
| **Sealed Defense Enclave** | Input Guard, Output Guard (blue's bundle) | gVisor, read-only rootfs, no egress, stdout/stderr to Authority only, bundle mounted read-only at ARM |
| **Model Clean Room** | Client LLM, Purity Fingerprint | New replica per trial, weights read-only and digest-pinned, KV cache per session and flushed, no network egress, tool-use disabled |
| **Observability** | Falco/Tetragon sensors, Canary Watcher + DLP, Anomaly Detector | Metadata only, push-only, can **invalidate** but never *read* plaintext |

**Data path for one test case:**
`Red → Arbiter → Enclave(input guard) → Model → Enclave(output guard) → Arbiter → Judge + Ledger → Equalizer → Red`

**Canonical response rule:** red receives either `ANSWERED + text` or `REFUSED (canonical)`. It cannot tell
whether the refusal came from the blue defense or from the model. The raw output stays sealed in the control plane until reveal.

**Adaptive red-teaming:** multi-turn and adaptive attacks are legitimate. In *adaptive mode*, red commits to its
**strategy/generator code + seed** instead of a static payload set, so the commitment still binds the behaviour.

---

## 5. Tech stack

| Concern | Choice (PoC) | Why | Alternative |
|---|---|---|---|
| Orchestration | Docker Compose (rootless) | Runs on any cloud VM or laptop; meets Objective 04 | kind/k3s + Helm (stretch) |
| Strong sandbox | **gVisor (`runsc`)** | User-space kernel; no special hardware | Kata / Firecracker (needs nested virt) |
| Syscall filtering | Custom **seccomp** JSON per zone, AppArmor | Least privilege | Landlock |
| Resource governance | **cgroups v2**: `cpuset`, `memory.max`, `pids.max`, `io.weight` | Fairness + reduces contention side channels | K8s Guaranteed QoS + static CPU manager |
| Network | Per-zone `internal: true` networks + **nftables** default-deny | Micro-segmentation | Cilium NetworkPolicy (eBPF) |
| Workload identity | mTLS with per-service certs (small internal CA, `step-ca` or `cfssl`) | SPIFFE-style identities | SPIRE |
| Policy / ABAC | **OPA (Rego)**, or **Cedar** | State-aware and time-aware rules | Casbin |
| Secrets / keys | **HashiCorp Vault** (dev mode) or `age` envelope encryption | Per-tenant keys, short-lived tokens | SOPS + KMS |
| Arbiter / API | **Python + FastAPI** (async) | Fast to build | Go |
| Ledger | SQLite/Postgres append-only table + SHA-256 hash chain + Merkle checkpoints + **Ed25519** signatures | Tamper evidence | Sigstore **Rekor** anchoring (stretch) |
| Model under test | **llama.cpp server** or Ollama running a small instruct model (≈0.5–1.5B, GGUF, CPU) | No GPU needed, deterministic at temp 0 | vLLM (GPU) |
| Blue defense (example bundle) | Rule layer + small safety classifier (e.g. Llama Guard 1B-class or a prompt-injection classifier) | Realistic defense to protect | Pure rules |
| Judge | Small safety classifier + refusal heuristics | Independent of red and blue | HarmBench-style classifier |
| Runtime detection | **Falco** or **Tetragon** (eBPF) | Detects cross-boundary syscalls, exec, file access | auditd |
| Metrics | Prometheus + Grafana (metadata only) | Standard | OpenTelemetry |
| War Room UI | **React/Next.js** or **Streamlit** + WebSocket feed | Live, visual | Svelte |
| Verifier | Python CLI (`dbverify`) | Offline, trusts nothing | Rust |

**Datasets (from the brief):** AdvBench, JailbreakBench, HarmBench, ToxiGen, the Lakera Gandalf dataset and Anthropic HH-RLHF.
They are imported **straight into the encrypted Red Vault as opaque records**. Only IDs and hashes appear anywhere else.
HH-RLHF benign prompts serve as **control prompts** for latency baselines and false-positive rates.

---

## 6. Coverage of judging objectives and verticals

### 6.1 Evaluation objectives → our answer

| Objective | Our answer | Evidence in demo |
|---|---|---|
| **01 Isolate without breaking function** | Zones + gVisor + cpusets. Equalizer buckets sized to model p95. | Overhead benchmark: baseline vs isolated p50/p95 |
| **02 Prevent information leakage** | Sealed enclave, canonical refusals, time/size equalization, canaries, DLP, metadata-only observability | Leakage Score drops from high to ≈50%. Canary drill caught. |
| **03 Guarantee audit integrity** | Hash chain + signed Merkle checkpoints + commit-reveal + verifier replay | Live tamper → verifier pinpoints the event |
| **04 Build for deployability** | One `docker compose up` on a stock VM. No special hardware. | Fresh-VM bring-up in the README |
| **05 Address LLM-native threats** | Per-session KV cache, no cross-tenant prefix reuse, ephemeral replicas, purity fingerprint, output isolation, egress-free inference | Purity fingerprint panel stays identical |
| **06 Quantify residual risk** | Scored risk register + guarantee break conditions + roadmap | Residual-risk radar + threat model doc |

### 6.2 Technical verticals → component

| Vertical | Component(s) |
|---|---|
| 1. Container & sandbox isolation | Rootless engine, gVisor, seccomp, cap_drop ALL, RO rootfs, userns |
| 2. Network segmentation | Per-zone internal nets, Arbiter-only broker, nftables, no egress, metadata-IP block |
| 3. Access control & secrets | ABAC (role × trial state × time), per-tenant keys, trial-scoped tokens |
| 4. Audit & forensic provenance | Ledger, Merkle checkpoints, Ed25519, commit-reveal, verifier, isolation certificate |
| 5. Resource governance & fairness | cgroups v2 cpusets/limits, Equalizer buckets, per-tenant query budgets |
| 6. LLM-specific threat surface | KV-cache scoping, context reset, output routing, purity fingerprint, canary DLP on outputs |
| 7. Observability & anomaly detection | eBPF sensors, canary watcher, anomaly detector, metadata-only push, role-scoped views |

---

## 7. Threat model and residual risk

### 7.1 Assets
Red payload sets · blue defense bundles and classifier weights · model weights and state · trial results ·
ledger signing key · tenant keys.

### 7.2 Adversaries
| ID | Adversary | Capability assumed |
|---|---|---|
| A1 | Curious/malicious **red** tenant | Full control of its own containers. Can send any test input. Can measure timing. |
| A2 | Curious/malicious **blue** tenant | Full control of its own workbench. Authors enclave code, which could try to smuggle data out. |
| A3 | **Contaminating input** | Test inputs that try to persist state in the model environment |
| A4 | **Log tamperer** | Write access to ledger storage but not the signing key |
| A5 | **Platform operator (insider)** | Root on host. **Out of scope** for full protection; see residual risks. |

### 7.3 STRIDE-style mapping (summary)
| Threat | Example | Control | Verified by |
|---|---|---|---|
| Spoofing | Red impersonates the Arbiter | mTLS workload identity | Breach drill |
| Tampering | Edit a result after the fact | Hash chain + signed checkpoints | Tamper demo + verifier |
| Repudiation | "We never submitted that defense" | Commitments in the ledger | Reveal verification |
| Info disclosure: direct | Blue reads red vault | Per-tenant keys + ABAC + network isolation | Breach drill + canaries |
| Info disclosure: side channel | Red infers the filter via latency/length | Equalizer + canonical refusals | Leakage Score |
| Info disclosure: enclave exfil | Blue bundle tries to phone home | No egress, gVisor, output schema = verdict only | Breach drill + DLP |
| DoS / fairness | One tenant starves others | cgroups cpusets/limits, query budgets | Load test |
| Elevation | Escape container to host | gVisor + seccomp + rootless + no caps | Config audit (e.g. docker-bench) |
| LLM contamination | State persists across sessions | Ephemeral replica + cache flush + fingerprint | Purity fingerprint |

### 7.4 Residual risk register (the honest part judges reward)
| # | Residual risk | Likelihood | Impact | Why it remains | Future mitigation |
|---|---|---|---|---|---|
| RR1 | Microarchitectural side channels on shared physical cores (cloud SMT) | Low | High | vCPU pinning ≠ physical core isolation on a shared host | Dedicated hosts, SMT off, confidential VMs |
| RR2 | Host kernel or gVisor vulnerability | Low | Critical | All sandboxes have a trusted computing base | MicroVMs (Firecracker/Kata), patch SLAs, CVE feed monitoring (NVD) |
| RR3 | Malicious platform operator with root | Med | Critical | The Arbiter is trusted by design | Confidential computing (SEV-SNP/TDX) + remote attestation, split-key custody |
| RR4 | Low-bandwidth covert channels below the bucket resolution | Low | Med | Buckets reduce leakage but don't eliminate it | Coarser buckets, randomized scheduling, query budgets |
| RR5 | Statistical inference of blue logic over many trials (aggregate outcomes) | Med | Med | Red has to see answered/refused to function | Per-trial query budgets, defense rotation, privacy-preserving aggregate reports |
| RR6 | Judge model error | Med | Med | Classifiers aren't perfect | Multi-judge ensemble + human review queue |
| RR7 | Signing key compromise | Low | High | Key lives on the host | HSM/KMS-backed keys, public anchoring (Rekor) |
| RR8 | GPU memory residue (if GPUs are used) | Med | High | PoC is CPU-only, so N/A for now | MIG partitioning, memory scrubbing between tenants |

### 7.5 Guarantee break conditions (explicit)
Our guarantees **do not hold** if: the host kernel is compromised · the operator is malicious · the signing key
leaks · tenants share physical cores with SMT on a hostile host · the Equalizer bucket is set below the model's
latency tail (a response then "spills" into a later bucket) · someone disables the breach drill.

---

## 8. Metrics we will show judges

| Metric | How measured | Target |
|---|---|---|
| **Isolation overhead** | p50/p95 latency on control prompts: bare Docker vs full DOUBLE-BLIND | Reported honestly, e.g. "<15% p50" |
| **Breach drill pass rate** | # forbidden flow-matrix cells tested and denied | 100% (N/N) |
| **Side-channel Leakage Score** | Train a simple classifier to tell *defense-refused* from *model-refused* using (latency, length). Run it with and without the Equalizer. | ≈50% (chance) with it, clearly higher without |
| **Canary detection latency** | Injected synthetic leak → alert → trial INVALIDATED | < 1 s |
| **Ledger tamper detection** | Mutate random bytes/events in N trials → verifier result | 100% detected, exact event located |
| **Purity stability** | F_pre == F_post across all trials | 100% |
| **Replay fidelity** | Verifier re-runs trial → identical output hashes (temp 0, fixed seed) | 100% on deterministic mode |

---

## 9. Repository layout

*As built. See [`README.md`](./README.md) for the quick start.*

```
Hih-bayonara/
├── plan.md · ARCHITECTURE.md · README.md
├── docker-compose.yml · Dockerfile · Makefile · pyproject.toml · requirements.txt
├── doubleblind/
│   ├── common/          crypto (commit-reveal, salted hashes, Ed25519, AES-GCM, tokens), Merkle, telemetry schema, mTLS
│   ├── authority/       Arbiter service + per-listener APIs, ledger, policy engine + policy.json,
│   │                    key broker, trial state machine, equalizer, judge
│   ├── zones/
│   │   ├── red/         encrypted vault, synthetic suite + benchmark importer, client
│   │   ├── blue/        bundle workbench (plants the canary), sample bundle, client
│   │   ├── enclave/     sealed declarative guards (input → model → output)
│   │   └── model/       stub + llama.cpp backends, per-session cache, purity fingerprint
│   ├── observability/   canary watcher, anomaly detector (metadata only)
│   ├── drill/           breach drill agents, flow_matrix.json, isolation certificates
│   ├── verifier/        dbverify: offline verification + deterministic replay
│   ├── bench/           leakage score, overhead, KV-cache isolation (+ small stats lib)
│   ├── deploy/          zone service runners, per-zone PKI, Docker-mode CLIs
│   ├── warroom/         dashboard (HTML/CSS/JS, no external dependencies)
│   ├── tools/tamper.py · local.py · demo.py · __main__.py
├── infra/
│   ├── seccomp/         derived allowlist profile + builder
│   ├── falco/           runtime rules for zone containers
│   └── firewall/        DOCKER-USER egress / metadata rules
├── scripts/             gen_env.py (host capability detection), docker_trial.sh
├── tests/               72 tests: unit, end-to-end trials, verifier, drill, live mTLS
└── docs/                architecture.svg, threat-model.md, residual-risk.md, results/, War Room screenshots
```

---

## 10. Team roles
*(Written for a team of 4. With 3, merge P3 into P2. With 5, split P1 into "runtime" and "network/identity".)*

| Role | Owns | Key deliverables |
|---|---|---|
| **P1: Isolation Engineer** | Compose topology, gVisor, seccomp, cgroups, networks, nftables, mTLS certs, breach drill | Zones up, flow matrix enforced, drill green |
| **P2: Platform Engineer** | Arbiter, state machine, policy engine, key broker, ledger, verifier | Trial lifecycle end-to-end, tamper demo |
| **P3: LLM/ML Engineer** | Model clean room, purity fingerprint, enclave bundle, judge, equalizer, leakage score, benchmarks | LLM-native controls + metrics |
| **P4: Experience Lead** | War Room UI, threat model docs, residual risk, pitch deck, demo script, backup video | A demo that lands |

---

## 11. Task breakdown (the backlog)

**Priority:** `P0` = MVP, must demo · `P1` = the wow factors · `P2` = stretch.
**Status:** `[ ]` todo · `[~]` partial · `[x]` done. *Updated after implementation, 2026-09-29.*

### Epic A: Foundation & topology (owner: P1)
| ID | Task | Pri | Done when |
|---|---|---|---|
| A1 | [x] Repo skeleton, Makefile targets (`up`, `down`, `drill`, `trial`, `verify`, `bench`, `demo`) | P0 | `make up` starts all services |
| A2 | [x] `docker-compose.yml` with 6 zones and one `internal: true` network per zone | P0 | `docker network inspect` shows isolation |
| A3 | [x] Arbiter is the only service attached to several networks | P0 | Flow matrix matches the ARCHITECTURE table |
| A4 | [~] Install gVisor; set `runtime: runsc` for red, enclave and model · *runsc is the compose default; the dev host has no gVisor, so runc + accepted risk `process.gvisor_sandbox` (recorded in the ledger)* | P0 | `dmesg` inside the container shows the gVisor banner |
| A5 | [x] Hardening baseline: `cap_drop: [ALL]`, `no-new-privileges`, `read_only: true`, tmpfs scratch, non-root user | P0 | Config audit passes (e.g. docker-bench-security) |
| A6 | [x] Per-zone seccomp allowlist profiles · *Docker default allowlist minus 37 syscalls: `infra/seccomp/`* | P1 | Services run; disallowed syscalls are denied |
| A7 | [~] cgroups v2 limits: `cpuset`, `mem_limit`, `pids_limit`, `blkio`/io weight per zone · *cpuset, memory, pids done; io weight not configured* | P0 | Limits are visible in `/sys/fs/cgroup` |
| A8 | [x] nftables default-deny, block cloud metadata IP, no internet egress from data-plane zones · *internal networks + `infra/firewall/docker-user.sh` (iptables DOCKER-USER)* | P1 | Drill cases for egress and metadata are denied |
| A9 | [x] Internal CA + per-service mTLS certs (scripted; no keys in git) · *one CA per zone; every listener pins exactly one client CA* | P1 | Arbiter rejects clients without certs |
| A10 | [ ] Rootless engine setup notes + script | P2 | Runs rootless on a fresh VM |

### Epic B: Trial Authority (owner: P2)
| ID | Task | Pri | Done when |
|---|---|---|---|
| B1 | [x] Arbiter FastAPI skeleton with endpoints: register, arm, submit-case, conclude, reveal, status | P0 | OpenAPI docs up |
| B2 | [x] Trial state machine (DRAFT→REGISTERED→ARMED→RUNNING→CONCLUDED→REVEALED→ATTESTED / INVALIDATED) | P0 | Illegal transitions are rejected; unit tests pass |
| B3 | [x] Brokered data path: Red → Enclave → Model → Enclave → Arbiter → Red | P0 | One test case completes end to end |
| B4 | [x] **Commit-reveal**: accept `H(artifact ‖ nonce)`, verify at reveal, INVALIDATE on mismatch | P1 (W1) | Mismatch demo → INVALIDATED |
| B5 | [x] Policy engine (OPA/Cedar): role × trial-state × resource rules, with policy unit tests · *own ABAC engine (`policy.json`) with *exhaustive* invariant checking instead of OPA/Cedar* | P0 | Blue→red-results is denied until REVEALED |
| B6 | [x] Key broker: per-tenant keys, envelope encryption for vaults, trial-scoped short-lived tokens | P1 | Tokens expire at CONCLUDE |
| B7 | [x] Judge service: scores outputs; red never self-grades | P0 | Score is stored per case |
| B8 | [~] Per-tenant query budgets + rate limits · *case budgets enforced; rate spikes are alerted, not throttled* | P1 | Budget exceeded → rejected + logged |
| B9 | [x] Findings report generator (per role, post-reveal) | P1 | JSON + Markdown report |

### Epic C: Ledger & verifier (owner: P2)
| ID | Task | Pri | Done when |
|---|---|---|---|
| C1 | [x] Append-only event store; each event holds `prev_hash`, `hash`, `ts`, `type`, payload hashes | P0 | Chain verifies |
| C2 | [x] Merkle checkpoint every N events + at state transitions; Ed25519 signature | P1 (W7) | Checkpoints validate with the public key |
| C3 | [x] `dbverify` CLI: verify chain, signatures, commitments, isolation certificate, fingerprints | P0 | Clean trial → ✅; tampered → ❌ with event index |
| C4 | [x] Deterministic replay: re-run revealed cases against the pinned model digest (temp 0, seed) and compare output hashes · *34/34 bit-for-bit* | P1 | Replay matches |
| C5 | [x] Tamper demo script (`make tamper`) that flips a byte | P1 | Verifier flags the exact event |
| C6 | [ ] Optional public anchor: post checkpoint root to Sigstore Rekor | P2 | Rekor entry UUID stored in ledger |

### Epic D: Model clean room & LLM-native controls (owner: P3)
| ID | Task | Pri | Done when |
|---|---|---|---|
| D1 | [~] Pick the model (≈0.5–1.5B instruct GGUF); pin the SHA-256 digest; mount weights read-only · *digest pinning implemented for stub and llama.cpp; no real GGUF downloadable on the dev host* | P0 | Digest is checked at startup |
| D2 | [x] llama.cpp/Ollama server in its own zone, no egress, tool-use disabled · *stub backend; llama.cpp backend tested against a fake llama.cpp API* | P0 | Responds via the Arbiter only |
| D3 | [~] Ephemeral replica per trial (spawn at ARM, destroy at CONCLUDE) · *reset + purity fingerprint per trial; container respawn per trial not automated* | P1 | New container ID per trial |
| D4 | [x] KV/prompt cache scoped to the session; no cross-tenant prefix reuse; flushed on session end | P0 | Config documented + tested |
| D5 | [x] **Purity Fingerprint**: golden probe set (benign) → hash of outputs at temp 0, taken pre and post | P1 (W4) | F_pre == F_post; mismatch → INVALIDATED |
| D6 | [x] Sample blue defense bundle (rules + small classifier) with a manifest format | P0 | Enclave loads the bundle |
| D7 | [x] Enclave runtime: gVisor, read-only bundle, output schema limited to `{verdict, reason_code}` · *bundles are declarative data, so no code runs in the enclave at all* | P0 (W2) | Bundle cannot open sockets or write outside tmpfs |
| D8 | [x] **Equalizer**: fixed release time buckets (set from p95), size padding/bucketing, canonical refusal | P1 (W3) | All refusals are byte-identical to red |
| D9 | [x] **Leakage Score experiment**: attacker classifier on (latency, length), with and without the Equalizer · *100% → 50.0% (95% CI 44.6–55.4%)* | P1 (W3) | Chart: e.g. 9x% → ~50% |
| D10 | [x] Dataset importer: benchmark sets → encrypted Red Vault as opaque records (IDs + hashes only outside) | P0 | UI shows no plaintext payloads |

### Epic E: Observability & canaries (owner: P1 + P3)
| ID | Task | Pri | Done when |
|---|---|---|---|
| E1 | [x] Canary generator: unique tokens planted in each vault + the enclave bundle | P1 (W5) | Registry of canaries per tenant |
| E2 | [x] DLP watcher at the Arbiter: scan every boundary crossing (hash-based matching, no plaintext storage) | P1 (W5) | Synthetic leak → alert < 1 s |
| E3 | [x] Canary hit → auto-INVALIDATE trial + ledger event | P1 | State flips live on the dashboard |
| E4 | [~] Falco/Tetragon rules: unexpected exec, network connect, sensitive file read per zone · *rules written in `infra/falco/`; Falco not available to validate on the dev host* | P1 | Alerts appear in the observability stream |
| E5 | [x] Metadata-only telemetry schema (no plaintext fields allowed; schema-enforced) | P0 | Schema validation rejects plaintext |
| E6 | [x] Anomaly detector: simple rules + z-score on per-tenant rates/latency | P2 | Alerts for abnormal probing rates |

### Epic F: Breach Drill (owner: P1)
| ID | Task | Pri | Done when |
|---|---|---|---|
| F1 | [x] Negative test for every ❌ cell in the flow matrix (network reachability between zones) | P0 (W6) | All denied |
| F2 | [x] Filesystem tests: no shared volumes, no access to other zones' mounts · *mount-point based* | P0 | All denied |
| F3 | [~] Process/namespace tests: other zones' processes are not visible · *per-container PID namespaces; no explicit drill check yet* | P1 | All denied |
| F4 | [x] Privilege tests: capabilities dropped, no-new-privileges set, rootfs read-only | P1 | All pass |
| F5 | [x] Egress & metadata-endpoint tests | P1 | All denied |
| F6 | [x] Drill output → signed **Isolation Certificate** → hash in ledger at ARM · *certificate hash in the ARMED event, covered by the signed checkpoint* | P1 | Certificate is shown on the dashboard |

### Epic G: War Room (owner: P4)
| ID | Task | Pri | Done when |
|---|---|---|---|
| G1 | [x] Layout: three lanes (Red / Model / Blue) + control strip | P0 | Static mock done |
| G2 | [x] Live WebSocket feed from the Arbiter (metadata only) | P0 | Cases animate across lanes |
| G3 | [x] Ledger ticker: scrolling hash chain, checkpoint badges | P1 | Ticks live |
| G4 | [x] Canary lights + isolation certificate panel + purity fingerprint panel | P1 | Turns red on drill |
| G5 | [x] Trial state timeline (the state-machine diagram lighting up) | P1 | Updates live |
| G6 | [x] Reveal Ceremony animation (commitments open → ✅ verified) | P1 | Wow moment |
| G7 | [x] Residual-risk radar + metrics panel (overhead, leakage score) | P1 | Numbers from `bench/` |
| G8 | [ ] Role-scoped views (red view, blue view, auditor view) | P2 | Each role sees only its data |

### Epic H: Measurement & docs (owner: P3 + P4)
| ID | Task | Pri | Done when |
|---|---|---|---|
| H1 | [x] Overhead benchmark: bare vs isolated (p50/p95/p99) on control prompts · *+3.6 ms (+5.8%) p50* | P0 | Table + chart |
| H2 | [x] `docs/threat-model.md` (assets, adversaries, STRIDE, trust boundaries) | P0 | Reviewed by the team |
| H3 | [x] `docs/residual-risk.md` (register + break conditions + roadmap) | P0 | Reviewed |
| H4 | [x] README quick start (fresh VM → demo in < 10 min) | P0 | A teammate follows it cold |
| H5 | [ ] Pitch deck (≤ 10 slides) · *team task* | P0 | Rehearsed |
| H6 | [ ] Backup demo video (in case of live failure) · *team task* | P0 | Recorded |
| H7 | [ ] K8s manifests (kind + Cilium + RuntimeClass gVisor) | P2 | `kubectl apply` works |

### Critical path (the MVP chain)
`A1 → A2 → A3 → A4 → B1 → B2 → D1/D2 → D6/D7 → B3 → C1 → C3 → F1 → G1/G2 → H1 → H4/H5`

**MVP definition (by 50% of hackathon time):** one trial runs end to end through isolated zones with a
hash-chained ledger, a verifier and a basic dashboard. Everything after that adds wow factors.

---

## 12. Timeline
*(Assumes a 36-hour event. Scale proportionally. Workstreams run in parallel; checkpoints are sync points.)*

| Window | P1 Isolation | P2 Platform | P3 LLM/ML | P4 Experience | Checkpoint |
|---|---|---|---|---|---|
| **H0–H2** | A1, A2 | B1 skeleton | D1 model pinned & running | G1 mock, deck skeleton | Kickoff; interfaces agreed (API + event schema) |
| **H2–H8** | A3, A4, A5, A7 | B2, B3 | D2, D4, D6, D10 | G2 feed stubbed | **CP1:** one case flows through Arbiter to the model |
| **H8–H14** | F1, F2, A9 | C1, C3, B5, B7 | D7 enclave | G2 live | **CP2 = MVP:** trial end to end + ledger + verifier |
| **H14–H20** | A6, A8, F3–F5 | B4 commit-reveal, C2 | D5 purity, D8 equalizer | G3, G5 | **CP3:** wow factors W1, W4, W8 working |
| **H20–H26** | E1–E4, F6 | B6, B8, C4, C5 | D9 leakage score, H1 bench | G4, G6, G7 | **CP4:** all P1s done; code freeze on new features |
| **H26–H30** | Hardening, fresh-VM test | Bug bash, B9 | Final metrics | H2, H3, H5 | **CP5:** feature freeze |
| **H30–H34** | Demo env lock | Demo data | Rehearse numbers | H6 video, rehearsals ×3 | **CP6:** full dress rehearsal |
| **H34–H36** | Buffer | Buffer | Buffer | Final polish | Submit |

**Rules we follow:** freeze interfaces at H2 · merge to `main` only when green · the demo machine is locked by H30 ·
never demo anything not rehearsed twice.

---

## 13. Demo script
*(5–6 minutes. Every beat maps to a judging objective.)*

1. **Hook (30 s):** "A drug trial where the doctors could read the patients' charts would be thrown out. That's
   what AI red-teaming looks like in a shared sandbox today." Show the three-lane War Room.
2. **Pre-registration (30 s) → Obj 03:** Red and blue submit commitments. Hashes land in the ledger.
3. **Arming (45 s) → Obj 01/02:** Breach drill runs live. Every forbidden cell turns ✅ *denied*. Isolation certificate
   issued. Purity fingerprint F_pre recorded.
4. **Blinded run (60 s) → Obj 01/05:** Test cases stream across the lanes as **IDs and hashes only**. Blue's lane shows
   "sealed". Red's lane shows canonical responses. Latency overhead number on screen.
5. **Side-channel proof (45 s) → Obj 02:** Toggle the Equalizer off: the attacker classifier distinguishes defense from
   model at high accuracy. Toggle on: ≈50%. *"We don't claim no leakage. We measure it."*
6. **Canary drill (30 s) → Obj 02/07:** Trigger a simulated leak of a blue canary. Alarm, trial **INVALIDATED**, ledger entry.
7. **Reveal ceremony (30 s) → Obj 03:** A clean trial concludes. F_post == F_pre. Commitments open. ✅ Verified. Merkle checkpoint signed.
8. **Tamper test (30 s) → Obj 03:** Flip one byte in the ledger. `dbverify` points to the exact event.
9. **Honesty slide (30 s) → Obj 06:** Residual-risk radar and guarantee break conditions. *"Here's exactly where this stops being safe, and what fixes it."*
10. **Close (15 s):** "`docker compose up` on any cloud VM. No special hardware. Trustworthy safety findings."

---

## 14. Pitch deck outline (≤ 10 slides)
1. Title: DOUBLE-BLIND, clinical-trial-grade isolation for AI safety testing
2. The problem: shared sandbox leads to invalid findings (the 5-row table from §1.2)
3. Insight: safety evaluation is an **experiment**, and experiments need blinding
4. The protocol: pre-register → blind → seal → monitor → reveal → attest
5. Architecture (diagram from ARCHITECTURE.md §1)
6. LLM-native threats and how we handle them
7. Proof, not promises: metrics table (§8)
8. Live demo
9. Threat model + residual risk + break conditions
10. Roadmap: microVMs, confidential computing, GPU partitioning, public anchoring

---

## 15. Execution risks and cut lines

| Risk | Mitigation | Cut line if behind |
|---|---|---|
| gVisor install problems on venue network/VM | Pre-install on the demo VM before the event; keep a runc + seccomp fallback | Fall back to runc + strict seccomp; state it in residual risk |
| Model too slow on CPU | Use the smallest instruct model; cap tokens; pre-warm | Smaller model, shorter outputs |
| Equalizer makes the demo feel slow | Set buckets from measured p95; show the trade-off explicitly | Larger single bucket, demo fewer cases |
| Falco/Tetragon needs kernel features that aren't available | Test on the target VM early | Drop to the canary + DLP layer only (still W5) |
| UI eats too much time | Streamlit fallback | Terminal dashboard (rich/textual) |
| Scope creep | MVP by H14, feature freeze at H26 | Drop P2s first, then G8, E6, C6 |
| Live demo failure | Backup video + pre-recorded ledger | Play the video, run the verifier live |

**Drop order when behind:** all P2 → G8 → E4 → C4 → D3 → A6. Never drop B4 (commit-reveal), C3 (verifier),
F1 (drill) or D5 (purity). They are cheap and they carry the story.

---

## 16. Stretch goals
- **Kubernetes profile:** kind/k3s + Cilium NetworkPolicy + RuntimeClass gVisor + static CPU manager.
- **MicroVM tier:** Kata Containers / Firecracker for the enclave and model zones.
- **Confidential computing:** SEV-SNP/TDX confidential VMs + remote attestation, so even the operator is blinded (addresses RR3).
- **GPU tier:** NVIDIA MIG partitioning + memory scrubbing between tenants (addresses RR8).
- **Supply-chain integrity:** cosign-signed images, SBOMs, SLSA provenance recorded in the ledger.
- **Formal policy checks:** automated analysis of Cedar/OPA policies to prove "blue can never read red before REVEAL".
- **Public transparency:** anchor checkpoints to Sigstore Rekor; publish a verifier-ready trial bundle.
- **Privacy-preserving leaderboards:** aggregate results with differential privacy to limit cross-trial inference (addresses RR5).

---

## 17. Pre-hackathon checklist
- [ ] Read up: gVisor architecture, Docker seccomp/AppArmor, cgroups v2 cpusets, OPA/Cedar basics, Merkle trees/Ed25519
- [ ] Provision the demo VM; install Docker (rootless), gVisor, Falco; confirm everything runs
- [ ] Download and checksum the model GGUF; measure CPU latency (p50/p95)
- [ ] Download benchmark datasets; write the vault importer so no one has to open raw files during the event
- [ ] Agree on the Arbiter API + ledger event schema (JSON) as a shared contract
- [ ] Prepare the War Room design mock + slide template
- [ ] Draft threat-model and residual-risk docs (≈70% can be done in advance)
- [ ] Dry-run: `docker compose up` from a clean clone on a fresh VM
- [ ] Assign roles; set up the repo, branch rules and task board mirroring §11

---

*Living document. Update statuses in §11 as tasks move.*
