# DOUBLE-BLIND — Architecture

> Isolation built to clinical-trial standards for Bayora's red-team / blue-team AI safety testing.
> Each safety finding is **pre-registered, blinded, sealed, and can be replayed independently**.

This file holds the diagrams. For the rationale, tasks and schedule, see [`plan.md`](./plan.md).

![DOUBLE-BLIND architecture](docs/architecture.svg)

*Pitch-ready diagram: [`docs/architecture.svg`](docs/architecture.svg) (PNG: [`docs/architecture.png`](docs/architecture.png)).
Regenerate it with `python3 docs/gen_architecture_svg.py docs/architecture.svg`. The Mermaid diagrams below are the
detailed, easy-to-edit versions.*

---

## 1. System architecture (trust zones)

Each coloured box is a **separate trust zone**. It has its own Docker network (`internal: true`), its own
cgroup/cpuset slice, and its own key material. **Zones never talk to each other directly.** Every
cross-zone message passes through the **Arbiter**, and the Arbiter writes each one to the ledger.

```mermaid
flowchart LR
    subgraph RED["RED ZONE · Tenant A · net-red"]
        RR["Red Runner<br/>attack harness<br/>(benchmark sets as opaque blobs)"]
        RV[("Red Vault<br/>payload sets<br/>encrypted with K_red")]
    end

    subgraph BLUE["BLUE ZONE · Tenant B · net-blue"]
        BW["Blue Workbench<br/>author + package<br/>defense bundles"]
        BV[("Blue Vault<br/>defense bundles, classifier weights<br/>encrypted with K_blue")]
    end

    subgraph AUTH["TRIAL AUTHORITY · control plane · net-ctrl"]
        ARB{{"ARBITER<br/>trial state machine<br/>+ sole message broker"}}
        EQ["Equalizer<br/>timing and size buckets<br/>canonical refusals"]
        PDP["Policy Engine<br/>OPA / Cedar ABAC<br/>time + state aware"]
        KMS["Key Broker<br/>per-tenant keys<br/>trial-scoped tokens"]
        JDG["Independent Judge<br/>scores each outcome"]
        LED[("TRIAL LEDGER<br/>hash chain +<br/>signed Merkle checkpoints")]
    end

    subgraph ENC["SEALED DEFENSE ENCLAVE · gVisor · no egress"]
        IG["Input Guard<br/>(blue bundle)"]
        OG["Output Guard<br/>(blue bundle)"]
    end

    subgraph MOD["MODEL CLEAN ROOM · ephemeral per trial · net-model"]
        LLM["Client LLM<br/>read-only, digest-pinned weights<br/>per-session KV cache, flushed"]
        PUR["Purity Fingerprint<br/>golden-probe hash<br/>before and after"]
    end

    subgraph OBS["OBSERVABILITY ZONE · metadata only · push-only"]
        RT["Runtime sensors<br/>Falco / Tetragon (eBPF)"]
        CAN["Canary Watcher<br/>+ egress DLP"]
        ANO["Anomaly Detector"]
    end

    WAR["WAR ROOM<br/>role-scoped dashboard"]
    VER["Verifier CLI<br/>offline replay + proof check"]

    RR -- "1 · sealed test case (mTLS)" --> ARB
    ARB -- "2" --> IG
    IG -- "3 · allowed input" --> LLM
    LLM -- "4 · raw output" --> OG
    OG -- "5 · verdict + output" --> ARB
    ARB -- "6" --> JDG
    ARB -- "7 · bucketed response" --> EQ
    EQ -- "8" --> RR

    BW -- "commit H(bundle)" --> ARB
    BV -. "bundle loaded read-only at ARM" .-> ENC
    RV -. "decrypt via trial token" .-> RR

    ARB <-.-> PDP
    ARB <-.-> KMS
    ARB == "every event" ==> LED

    RT --> ANO
    CAN --> ANO
    ANO -- "alert → INVALIDATE trial" --> ARB
    ARB -. "hashes / sizes / timings only" .-> CAN
    PUR -. "fingerprint" .-> ARB

    LED --> VER
    LED --> WAR
    ANO --> WAR

    classDef red fill:#fde2e2,stroke:#c0392b,color:#5b1a13;
    classDef blue fill:#dde9fb,stroke:#2463b8,color:#0f2c57;
    classDef auth fill:#fff4d6,stroke:#b8860b,color:#4d3800;
    classDef enc fill:#e6e0f8,stroke:#6c4bb6,color:#2b1a57;
    classDef mod fill:#dff5e5,stroke:#2e8b57,color:#113d24;
    classDef obs fill:#eeeeee,stroke:#555,color:#222;
    class RR,RV red;
    class BW,BV blue;
    class ARB,EQ,PDP,KMS,JDG,LED auth;
    class IG,OG enc;
    class LLM,PUR mod;
    class RT,CAN,ANO obs;
```

### Allowed-flow matrix (default deny, and the breach drill checks every cell)

| From ↓ / To → | Red | Blue | Arbiter | Enclave | Model | Ledger | Observability | Internet |
|---|---|---|---|---|---|---|---|---|
| **Red**        | —  | ❌ | ✅ mTLS | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Blue**       | ❌ | —  | ✅ mTLS | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Arbiter**    | ✅ (equalized only) | ✅ (post-reveal only) | — | ✅ | ✅ (control only) | ✅ append | ✅ metadata | ❌ |
| **Enclave**    | ❌ | ❌ | ✅ verdict | — | ✅ | ❌ | ❌ | ❌ |
| **Model**      | ❌ | ❌ | ✅ fingerprint | ✅ output | — | ❌ | ❌ | ❌ |
| **Observability** | ❌ | ❌ | ✅ alerts | ❌ | ❌ | ❌ | — | ❌ |

---

## 2. Life of a trial (sequence)

```mermaid
sequenceDiagram
    autonumber
    participant R as Red Runner
    participant B as Blue Workbench
    participant A as Arbiter
    participant L as Trial Ledger
    participant O as Observability
    participant E as Sealed Enclave
    participant M as Model Clean Room
    participant J as Judge

    Note over R,B: PRE-REGISTRATION (commit)
    B->>A: C_blue = H(defense_bundle ‖ nonce_b)
    R->>A: C_red = H(payload_set ‖ nonce_r)
    A->>L: REGISTERED {C_red, C_blue, model_digest, policy_hash}

    Note over A,M: ARMING
    A->>O: run Breach Drill (cross-zone negative tests)
    O-->>A: Isolation Certificate (all denied)
    A->>M: spawn fresh replica from pinned digest
    M-->>A: Purity Fingerprint F_pre
    A->>E: load sealed blue bundle (read-only)
    A->>L: ARMED {cert_hash, F_pre}

    Note over R,J: BLINDED RUN
    loop each test case i
        R->>A: case_i (encrypted to Arbiter)
        A->>E: input guard(case_i)
        E->>M: allowed input
        M-->>E: output_i
        E-->>A: verdict_i + output_i (inside control plane only)
        A->>J: score(case_i, output_i)
        A->>L: EVENT {H(case_i), H(output_i), verdict_i, score_i, t_i}
        A-->>R: equalized response (fixed time + size bucket)
    end

    Note over A,M: CONCLUDE
    A->>M: golden probes
    M-->>A: F_post (must equal F_pre)
    A->>M: destroy replica, wipe cache
    A->>L: CONCLUDED {F_post}

    Note over R,B: REVEAL CEREMONY
    R->>A: open(payload_set, nonce_r)
    B->>A: open(defense_bundle, nonce_b)
    A->>A: verify commitments, policy unlocks cross-visibility
    A->>L: REVEALED + signed Merkle checkpoint
    A-->>R: findings report
    A-->>B: findings report + blocked-case detail
```

---

## 3. Trial state machine

```mermaid
stateDiagram-v2
    [*] --> DRAFT
    DRAFT --> REGISTERED: both commitments received
    REGISTERED --> ARMED: breach drill passes and F_pre recorded
    REGISTERED --> INVALIDATED: breach drill fails
    ARMED --> RUNNING: start signal
    RUNNING --> CONCLUDED: all cases done and F_post == F_pre
    RUNNING --> INVALIDATED: canary hit / policy violation / anomaly
    CONCLUDED --> INVALIDATED: F_post != F_pre (contamination)
    CONCLUDED --> REVEALED: commitments open and verify
    CONCLUDED --> INVALIDATED: commitment mismatch
    REVEALED --> ATTESTED: Merkle checkpoint signed (+ optional public anchor)
    ATTESTED --> [*]
    INVALIDATED --> [*]
```

---

## 4. Defense in depth: layers per zone

```mermaid
flowchart TB
    subgraph L7["L7 · Protocol and LLM layer"]
        a1["Commit-reveal blinding"]
        a2["Equalizer: time/size buckets, canonical refusals"]
        a3["Per-session KV cache, no cross-tenant prefix reuse"]
        a4["Purity fingerprint, ephemeral replicas"]
        a5["Canary tokens + DLP on every boundary"]
    end
    subgraph L5["L5 · Identity and data"]
        b1["mTLS per workload (SPIFFE-style IDs)"]
        b2["ABAC: role × trial-state × time"]
        b3["Envelope encryption, per-tenant keys"]
        b4["Trial-scoped short-lived tokens"]
    end
    subgraph L3["L3 · Network"]
        c1["One internal network per zone"]
        c2["Arbiter is the only multi-homed service"]
        c3["nftables default-deny, no egress, no metadata IP"]
    end
    subgraph L1["L1 · Runtime and kernel"]
        d1["Rootless engine + user namespaces"]
        d2["gVisor runsc for enclave + model + red"]
        d3["seccomp allowlists, cap_drop ALL, no-new-privileges"]
        d4["Read-only rootfs, tmpfs scratch"]
        d5["cgroups v2: cpuset pinning, memory, pids, io.weight"]
    end
    L7 --> L5 --> L3 --> L1
```

---

## 5. Deployment topology (PoC on one standard cloud VM)

```mermaid
flowchart LR
    subgraph VM["Single cloud VM (e.g. 8 vCPU / 32 GB, no GPU needed)"]
        direction TB
        subgraph CPU["cpuset partitioning"]
            c01["cores 0-1 → Trial Authority + Observability"]
            c23["cores 2-3 → Red Zone"]
            c45["cores 4-5 → Blue Zone + Enclave"]
            c67["cores 6-7 → Model Clean Room"]
        end
        DC["Docker / Podman (rootless)<br/>RuntimeClass: runc | runsc (gVisor)"]
    end
    VM --> OPT["Optional: kind / k3s + Cilium NetworkPolicy + RuntimeClass gVisor"]
```

> **Why one VM?** The problem asks for deployability on standard cloud and container runtimes. The same
> Compose file also runs on a laptop. The K8s manifests are a stretch goal that shows the design scales.

---

## 6. Implementation map

| Diagram component | Code | Verified by |
|---|---|---|
| Arbiter (state machine + broker) | `doubleblind/authority/service.py`, `authority/api.py` | `tests/test_e2e.py` |
| Equalizer | `authority/equalizer.py` | `bench/leakage.py`, e2e identical-size assertion |
| Policy Engine (ABAC) | `authority/policy.py`, `authority/policy.json` | exhaustive invariants (`python -m doubleblind policy`) |
| Key Broker | `authority/keybroker.py` | `tests/test_core.py` |
| Independent Judge | `authority/judge.py` | `tests/test_zones.py` |
| Trial Ledger + checkpoints | `authority/ledger.py`, `common/merkle.py` | tamper tests, verifier |
| Commit-Reveal Registry | `common/crypto.py`, `service.py::reveal` | `test_reveal_mismatch_invalidates`, `test_cases_outside_committed_set_invalidate` |
| Breach Drill → Isolation Cert | `drill/drill.py`, `drill/flow_matrix.json` | `make drill` in Docker (113/118, 8/8 positive controls) |
| Sealed Defense Enclave | `zones/enclave/` | bundle validation + enclave pipeline tests |
| Model Clean Room + Purity | `zones/model/` | purity drift + cache scoping tests, `bench/kvcache.py` |
| Canary Watcher + DLP, Anomaly Detector | `observability/` | canary breach/contained tests, canary drill |
| Pinned per-zone mTLS | `common/tls.py`, `deploy/certs.py` | `tests/test_mtls.py`, drill `mtls.*` |
| Verifier CLI | `verifier/` | `tests/test_verifier_drill_bench.py` |
| War Room | `warroom/` | headless-browser check (no console errors, no mobile overflow) |
| Host hardening | `docker-compose.yml`, `infra/` | drill `process.*`, `net.*`, `dns.*` checks |
