# Measured results

Produced by `make bench` (`python -m doubleblind bench`). Environment: local simulation, meaning the
deterministic stub model with a simulated latency profile and in-process zones. The numbers demonstrate the
*mechanisms*; rerun against the Docker deployment with a real model for production latency.

| File | Question | Result |
|---|---|---|
| [`leakage.json`](leakage.json) | From latency + size alone, can red tell a **guard** refusal from a **model** refusal? kNN (k=5) and best-threshold attackers, 5-fold CV, balanced classes (chance = 50%) | Equalizer off: **100%** (CI 98.8–100%). Equalizer on: **50.0%** (CI 44.6–55.4%), consistent with chance |
| [`kvcache.json`](kvcache.json) | Can one session tell, from latency alone, whether another session just sent a prefix? | Shared cache: **100%** (seen-prefix p50 11.4 ms vs 34.3 ms). Per-session cache: **45%** (CI 38–52%), consistent with chance |
| [`overhead.json`](overhead.json) | What does isolation cost on benign prompts? Identical bundle and prompts in every setup | bare p50 61.7 ms → isolated **65.3 ms (+3.6 ms, +5.8%)** → equalized 152.3 ms (the 150 ms bucket, by design) |

The War Room's "Proof, not promises" panel reads these files.
