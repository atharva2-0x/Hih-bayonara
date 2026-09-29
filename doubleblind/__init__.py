"""DOUBLE-BLIND: clinical-trial-grade isolation for adversarial AI safety testing.

Package layout:
    common/         crypto primitives, Merkle trees, telemetry schema, TLS helpers
    authority/      Trial Authority (control plane): ledger, policy, key broker,
                    trial state machine, equalizer, judge, Arbiter service + APIs
    zones/          tenant and data-plane zones: red, blue, enclave, model
    observability/  canary watcher, anomaly detector (metadata only)
    drill/          breach drill -> isolation certificate
    verifier/       offline verifier (dbverify)
    bench/          overhead, side-channel leakage and KV-cache isolation benchmarks
"""

__version__ = "0.1.0"
