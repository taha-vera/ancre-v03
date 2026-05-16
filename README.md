# ANCRE Rust v0.7 — ancre-v03

Pure epsilon=0.5-DP aggregation engine. 59/59 tests. ARM64.

## Guarantee

M_ANCRE(D) = clamp(TMoM_a(D) + DLap_r(Delta/eps), 0, 1)
epsilon=0.5-DP (delta=0) under substitute adjacency (Theorem 1)

## Security Properties

| Mechanism | Status |
|---|---|
| TMoM sensitivity 1/(0.8n) | [PROVEN] |
| DLap exact (delta=0) | [PROVEN] |
| EpsilonBudget monotone | [PROVEN] |
| Kill-switch | [OPERATIONAL] |
| max_per_device=1 | [ARCHITECTURAL] |
| HMAC audit chain | [ARCHITECTURAL] rollback only |

## Not Claimed

- Byzantine server resistance
- Infrastructure-level security
- Cryptographic unlinkability of audit chain

## Parameters

K_MIN=100, eps=0.5, eps_MAX=1.5, alpha=0.1, r=1000
scale_int=25 for n=100, eps=0.5

## Build & Test

cargo test  # 59/59 tests
cargo build --release

## Python Layer

https://github.com/taha-vera/ancre-final

## Whitepaper

Auto-compiled PDF: https://github.com/taha-vera/ancre-final/actions

## RFC3161 Anchor

FreeTSA, 2026-03-31T21:01:11 UTC

## License

MIT — Taha Houari, SAS VERA Paris
