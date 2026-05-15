# ANCRE Rust v0.7 — Discrete Laplace DP Engine

Pure ε=0.5-DP (δ=0) aggregation in Rust. Android/ARM64 compatible.

## Guarantee
M_ANCRE(D) = clamp(TMoM_α(D) + DLap_r(Δ/ε), 0, 1)
ε=0.5-DP (δ=0) under substitute adjacency

## Build & Test
cargo build
cargo test

## Results
59/59 tests — 0.8s on ARM64
KS stat = 0.0089 < 0.020 ✓

## Parameters
K_MIN=100, ε=0.5, ε_MAX=1.5, α=0.1, r=1000

## Python Layer
https://github.com/taha-vera/ancre-final

## License
MIT — Taha Houari, SAS VERA Paris
