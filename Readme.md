# Start benchmark
EC-VRF
```
cargo test --package vrf --lib -- ec_vrf::tests::bench_ec_vrf_1000 --exact --nocapture
```

RKA-VRF
```
cargo test --package vrf --lib -- rka_vrf::tests::bench_ed25519_vrf_1000 --exact --nocapture
```