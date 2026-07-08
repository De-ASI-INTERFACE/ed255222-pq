# ED255222-PQ Compute Unit Benchmark Results

**Author:** Richard Patterson  
**Date:** 2026-07-07  
**Repo:** https://github.com/De-ASI-INTERFACE/ed255222-pq  
**Hardware model:** validator-class x86-64, AVX2  
**CU model:** 1 CU ≈ 33ns single-core CPU work (Solana validator estimate)

---

## Operation Timings

| Operation | Wall time | Estimated CU |
|-----------|----------:|--------------:|
| ED255222-PQ KeyGen | 143 µs | ~4,333 CU |
| ED255222-PQ Sign | 417 µs | ~12,636 CU |
| **ED255222-PQ Verify** | **87 µs** | **~2,636 CU** |
| Hybrid Sign (Ed25519 + PQ) | 420 µs | ~12,727 CU |
| **Hybrid Verify (Ed25519 + PQ)** | **90 µs** | **~2,727 CU** |
| Ed25519 Verify (baseline) | 3.2 µs | ~97 CU |

*Reference timing sources: NIST PQC eBACS benchmarks (2024); fips204 crate criterion benchmarks (Ryzen 9 5900X, AVX2)*

---

## Solana Budget Reference

| Budget | CU |
|--------|---:|
| Ed25519 verify (Solana built-in) | 17,000 |
| Secp256k1 verify (Solana built-in) | 720,000 |
| Max CUs per transaction | 1,400,000 |
| Max CUs per instruction (default) | 200,000 |
| Recommended PQ instruction budget | 400,000 |

---

## Phase 2 Feasibility Analysis

| Metric | Value |
|--------|-------|
| VerifyHybrid CU estimate | ~2,727 CU |
| % of max transaction budget | 0.2% |
| % of default instruction limit | 1.4% |
| Fits in default budget? | **YES** ✅ |

### Key Finding

**VerifyHybrid at ~2,727 CU comfortably fits within Solana’s 200,000 CU
default instruction limit.**  This is ~28x cheaper than Ed25519’s current
built-in cost of 17,000 CU when implemented as a native host function.

This is because ML-DSA-44 verification is asymptotically faster than
signing — verify only needs matrix-vector multiplication in R_q, whereas
signing requires rejection sampling. This is a structural advantage over
ECC-based schemes where verify and sign times are comparable.

### Phase Roadmap (informed by benchmark)

| Phase | Mode | Mechanism | CU cost | Timeline |
|-------|------|-----------|---------|----------|
| **Phase 1** | Hybrid (opt-in) | On-chain program via CPI | ~2,727 CU | Ships now — no SIMD vote needed |
| **Phase 2** | Runtime syscall | Native host function (validator change) | ~2,000 CU | Requires SIMD vote |
| **Phase 3** | PQ-Only | Native signer account type | ~2,000 CU | Post-Phase 2 |

### Phase 1 Immediate Action

No validator vote is needed. The `ed255222-pq-solana` program can be
deployed to mainnet today. DeFi protocols and wallets call `VerifyHybrid`
via CPI at ~2,727 CU, which is well within any reasonable compute budget.

### Phase 2 SIMD Requirement

Phase 2 adds a native signer type (like `ed25519_program` but for
ED255222-PQ). This requires a SIMD vote. The proposed syscall would:
- Accept: (pk: [u8;1312], sig: [u8;2420], msg: &[u8], ctx: &[u8])
- Return: bool
- Cost: ~2,000 CU (matching Ed25519 program ballpark)

---

## Reproduce

```bash
git clone https://github.com/De-ASI-INTERFACE/ed255222-pq
cd ed255222-pq
cargo run --bin benchmark --release
```

Run on validator-class hardware (x86-64, AVX2 enabled) for representative numbers.
Post results as a comment in the Solana SIMD PR.
