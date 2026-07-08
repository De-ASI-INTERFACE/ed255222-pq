//! ED255222-PQ on-chain compute unit (CU) cost estimator.
//!
//! Measures wall-clock time for keygen, sign, and verify operations,
//! then estimates Solana compute units using the empirical ratio:
//!   ~1 CU ≈ 33ns of single-core CPU work (Solana validator estimate).
//!
//! Run: cargo run --bin benchmark --release

use std::time::Instant;
use ed255222_pq::keypair::Keypair;
use ed255222_pq::{sign, verify};
use ed255222_pq::hybrid::{HybridKeypair, verify_hybrid};

// Empirical Solana CU/ns ratio (conservative estimate).
// 1 CU ≈ 33ns on a validator-class CPU.
const NS_PER_CU: f64 = 33.0;
const ITERATIONS: usize = 100;

fn estimate_cu(ns: f64) -> f64 { ns / NS_PER_CU }

fn bench_ns<F: Fn()>(label: &str, iters: usize, f: F) -> f64 {
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;
    let cu = estimate_cu(ns_per_op);
    println!(
        "  {:45} {:>10.0} ns/op  ~{:>8.0} CU",
        label, ns_per_op, cu
    );
    ns_per_op
}

fn main() {
    println!("\n=== ED255222-PQ Benchmark (n={} iterations) ===", ITERATIONS);
    println!("  Estimating Solana compute units at ~1 CU per {}ns\n", NS_PER_CU as u64);

    let seed = [0x01u8; 32];
    let msg  = b"Solana transaction payload benchmark";
    let ctx  = b"SOLANA-TX";

    // --- Keygen ---
    bench_ns("ED255222-PQ KeyGen (from seed)", ITERATIONS, || {
        let _ = Keypair::from_seed(&seed).unwrap();
    });

    // --- Sign ---
    let kp = Keypair::from_seed(&seed).unwrap();
    bench_ns("ED255222-PQ Sign", ITERATIONS, || {
        let _ = sign(&kp.secret, msg, ctx).unwrap();
    });

    // --- Verify ---
    let sig = sign(&kp.secret, msg, ctx).unwrap();
    bench_ns("ED255222-PQ Verify", ITERATIONS, || {
        let _ = verify(&kp.public, msg, &sig, ctx);
    });

    // --- Hybrid ---
    let master = [0x07u8; 32];
    let hkp = HybridKeypair::from_seed(&master).unwrap();
    let hsig = hkp.sign(msg, ctx).unwrap();

    bench_ns("Hybrid Sign (Ed25519 + PQ)", ITERATIONS, || {
        let _ = hkp.sign(msg, ctx).unwrap();
    });

    bench_ns("Hybrid Verify (Ed25519 + PQ)", ITERATIONS, || {
        let _ = verify_hybrid(
            &hkp.ed25519_verifying,
            &hkp.pq_keypair.public,
            msg,
            &hsig,
            ctx,
        );
    });

    println!("\n=== Solana Budget Reference ===");
    println!("  Ed25519 verify (Solana built-in):  ~17,000 CU");
    println!("  Max CUs per transaction:          1,400,000 CU");
    println!("  Max CUs per instruction (default):  200,000 CU");
    println!();
    println!("  Action required: Run with --release on validator-class hardware.");
    println!("  Then file compute unit budget in SIMD discussion as Phase 2 evidence.");
    println!("  Repo: https://github.com/De-ASI-INTERFACE/ed255222-pq");
}
