# ED255222-PQ

**A Post-Quantum Signature Profile Based on ML-DSA-44**

> Authored by **Richard Patterson** | [@De-ASI-INTERFACE](https://github.com/De-ASI-INTERFACE)

---

## Overview

ED255222-PQ is a named, versioned post-quantum digital signature scheme designed as an architectural replacement for Ed25519 in high-throughput distributed ledgers, with primary integration targeting the **Solana** blockchain.

It is a profile of **ML-DSA-44 (NIST FIPS 204)**, extended with:
- Solana-specific domain separation tags
- A hybrid Ed25519 + PQ construction for graceful migration
- A Lean 4 formal specification
- A Solana on-chain verification program
- An IETF Internet-Draft submission
- A Solana SIMD proposal

---

## Repository Structure

```
ed255222-pq/
├── Cargo.toml                        # Workspace root
├── crates/
│   ├── ed255222-pq/                  # Core PQ Rust crate
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── constants.rs
│   │       ├── errors.rs
│   │       ├── keypair.rs
│   │       ├── sign.rs
│   │       ├── verify.rs
│   │       └── hybrid.rs
│   └── ed255222-pq-solana/           # Solana verification program
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── processor.rs
│           ├── instructions.rs
│           └── state.rs
├── lean/
│   └── ED255222PQ/
│       ├── lakefile.toml
│       ├── Basics.lean
│       ├── KeyGen.lean
│       ├── Sign.lean
│       ├── Verify.lean
│       ├── Hybrid.lean
│       └── Correctness.lean
├── test-vectors/
│   └── ed255222-pq-tv.json
├── docs/
│   ├── draft-patterson-cfrg-ed255222-pq-00.txt  # IETF Internet-Draft
│   └── SIMD-ed255222-pq.md                      # Solana SIMD proposal
└── .github/
    └── workflows/
        └── ci.yml
```

---

## Key Parameters

| Parameter          | Value                       |
|--------------------|-----------------------------|
| Base scheme        | ML-DSA (FIPS 204)           |
| Parameter set      | ML-DSA-44                   |
| Public key size    | 1,312 bytes                 |
| Secret key size    | 2,560 bytes                 |
| Signature size     | 2,420 bytes                 |
| Hybrid sig size    | 2,484 bytes (Ed25519 + PQ)  |
| Hash / XOF         | SHAKE256                    |
| Classical security | ~128-bit (NIST category 2)  |
| PQ security        | NIST category 2             |

---

## Quick Start

```bash
# Clone
git clone https://github.com/De-ASI-INTERFACE/ed255222-pq
cd ed255222-pq

# Build
cargo build --workspace

# Test (generates and validates test vectors)
cargo test --workspace

# Run test vector generation
cargo run --bin generate-vectors
```

---

## Domain Separation Tags

| Tag                    | Hex                                               | Use         |
|------------------------|---------------------------------------------------|-------------|
| `ED255222-PQ-KEYGEN`   | `4544323535323232...` | Key generation |
| `ED255222-PQ-SIGN`     | `4544323535323232...` | Signing        |

---

## Migration Phases

| Phase | Mode       | Required signatures        |
|-------|------------|----------------------------|
| 1     | Hybrid     | Ed25519 AND ED255222-PQ    |
| 2     | PQ-Only    | ED255222-PQ only           |
| 3     | Deprecated | Ed25519 (legacy fallback)  |

---

## Standards Submissions

- **IETF Internet-Draft**: `draft-patterson-cfrg-ed255222-pq-00`  
  → [docs/draft-patterson-cfrg-ed255222-pq-00.txt](docs/draft-patterson-cfrg-ed255222-pq-00.txt)
- **Solana SIMD**: Hybrid Post-Quantum Signer Accounts  
  → [docs/SIMD-ed255222-pq.md](docs/SIMD-ed255222-pq.md)

---

## Security Notice

> **ED255222-PQ is a new cryptographic construction currently in the proposal phase.**
> It MUST NOT be used in production without independent security review.
> The ML-DSA-44 base (FIPS 204) is standardized; this profile adds domain separation
> and integration rules that require separate auditing.

Known upstream: CVE-2026-24850 in `ml-dsa < 0.1.1` (duplicate hint indices). This crate pins `ml-dsa = "0.1.1"` or higher.

---

## License

MIT OR Apache-2.0

---

## Author

**Richard Patterson**  
Founder & Architect | Akron, Ohio, US  
GitHub: [@De-ASI-INTERFACE](https://github.com/De-ASI-INTERFACE)
