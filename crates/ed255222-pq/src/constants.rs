//! ED255222-PQ parameter constants (ML-DSA-44, FIPS 204).

pub const SEED_LEN:    usize = 32;
pub const PK_LEN:      usize = 1312;
pub const SK_LEN:      usize = 2560;
pub const SIG_LEN:     usize = 2420;
pub const MAX_CTX_LEN: usize = 255;

/// Domain separation tag: key generation.
pub const DST_KEYGEN: &[u8] = b"ED255222-PQ-KEYGEN";

/// Domain separation tag: signing.
pub const DST_SIGN:   &[u8] = b"ED255222-PQ-SIGN";

// Hybrid construction sizes.
pub const ED25519_PK_LEN:  usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const HYBRID_PK_LEN:   usize = ED25519_PK_LEN + PK_LEN;   // 1344
pub const HYBRID_SIG_LEN:  usize = ED25519_SIG_LEN + SIG_LEN; // 2484
