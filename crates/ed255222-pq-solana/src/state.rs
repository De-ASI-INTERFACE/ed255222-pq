//! On-chain hybrid signer account state.

use borsh::{BorshSerialize, BorshDeserialize};
use ed255222_pq::constants::{ED25519_PK_LEN, PK_LEN};

/// Hybrid signer account: stores Ed25519 pk + ED255222-PQ pk.
/// Total size: 1 + 32 + 1312 + 1 = 1346 bytes.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct HybridSignerV1 {
    /// Account version discriminator.
    pub version: u8,
    /// Ed25519 public key (32 bytes).
    pub ed25519_pk: [u8; ED25519_PK_LEN],
    /// ED255222-PQ public key (1312 bytes).
    pub pq_pk: [u8; PK_LEN],
    /// Migration phase: 1 = Hybrid, 2 = PQ-Only, 3 = Legacy-Deprecated.
    pub phase: u8,
}

impl HybridSignerV1 {
    pub const VERSION: u8 = 1;

    pub fn account_size() -> usize {
        1 + ED25519_PK_LEN + PK_LEN + 1 // 1346 bytes
    }
}
