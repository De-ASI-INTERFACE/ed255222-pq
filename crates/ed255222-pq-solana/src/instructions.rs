//! ED255222-PQ Solana program instruction definitions.

use borsh::{BorshSerialize, BorshDeserialize};
use ed255222_pq::constants::{ED25519_PK_LEN, ED25519_SIG_LEN, PK_LEN, SIG_LEN};

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum Ed255222PQInstruction {
    /// Create a new hybrid signer account.
    /// Accounts: [0] new HybridSignerV1 account (writable), [1] payer (signer)
    CreateHybridSigner {
        ed25519_pk: [u8; ED25519_PK_LEN],
        pq_pk:      [u8; PK_LEN],
    },

    /// Verify a hybrid signature (Ed25519 + ED255222-PQ) for a message.
    /// Accounts: [0] HybridSignerV1 account (readonly)
    VerifyHybrid {
        message:     Vec<u8>,
        ed25519_sig: [u8; ED25519_SIG_LEN],
        pq_sig:      [u8; SIG_LEN],
        context:     Vec<u8>,  // <= 255 bytes
    },

    /// Upgrade account to PQ-Only mode (Phase 2).
    /// Accounts: [0] HybridSignerV1 account (writable), [1] authority (signer)
    UpgradeToPQOnly {
        /// PQ signature authorizing the upgrade.
        auth_pq_sig: [u8; SIG_LEN],
    },
}
