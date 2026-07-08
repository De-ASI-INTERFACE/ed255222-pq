//! ED255222-PQ verification algorithm.
//!
//! Spec reference: Section 6 of draft-patterson-cfrg-ed255222-pq-00

use fips204::ml_dsa_44::{self, PublicKey as MlPk};
use fips204::traits::{SerDes, Verifier};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

use crate::constants::*;
use crate::errors::Ed255222PQError;
use crate::keypair::PublicKey;

/// Verify an ED255222-PQ signature.
///
/// Reconstructs the same m_hash as sign() and passes it to ML-DSA-44 verify.
///
/// # Rejection conditions (all return Err)
/// - context.len() > 255
/// - ML-DSA-44 verify returns false
/// - Invalid key or signature encoding
pub fn verify(
    pk: &PublicKey,
    message: &[u8],
    signature: &[u8; SIG_LEN],
    context: &[u8],
) -> Result<(), Ed255222PQError> {
    if context.len() > MAX_CTX_LEN {
        return Err(Ed255222PQError::ContextTooLong);
    }

    // Reconstruct m_hash identically to sign().
    let mut m_hash = [0u8; 64];
    {
        let mut h = Shake256::default();
        h.update(DST_SIGN);
        h.update(&[context.len() as u8]);
        h.update(context);
        h.update(message);
        let mut xof = h.finalize_xof();
        xof.read(&mut m_hash);
    }

    // Deserialize public key.
    let ml_pk = MlPk::try_from_bytes(&pk.0)
        .map_err(|_| Ed255222PQError::InvalidPublicKeyLength)?;

    // ML-DSA-44 verification.
    let valid = ml_pk.verify(&m_hash, signature, b"")
        .map_err(|_| Ed255222PQError::VerificationFailed)?;

    if valid {
        Ok(())
    } else {
        Err(Ed255222PQError::VerificationFailed)
    }
}
