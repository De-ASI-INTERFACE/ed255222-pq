//! ED255222-PQ verification algorithm.
//!
//! Spec reference: Section 6 of draft-patterson-cfrg-ed255222-pq-00

use ml_dsa::{MlDsa44, EncodedVerifyingKey, VerifyingKey, EncodedSignature};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

use crate::constants::*;
use crate::errors::Ed255222PQError;
use crate::keypair::PublicKey;

/// Verify an ED255222-PQ signature.
///
/// # Arguments
/// * `pk`        - 1312-byte public key
/// * `message`   - original message
/// * `signature` - 2420-byte signature
/// * `context`   - same context used during signing, max 255 bytes
///
/// # Returns
/// `Ok(())` on valid signature; `Err` on any rejection condition.
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
    let ctx_len_byte = [context.len() as u8];
    let mut m_hash = [0u8; 64];
    let mut hasher = Shake256::default();
    hasher.update(DST_SIGN);
    hasher.update(&ctx_len_byte);
    hasher.update(context);
    hasher.update(message);
    let mut xof = hasher.finalize_xof();
    xof.read(&mut m_hash);

    // Decode verifying key.
    let vk_enc = EncodedVerifyingKey::<MlDsa44>::try_from(pk.0.as_ref())
        .map_err(|_| Ed255222PQError::InvalidPublicKeyLength)?;
    let verifying_key = VerifyingKey::try_from(&vk_enc)
        .map_err(|_| Ed255222PQError::InvalidPublicKeyLength)?;

    // Decode signature.
    let sig_enc = EncodedSignature::<MlDsa44>::try_from(signature.as_ref())
        .map_err(|_| Ed255222PQError::InvalidSignatureLength)?;
    let sig = ml_dsa::Signature::try_from(&sig_enc)
        .map_err(|_| Ed255222PQError::VerificationFailed)?;

    verifying_key.verify(&m_hash, &sig)
        .map_err(|_| Ed255222PQError::VerificationFailed)
}
