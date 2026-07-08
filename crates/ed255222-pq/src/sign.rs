//! ED255222-PQ signing algorithm.
//!
//! Spec reference: Section 5 of draft-patterson-cfrg-ed255222-pq-00

use ml_dsa::{MlDsa44, EncodedSigningKey, SigningKey, Signature as MlDsaSig};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

use crate::constants::*;
use crate::errors::Ed255222PQError;
use crate::keypair::SecretKey;

/// Sign a message under ED255222-PQ.
///
/// # Arguments
/// * `sk`      - 2560-byte secret key
/// * `message` - arbitrary-length message
/// * `context` - domain context string, max 255 bytes (e.g. b"SOLANA-TX")
///
/// # Returns
/// 2420-byte signature on success.
pub fn sign(
    sk: &SecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<[u8; SIG_LEN], Ed255222PQError> {
    if context.len() > MAX_CTX_LEN {
        return Err(Ed255222PQError::ContextTooLong);
    }

    // Build domain-separated message hash:
    // m_hash = SHAKE256(DST_SIGN || byte(len(context)) || context || message, 64 bytes)
    let ctx_len_byte = [context.len() as u8];
    let mut m_hash = [0u8; 64];
    let mut hasher = Shake256::default();
    hasher.update(DST_SIGN);
    hasher.update(&ctx_len_byte);
    hasher.update(context);
    hasher.update(message);
    let mut xof = hasher.finalize_xof();
    xof.read(&mut m_hash);

    // Decode signing key and sign.
    let sk_enc = EncodedSigningKey::<MlDsa44>::try_from(sk.0.as_ref())
        .map_err(|_| Ed255222PQError::MlDsaError)?;
    let signing_key = SigningKey::try_from(&sk_enc)
        .map_err(|_| Ed255222PQError::MlDsaError)?;

    let sig: MlDsaSig<MlDsa44> = signing_key.sign(&m_hash);
    let sig_enc = sig.encode();

    let mut out = [0u8; SIG_LEN];
    out.copy_from_slice(sig_enc.as_ref());
    Ok(out)
}
