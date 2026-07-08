//! ED255222-PQ signing algorithm.
//!
//! Domain-separated SHAKE256 hash of context+message, then ML-DSA-44 sign.
//!
//! Spec reference: Section 5 of draft-patterson-cfrg-ed255222-pq-00

use fips204::ml_dsa_44::{self, PrivateKey as MlSk};
use fips204::traits::{SerDes, Signer};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

use crate::constants::*;
use crate::errors::Ed255222PQError;
use crate::keypair::SecretKey;

/// Sign a message under ED255222-PQ.
///
/// # Domain separation
/// m_hash = SHAKE256(DST_SIGN || byte(len(context)) || context || message, 64)
///
/// # Arguments
/// * `sk`      — 2560-byte secret key
/// * `message` — arbitrary byte string
/// * `context` — <=255 bytes (e.g. b"SOLANA-TX", b"IDENTITY")
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

    // Build domain-separated 64-byte message hash.
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

    // Deserialize secret key from bytes.
    let ml_sk = MlSk::try_from_bytes(&sk.0)
        .map_err(|_| Ed255222PQError::InvalidSecretKeyLength)?;

    // ML-DSA-44 deterministic signing (FIPS 204 §5.2, Algorithm 2).
    // try_sign_with_seed uses the deterministic (hedged = false) path.
    let sig: [u8; SIG_LEN] = ml_sk.try_sign(&m_hash, b"")
        .map_err(|_| Ed255222PQError::MlDsaError)?;

    Ok(sig)
}
