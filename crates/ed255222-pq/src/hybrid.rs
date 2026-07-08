//! ED255222-PQ hybrid construction: Ed25519 + ED255222-PQ.
//!
//! Spec reference: Section 7 of draft-patterson-cfrg-ed255222-pq-00

use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey,
                    Signer, Verifier, Signature as Ed25519Sig};
use crate::constants::*;
use crate::errors::Ed255222PQError;
use crate::keypair::{PublicKey as PqPublicKey, SecretKey as PqSecretKey, Keypair as PqKeypair};
use crate::{sign as pq_sign, verify as pq_verify};

/// A hybrid keypair: Ed25519 + ED255222-PQ.
pub struct HybridKeypair {
    pub ed25519_signing:   Ed25519SigningKey,
    pub ed25519_verifying: Ed25519VerifyingKey,
    pub pq_keypair:        PqKeypair,
}

/// A hybrid signature: Ed25519 sig (64 bytes) + ED255222-PQ sig (2420 bytes).
pub struct HybridSignature {
    pub ed25519_sig: [u8; ED25519_SIG_LEN],
    pub pq_sig:      [u8; SIG_LEN],
}

impl HybridKeypair {
    /// Generate a new hybrid keypair from a 32-byte master seed.
    /// Ed25519 derives from first SHAKE256 expansion, PQ from second.
    pub fn from_seed(master_seed: &[u8; 32]) -> Result<Self, Ed255222PQError> {
        use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

        // Derive Ed25519 seed.
        let mut ed_seed = [0u8; 32];
        let mut h = Shake256::default();
        h.update(b"ED255222-PQ-HYBRID-ED25519-");
        h.update(master_seed);
        let mut xof = h.finalize_xof();
        xof.read(&mut ed_seed);

        // Derive PQ seed.
        let mut pq_seed = [0u8; 32];
        let mut h2 = Shake256::default();
        h2.update(b"ED255222-PQ-HYBRID-PQ-");
        h2.update(master_seed);
        let mut xof2 = h2.finalize_xof();
        xof2.read(&mut pq_seed);

        let ed_sk = Ed25519SigningKey::from_bytes(&ed_seed);
        let ed_vk = ed_sk.verifying_key();
        let pq_kp = PqKeypair::from_seed(&pq_seed)?;

        Ok(Self {
            ed25519_signing:   ed_sk,
            ed25519_verifying: ed_vk,
            pq_keypair:        pq_kp,
        })
    }

    /// Sign a message with both Ed25519 and ED255222-PQ.
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<HybridSignature, Ed255222PQError> {
        // Ed25519 signature.
        let ed_sig: Ed25519Sig = self.ed25519_signing.sign(message);
        let ed_sig_bytes: [u8; ED25519_SIG_LEN] = ed_sig.to_bytes();

        // PQ signature.
        let pq_sig = pq_sign(&self.pq_keypair.secret, message, context)?;

        Ok(HybridSignature {
            ed25519_sig: ed_sig_bytes,
            pq_sig,
        })
    }
}

/// Verify a hybrid signature. Both components MUST pass.
pub fn verify_hybrid(
    ed25519_vk: &Ed25519VerifyingKey,
    pq_pk: &PqPublicKey,
    message: &[u8],
    hybrid_sig: &HybridSignature,
    context: &[u8],
) -> Result<(), Ed255222PQError> {
    // Ed25519 verification.
    let ed_sig = Ed25519Sig::from_bytes(&hybrid_sig.ed25519_sig);
    ed25519_vk.verify(message, &ed_sig)
        .map_err(|_| Ed255222PQError::Ed25519VerificationFailed)?;

    // PQ verification.
    pq_verify(pq_pk, message, &hybrid_sig.pq_sig, context)
        .map_err(|_| Ed255222PQError::VerificationFailed)?;

    Ok(())
}
