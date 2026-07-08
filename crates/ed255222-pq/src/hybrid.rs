//! Hybrid construction: Ed25519 + ED255222-PQ.
//!
//! Spec reference: Section 7 of draft-patterson-cfrg-ed255222-pq-00
//!
//! Security: EUF-CMA secure if at least one component is EUF-CMA secure.

use ed25519_dalek::{
    SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
    Signer, Verifier,
    Signature as Ed25519Sig,
};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

use crate::constants::*;
use crate::errors::Ed255222PQError;
use crate::keypair::{PublicKey as PqPublicKey, SecretKey as PqSecretKey, Keypair as PqKeypair};
use crate::{sign as pq_sign, verify as pq_verify};

/// A hybrid keypair: Ed25519 + ED255222-PQ.
/// Both keys are derived deterministically from a 32-byte master seed.
pub struct HybridKeypair {
    pub ed25519_signing:   Ed25519SigningKey,
    pub ed25519_verifying: Ed25519VerifyingKey,
    pub pq_keypair:        PqKeypair,
}

/// A hybrid signature blob: Ed25519 (64 bytes) + ED255222-PQ (2420 bytes).
pub struct HybridSignature {
    pub ed25519_sig: [u8; ED25519_SIG_LEN],
    pub pq_sig:      [u8; SIG_LEN],
}

impl HybridKeypair {
    /// Derive a hybrid keypair from a 32-byte master seed.
    ///
    /// Ed25519 key:  SHAKE256("ED255222-PQ-HYBRID-ED25519-" || master_seed)[0..32]
    /// PQ key seed:  SHAKE256("ED255222-PQ-HYBRID-PQ-"      || master_seed)[0..32]
    pub fn from_seed(master_seed: &[u8; 32]) -> Result<Self, Ed255222PQError> {
        let mut ed_seed = Zeroizing::new([0u8; 32]);
        {
            let mut h = Shake256::default();
            h.update(b"ED255222-PQ-HYBRID-ED25519-");
            h.update(master_seed);
            let mut xof = h.finalize_xof();
            xof.read(ed_seed.as_mut());
        }

        let mut pq_seed = Zeroizing::new([0u8; 32]);
        {
            let mut h = Shake256::default();
            h.update(b"ED255222-PQ-HYBRID-PQ-");
            h.update(master_seed);
            let mut xof = h.finalize_xof();
            xof.read(pq_seed.as_mut());
        }

        let ed_sk = Ed25519SigningKey::from_bytes(&ed_seed);
        let ed_vk = ed_sk.verifying_key();
        let pq_kp = PqKeypair::from_seed(pq_seed.as_ref())?;

        Ok(Self {
            ed25519_signing:   ed_sk,
            ed25519_verifying: ed_vk,
            pq_keypair:        pq_kp,
        })
    }

    /// Sign a message with both Ed25519 and ED255222-PQ.
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<HybridSignature, Ed255222PQError> {
        let ed_sig: Ed25519Sig = self.ed25519_signing.sign(message);
        let pq_sig = pq_sign(&self.pq_keypair.secret, message, context)?;
        Ok(HybridSignature {
            ed25519_sig: ed_sig.to_bytes(),
            pq_sig,
        })
    }
}

use zeroize::Zeroizing;

/// Verify a hybrid signature. Both Ed25519 AND ED255222-PQ must pass.
///
/// Returns Ok(()) iff both components verify successfully.
pub fn verify_hybrid(
    ed25519_vk: &Ed25519VerifyingKey,
    pq_pk: &PqPublicKey,
    message: &[u8],
    hybrid_sig: &HybridSignature,
    context: &[u8],
) -> Result<(), Ed255222PQError> {
    // Ed25519 component.
    let ed_sig = Ed25519Sig::from_bytes(&hybrid_sig.ed25519_sig);
    ed25519_vk
        .verify(message, &ed_sig)
        .map_err(|_| Ed255222PQError::Ed25519VerificationFailed)?;

    // ED255222-PQ component.
    pq_verify(pq_pk, message, &hybrid_sig.pq_sig, context)
        .map_err(|_| Ed255222PQError::VerificationFailed)?;

    Ok(())
}
