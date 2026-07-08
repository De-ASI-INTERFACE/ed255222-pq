//! ED255222-PQ key generation.
//!
//! Uses fips204 crate (pure-Rust FIPS 204 ML-DSA-44) with a
//! domain-separated SHAKE256 seed expansion.
//!
//! Spec reference: Section 4 of draft-patterson-cfrg-ed255222-pq-00

use fips204::ml_dsa_44::{self, PublicKey as MlPk, PrivateKey as MlSk};
use fips204::traits::{KeyGen, SerDes, Signer};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use zeroize::{Zeroize, Zeroizing};
use rand::RngCore;

use crate::constants::*;
use crate::errors::Ed255222PQError;

/// ED255222-PQ secret key (serialized ML-DSA-44 private key, 2560 bytes).
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub(crate) Box<[u8; SK_LEN]>);

/// ED255222-PQ public key (serialized ML-DSA-44 public key, 1312 bytes).
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey(pub [u8; PK_LEN]);

/// An ED255222-PQ keypair.
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    /// Generate a new keypair using a cryptographically secure RNG.
    pub fn generate<R: RngCore>(mut rng: R) -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        rng.fill_bytes(seed.as_mut());
        Self::from_seed(&*seed).expect("RNG-generated 32-byte seed is always valid")
    }

    /// Derive a keypair deterministically from a 32-byte seed.
    ///
    /// The seed is expanded via SHAKE256 with domain tag `ED255222-PQ-KEYGEN`
    /// before being passed to ML-DSA-44 key generation.
    pub fn from_seed(seed: &[u8]) -> Result<Self, Ed255222PQError> {
        if seed.len() != SEED_LEN {
            return Err(Ed255222PQError::InvalidSeedLength);
        }

        // Domain-separated seed expansion:
        // mldsa_seed = SHAKE256("ED255222-PQ-KEYGEN" || seed)[0..32]
        let mut mldsa_seed = Zeroizing::new([0u8; 32]);
        {
            let mut h = Shake256::default();
            h.update(DST_KEYGEN);
            h.update(seed);
            let mut xof = h.finalize_xof();
            xof.read(mldsa_seed.as_mut());
        }

        // ML-DSA-44 key generation from seed (fips204 API).
        // try_keygen_with_seed takes a [u8; 32] xi seed per FIPS 204 §5.1.
        let (pk, sk) = ml_dsa_44::try_keygen_with_seed(*mldsa_seed)
            .map_err(|_| Ed255222PQError::MlDsaError)?;

        // Serialize keys to fixed-length byte arrays.
        let pk_bytes: [u8; PK_LEN] = pk.into_bytes();
        let sk_bytes: [u8; SK_LEN] = sk.into_bytes();

        Ok(Keypair {
            secret: SecretKey(Box::new(sk_bytes)),
            public: PublicKey(pk_bytes),
        })
    }
}
