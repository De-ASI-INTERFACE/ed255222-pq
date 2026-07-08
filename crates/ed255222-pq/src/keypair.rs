//! ED255222-PQ key generation (ML-DSA-44 via domain-separated SHAKE256 seed expansion).

use ml_dsa::{MlDsa44, EncodedSigningKey, EncodedVerifyingKey, KeyGen};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use zeroize::{Zeroize, Zeroizing};
use rand::RngCore;

use crate::constants::*;
use crate::errors::Ed255222PQError;

/// ED255222-PQ secret key (ML-DSA-44 encoded signing key, 2560 bytes).
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub(crate) Box<[u8; SK_LEN]>);

/// ED255222-PQ public key (ML-DSA-44 encoded verifying key, 1312 bytes).
#[derive(Clone, Debug)]
pub struct PublicKey(pub [u8; PK_LEN]);

/// An ED255222-PQ keypair.
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    /// Generate a new keypair from a cryptographically secure RNG.
    pub fn generate<R: RngCore>(mut rng: R) -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        rng.fill_bytes(seed.as_mut());
        Self::from_seed(&*seed).expect("RNG-generated seed always valid")
    }

    /// Derive a keypair deterministically from a 32-byte seed.
    /// Returns Err if seed length is not exactly SEED_LEN.
    pub fn from_seed(seed: &[u8]) -> Result<Self, Ed255222PQError> {
        if seed.len() != SEED_LEN {
            return Err(Ed255222PQError::InvalidSeedLength);
        }

        // Domain-separated seed expansion: SHAKE256(DST_KEYGEN || seed) -> 32 bytes
        let mut mldsa_seed = Zeroizing::new([0u8; 32]);
        let mut hasher = Shake256::default();
        hasher.update(DST_KEYGEN);
        hasher.update(seed);
        let mut xof = hasher.finalize_xof();
        xof.read(mldsa_seed.as_mut());

        // ML-DSA-44 key generation.
        let (signing_key, verifying_key) = MlDsa44::key_gen_from_seed(*mldsa_seed)
            .map_err(|_| Ed255222PQError::MlDsaError)?;

        let sk_enc: EncodedSigningKey<MlDsa44> = signing_key.encode();
        let vk_enc: EncodedVerifyingKey<MlDsa44> = verifying_key.encode();

        let mut sk_bytes = Box::new([0u8; SK_LEN]);
        let mut pk_bytes = [0u8; PK_LEN];
        sk_bytes.copy_from_slice(sk_enc.as_ref());
        pk_bytes.copy_from_slice(vk_enc.as_ref());

        Ok(Keypair {
            secret: SecretKey(sk_bytes),
            public: PublicKey(pk_bytes),
        })
    }
}
