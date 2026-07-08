//! ED255222-PQ: Post-quantum signature profile based on ML-DSA-44 (FIPS 204).
//!
//! Author: Richard Patterson
//! Spec:   draft-patterson-cfrg-ed255222-pq-00

pub mod constants;
pub mod errors;
pub mod keypair;
pub mod sign;
pub mod verify;
pub mod hybrid;

pub use keypair::{Keypair, PublicKey, SecretKey};
pub use sign::sign;
pub use verify::verify;
pub use hybrid::{HybridKeypair, HybridSignature, verify_hybrid};
