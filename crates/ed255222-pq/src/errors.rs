use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum Ed255222PQError {
    #[error("Invalid public key length (expected 1312 bytes)")]
    InvalidPublicKeyLength,
    #[error("Invalid secret key length (expected 2560 bytes)")]
    InvalidSecretKeyLength,
    #[error("Invalid signature length (expected 2420 bytes)")]
    InvalidSignatureLength,
    #[error("Context exceeds maximum length of 255 bytes")]
    ContextTooLong,
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Invalid seed length (expected 32 bytes)")]
    InvalidSeedLength,
    #[error("Underlying ML-DSA-44 operation failed")]
    MlDsaError,
    #[error("Ed25519 component verification failed")]
    Ed25519VerificationFailed,
}
