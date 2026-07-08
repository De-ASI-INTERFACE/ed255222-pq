//! ED255222-PQ integration tests.

use ed255222_pq::keypair::Keypair;
use ed255222_pq::{sign, verify};
use ed255222_pq::hybrid::{HybridKeypair, verify_hybrid};

#[test]
fn round_trip_solana_tx() {
    let seed = [0x01u8; 32];
    let kp = Keypair::from_seed(&seed).unwrap();
    let msg = b"Test message for Solana transaction";
    let ctx = b"SOLANA-TX";
    let sig = sign(&kp.secret, msg, ctx).expect("sign ok");
    assert!(verify(&kp.public, msg, &sig, ctx).is_ok());
}

#[test]
fn round_trip_empty_message() {
    let seed = [0x02u8; 32];
    let kp = Keypair::from_seed(&seed).unwrap();
    let sig = sign(&kp.secret, b"", b"IDENTITY").expect("sign ok");
    assert!(verify(&kp.public, b"", &sig, b"IDENTITY").is_ok());
}

#[test]
fn reject_tampered_signature() {
    let seed = [0x03u8; 32];
    let kp = Keypair::from_seed(&seed).unwrap();
    let msg = b"Tamper test";
    let ctx = b"SOLANA-TX";
    let mut sig = sign(&kp.secret, msg, ctx).unwrap();
    sig[0] ^= 0xff;
    assert!(verify(&kp.public, msg, &sig, ctx).is_err());
}

#[test]
fn reject_wrong_message() {
    let seed = [0x04u8; 32];
    let kp = Keypair::from_seed(&seed).unwrap();
    let ctx = b"SOLANA-TX";
    let sig = sign(&kp.secret, b"original", ctx).unwrap();
    assert!(verify(&kp.public, b"tampered", &sig, ctx).is_err());
}

#[test]
fn reject_wrong_context() {
    let seed = [0x05u8; 32];
    let kp = Keypair::from_seed(&seed).unwrap();
    let msg = b"Context test";
    let sig = sign(&kp.secret, msg, b"SOLANA-TX").unwrap();
    assert!(verify(&kp.public, msg, &sig, b"IDENTITY").is_err());
}

#[test]
fn reject_context_too_long() {
    let seed = [0x06u8; 32];
    let kp = Keypair::from_seed(&seed).unwrap();
    let long_ctx = vec![0x41u8; 256]; // 256 bytes > MAX_CTX_LEN
    let result = sign(&kp.secret, b"msg", &long_ctx);
    assert!(result.is_err());
}

#[test]
fn hybrid_round_trip() {
    let master_seed = [0x07u8; 32];
    let hkp = HybridKeypair::from_seed(&master_seed).unwrap();
    let msg = b"Hybrid signature test";
    let ctx = b"SOLANA-TX";
    let hsig = hkp.sign(msg, ctx).unwrap();
    assert!(verify_hybrid(
        &hkp.ed25519_verifying,
        &hkp.pq_keypair.public,
        msg,
        &hsig,
        ctx,
    ).is_ok());
}

#[test]
fn hybrid_reject_tampered_pq_sig() {
    let master_seed = [0x08u8; 32];
    let hkp = HybridKeypair::from_seed(&master_seed).unwrap();
    let msg = b"Hybrid tamper test";
    let ctx = b"SOLANA-TX";
    let mut hsig = hkp.sign(msg, ctx).unwrap();
    hsig.pq_sig[0] ^= 0xff;
    assert!(verify_hybrid(
        &hkp.ed25519_verifying,
        &hkp.pq_keypair.public,
        msg,
        &hsig,
        ctx,
    ).is_err());
}
