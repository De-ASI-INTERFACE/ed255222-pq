//! Generate real ED255222-PQ test vectors using live ML-DSA-44 (fips204).
//!
//! Writes to test-vectors/ed255222-pq-tv.json.
//! Run: cargo run --bin generate-vectors

use ed255222_pq::keypair::Keypair;
use ed255222_pq::{sign, verify};
use serde::{Serialize, Deserialize};
use std::fs;

#[derive(Serialize, Deserialize, Debug)]
struct TestCase {
    name:       String,
    seed:       String,
    public_key: String,
    context:    String,
    message_hex:String,
    message_ascii: String,
    signature:  String,
    sig_len:    usize,
    pk_len:     usize,
    valid:      bool,
    comment:    String,
}

fn hex(b: &[u8]) -> String { ::hex::encode(b) }

fn make_case(
    name: &str,
    seed: [u8; 32],
    message: &[u8],
    context: &[u8],
    comment: &str,
    tamper: bool,
) -> TestCase {
    let kp = Keypair::from_seed(&seed).expect("valid seed");
    let mut sig = sign(&kp.secret, message, context).expect("sign ok");
    if tamper { sig[0] ^= 0xff; }
    let valid = verify(&kp.public, message, &sig, context).is_ok();
    TestCase {
        name:          name.to_string(),
        seed:          hex(&seed),
        public_key:    hex(&kp.public.0),
        context:       String::from_utf8_lossy(context).to_string(),
        message_hex:   hex(message),
        message_ascii: String::from_utf8_lossy(message).to_string(),
        signature:     hex(&sig),
        sig_len:       sig.len(),
        pk_len:        kp.public.0.len(),
        valid,
        comment:       comment.to_string(),
    }
}

fn main() {
    let vectors = vec![
        make_case(
            "ED255222-PQ-TV-1",
            [0x01; 32],
            b"Test message for Solana transaction",
            b"SOLANA-TX",
            "Basic sign/verify round-trip",
            false,
        ),
        make_case(
            "ED255222-PQ-TV-2",
            [0x02; 32],
            b"",
            b"IDENTITY",
            "Empty message, IDENTITY context",
            false,
        ),
        make_case(
            "ED255222-PQ-TV-3",
            [0x03; 32],
            b"Richard Patterson - ED255222-PQ draft-patterson-cfrg-ed255222-pq-00",
            b"MESSAGE",
            "Author signing with MESSAGE context",
            false,
        ),
        make_case(
            "ED255222-PQ-TV-4",
            [0x04; 32],
            b"DeFi protocol authorization token",
            b"DEFI-AUTH",
            "DeFi authorization context",
            false,
        ),
        make_case(
            "ED255222-PQ-TV-5-TAMPERED",
            [0x01; 32],
            b"Test message for Solana transaction",
            b"SOLANA-TX",
            "TV-1 signature with byte[0] XOR 0xff: MUST be invalid (valid=false)",
            true,
        ),
    ];

    let doc = serde_json::json!({
        "schema_version": "1.0",
        "scheme": "ED255222-PQ",
        "base": "ML-DSA-44 (FIPS 204 via fips204 crate)",
        "dst_keygen": "ED255222-PQ-KEYGEN",
        "dst_sign": "ED255222-PQ-SIGN",
        "hash_xof": "SHAKE256",
        "author": "Richard Patterson",
        "repo": "https://github.com/De-ASI-INTERFACE/ed255222-pq",
        "date": "2026-07-07",
        "params": {
            "pk_len": 1312,
            "sk_len": 2560,
            "sig_len": 2420,
            "seed_len": 32,
            "max_ctx_len": 255
        },
        "vectors": vectors,
    });

    let out = serde_json::to_string_pretty(&doc).unwrap();
    fs::write("test-vectors/ed255222-pq-tv.json", &out).expect("write ok");
    println!("[ED255222-PQ] Test vectors written to test-vectors/ed255222-pq-tv.json");
    println!("{}", out);
}
