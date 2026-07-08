//! Generate real ED255222-PQ test vectors and write to test-vectors/ed255222-pq-tv.json.
//!
//! Run: cargo run --bin generate-vectors

use ed255222_pq::keypair::Keypair;
use ed255222_pq::{sign, verify};
use serde::{Serialize, Deserialize};
use std::fs;

#[derive(Serialize, Deserialize)]
struct TestCase {
    name:       String,
    seed:       String,
    public_key: String,
    context:    String,
    message:    String,
    signature:  String,
    valid:      bool,
    comment:    String,
}

fn to_hex(b: &[u8]) -> String {
    hex::encode(b)
}

fn run_case(
    name: &str,
    seed: [u8; 32],
    message: &[u8],
    context: &[u8],
    comment: &str,
    tamper: bool,
) -> TestCase {
    let kp = Keypair::from_seed(&seed).expect("valid seed");
    let mut sig = sign(&kp.secret, message, context).expect("sign ok");
    if tamper {
        sig[0] ^= 0xff; // corrupt first byte
    }
    let valid = verify(&kp.public, message, &sig, context).is_ok();

    TestCase {
        name:       name.to_string(),
        seed:       to_hex(&seed),
        public_key: to_hex(&kp.public.0),
        context:    String::from_utf8_lossy(context).to_string(),
        message:    to_hex(message),
        signature:  to_hex(&sig),
        valid,
        comment:    comment.to_string(),
    }
}

fn main() {
    let vectors: Vec<TestCase> = vec![
        run_case(
            "ED255222-PQ-TV-1",
            [0x01u8; 32],
            b"Test message for Solana transaction",
            b"SOLANA-TX",
            "Basic sign/verify round-trip",
            false,
        ),
        run_case(
            "ED255222-PQ-TV-2",
            [0x02u8; 32],
            b"",
            b"IDENTITY",
            "Empty message",
            false,
        ),
        run_case(
            "ED255222-PQ-TV-3",
            [0x03u8; 32],
            b"Richard Patterson - ED255222-PQ",
            b"MESSAGE",
            "Author signing",
            false,
        ),
        run_case(
            "ED255222-PQ-TV-4-TAMPERED",
            [0x01u8; 32],
            b"Test message for Solana transaction",
            b"SOLANA-TX",
            "Tampered signature - must be invalid",
            true,
        ),
    ];

    let out = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": "1.0",
        "scheme": "ED255222-PQ",
        "base": "ML-DSA-44 (FIPS 204)",
        "dst_keygen": "ED255222-PQ-KEYGEN",
        "dst_sign": "ED255222-PQ-SIGN",
        "author": "Richard Patterson",
        "date": "2026-07-07",
        "vectors": vectors,
    })).expect("json ok");

    fs::write("test-vectors/ed255222-pq-tv.json", &out)
        .expect("write test vectors");
    println!("Test vectors written to test-vectors/ed255222-pq-tv.json");
    println!("{}", out);
}
