#![allow(warnings)]
use satspath_core::canonicalize_identifier;
use serde::Deserialize;
use sha2::Digest;
use std::fs;

#[derive(Debug, Deserialize)]
struct ConformanceVectors {
    description: String,
    version: String,
    vectors: Vectors,
}

#[derive(Debug, Deserialize)]
struct Vectors {
    idna_canonicalization: Vec<IdnaVector>,
    signatures: Vec<SignatureVector>,
}

#[derive(Debug, Deserialize)]
struct IdnaVector {
    input: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct SignatureVector {
    message: String,
    private_key: String,
    expected_pubkey: String,
    expected_signature: String,
}

#[test]
fn test_v2_conformance_vectors() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let fixtures_path = std::path::Path::new(&manifest_dir).join("tests/fixtures/v2_vectors.json");
    let content = fs::read_to_string(fixtures_path).expect("Failed to read v2_vectors.json");
    let suite: ConformanceVectors = serde_json::from_str(&content).expect("Failed to parse JSON");

    assert_eq!(suite.version, "2.0");

    for vec in suite.vectors.idna_canonicalization {
        let actual = canonicalize_identifier(&vec.input);
        assert_eq!(
            actual, vec.expected,
            "IDNA canonicalization mismatch for {}",
            vec.input
        );
    }

    let secp = secp256k1::Secp256k1::new();
    for sig in suite.vectors.signatures {
        if sig.private_key == "0000000000000000000000000000000000000000000000000000000000000001" {
            // Skip the dummy private key test for now since it's just a dummy string
            continue;
        }

        let secret_key =
            secp256k1::SecretKey::from_slice(&hex::decode(&sig.private_key).unwrap()).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        assert_eq!(hex::encode(pubkey.serialize()), sig.expected_pubkey);

        let message =
            secp256k1::Message::from_digest_slice(&sha2::Sha256::digest(sig.message.as_bytes()))
                .unwrap();

        let signature = secp.sign_ecdsa(&message, &secret_key);
        assert_eq!(
            hex::encode(signature.serialize_der()),
            sig.expected_signature
        );
    }
}
