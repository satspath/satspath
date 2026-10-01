//! End-to-end ownership-proof flow, driven through the real `satspath` binary.
//!
//! Covers: register (saves identity key) → attach-proof → show (verified badge),
//! for both the cryptographic on-chain path and the manual self-attestation path.

use std::path::Path;
use std::process::Command;

use bitcoin::{Address, CompressedPublicKey, Network};
use satspath_core::crypto::{generate_identity_keypair, sign_message};
use satspath_core::ownership::ownership_challenge_message;
use satspath_core::registry::Registry;
use satspath_core::PaymentMethod;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_satspath")
}

fn run(dir: &Path, args: &[&str]) -> (String, String, bool) {
    let out = Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("SATSPATH_PASSWORD", "")
        .output()
        .expect("failed to run satspath binary");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.success(),
    )
}

#[test]
fn onchain_ownership_proof_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // An on-chain key the "user" controls, and its P2WPKH mainnet address.
    let addr_kp = generate_identity_keypair();
    let cpk = CompressedPublicKey::from_slice(&addr_kp.public_key.serialize()).unwrap();
    let address = Address::p2wpkh(&cpk, Network::Bitcoin).to_string();
    let addr_pubkey_hex = hex::encode(addr_kp.public_key.serialize());

    let alias = "rodrigo@satspath.dev";

    let (_o, _e, ok) = run(dir, &["init"]);
    assert!(ok, "init failed");
    let (_o, _e, ok) = run(
        dir,
        &[
            "register",
            alias,
            "--ln-address",
            "trujasx@blink.sv",
            "--onchain",
            &address,
        ],
    );
    assert!(ok, "register failed");

    // Read the freshly-signed profile to learn the identity pubkey and the
    // on-chain method's index + descriptor (registry stores unmasked data).
    let (identity_pubkey, method_index, descriptor) = {
        let reg = Registry::open(&dir.join(".satspath")).unwrap();
        let signed = reg.resolve_alias(alias).unwrap();
        let (idx, method) = signed
            .profile
            .methods
            .iter()
            .enumerate()
            .find(|(_, m)| matches!(m, PaymentMethod::Onchain { .. }))
            .expect("onchain method present");
        (
            signed.profile.identity_pubkey.clone(),
            idx,
            method.ownership_descriptor(),
        )
    };

    // The address key holder signs the SatsPath challenge externally.
    let issued_at: i64 = 1_700_000_000;
    let message = ownership_challenge_message(&identity_pubkey, &descriptor, issued_at);
    let signature = sign_message(&message, &addr_kp.secret_key);

    // Attach the public signature material; the profile is re-signed internally.
    let (out, err, ok) = run(
        dir,
        &[
            "attach-proof",
            alias,
            "--method-index",
            &method_index.to_string(),
            "--type",
            "onchain",
            "--issued-at",
            &issued_at.to_string(),
            "--pubkey",
            &addr_pubkey_hex,
            "--signature",
            &signature,
        ],
    );
    assert!(ok, "attach-proof failed: {err}{out}");
    assert!(out.contains("verified"), "attach output: {out}");

    // `show` must now display the cryptographic badge for the on-chain method.
    let (out, _e, ok) = run(dir, &["show", alias]);
    assert!(ok, "show failed");
    assert!(
        out.contains("verified · cryptographic"),
        "show did not report cryptographic verification:\n{out}"
    );
    assert!(
        out.contains("1 of 2 method(s) independently verified"),
        "ownership summary wrong:\n{out}"
    );
}

#[test]
fn manual_self_attestation_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let alias = "alice@satspath.dev";

    assert!(run(dir, &["init"]).2);
    assert!(
        run(
            dir,
            &[
                "register",
                alias,
                "--ln-address",
                "alice@walletofsatoshi.com"
            ]
        )
        .2
    );

    // Self-attest the Lightning method (index 0) — no external signature needed.
    let (out, err, ok) = run(
        dir,
        &[
            "attach-proof",
            alias,
            "--method-index",
            "0",
            "--type",
            "manual",
        ],
    );
    assert!(ok, "manual attach failed: {err}{out}");

    let (out, _e, ok) = run(dir, &["show", alias]);
    assert!(ok);
    assert!(
        out.contains("self-asserted"),
        "manual attestation badge missing:\n{out}"
    );
}

#[test]
fn domain_control_proof_via_body_file_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    // The Lightning Address domain (example.com) is what the proof binds to; the
    // well-known URL https://example.com/.well-known/satspath/alice is derived.
    let alias = "alice@example.com";

    assert!(run(dir, &["init"]).2);
    assert!(
        run(
            dir,
            &["register", alias, "--ln-address", "alice@example.com"]
        )
        .2
    );

    // Learn the identity pubkey to put in the served file.
    let identity_pubkey = {
        let reg = Registry::open(&dir.join(".satspath")).unwrap();
        reg.resolve_alias(alias)
            .unwrap()
            .profile
            .identity_pubkey
            .clone()
    };

    // Write the content the domain "serves": it must contain the identity pubkey.
    let served = dir.join("served.txt");
    std::fs::write(&served, format!("satspath-identity={identity_pubkey}\n")).unwrap();

    // Attach a domain proof, verifying the local served copy (no network needed).
    let (out, err, ok) = run(
        dir,
        &[
            "attach-proof",
            alias,
            "--method-index",
            "0",
            "--type",
            "domain",
            "--body-file",
            served.to_str().unwrap(),
        ],
    );
    assert!(ok, "domain attach failed: {err}{out}");
    assert!(
        out.contains("verified · domain control"),
        "attach should report domain control at mint time:\n{out}"
    );

    // Offline `show` is honest: it did not fetch, so the proof is "claimed".
    let (out, _e, ok) = run(dir, &["show", alias]);
    assert!(ok);
    assert!(
        out.contains("claimed · domain control"),
        "offline show should report claimed (re-verify on fetch):\n{out}"
    );
}

#[test]
fn domain_proof_rejects_body_missing_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let alias = "bob@example.com";

    assert!(run(dir, &["init"]).2);
    assert!(run(dir, &["register", alias, "--ln-address", "bob@example.com"]).2);

    // Served content does NOT contain the identity pubkey → must be rejected.
    let served = dir.join("bad.txt");
    std::fs::write(&served, "nothing useful here\n").unwrap();

    let (_o, _e, ok) = run(
        dir,
        &[
            "attach-proof",
            alias,
            "--method-index",
            "0",
            "--type",
            "domain",
            "--body-file",
            served.to_str().unwrap(),
        ],
    );
    assert!(!ok, "a body without the identity binding must be rejected");
}

#[test]
fn attach_proof_rejects_forged_onchain_signature() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let alias = "mallory@satspath.dev";

    // Register with an address controlled by key A...
    let real_kp = generate_identity_keypair();
    let cpk = CompressedPublicKey::from_slice(&real_kp.public_key.serialize()).unwrap();
    let address = Address::p2wpkh(&cpk, Network::Bitcoin).to_string();

    assert!(run(dir, &["init"]).2);
    assert!(run(dir, &["register", alias, "--onchain", &address]).2);

    let (identity_pubkey, idx, descriptor) = {
        let reg = Registry::open(&dir.join(".satspath")).unwrap();
        let signed = reg.resolve_alias(alias).unwrap();
        let (idx, m) = signed
            .profile
            .methods
            .iter()
            .enumerate()
            .find(|(_, m)| matches!(m, PaymentMethod::Onchain { .. }))
            .unwrap();
        (
            signed.profile.identity_pubkey.clone(),
            idx,
            m.ownership_descriptor(),
        )
    };

    // ...but sign with an UNRELATED key B that does not control the address.
    let forger = generate_identity_keypair();
    let issued_at: i64 = 1_700_000_000;
    let message = ownership_challenge_message(&identity_pubkey, &descriptor, issued_at);
    let forged_sig = sign_message(&message, &forger.secret_key);
    let forged_pubkey = hex::encode(forger.public_key.serialize());

    let (_out, _err, ok) = run(
        dir,
        &[
            "attach-proof",
            alias,
            "--method-index",
            &idx.to_string(),
            "--type",
            "onchain",
            "--issued-at",
            &issued_at.to_string(),
            "--pubkey",
            &forged_pubkey,
            "--signature",
            &forged_sig,
        ],
    );
    assert!(
        !ok,
        "a key that does not control the address must be rejected"
    );
}
