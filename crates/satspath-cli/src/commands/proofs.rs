//! `satspath prove` and `satspath attach-proof` — mint ownership proofs.
//!
//! Key-safe by design. SatsPath never handles a method's spending key:
//! - on-chain / Ark: the key holder signs a challenge in their own wallet; only
//!   the public signature is attached.
//! - domain (LN): the domain serves a file containing the identity pubkey, which
//!   SatsPath fetches and verifies.
//! - manual: identity self-attestation (weakest tier).
//!
//! Attaching a proof re-signs the profile with the locally stored identity key.

use anyhow::Result;

use satspath_core::{
    attach_signature_proof, attach_well_known_proof, build_manual_attestation,
    crypto::sign_profile, evaluate_method_trust, ownership_challenge_message,
    upsert_method_verification, well_known_url_for_method, PaymentMethod, ProofType,
};

use super::{keystore, open_registry, satspath_dir};

fn method_at(profile: &satspath_core::PaymentProfile, index: usize) -> Result<&PaymentMethod> {
    profile.methods.get(index).ok_or_else(|| {
        anyhow::anyhow!(
            "no method at index {index} — profile has {} method(s) (0..{})",
            profile.methods.len(),
            profile.methods.len().saturating_sub(1)
        )
    })
}

/// Print what a method's key/domain holder must do to prove ownership.
pub fn cmd_prove(alias: &str, method_index: usize) -> Result<()> {
    let registry = open_registry()?;
    let signed = registry
        .resolve_alias(alias)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let method = method_at(&signed.profile, method_index)?;
    let identity_pubkey = &signed.profile.identity_pubkey;
    let descriptor = method.ownership_descriptor();

    println!(
        "Method [{method_index}]: {} — {descriptor}",
        method.method_name()
    );
    println!();

    match method {
        PaymentMethod::Lightning { .. } => {
            if let Some(url) = well_known_url_for_method(method) {
                println!("Prove control of this Lightning address's DOMAIN by serving a file");
                println!("containing your identity pubkey at:");
                println!("  {url}");
                println!();
                println!("Minimum content to serve (any file containing this line works):");
                println!("  satspath-identity={identity_pubkey}");
                println!();
                println!("Then attach — SatsPath fetches the URL and verifies it:");
                println!(
                    "  satspath attach-proof {alias} --method-index {method_index} --type domain"
                );
                println!();
                println!("Already serving it? Verify from your local copy instead of fetching:");
                println!(
                    "  satspath attach-proof {alias} --method-index {method_index} --type domain \\"
                );
                println!("    --body-file served.txt");
            } else {
                println!("No standard ownership proof supported for this Lightning pointer yet.");
            }
            println!();
            println!("Or a self-attestation only (weakest tier, no domain needed):");
            println!("  satspath attach-proof {alias} --method-index {method_index} --type manual");
        }
        PaymentMethod::Bolt12(_) => {
            println!("Prove control of this BOLT12 offer by providing a signature over the identity pubkey");
            println!("signed by the BOLT12 offer issuer key.");
            println!("(Interactive challenge coming soon)");
        }
        PaymentMethod::Onchain { .. } | PaymentMethod::Ark { .. } => {
            let issued_at = chrono::Utc::now().timestamp();
            let message = ownership_challenge_message(identity_pubkey, &descriptor, issued_at);
            let suggested = if matches!(method, PaymentMethod::Onchain { .. }) {
                "onchain"
            } else {
                "ark"
            };
            println!("Sign EXACTLY this challenge with the key that controls the method");
            println!("(your wallet's signmessage for on-chain, your Ark tool for Ark):");
            println!();
            println!("----- BEGIN SATSPATH CHALLENGE -----");
            println!("{message}");
            println!("----- END SATSPATH CHALLENGE -----");
            println!();
            println!("Then attach (no private key needed by SatsPath):");
            println!("  satspath attach-proof {alias} \\");
            println!(
                "    --method-index {method_index} --type {suggested} --issued-at {issued_at} \\"
            );
            println!("    --pubkey <compressed-pubkey-hex> --signature <der-signature-hex>");
        }
    }
    Ok(())
}

/// Fetch the body served at a well-known URL.
async fn fetch_body(url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let resp = client.get(url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("fetching {url} returned HTTP {status}");
    }
    Ok(resp.text().await?)
}

/// Attach a proof to a method and re-sign the profile.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_attach_proof(
    alias: &str,
    method_index: usize,
    proof_type: &str,
    issued_at: Option<i64>,
    pubkey: Option<&str>,
    signature: Option<&str>,
    url: Option<&str>,
    nonce: Option<&str>,
    body_file: Option<&str>,
    expires_in: Option<i64>,
) -> Result<()> {
    let mut registry = open_registry()?;
    let signed = registry
        .resolve_alias(alias)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .clone();
    let method = method_at(&signed.profile, method_index)?.clone();
    let identity_pubkey = signed.profile.identity_pubkey.clone();

    // We must re-sign the profile, so the identity key has to be available locally.
    let identity_key = keystore::load_identity_key(&satspath_dir(), &identity_pubkey)?;

    let now = chrono::Utc::now().timestamp();
    // For domain proofs we hold the served body here, so the final badge can show
    // the true tier (✓ domain control) rather than "needs network check".
    let mut well_known_body: Option<String> = None;
    let verification = match proof_type {
        "onchain" | "ark" => {
            let proof = if proof_type == "onchain" {
                ProofType::OnchainAddressSignature
            } else {
                ProofType::ArkPubkeySignature
            };
            let issued = issued_at.ok_or_else(|| {
                anyhow::anyhow!(
                    "--issued-at is required for {proof_type} proofs (use the value \
                     printed by `satspath prove`)"
                )
            })?;
            let pk = pubkey
                .ok_or_else(|| anyhow::anyhow!("--pubkey is required for {proof_type} proofs"))?;
            let sig = signature.ok_or_else(|| {
                anyhow::anyhow!("--signature is required for {proof_type} proofs")
            })?;
            let expires_at = expires_in.map(|s| issued + s);
            attach_signature_proof(
                &method,
                &identity_pubkey,
                proof,
                pk,
                sig,
                issued,
                expires_at,
            )
            .map_err(|e| anyhow::anyhow!("proof rejected: {e}"))?
        }
        "domain" => {
            let issued = issued_at.unwrap_or(now);
            let expires_at = expires_in.map(|s| issued + s);
            let (proof, default_url) = match &method {
                PaymentMethod::Lightning { .. } => (
                    ProofType::LightningAddressChallenge,
                    well_known_url_for_method(&method),
                ),
                _ => (ProofType::DomainWellKnown, None),
            };
            let resolved_url = url.map(str::to_string).or(default_url).ok_or_else(|| {
                anyhow::anyhow!("--url is required for domain proofs on non-Lightning methods")
            })?;
            let nonce_val = nonce.unwrap_or(identity_pubkey.as_str()).to_string();
            let body = match body_file {
                Some(path) => std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("reading --body-file {path}: {e}"))?,
                None => fetch_body(&resolved_url).await?,
            };
            well_known_body = Some(body.clone());
            attach_well_known_proof(
                &method,
                &identity_pubkey,
                proof,
                &resolved_url,
                &nonce_val,
                &body,
                issued,
                expires_at,
            )
            .map_err(|e| anyhow::anyhow!("proof rejected: {e}"))?
        }
        "manual" => {
            let issued = issued_at.unwrap_or(now);
            let expires_at = expires_in.map(|s| issued + s);
            build_manual_attestation(&method, &identity_pubkey, &identity_key, issued, expires_at)
                .map_err(|e| anyhow::anyhow!("{e}"))?
        }
        other => {
            anyhow::bail!("unknown --type '{other}' (expected: onchain | ark | domain | manual)")
        }
    };

    // Attach + re-sign + persist.
    let mut profile = signed.profile.clone();
    upsert_method_verification(&mut profile.method_verifications, verification);
    profile.updated_at = now;
    profile.sequence = profile.sequence.map(|s| s + 1).or(Some(1));
    let resigned = sign_profile(profile, &identity_key).map_err(|e| anyhow::anyhow!("{e}"))?;
    registry
        .update_profile(resigned.clone())
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let trust = evaluate_method_trust(
        &method,
        &identity_pubkey,
        &resigned.profile.method_verifications,
        now,
        well_known_body.as_deref(),
    );
    println!(
        "Attached {} proof to method [{method_index}] {}.",
        proof_type,
        method.method_name()
    );
    println!("Ownership now: {}", trust.badge());
    println!("Profile re-signed and updated in .satspath/registry.json");
    Ok(())
}
