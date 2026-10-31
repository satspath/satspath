//! Lab-only client. Usage and out-of-band bootstrap: docs/secure-identity-lab.md.
use anyhow::{bail, ensure, Context, Result};
use satspath_core::{lab::*, transparency::*, *};
use serde::de::DeserializeOwned;
use std::{path::Path, time::Duration};

async fn json<T: DeserializeOwned>(request: reqwest::RequestBuilder) -> Result<T> {
    let mut response = request.send().await?.error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 65_536,
            "response exceeds 64 KiB"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn endpoint(pin: &NamespaceDescriptor) -> Result<String> {
    ensure!(
        pin.verify(chrono::Utc::now().timestamp())?,
        "invalid/expired trusted descriptor"
    );
    ensure!(
        pin.domain == LAB_NAMESPACE && (1..=8).contains(&pin.endpoint_urls.len()),
        "lab descriptor required"
    );
    let base = pin.endpoint_urls[0].trim_end_matches('/');
    let url = url::Url::parse(base)?;
    let loopback = url.host_str().is_some_and(|h| {
        h == "localhost"
            || h.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "HTTPS or loopback HTTP required"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "endpoint must be an origin"
    );
    Ok(base.into())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(args.len() >= 2, "bootstrap AUTHORITY_HOME ORIGIN OUTPUT | register PIN CLIENT_HOME ALIAS LIGHTNING_ADDRESS | resolve PIN CLIENT_HOME ALIAS");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    if args[1] == "verify-transport" {
        ensure!(
            args.len() == 5,
            "verify-transport PIN ENVELOPE PUBLIC_PROFILE"
        );
        let pin: NamespaceDescriptor = serde_json::from_slice(&std::fs::read(&args[2])?)?;
        let envelope: ResolutionEnvelope = serde_json::from_slice(&std::fs::read(&args[3])?)?;
        let candidate: SignedPaymentProfile = serde_json::from_slice(&std::fs::read(&args[4])?)?;
        ensure!(
            profile_hash(&candidate)? == profile_hash(&envelope.signed_profile)?,
            "transport profile differs from authenticated S2S state"
        );
        verify_resolution(
            &envelope.identifier,
            &pin,
            &envelope,
            None,
            chrono::Utc::now().timestamp(),
        )?;
        println!("Public transport profile matches independently verified S2S evidence; synthetic lab only, not payment-ready.");
        return Ok(());
    }
    if args[1] == "bootstrap" {
        ensure!(args.len() == 5, "bootstrap AUTHORITY_HOME ORIGIN OUTPUT");
        let home = Path::new(&args[2]);
        let pin: NamespaceDescriptor = json(client.get(format!(
            "{}/.well-known/satspath-authority",
            args[3].trim_end_matches('/')
        )))
        .await?;
        let operator = secp256k1::SecretKey::from_slice(&hex::decode(
            std::fs::read_to_string(home.join("transparency/operator.key"))?.trim(),
        )?)?;
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &operator)
            .to_string();
        ensure!(
            pin.authority_pubkey == pubkey
                && pin.log_id == TransactionalTransparencyStore::open_read_only(home)?.log_id(),
            "descriptor differs from local operator state"
        );
        ensure!(
            endpoint(&pin)? == args[3].trim_end_matches('/'),
            "endpoint mismatch"
        );
        write_new(Path::new(&args[4]), &serde_json::to_vec_pretty(&pin)?)?;
        println!("Trusted lab descriptor exported; transfer through an authenticated channel.");
        return Ok(());
    }
    ensure!(
        args.len() >= 5,
        "register/resolve PIN CLIENT_HOME ALIAS [LIGHTNING_ADDRESS]"
    );
    let pin: NamespaceDescriptor = serde_json::from_slice(&std::fs::read(&args[2])?)?;
    let base = endpoint(&pin)?;
    let home = Path::new(&args[3]);
    std::fs::create_dir_all(home)?;
    let alias = &args[4];
    require_lab("regtest", true, alias)?;
    if args[1] == "register" {
        ensure!(
            args.len() == 6,
            "register PIN CLIENT_HOME ALIAS LIGHTNING_ADDRESS"
        );
        validation::validate_lightning_address(&args[5])?;
        let path = home.join("lab-identity.key");
        if !path.try_exists()? {
            write_new(
                &path,
                hex::encode(generate_identity_keypair().secret_key.secret_bytes()).as_bytes(),
            )?;
        }
        let secret =
            secp256k1::SecretKey::from_slice(&hex::decode(std::fs::read_to_string(path)?.trim())?)?;
        let key = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret)
            .to_string();
        // This is operator-assisted admission; never distribute this token to hosted users.
        let token = std::env::var("SATSPATHD_AUTH_TOKEN")
            .context("operator authorization token required for lab admission")?;
        let challenge: RegistrationChallenge = json(
            client
                .post(format!("{base}/v1/lab/registrations/reserve"))
                .bearer_auth(&token)
                .json(&serde_json::json!({"alias":alias,"identity_pubkey":key})),
        )
        .await?;
        let now = chrono::Utc::now().timestamp();
        ensure!(
            challenge.identifier == *alias
                && challenge.identity_pubkey == key
                && challenge.namespace == LAB_NAMESPACE
                && challenge.log_id == pin.log_id
                && challenge.authority_pubkey == pin.authority_pubkey
                && challenge.operation == "register"
                && challenge.expires_at > now
                && challenge.expires_at <= now + 600,
            "challenge binding rejected"
        );
        let signed = sign_profile(
            PaymentProfile {
                alias: alias.clone(),
                identity_pubkey: key,
                methods: vec![PaymentMethod::Lightning {
                    label: "lab self-asserted".into(),
                    lightning_address: Some(args[5].clone()),
                    lnurl: None,
                    bolt12: None,
                    receiver_pubkey: None,
                }],
                updated_at: now,
                expires_at: Some(now + 3600),
                sequence: Some(0),
                preferences: vec![],
                nonce: Some(generate_nonce()),
                rotation: None,
                method_verifications: vec![],
                hybrid_pubkey: None,
                pqc_required: false,
                revoked: false,
            },
            &secret,
        )?;
        let mut event = NameEvent {
            version: 1,
            identifier_hash: identifier_hash(alias),
            action: NameAction::Register,
            identity_pubkey: signed.profile.identity_pubkey.clone(),
            profile_hash: profile_hash(&signed)?,
            sequence: 0,
            previous_event_hash: None,
            created_at: now,
            identifier_attestation_hash: None,
            removed_method_hashes: vec![],
            rotation: None,
            owner_signature: String::new(),
        };
        event.sign(&secret)?;
        let response: serde_json::Value = json(client.post(format!("{base}/v1/lab/registrations/complete")).bearer_auth(token)
            .json(&serde_json::json!({"possession_signature":sign_message(&challenge.signing_message()?, &secret),
                "challenge":challenge,"signed_profile":signed,"event":event}))).await?;
        ensure!(
            response.get("status").and_then(|v| v.as_str()) == Some("registered"),
            "registration rejected"
        );
        println!("{response}");
    } else if args[1] == "update" {
        ensure!(
            args.len() == 6,
            "update PIN OWNER_HOME ALIAS LIGHTNING_ADDRESS"
        );
        validation::validate_lightning_address(&args[5])?;
        let secret = secp256k1::SecretKey::from_slice(&hex::decode(
            std::fs::read_to_string(home.join("lab-identity.key"))?.trim(),
        )?)?;
        let prior = fetch_lab_resolution(&pin, &base, alias, None)
            .await
            .map_err(|e| anyhow::anyhow!("authority evidence rejected: {e:?}"))?;
        let old = prior.name_events.last().context("missing owner history")?;
        let mut profile = prior.signed_profile.profile.clone();
        let key = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret)
            .to_string();
        ensure!(
            profile.identity_pubkey == key,
            "local key is not current owner"
        );
        let now = chrono::Utc::now().timestamp();
        profile.updated_at = now;
        profile.expires_at = Some(now + 3600);
        profile.sequence = Some(old.sequence.checked_add(1).context("sequence exhausted")?);
        profile.nonce = Some(generate_nonce());
        // Destination edits invalidate previous method ownership proofs.
        profile.method_verifications.clear();
        profile.methods = vec![PaymentMethod::Lightning {
            label: "lab self-asserted".into(),
            lightning_address: Some(args[5].clone()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }];
        let signed = sign_profile(profile, &secret)?;
        let mut event = NameEvent {
            version: 1,
            identifier_hash: identifier_hash(alias),
            action: NameAction::UpdateProfile,
            identity_pubkey: key,
            profile_hash: profile_hash(&signed)?,
            sequence: old.sequence + 1,
            previous_event_hash: Some(old.event_hash()?),
            created_at: now,
            identifier_attestation_hash: None,
            removed_method_hashes: vec![],
            rotation: None,
            owner_signature: String::new(),
        };
        event.sign(&secret)?;
        let token =
            std::env::var("SATSPATHD_AUTH_TOKEN").context("operator lab authorization required")?;
        let response: serde_json::Value = json(
            client
                .post(format!("{base}/v1/lab/profiles/mutate"))
                .bearer_auth(token)
                .json(&serde_json::json!({"signed_profile":signed,"event":event})),
        )
        .await?;
        ensure!(
            response.get("status").and_then(|v| v.as_str()) == Some("updated"),
            "update rejected"
        );
    } else if args[1] != "resolve" {
        bail!("unknown command");
    }
    let pins = CheckpointStore::new(home);
    let previous = pins.load()?.into_iter().find(|p| p.log_id == pin.log_id);
    let (source, envelope) = resolve_lab_network(&pin, alias, previous.as_ref()).await?;
    pins.pin(&envelope.checkpoint)?;
    println!(
        "{}",
        serde_json::json!({"identifier":alias,"environment":"synthetic_lab",
        "namespace_trust":"explicit_operator_pin","owner_signature":"verified_locally",
        "log_inclusion":"verified_locally","current_state":"verified_locally",
        "witness_quorum":if pin.witness_quorum == 0 {"not_deployed"} else {"policy_satisfied"},
        "trust_status":if pin.witness_quorum == 0 {"degraded_unwitnessed_lab"} else {"synthetic_lab_with_witness_evidence"},
        "method_ownership":"not_verified",
        "production_payment_ready":false,"served_by":source,"max_checkpoint_age_seconds":300,"profile_sequence":envelope.signed_profile.profile.sequence,"tree_size":envelope.checkpoint.log_size})
    );
    Ok(())
}
