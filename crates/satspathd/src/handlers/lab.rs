//! Admin-authorized synthetic registrations; owner private keys stay external.
use super::transparency::load_or_create_transparency_operator;
use crate::config::AppState;
use anyhow::Result;
use satspath_core::{
    lab::RegistrationChallenge, NameEvent, SignedPaymentProfile, TransactionalTransparencyStore,
};
use serde::Deserialize;

pub(crate) fn enabled() -> bool {
    std::env::var("SATSPATH_ENABLE_LAB_REGISTRATION").as_deref() == Ok("1")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReserveRequest {
    pub alias: String,
    pub identity_pubkey: String,
}

pub(crate) fn reserve(state: &AppState, body: ReserveRequest) -> Result<RegistrationChallenge> {
    // The router's admin bearer authorization is the allocation decision.
    satspath_core::lab::require_lab(&state.network, enabled(), &body.alias)?;
    let store = TransactionalTransparencyStore::open(&state.home)?;
    let operator = load_or_create_transparency_operator(&state.home)?;
    let pubkey =
        secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &operator).to_string();
    let expires = chrono::Utc::now().timestamp() + 300;
    let approval = satspath_core::sign_message(
        &satspath_core::lab::admission_message(
            store.log_id(),
            &body.alias,
            &body.identity_pubkey,
            expires,
        ),
        &operator,
    );
    Ok(store.reserve_lab_name(
        &state.network,
        enabled(),
        &body.alias,
        &body.identity_pubkey,
        &pubkey,
        &approval,
        expires,
    )?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompleteRequest {
    pub challenge: RegistrationChallenge,
    pub possession_signature: String,
    pub signed_profile: SignedPaymentProfile,
    pub event: NameEvent,
}

pub(crate) fn complete(state: &AppState, body: CompleteRequest) -> Result<serde_json::Value> {
    satspath_core::lab::require_lab(&state.network, enabled(), &body.challenge.identifier)?;
    let store = TransactionalTransparencyStore::open(&state.home)?;
    let operator = load_or_create_transparency_operator(&state.home)?;
    let candidate = store
        .load_log()?
        .prepare_append(body.event.clone(), &body.signed_profile)?;
    let checkpoint = candidate.prepare_checkpoint(&operator)?;
    store.complete_lab_registration(
        &state.network,
        enabled(),
        &body.challenge,
        &body.possession_signature,
        &body.signed_profile,
        &body.event,
        &checkpoint,
    )?;
    Ok(
        serde_json::json!({"status":"registered", "environment":"synthetic_lab", "production_payment_ready":false}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MutationRequest {
    pub signed_profile: SignedPaymentProfile,
    pub event: NameEvent,
}

pub(crate) fn mutate(state: &AppState, body: MutationRequest) -> Result<serde_json::Value> {
    use satspath_core::NameAction;
    let alias = &body.signed_profile.profile.alias;
    satspath_core::lab::require_lab(&state.network, enabled(), alias)?;
    anyhow::ensure!(
        matches!(
            body.event.action,
            NameAction::UpdateProfile | NameAction::RotateKey | NameAction::Revoke
        ),
        "only owner-signed update, rotation or revocation permitted"
    );
    let profile = &body.signed_profile.profile;
    let now = chrono::Utc::now().timestamp();
    anyhow::ensure!(
        profile.expires_at.is_some_and(|t| t > now) && profile.updated_at <= now + 300,
        "invalid profile freshness"
    );
    anyhow::ensure!(
        profile.revoked == (body.event.action == NameAction::Revoke),
        "revocation flag must match action"
    );
    let store = TransactionalTransparencyStore::open(&state.home)?;
    anyhow::ensure!(
        store.profile(alias)?.is_some(),
        "name must be registered through admission first"
    );
    let candidate = store
        .load_log()?
        .prepare_append(body.event.clone(), &body.signed_profile)?;
    let checkpoint =
        candidate.prepare_checkpoint(&load_or_create_transparency_operator(&state.home)?)?;
    store.commit_profile_event_checkpoint(alias, &body.signed_profile, &body.event, &checkpoint)?;
    Ok(
        serde_json::json!({"status":"updated","sequence":body.event.sequence,"production_payment_ready":false}),
    )
}
