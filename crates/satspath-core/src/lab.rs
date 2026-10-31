//! Explicit, synthetic namespace admission. Never a production delegation proof.
use crate::{Result, SatsPathError};
use serde::{Deserialize, Serialize};

pub const LAB_NAMESPACE: &str = "lab.satspath.test";

pub fn require_lab(network: &str, enabled: bool, alias: &str) -> Result<()> {
    let local = alias.strip_suffix("@lab.satspath.test").unwrap_or("");
    if !enabled
        || !matches!(network, "regtest" | "devnet")
        || local.is_empty()
        || local.len() > 64
        || !local
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
    {
        return Err(SatsPathError::RegistryError("synthetic registration requires explicit regtest/devnet lab mode and a canonical lab.satspath.test alias".into()));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistrationChallenge {
    pub namespace: String,
    pub identifier: String,
    pub identity_pubkey: String,
    pub log_id: String,
    pub authority_pubkey: String,
    pub operation: String,
    pub nonce: String,
    pub expires_at: i64,
}

impl RegistrationChallenge {
    pub fn signing_message(&self) -> Result<String> {
        Ok(format!(
            "SatsPathLabRegistrationV1\n{}",
            serde_json::to_string(self)?
        ))
    }
}

/// Operator approval is distinct from owner proof of possession. Sign this on
/// the authority only, after authorizing allocation to the indicated public key.
pub fn admission_message(log_id: &str, alias: &str, pubkey: &str, expires_at: i64) -> String {
    format!("SatsPathLabAdmissionV1\n{LAB_NAMESPACE}\n{log_id}\n{alias}\n{pubkey}\nregister\n{expires_at}")
}

/// Offline verification against an OUT-OF-BAND trusted descriptor, never one
/// learned solely from the responding server. Zero witnesses is lab-only trust.
/// The returned checkpoint must be pinned by the client after success.
pub fn verify_resolution(
    expected_identifier: &str,
    trusted: &crate::transparency::NamespaceDescriptor,
    envelope: &crate::transparency::ResolutionEnvelope,
    previous: Option<&crate::PinnedCheckpoint>,
    now: i64,
) -> Result<()> {
    use crate::transparency::*;
    let fail = || SatsPathError::RegistryError("lab resolution evidence rejected".into());
    require_lab("regtest", true, expected_identifier)?;
    let descriptor = &envelope.namespace_descriptor;
    if !trusted.verify(now)?
        || !descriptor.verify(now)?
        || trusted.domain != LAB_NAMESPACE
        || descriptor.domain != trusted.domain
        || descriptor.log_id != trusted.log_id
        || descriptor.authority_pubkey != trusted.authority_pubkey
        || descriptor.endpoint_urls != trusted.endpoint_urls
        || descriptor.witness_quorum != trusted.witness_quorum
        || descriptor.witness_pubkeys != trusted.witness_pubkeys
        || envelope.version != 2
        || envelope.identifier != expected_identifier
        || envelope.signed_profile.profile.alias != expected_identifier
        || envelope.checkpoint.log_id != trusted.log_id
        || envelope.checkpoint.operator_pubkey != trusted.authority_pubkey
        || envelope.name_events.is_empty()
        || envelope.name_events.len() > 256
        || !crate::verify_signed_profile(&envelope.signed_profile)?
    {
        return Err(fail());
    }
    let profile = &envelope.signed_profile.profile;
    if profile.revoked
        || profile.expires_at.is_none_or(|t| t <= now)
        || profile.updated_at > now + 300
        || envelope.checkpoint.created_at > now + 300
        || envelope.checkpoint.created_at < now - 300
    {
        return Err(fail());
    }
    verify_identifier_history(&envelope.name_events)?;
    let latest = envelope.name_events.last().ok_or_else(fail)?;
    if latest.identifier_hash != crate::identifier_hash(expected_identifier)
        || latest.action == NameAction::Revoke
        || !verify_event_profile(latest, &envelope.signed_profile)?
    {
        return Err(fail());
    }
    let hash = latest.event_hash()?;
    verify_checkpoint_inclusion(&hash, &envelope.inclusion_proof, &envelope.checkpoint)?;
    let state = envelope.current_state_proof.as_ref().ok_or_else(fail)?;
    verify_checkpoint_state_binding(state, &envelope.checkpoint)?;
    let value = state.value.as_ref().ok_or_else(fail)?;
    if state.key_hash != latest.identifier_hash
        || value.latest_event_hash != hash
        || value.sequence != latest.sequence
        || value.status != IdentifierStatus::Registered
    {
        return Err(fail());
    }
    if let Some(pin) = previous {
        if pin.tree_size == envelope.checkpoint.log_size
            && pin.checkpoint_hash != envelope.checkpoint.checkpoint_hash()?
        {
            return Err(fail());
        }
        verify_checkpoint_transition(
            pin,
            &envelope.checkpoint,
            envelope.consistency_proof.as_ref(),
        )?;
    }
    if trusted.witness_quorum > 0
        && !matches!(
            verify_witness_quorum_against_checkpoint(
                Some(&envelope.checkpoint),
                &envelope.witness_cosignatures,
                trusted.witness_quorum,
                &trusted.witness_pubkeys
            ),
            DimensionStatus::Verified
        )
    {
        return Err(fail());
    }
    Ok(())
}
