//! Shared client/replica verification. Transport never establishes authority.
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::*;
use crate::{Result, SatsPathError};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustMode {
    Public,
    /// Explicitly permits zero witnesses. Never inferred from missing config.
    Laboratory,
}

/// This policy must arrive from independent trusted configuration, never from
/// the peer being queried. A signed descriptor is not a DNS ownership proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolutionTrustPolicy {
    pub descriptor: NamespaceDescriptor,
    pub freshness: FreshnessPolicy,
    pub mode: TrustMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointLink {
    pub cursor: CheckpointCursor,
    pub consistency: Option<MerkleConsistencyProof>,
}

fn db_error(error: impl std::fmt::Display) -> SatsPathError {
    SatsPathError::RegistryError(format!("replica database: {error}"))
}

impl ResolutionTrustPolicy {
    pub fn validate(&self, now: i64) -> Result<()> {
        self.freshness.validate()?;
        let d = &self.descriptor;
        if !d.verify(now)?
            || d.domain.is_empty()
            || d.domain != d.domain.to_ascii_lowercase()
            || d.log_id.is_empty()
            || d.endpoint_urls.len() > 8
            || (self.mode == TrustMode::Public && d.witness_quorum == 0)
        {
            return Err(TransparencyError::TrustPolicyMismatch.into());
        }
        if self.mode == TrustMode::Public {
            for url in &d.endpoint_urls {
                crate::outbound::validate_request_url(url)?;
            }
        }
        Ok(())
    }

    fn verify_head(&self, checkpoint: &TransparencyCheckpoint, now: i64) -> Result<()> {
        if checkpoint.log_id != self.descriptor.log_id
            || checkpoint.operator_pubkey != self.descriptor.authority_pubkey
        {
            return Err(TransparencyError::UnexpectedOperatorKey.into());
        }
        if !verify_checkpoint(checkpoint)? {
            return Err(TransparencyError::InvalidCheckpointSignature.into());
        }
        self.freshness.check(checkpoint, now)
    }

    fn verify_envelope(&self, envelope: &ResolutionEnvelope, now: i64) -> Result<()> {
        let invalid = || SatsPathError::from(TransparencyError::InvalidResolutionEvidence);
        let profile = &envelope.signed_profile.profile;
        if envelope.version != 2
            || envelope.namespace_descriptor != self.descriptor
            || envelope.identifier != crate::canonical_identifier(&envelope.identifier)
            || envelope
                .identifier
                .rsplit_once('@')
                .map(|(_, domain)| domain)
                != Some(self.descriptor.domain.as_str())
            || profile.alias != envelope.identifier
            || profile.expires_at.is_none_or(|expiry| expiry <= now)
            || profile.updated_at > now.saturating_add(self.freshness.future_skew_secs)
            || envelope.name_events.is_empty()
            || envelope.name_events.len() > 256
        {
            return Err(invalid());
        }
        self.verify_head(&envelope.checkpoint, now)?;
        verify_identifier_history(&envelope.name_events)?;
        let event = envelope.name_events.last().ok_or_else(invalid)?;
        if event.identifier_hash != crate::identifier_hash(&envelope.identifier)
            || profile.sequence != Some(event.sequence)
            || !verify_event_profile(event, &envelope.signed_profile)?
        {
            return Err(invalid());
        }
        let hash = event.event_hash()?;
        verify_checkpoint_inclusion(&hash, &envelope.inclusion_proof, &envelope.checkpoint)?;
        let proof = envelope.current_state_proof.as_ref().ok_or_else(invalid)?;
        verify_checkpoint_state_binding(proof, &envelope.checkpoint)?;
        let value = proof.value.as_ref().ok_or_else(invalid)?;
        let revoked = event.action == NameAction::Revoke;
        if proof.key_hash != event.identifier_hash
            || value.latest_event_hash != hash
            || value.sequence != event.sequence
            || profile.revoked != revoked
            || value.status
                != if revoked {
                    IdentifierStatus::Revoked
                } else {
                    IdentifierStatus::Registered
                }
        {
            return Err(invalid());
        }
        if self.descriptor.witness_quorum > 0
            && verify_witness_quorum_against_checkpoint(
                Some(&envelope.checkpoint),
                &envelope.witness_cosignatures,
                self.descriptor.witness_quorum,
                &self.descriptor.witness_pubkeys,
            ) != DimensionStatus::Verified
        {
            return Err(TransparencyError::WitnessQuorumNotMet.into());
        }
        Ok(())
    }
}

impl TransactionalTransparencyStore {
    /// Pins the entire policy exactly once. Changes, including lab downgrade,
    /// require a future explicit authenticated migration workflow.
    pub fn pin_resolution_policy(&self, policy: &ResolutionTrustPolicy, now: i64) -> Result<()> {
        policy.validate(now)?;
        let connection = self.connection()?;
        let raw = serde_json::to_string(policy)?;
        connection
            .execute(
                "INSERT OR IGNORE INTO replica_trust(log_id, policy_json) VALUES (?1, ?2)",
                params![policy.descriptor.log_id, raw],
            )
            .map_err(db_error)?;
        let pinned: String = connection
            .query_row(
                "SELECT policy_json FROM replica_trust WHERE log_id=?1",
                [&policy.descriptor.log_id],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if pinned != raw {
            return Err(TransparencyError::TrustPolicyMismatch.into());
        }
        Ok(())
    }

    pub fn replica_cursor(&self, log_id: &str) -> Result<Option<CheckpointCursor>> {
        let raw: Option<String> = self
            .connection()?
            .query_row(
                "SELECT cursor_json FROM replica_trust WHERE log_id=?1",
                [log_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?
            .flatten();
        raw.map(|raw| serde_json::from_str(&raw).map_err(Into::into))
            .transpose()
    }

    /// Verify a bounded contiguous journal page and a public profile, then commit
    /// the full pin and envelope together. Invalid evidence never becomes state.
    /// Authenticated root conflicts are retained even though the import fails.
    pub fn import_verified_resolution(
        &self,
        policy: &ResolutionTrustPolicy,
        links: &[CheckpointLink],
        envelope: &ResolutionEnvelope,
        now: i64,
    ) -> Result<()> {
        policy.validate(now)?;
        if links.len() > 256
            || serde_json::to_vec(envelope)?.len() > 262_144
            || serde_json::to_vec(links)?.len() > 262_144
        {
            return Err(TransparencyError::InvalidResolutionEvidence.into());
        }
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let (raw_policy, raw_cursor, conflict): (String, Option<String>, Option<String>) = tx
            .query_row(
                "SELECT policy_json, cursor_json, conflict_json FROM replica_trust WHERE log_id=?1",
                [&policy.descriptor.log_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(db_error)?
            .ok_or(TransparencyError::TrustPolicyMismatch)?;
        if raw_policy != serde_json::to_string(policy)? {
            return Err(TransparencyError::TrustPolicyMismatch.into());
        }
        if conflict.is_some() {
            return Err(TransparencyError::QuarantinedHistory.into());
        }
        let mut cursor: Option<CheckpointCursor> =
            raw_cursor.map(|s| serde_json::from_str(&s)).transpose()?;
        // A signed fork is durable evidence independently of the envelope's proofs.
        if let Some(pin) = &cursor {
            for candidate in links
                .iter()
                .map(|link| &link.cursor.checkpoint)
                .chain(std::iter::once(&envelope.checkpoint))
            {
                if candidate.log_id == pin.checkpoint.log_id
                    && candidate.operator_pubkey == pin.checkpoint.operator_pubkey
                    && candidate.log_size == pin.checkpoint.log_size
                    && (candidate.log_root != pin.checkpoint.log_root
                        || candidate.map_root != pin.checkpoint.map_root)
                    && verify_checkpoint(candidate).unwrap_or(false)
                {
                    tx.execute(
                        "UPDATE replica_trust SET conflict_json=?1 WHERE log_id=?2",
                        params![
                            serde_json::to_string(&(pin, candidate))?,
                            policy.descriptor.log_id
                        ],
                    )
                    .map_err(db_error)?;
                    tx.commit().map_err(db_error)?;
                    return Err(TransparencyError::ConflictingCheckpoint.into());
                }
            }
        }
        for link in links {
            if let Some(previous) = &cursor {
                if link.cursor == *previous {
                    continue;
                }
                if previous.index.checked_add(1) != Some(link.cursor.index) {
                    return Err(TransparencyError::CheckpointHistoryGap.into());
                }
                verify_checkpoint_successor(
                    &previous.checkpoint,
                    &link.cursor.checkpoint,
                    link.consistency.as_ref(),
                )?;
            } else {
                self_check_bootstrap(policy, &link.cursor.checkpoint)?;
            }
            cursor = Some(link.cursor.clone());
        }
        let cursor = cursor.ok_or(TransparencyError::CheckpointHistoryGap)?;
        if cursor.checkpoint.checkpoint_hash()? != envelope.checkpoint.checkpoint_hash()? {
            return Err(TransparencyError::CheckpointHistoryGap.into());
        }
        policy.verify_envelope(envelope, now)?;
        let count: u64 = tx
            .query_row(
                "SELECT count(*) FROM replica_envelopes WHERE log_id=?1",
                [&policy.descriptor.log_id],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM replica_envelopes WHERE log_id=?1 AND identifier=?2)",
                params![policy.descriptor.log_id, envelope.identifier],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if count >= 1024 && !exists {
            return Err(TransparencyError::InvalidResolutionEvidence.into());
        }
        tx.execute("INSERT INTO replica_envelopes(log_id,identifier,envelope_json) VALUES (?1,?2,?3) ON CONFLICT(log_id,identifier) DO UPDATE SET envelope_json=excluded.envelope_json",
            params![policy.descriptor.log_id, envelope.identifier, serde_json::to_string(envelope)?]).map_err(db_error)?;
        tx.execute(
            "UPDATE replica_trust SET cursor_json=?1 WHERE log_id=?2",
            params![serde_json::to_string(&cursor)?, policy.descriptor.log_id],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)?;
        Ok(())
    }

    /// Returns only reverified, fresh data at the current durable head. A newer
    /// pin invalidates cached proofs until the replica obtains refreshed proofs.
    pub fn verified_replica_resolution(
        &self,
        policy: &ResolutionTrustPolicy,
        identifier: &str,
        now: i64,
    ) -> Result<Option<ResolutionEnvelope>> {
        policy.validate(now)?;
        let connection = self.connection()?;
        let (pinned, cursor, conflict): (String, Option<String>, Option<String>) = connection
            .query_row(
                "SELECT policy_json,cursor_json,conflict_json FROM replica_trust WHERE log_id=?1",
                [&policy.descriptor.log_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(db_error)?;
        if pinned != serde_json::to_string(policy)? {
            return Err(TransparencyError::TrustPolicyMismatch.into());
        }
        if conflict.is_some() {
            return Err(TransparencyError::QuarantinedHistory.into());
        }
        let raw: Option<String> = connection
            .query_row(
                "SELECT envelope_json FROM replica_envelopes WHERE log_id=?1 AND identifier=?2",
                params![policy.descriptor.log_id, identifier],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?;
        let Some(raw) = raw else {
            return Ok(None);
        }; // cache miss, NOT authenticated absence
        let envelope: ResolutionEnvelope = serde_json::from_str(&raw)?;
        let cursor: CheckpointCursor =
            serde_json::from_str(&cursor.ok_or(TransparencyError::CheckpointHistoryGap)?)?;
        if cursor.checkpoint.checkpoint_hash()? != envelope.checkpoint.checkpoint_hash()? {
            return Err(TransparencyError::CheckpointHistoryGap.into());
        }
        policy.verify_envelope(&envelope, now)?;
        if envelope.signed_profile.profile.revoked {
            return Err(TransparencyError::RevokedIdentifier.into());
        }
        Ok(Some(envelope))
    }
}

fn self_check_bootstrap(
    policy: &ResolutionTrustPolicy,
    checkpoint: &TransparencyCheckpoint,
) -> Result<()> {
    if checkpoint.log_id != policy.descriptor.log_id
        || checkpoint.operator_pubkey != policy.descriptor.authority_pubkey
    {
        return Err(TransparencyError::UnexpectedOperatorKey.into());
    }
    if !verify_checkpoint(checkpoint)? {
        return Err(TransparencyError::InvalidCheckpointSignature.into());
    }
    Ok(())
}
