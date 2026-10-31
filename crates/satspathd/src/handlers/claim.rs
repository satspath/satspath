//! Claim handlers: inspect invite, claim invite, list invites, list notifications.

use anyhow::Result;
use satspath_core::crypto::verify_message_signature;

use satspath_core::profile::{ClaimNotification, InviteRecord, InviteStatus};
use satspath_core::InviteStore;

use crate::config::AppState;

use crate::types::{ClaimRequest, ClaimResponse, InspectInviteResponse};

pub(crate) fn inspect_invite_handler(
    state: &AppState,
    invite_id: &str,
) -> Result<InspectInviteResponse> {
    let store = InviteStore::open(&state.home)?;
    let invite = store
        .get(invite_id)
        .ok_or_else(|| anyhow::anyhow!("invite '{}' not found", invite_id))?;

    let now = chrono::Utc::now().timestamp();
    let is_expired = now >= invite.expires_at || invite.status == InviteStatus::Expired;
    let is_claimable = !is_expired
        && invite.status != InviteStatus::ClaimedWithPublicProfile
        && invite.status != InviteStatus::Cancelled;

    let sender_verified =
        if let (Some(sig), Some(pubkey)) = (&invite.sender_signature, &invite.sender_pubkey) {
            let message = format!(
                "SatsPath Invite v1\nalias_hash={}\namount_sats={}\ncreated_at={}\nexpires_at={}",
                invite.identifier_hash, invite.amount_sats, invite.created_at, invite.expires_at
            );
            verify_message_signature(&message, sig, pubkey).unwrap_or(false)
        } else {
            false
        };

    Ok(InspectInviteResponse {
        invite_id: invite.invite_id,
        identifier_hash: invite.identifier_hash,
        display_hint: invite.display_hint,
        amount_sats: invite.amount_sats,
        memo: invite.memo,
        status: invite.status,
        is_expired,
        is_claimable,
        created_at: invite.created_at,
        expires_at: invite.expires_at,
        sender_verified,
        sender_pubkey: invite.sender_pubkey,
    })
}

pub(crate) fn claim_invite_handler(
    _state: &AppState,
    _body: ClaimRequest,
) -> Result<ClaimResponse> {
    anyhow::bail!("invite publication disabled until namespace authorization is integrated; use secure lab registration")
}
pub(crate) fn list_invites_handler(state: &AppState) -> Result<Vec<InviteRecord>> {
    let mut store = InviteStore::open(&state.home)?;
    store.list()
}

pub(crate) fn list_notifications_handler(state: &AppState) -> Result<Vec<ClaimNotification>> {
    let store = InviteStore::open(&state.home)?;
    Ok(store.notifications().to_vec())
}

pub(crate) fn mark_notification_read_handler(
    state: &AppState,
    notification_id: &str,
) -> Result<serde_json::Value> {
    let mut store = InviteStore::open(&state.home)?;
    store.mark_notification_read(notification_id)?;
    Ok(serde_json::json!({
        "status": "ok",
        "notification_id": notification_id,
        "read": true
    }))
}

pub(crate) fn mark_all_notifications_read_handler(state: &AppState) -> Result<serde_json::Value> {
    let mut store = InviteStore::open(&state.home)?;
    store.mark_all_notifications_read()?;
    Ok(serde_json::json!({
        "status": "ok",
        "all_read": true
    }))
}
