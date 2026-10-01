use serde::{Deserialize, Serialize};

use super::{NameEvent, TransparencyCheckpoint};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationChallengeRequest {
    pub identifier: String,
    pub proposed_owner_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationChallengeResponse {
    pub nonce: String,
    pub expiry: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationSubmitRequest {
    pub challenge_nonce: String,
    pub event: NameEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MutationStatus {
    AcceptedPendingCheckpoint,
    Included(Box<TransparencyCheckpoint>),
    Conflict,
    Unauthorized,
    Revoked,
    PolicyRejected(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationResponse {
    pub status: MutationStatus,
    pub event_hash: String,
}
