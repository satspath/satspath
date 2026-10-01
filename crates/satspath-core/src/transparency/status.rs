use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Fully verified: valid DNSSEC, complete Merkle inclusion, witness quorum satisfied, payment method bound.
    VerifiedSovereign,
    /// Verified against WebPKI authority or TOFU pin; witness quorum satisfied.
    VerifiedStandard,
    /// Verified hosted sub-identifier under third-party authority.
    VerifiedHosted,
    /// Verification failed due to cryptographic integrity or consistency violation.
    TerminalFailure,
    /// Server unreachable or timed out; cryptography untouched.
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum S2SErrorCode {
    // Namespace & Authority
    ErrDnssecValidationFailed,
    ErrNamespaceDescriptorMismatch,
    ErrAuthorityPinMismatch,

    // Identity & History
    ErrKeySubstitution,
    ErrInvalidEventSignature,
    ErrBrokenHistoryChain,
    ErrUnauthorizedKeyReplacement,
    ErrIdentifierRevoked,
    ErrRecoveryDisabled,

    // Merkle Log & Checkpoints
    ErrInclusionMismatch,
    ErrInvalidInclusionProof,
    ErrInvalidConsistencyProof,
    ErrCheckpointSignatureInvalid,
    ErrCheckpointRollback,
    ErrOperatorRotationInvalid,

    // Witnesses & Consistency
    ErrInsufficientWitnesses,
    ErrWitnessQuorumFailed,
    ErrConflictingCheckpoint,

    // Freshness & State
    ErrStaleCheckpoint,
    ErrNonInclusionUnverified,
    ErrProfileHashMismatch,
    ErrMethodBindingInvalid,

    // Transport & Network
    ErrServerUnavailable,
    ErrPayloadTooLarge,
    ErrMalformedEnvelope,
}
