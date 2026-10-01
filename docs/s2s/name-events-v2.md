# SatsPath v2 Name Events

## Goal

Make the authoritative server an admission and storage service, never the author of identity state. Every accepted mutation must be independently verifiable from the signed event history.

## Event Model

Canonical events for the lifecycle of a namespace identifier:

- `Register`
- `ProfileUpdate`
- `RotateOwnerKey`
- `Revoke`
- `RecoverKey` (optional, disabled by default)

Every event MUST bind:

- `identifier_hash`
- Namespace identifier
- `action` (event type)
- `sequence`
- `previous_event_hash`
- `profile_hash`
- policy epoch
- validity/freshness fields (`created_at`)

## Authorization Rules

1. **Registration**: Requires namespace issuance authorization plus proof that the proposed owner key accepts the binding (sequence 0, no previous event hash).
2. **Profile Updates**: Requires the signature of the current owner key.
3. **Key Rotation**: Requires authorization by the old key and acceptance by the new key.
4. **Revocation**: Requires the current owner key. This is a terminal state.
5. **Continuous Sequence**: Sequence must advance by exactly one.
6. **Chaining**: `previous_event_hash` must match the cryptographic hash of the current state.
7. **Compare-and-set**: Concurrent mutations use compare-and-set semantics; only one successor to a history head can commit.
8. **No Server Forgery**: A server must reject a syntactically valid self-signed replacement key that lacks history continuity.

## Namespace Policy

Namespaces control admission, reserved names, and expiration, but they do NOT gain the ability to forge owner updates. Policy changes must be versioned and cannot retroactively weaken already-issued identifiers.
