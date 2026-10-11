# Key Recovery Architecture & Specifications

## Overview

In SatsPath, identity keys represent self-sovereign cryptographic control over payment routing profiles and aliases. If a user loses their device or identity key material, SatsPath provides sovereign key recovery mechanisms without relying on custodial or federated third parties.

## Threat Model & Rejected Alternatives

### Strict Rejection of Email & SMS Recovery
Traditional web services rely on email confirmation links or SMS OTP codes for password and key reset. SatsPath **strictly rejects** email and SMS recovery for identity keys:
- **Email/DNS Compromise:** Mail servers, DNS providers, and email account custodians can be compelled, hacked, or spoofed (e.g. via BGP hijacking or SIM swapping), allowing attackers to steal aliases.
- **Fail-Closed Sovereign Security:** In accordance with the Bitcoin security model, no centralized service or protocol operator can forcibly reassign or "recover" an identifier without valid cryptographic authorization.

---

## Recovery Mechanisms

SatsPath defines two complementary recovery tiers:

### 1. Deterministic Seed-Based Derivation (Local Sovereign Recovery)

Users with an existing BIP-39 mnemonic or wallet master seed can deterministically derive their SatsPath identity key:
- **Derivation Algorithm:** HMAC-SHA512
- **Domain Separator:** `b"SatsPath Identity Key m/9737'/0'"`
- **Inputs:** `seed_bytes` + `account_index` (big-endian `u32`)

```text
HMAC-SHA512(key = "SatsPath Identity Key m/9737'/0'", data = seed || account_index)
Candidate scalar = first 32 bytes (must be valid secp256k1 scalar)
```

**Key Isolation Invariant:** This derivation is strictly isolated from Bitcoin spending keys (e.g., `m/84'/0'/0'` or `m/86'/0'/0'`). The identity key is purely an Ed25519 or secp256k1 Schnorr identity signing key; it never signs transactions, touches UTXOs, or exposes wallet funds.

### 2. M-of-N Threshold Guardian Recovery (Social / Multi-Device Recovery)

For users wishing to guard against total key and seed loss, SatsPath supports pre-committed threshold guardian recovery.

#### Fail-Closed Pre-Commitment Rule
Key recovery cannot be retroactively claimed:
- A user must have committed a `RecoveryPolicy` in their profile and transparency log events *prior* to losing access.
- If an identifier has no active `RecoveryPolicy` (`recovery_policy: None`), any attempt to execute `NameAction::RecoverKey` fails immediately with `TransparencyError::RecoveryDisabled`.

#### Policy Structure
```rust
pub struct RecoveryPolicy {
    pub threshold: u32,                  // M, where 1 <= M <= N <= 32
    pub guardian_pubkeys: Vec<String>,   // N unique compressed secp256k1 pubkeys
}
```

#### Two-Phase Cryptographic Binding & Domain Separation
Recovery authorization requires distinct domain-separated signatures:

1. **Guardian Authorization (`SatsPathKeyRecoveryAuthorizationV1`):**
   Each guardian signs:
   ```text
   SatsPathKeyRecoveryAuthorizationV1
   identifier_hash: <HEX>
   previous_pubkey: <HEX>
   new_pubkey: <HEX>
   previous_event_hash: <HEX>
   sequence: <U64>
   ```

2. **New Key Acceptance (`SatsPathKeyRecoveryAcceptanceV1`):**
   The new identity key signs:
   ```text
   SatsPathKeyRecoveryAcceptanceV1
   identifier_hash: <HEX>
   previous_pubkey: <HEX>
   new_pubkey: <HEX>
   previous_event_hash: <HEX>
   sequence: <U64>
   ```

Both authorization and acceptance strictly commit to the exact `previous_event_hash` and monotonic `sequence`, preventing replay attacks across rotations or forks.

---

## Log Verification Rules for `NameAction::RecoverKey`

When an identifier transition occurs via `RecoverKey`:
1. **Active Policy Presence:** The previous state MUST have an active `RecoveryPolicy`.
2. **Predecessor Binding:** The proof's `previous_pubkey` must match the current active identity key.
3. **Threshold Quorum:** The proof must include at least $M$ valid, distinct signatures from guardian pubkeys registered in the active policy.
4. **Acceptance Signature:** The proof must include a valid acceptance signature from `new_pubkey`.
5. **Sequence & Continuity:** `sequence == predecessor.sequence + 1`, and `previous_event_hash == predecessor.signed_event_hash()`.
6. **Policy Continuation:** If the recovery event does not specify a new `recovery_policy`, the previous policy remains active; if specified, the new policy replaces it.

---

## CLI & Daemon Interface

### CLI Commands
```bash
# Recover from deterministic seed
satspath wallet recover --seed-hex <HEX_SEED> --account-index 0 --alias alice@example.com

# Recover via guardian proof file
satspath wallet recover --proof-file proof.json --alias alice@example.com
```

### Daemon Endpoint
`POST /v1/profile/recover`
Payload:
```json
{
  "alias": "alice@example.com",
  "proof": {
    "identifier_hash": "...",
    "previous_pubkey": "...",
    "new_pubkey": "...",
    "new_key_signature": "...",
    "previous_event_hash": "...",
    "sequence": 1,
    "guardian_signatures": [
      { "pubkey": "...", "signature": "..." },
      { "pubkey": "...", "signature": "..." }
    ]
  },
  "signed_profile": { ... }
}
```
Response:
```json
{
  "alias": "alice@example.com",
  "sequence": 1,
  "previous_fingerprint": "...",
  "new_fingerprint": "...",
  "event_hash": "...",
  "checkpoint_hash": "..."
}
```
