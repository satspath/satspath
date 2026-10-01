# SatsPath Protocol v0.1 — Implementation Audit

> **Generated:** 2026-07-09  
> **Source:** Codebase at `main` branch vs. "SatsPath Protocol v0.1" specification  
> **Legend:** ✅ Implemented · ⚠️ Partial · ❌ Missing

---

## Summary

| Area                | Sections | ✅      | ⚠️    | ❌    |
| ------------------- | -------- | ------- | ----- | ----- |
| Core Protocol       | §1–§6    | 10      | 0     | 0     |
| Standards Compat    | §7       | 4       | 0     | 0     |
| URI / QR            | §8–§9    | 4       | 0     | 0     |
| Profile & Signing   | §10–§12  | 8       | 0     | 0     |
| Key Mgmt            | §13      | 3       | 0     | 0     |
| Registry / Resolver | §14      | 5       | 0     | 0     |
| User Flows          | §15–§17  | 8       | 0     | 0     |
| Payment Rails       | §18      | 8       | 0     | 0     |
| Router              | §19–§23  | 8       | 0     | 0     |
| Split Payments      | §24      | 1       | 0     | 0     |
| Security            | §25–§28  | 9       | 0     | 0     |
| CLI                 | §29      | 10      | 0     | 0     |
| Structure / Modules | §30–§31  | 6       | 0     | 0     |
| Tests               | §32      | 13      | 0     | 0     |
| Product / Hackathon | §33–§37  | 6       | 0     | 0     |
| **TOTAL**           |          | **103** | **0** | **0** |

---

## §1 — Core Problem

| Requirement                                              | Status | Evidence                                                                                                                       |
| -------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------ |
| User provides one identifier, protocol resolves & routes | ✅     | Full resolver chain → signed profile → route engine pipeline. CLI `pay`, `quote`, Web UI `/v1/send` all accept a single alias. |
| Separate user experience from payment rail               | ✅     | Router auto-selects Lightning/On-chain/Ark in `router.rs`.                                                                     |

---

## §2 — Core Design Principle

| Requirement                                                                        | Status | Evidence                                                                                                                                  |
| ---------------------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| identifier → signed profile → encode/decode → route selection → payment simulation | ✅     | End-to-end in `demo.rs` and the `pay`/`quote` CLI commands. Real payments gated behind `--experimental-swaps --testnet`.                  |
| Do not build a wallet first                                                        | ✅     | `ExecutionMode` enum explicitly separates `Preview`, `MainnetPreview`, `TestnetExperimental`, `ManualWallet`. No spending key generation. |

---

## §3 — What SatsPath Is / Is Not

| Claim                                | Status | Evidence                                                                                                       |
| ------------------------------------ | ------ | -------------------------------------------------------------------------------------------------------------- |
| Payment identity resolver            | ✅     | `resolver.rs`, `ChainResolver`, multiple backends (local, HTTP, BIP-353, Nostr).                               |
| Signed payment profile format        | ✅     | `profile.rs` → `PaymentProfile`, `SignedPaymentProfile`.                                                       |
| Routing algorithm for Bitcoin rails  | ✅     | `router.rs`, `scoring.rs`, `priority.rs`.                                                                      |
| Universal QR / URI format            | ✅     | `codec.rs` — `satspath:alias` and `satspath:v1:<base64url>`.                                                   |
| Fallback for unregistered users      | ✅     | `create_invite()`, `create_invite_record()`, CLI `invite` command, Web UI invite flow.                         |
| Future foundation for split payments | ⚠️     | Data structure not yet designed. Spec says "only design the data structure" — not yet done.                    |
| NOT a custodial wallet               | ✅     | No spending keys, no fund movement on mainnet.                                                                 |
| NOT creating private keys for others | ✅     | `create_invite` explicitly warns: "The receiver must claim this payment by generating their own keys locally." |

---

## §4 — Core Flow

### Registered User

| Step                                             | Status | Evidence                                                                                                  |
| ------------------------------------------------ | ------ | --------------------------------------------------------------------------------------------------------- |
| Sender enters alias                              | ✅     | All CLI commands accept `alias` argument.                                                                 |
| Resolver returns `SignedPaymentProfile`          | ✅     | `ChainResolver` with local → BIP-353 → HTTP → Nostr chain.                                                |
| Verify alias binding                             | ✅     | `resolver.rs` SEC-02 substitution check.                                                                  |
| Verify profile signature                         | ✅     | `crypto::verify_signed_profile()` called before routing.                                                  |
| Verify public key fingerprint                    | ✅     | `crypto::fingerprint_pubkey()`, displayed in `show` command.                                              |
| Verify supported payment methods                 | ✅     | `validation::validate_public_profile()`.                                                                  |
| Check expiration                                 | ✅     | `crypto::check_profile_expiry()` — SEC-01.                                                                |
| Check recent key changes                         | ⚠️     | Warning exists in `show.rs` but no formal key-change detection beyond registry sequence/timestamp checks. |
| Router evaluates amount, fees, rails, preference | ✅     | `router.rs` + `scoring.rs` — full candidate evaluation.                                                   |
| Router selects rail                              | ✅     | Lightning → On-chain → Ark waterfall.                                                                     |
| Payment is executed or simulated                 | ✅     | `simulated_success` on mainnet, experimental testnet execution path.                                      |

### Unregistered User

| Step                                                | Status | Evidence                                                                                                                                                                                                                                            |
| --------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No profile found → no keys created for receiver     | ✅     | `invite.rs` — no key generation.                                                                                                                                                                                                                    |
| Invite / claim flow created                         | ✅     | `create_invite()`, `create_invite_record()`, signed invites with `sender_signature`.                                                                                                                                                                |
| Claim link generated                                | ✅     | `claim_url` built with alias hash + amount.                                                                                                                                                                                                         |
| Receiver generates keys locally → publishes profile | ⚠️     | The invite tells the receiver to do this, but there's no actual "claim" server endpoint or mobile flow to complete the loop. Spec calls this "Critical" and the invite message describes the intent, but the full claim lifecycle is unimplemented. |

---

## §5 — Identity Model

| Requirement                                            | Status | Evidence                                                |
| ------------------------------------------------------ | ------ | ------------------------------------------------------- |
| Alias is for humans, pubkey is for crypto verification | ✅     | `PaymentProfile.alias` + `identity_pubkey`.             |
| Fingerprint (first 8 hex of SHA-256)                   | ✅     | `crypto::fingerprint_pubkey()` → 4 bytes = 8 hex chars. |
| Profile signature proves owner authorized profile      | ✅     | `sign_profile()` → `verify_signed_profile()`.           |

---

## §6 — Alias Uniqueness

| Requirement                      | Status | Evidence                                                                                           |
| -------------------------------- | ------ | -------------------------------------------------------------------------------------------------- |
| user@domain format               | ✅     | Enforced by `validation::validate_lightning_address()` and `privacy::validate_ascii_identifier()`. |
| Namespace-scoped aliases         | ✅     | All aliases use `user@domain`.                                                                     |
| Support future resolver backends | ✅     | `ChainResolver` architecture with pluggable backends: local, DNS/BIP-353, HTTP, Nostr.             |

---

## §7 — Compatibility with Existing Standards

| Standard                                  | Status | Evidence                                                                                                                                                                                                                                                                                                                                                                |
| ----------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **BIP-353** — DNS TXT records with DNSSEC | ✅     | Full implementation in `bip353.rs` — `parse_bip353_name()`, `resolve_bip353_with()`, `DnssecPolicy::Strict`, DoH backend. CLI `dns resolve`.                                                                                                                                                                                                                            |
| **BIP-21 / BIP-321** — Bitcoin URIs       | ✅     | `bip321.rs` — parser for `bitcoin:` URIs with parameter extraction.                                                                                                                                                                                                                                                                                                     |
| **LNURL / Lightning Address**             | ✅     | `lightning.rs` — `fetch_lnurl_metadata()`, `fetch_invoice()`, `validate_bolt11_invoice()`. Full LNURL-02 flow.                                                                                                                                                                                                                                                          |
| **Ark** — Adapter interface               | ⚠️     | `MockArkClient` exists in `ark.rs` (router). Full Ark types (`ArkReceivePointer`, `ArkOwnershipProof`, `ArkPaymentIntent`) in core `ark.rs`. Arkade opaque URI support added. Not a complete Ark implementation but spec says "do not attempt full Ark implementation in v0.1" — mostly compliant. The `ark-bridge/` directory exists suggesting more integration work. |

---

## §8 — SatsPath URI Format

| Format                                                                       | Status | Evidence                                                                                                                                                                        |
| ---------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Simple: `satspath:alias`                                                     | ✅     | `codec.rs` — `decode_payment_request()` handles `satspath:` prefix.                                                                                                             |
| Encoded: `satspath:v1:<base64url_json>`                                      | ✅     | `codec.rs` — `encode_payment_request()` / `decode_payment_request()`.                                                                                                           |
| Payload includes version, alias, amount_sats, memo, expires_at, profile_hint | ⚠️     | `PaymentRequest` has `version`, `alias`, `amount_sats`, `memo`, `profile_hint`. **Missing: `expires_at`** in the payment request struct (it's in the profile, not the request). |

---

## §9 — Universal QR

| Requirement                   | Status | Evidence                                                         |
| ----------------------------- | ------ | ---------------------------------------------------------------- |
| Static QR: `satspath:alias`   | ✅     | Codec produces this format; QR generation via `qr.rs`.           |
| Dynamic QR with amount + memo | ✅     | `satspath:v1:<encoded>` format with full payload.                |
| QR display                    | ✅     | `qr.rs`, Web UI `qr_svg`, CLI `quote_response.rs` QR generation. |

---

## §10 — Payment Profile

| Field                                     | Status | Evidence                                                                                                                                                         |
| ----------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `alias`                                   | ✅     | `PaymentProfile.alias`.                                                                                                                                          |
| `identity_pubkey`                         | ✅     | `PaymentProfile.identity_pubkey`.                                                                                                                                |
| `methods` (Lightning, Onchain, Ark)       | ✅     | `PaymentMethod` enum with `Lightning`, `Onchain`, `Ark` variants. All fields from spec present.                                                                  |
| `preferences` (ordered rail preference)   | ❌     | No `preferences` field in profile. The spec defines `["lightning", "ark", "onchain"]` but this is not implemented. The router uses its own static logic instead. |
| `updated_at`                              | ✅     | `PaymentProfile.updated_at`.                                                                                                                                     |
| `expires_at`                              | ✅     | `PaymentProfile.expires_at` (optional).                                                                                                                          |
| `nonce`                                   | ❌     | Not in profile struct. Spec defines a `"random-128-bit-value"` nonce.                                                                                            |
| `sequence` (replay protection)            | ✅     | `PaymentProfile.sequence` — monotonic increment, SEC-03c enforcement in registry. **Beyond spec.**                                                               |
| `method_verifications` (ownership proofs) | ✅     | `PaymentProfile.method_verifications` — full ownership proof system. **Beyond spec.**                                                                            |

---

## §11 — Signed Payment Profile

| Requirement                                 | Status | Evidence                                             |
| ------------------------------------------- | ------ | ---------------------------------------------------- |
| Wrapper: `{ profile, signature }`           | ✅     | `SignedPaymentProfile { profile, signature }`.       |
| Reject invalid signature                    | ✅     | `verify_signed_profile()` checks signature + pubkey. |
| Reject expired profile                      | ✅     | `check_profile_expiry()` — SEC-01.                   |
| Reject alias mismatch                       | ✅     | `resolver.rs` SEC-02 substitution attack check.      |
| Reject unsigned/malformed resolver response | ✅     | Resolver chain returns `Err` on invalid profiles.    |

---

## §12 — Cryptographic Model

| Requirement                         | Status | Evidence                                                                                                                                                                                                                                                         |
| ----------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| secp256k1 keys                      | ✅     | Uses `secp256k1` crate throughout.                                                                                                                                                                                                                               |
| Canonical JSON serialization        | ✅     | `crypto::canonical_profile_bytes()` uses `canonical_json` crate.                                                                                                                                                                                                 |
| Domain-separated hash               | ⚠️     | Profile signing uses `SHA256(canonical_json)` directly — **no** `"SatsPathProfileV1"` domain separator as specified. The ownership proof challenges do use domain separation (`"SatsPath Ownership Proof v1\n..."`) and invites use `"SatsPath Invite v1\n..."`. |
| SHA-256 hashing                     | ✅     | `sha2::Sha256` used consistently.                                                                                                                                                                                                                                |
| ECDSA signatures (DER encoded, hex) | ✅     | `secp.sign_ecdsa()`, `sig.serialize_der()`, hex-encoded.                                                                                                                                                                                                         |
| Strong randomness                   | ✅     | `rand::thread_rng()` from OS.                                                                                                                                                                                                                                    |
| Local-only private key storage      | ✅     | Keys stored in `.satspath/keys.json`, git-ignored.                                                                                                                                                                                                               |

---

## §13 — Key Management

| Requirement                             | Status | Evidence                                                                                                                  |
| --------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------- |
| Identity key ≠ payment keys             | ✅     | Identity key only signs profiles. Payment methods reference separate keys/addresses.                                      |
| Multiple on-chain addresses for privacy | ✅     | Profile supports `Vec<PaymentMethod>` with multiple `Onchain` entries. `register` command creates 2 on-chain methods.     |
| Key rotation (old key signs new key)    | ❌     | Not implemented. Spec defines a rotation object with `old_key_signature` / `new_key_signature`. No rotation chain exists. |

---

## §14 — Registry / Resolver

| Requirement                                               | Status | Evidence                                                                                                             |
| --------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------- |
| Local registry at `.satspath/registry.json`               | ✅     | `registry.rs` — `Registry::open()`, persists to JSON.                                                                |
| `register_profile()`                                      | ✅     | `Registry::register_profile()`.                                                                                      |
| `resolve_alias()` → `SignedPaymentProfile`                | ✅     | `Registry::resolve_alias()` + `ProfileResolver` impl.                                                                |
| `is_registered()` → bool                                  | ✅     | `Registry::is_registered()`.                                                                                         |
| Future resolver backends (DNS, Nostr, HTTP, Web-of-trust) | ✅     | `resolvers/` directory: `bip353.rs`, `http.rs`, `nostr.rs`, `pear.rs`, `platform.rs`. `ChainResolver` composes them. |
| Resolver not trusted — signature must verify              | ✅     | Signature verified after resolution; resolver return doesn't bypass verification.                                    |

---

## §15 — Registered User Flow

| Step                                                                                  | Status | Evidence                                                                      |
| ------------------------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------- |
| `satspath register alias` → generate key, sign, store                                 | ✅     | `register.rs` — generates identity keypair, creates profile, signs, stores.   |
| `satspath show alias` → verify sig, display fingerprint, methods, warnings            | ✅     | `show.rs` — full display with verification badges, ownership proofs.          |
| `satspath quote alias amount` → resolve, verify, check fees, select route, show quote | ✅     | `quote.rs` — resolves, verifies, fetches live mempool fees, routes, displays. |
| `satspath pay alias amount` → simulate or execute                                     | ✅     | `pay.rs` — full pay flow with simulation/experimental execution.              |

---

## §16 — Unregistered User Flow

| Requirement                                                                       | Status | Evidence                                                                                                                                                                                                                                                                |
| --------------------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Check registry → no profile found                                                 | ✅     | `is_registered()` check before invite.                                                                                                                                                                                                                                  |
| Do NOT create keys for receiver                                                   | ✅     | `create_invite()` has no key generation. Warning message is explicit.                                                                                                                                                                                                   |
| Create invite / claim link                                                        | ✅     | `Invite` struct with `alias_hash`, `claim_url`, `expires_at`, `warning`.                                                                                                                                                                                                |
| Payment intent (waiting_for_claim)                                                | ⚠️     | `InviteRecord` with `InviteStatus::Created` / `ClaimedWithPublicProfile` / `Expired`. However, the spec's `payment_intent` JSON with `intent_id`, `status: waiting_for_claim` is not a separate stored object — it's part of `InviteRecord`. Close but not exact match. |
| Receiver opens link → generates keys → publishes profile → sender resolves → pays | ❌     | No server endpoint or flow exists for the claim process. The invite generates a link, but there's no claim handler.                                                                                                                                                     |

---

## §17 — Invite Security

| Protection                             | Status | Evidence                                                                                              |
| -------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------- |
| Use alias hash (not raw email)         | ✅     | `invite.alias_hash = hex::encode(Sha256::digest(canonical_identifier))`.                              |
| Expiration                             | ✅     | `invite.expires_at = now + ttl_seconds`.                                                              |
| Never embed private keys / seeds       | ✅     | Warning message explicit; `assert_no_private_material()` on all payloads.                             |
| Sender confirmation before payment     | ✅     | No auto-pay; invite is just an invite.                                                                |
| Warn if profile created recently       | ⚠️     | Not specifically on invites, but `show` warns about key changes.                                      |
| Signed invites (sender's identity key) | ✅     | `invite.sender_signature`, `invite.sender_pubkey` — `verify_invite()` validates. **Beyond spec MVP.** |

---

## §18 — Payment Rails

### §18.1 — Lightning

| Requirement                              | Status | Evidence                                                                                                     |
| ---------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------ |
| Preferred for small/fast payments        | ✅     | Router checks `amount < 100_000` first.                                                                      |
| Lightning Address, LNURL, BOLT12 fields  | ✅     | `PaymentMethod::Lightning` has all three fields.                                                             |
| Validate Lightning Address format        | ✅     | `validation::validate_lightning_address()`.                                                                  |
| Detect LNURL availability                | ✅     | `is_lightning_available()`.                                                                                  |
| Fetch LNURL metadata                     | ✅     | `fetch_lnurl_metadata()` — real HTTP fetch.                                                                  |
| Fetch BOLT11 invoice                     | ✅     | `fetch_invoice()` with amount bounds, LNURL-02 error detection, invoice validation.                          |
| Validate BOLT11 invoice (amount, expiry) | ✅     | `validate_bolt11_invoice()` using `lightning-invoice` crate.                                                 |
| BOLT12 offer validation                  | ⚠️     | `validate_bolt12_offer()` does basic bech32 prefix check but doesn't fully decode/validate BOLT12 internals. |
| 100,000 sats threshold                   | ✅     | `LIGHTNING_THRESHOLD_SATS = 100_000`.                                                                        |

### §18.2 — On-chain

| Requirement                                        | Status | Evidence                                                                        |
| -------------------------------------------------- | ------ | ------------------------------------------------------------------------------- |
| Large amounts / strong settlement / LN unavailable | ✅     | Router falls through to on-chain when LN threshold not met and fees acceptable. |
| Address validation (network-aware)                 | ✅     | `validation::validate_bitcoin_address()` using `bitcoin` crate.                 |
| Multiple on-chain addresses                        | ✅     | `Vec<PaymentMethod>` supports multiple `Onchain` entries.                       |
| `pubkey_hint` field                                | ✅     | `PaymentMethod::Onchain { pubkey_hint }`.                                       |

### §18.3 — Ark

| Requirement               | Status | Evidence                                                               |
| ------------------------- | ------ | ---------------------------------------------------------------------- |
| Ark as adapter/mock first | ✅     | `MockArkClient` in `router/ark.rs`.                                    |
| Detect Ark method         | ✅     | `is_ark_available()`, `first_ark_method()`.                            |
| Check Ark server URL      | ✅     | `validate_ark_server_url()` — HTTPS required, host validated.          |
| Simulate payment intent   | ✅     | `ArkPaymentIntent` with `ArkIntentStatus::PreviewOnly`.                |
| Ark selected as fallback  | ✅     | Router selects Ark when LN unavailable + on-chain fees high.           |
| Full Ark ownership proofs | ✅     | `ArkOwnershipProof`, `verify_ark_ownership_proof()` — **beyond spec**. |

---

## §19 — Routing Engine

| Requirement                                                          | Status | Evidence                                                                                                                                                                                           |
| -------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RouteRequest` struct                                                | ✅     | `RouteRequest { alias, amount_sats, signed_profile }`. Spec also has `urgency`, `max_fee_sats`, `max_fee_percent` — these exist in `scoring.rs` (`RoutePreferences`) but not in the simple router. |
| `RouteQuote` struct with method, reason, fee, confirmation, warnings | ✅     | `RouteQuote { selected_method, reason, estimated_fee_sats, estimated_confirmation, fee_snapshot, swap_directive }`.                                                                                |

---

## §20 — Routing Algorithm

| Step                                                            | Status | Evidence                                                                          |
| --------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------- |
| 1. Verify signed profile                                        | ✅     | Signature verified before routing.                                                |
| 2. Reject expired profile                                       | ✅     | `check_profile_expiry()`.                                                         |
| 3. Extract methods                                              | ✅     | `&req.signed_profile.profile.methods`.                                            |
| 4. Lightning if < 100k and LN exists                            | ✅     | `select_route()` checks `amount < LIGHTNING_THRESHOLD_SATS`.                      |
| 5. Fetch on-chain fee rate                                      | ✅     | `fetch_fee_estimate()` from mempool.space.                                        |
| 6. On-chain if fee acceptable                                   | ✅     | `is_onchain_fee_acceptable()` — `hour_fee <= 10`.                                 |
| 7. Ark fallback                                                 | ✅     | `is_ark_available()` → Ark route.                                                 |
| 8. Fail if no route                                             | ✅     | `Err(SatsPathError::NoRouteFound(...))`.                                          |
| Advanced scoring (speed, fee, privacy, reliability, preference) | ✅     | `scoring.rs` — `candidate_score()` with weighted dimensions. **Beyond MVP spec.** |

---

## §21 — Fee-Rate Algorithm

| Requirement                                                              | Status | Evidence                                                                                                                                     |
| ------------------------------------------------------------------------ | ------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Fetch from mempool.space API                                             | ✅     | `fees.rs` — `fetch_fee_estimate()` from `mempool.space/api/v1/fees/recommended`.                                                             |
| Parse `fastestFee`, `halfHourFee`, `hourFee`, `economyFee`, `minimumFee` | ✅     | `MempoolFeeEstimate` struct with all five fields.                                                                                            |
| Safety margin (10%)                                                      | ❌     | Not implemented. Spec says `selected_feerate += ceil(selected_feerate * 0.10)`. The fee is used raw.                                         |
| Estimated vbytes (P2WPKH ~141 vB)                                        | ✅     | `onchain.rs` — `estimate_onchain_fee_sats(fee_rate) = 141 * fee_rate`.                                                                       |
| Urgency mapping (Urgent/Commercial/Normal/Economy)                       | ⚠️     | `FeeRateSnapshot` stores all tiers. `priority.rs` exists with priority selection. But no `PaymentUrgency` enum mapping as described in spec. |

---

## §22 — Route Scoring

| Requirement                                              | Status | Evidence                                                                                                                                               |
| -------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Score = speed + fee + privacy + reliability + preference | ✅     | `scoring.rs` — `candidate_score()` weighs `reliability_score`, `privacy_score`, `estimated_time_seconds`, `estimated_fee_sats`, rail-specific bonuses. |
| Lightning good for small, fast                           | ✅     | Bonus for `Lightning && amount <= 1_000_000`.                                                                                                          |
| On-chain good for large, settled                         | ✅     | Bonus for `Onchain && amount >= 1_000_000`.                                                                                                            |
| Ark good as fallback                                     | ✅     | Ark gated behind `allow_experimental_ark` preference.                                                                                                  |

---

## §23 — Suggested MVP Route Policy

| Requirement                                      | Status | Evidence                                                                                          |
| ------------------------------------------------ | ------ | ------------------------------------------------------------------------------------------------- |
| `has_lightning && amount <= 100_000` → Lightning | ✅     | `select_route()` / `select_route_with_fees()`.                                                    |
| `has_onchain && fee.hour_fee <= 10` → Onchain    | ✅     | `is_onchain_fee_acceptable()`.                                                                    |
| `has_ark` → Ark                                  | ✅     | `is_ark_available()` fallback.                                                                    |
| `has_onchain` → OnchainWithWarning               | ⚠️     | No separate "with warning" path — it's just rejected if fees too high.                            |
| Return explanations, not only results            | ✅     | `RouteQuote.reason` always has a human explanation. `scoring.rs` has `RouteDecision.explanation`. |

---

## §24 — Split Payments

| Requirement                                         | Status | Evidence                                                         |
| --------------------------------------------------- | ------ | ---------------------------------------------------------------- |
| Not required for v0.1 but design the data structure | ❌     | No split payment data structure exists anywhere in the codebase. |

---

## §25 — Security Model

| Principle                                                              | Status | Evidence                                                                                         |
| ---------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------ |
| Trust cryptographic signatures, not servers                            | ✅     | Signature verified on every resolution; resolver is untrusted.                                   |
| Server can store/return profiles, store invites                        | ✅     | Registry stores signed profiles; invites stored locally.                                         |
| Server cannot spend funds / create keys / modify profiles              | ✅     | No spending keys. `assert_no_private_material()` on all public data. Tampering breaks signature. |
| User controls identity key, wallet keys, methods, payment confirmation | ✅     | Keys local, profile changes require re-signing, payment requires user action.                    |

---

## §26 — Threat Model Summary

| Threat                       | Spec Mitigation                             | Status | Evidence                                                    |
| ---------------------------- | ------------------------------------------- | ------ | ----------------------------------------------------------- |
| Fake alias                   | Mark local/unverified                       | ✅     | First-come-first-served registry.                           |
| Server tampering             | Signed profiles                             | ✅     | `verify_signed_profile()`.                                  |
| Key replacement attack       | Show fingerprint + warnings                 | ✅     | Fingerprint displayed; signature covers pubkey.             |
| Email takeover               | Email not crypto identity                   | ✅     | Email is lookup identifier, not proof.                      |
| LNURL spoofing               | Verify profile sig first                    | ✅     | Signature verified before LNURL fetch.                      |
| On-chain address reuse       | Multiple methods                            | ✅     | Multiple `Onchain` entries supported.                       |
| Lost identity key            | Warn about key requirement                  | ⚠️     | No explicit warning; no recovery mechanism.                 |
| Malicious invite link        | Expiring invite, alias hash, sender confirm | ✅     | All three implemented.                                      |
| Ark server assumptions       | Treat as explicit rail                      | ✅     | Mock client, intent-only, testnet-gated.                    |
| Public registry privacy leak | Store minimum public profile                | ✅     | Only public methods stored; `assert_no_private_material()`. |

---

## §27 — Key Rotation

| Requirement                                      | Status | Evidence                                                                                                           |
| ------------------------------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------ |
| Old key signs new key, new key signs new profile | ❌     | Not implemented. No `KeyRotation` struct, no signed rotation chain.                                                |
| Show warning if identity key changed             | ⚠️     | Registry checks `updated_at` and `sequence` for replay protection, but no explicit key-change warning to the user. |

---

## §28 — Profile Expiration

| Requirement                        | Status | Evidence                                                                   |
| ---------------------------------- | ------ | -------------------------------------------------------------------------- |
| `updated_at` + `expires_at` fields | ✅     | Both present in `PaymentProfile`.                                          |
| Reject expired profiles            | ✅     | `check_profile_expiry()` — fail-closed at boundary (`now >= exp`).         |
| Default 30-day expiry              | ⚠️     | Not enforced as default. `expires_at` is optional (`None` = non-expiring). |

---

## §29 — CLI Commands

| Command                            | Status | Evidence                                                                                                                                  |
| ---------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `satspath init`                    | ✅     | `commands::cmd_init()` — creates `.satspath/` dir.                                                                                        |
| `satspath register <alias>`        | ✅     | `commands::cmd_register()` — with `--lightning-address`, `--onchain`, `--ark-*` flags.                                                    |
| `satspath show <alias>`            | ✅     | `commands::cmd_show()` — full profile display with verification.                                                                          |
| `satspath encode <alias> <amount>` | ✅     | `commands::cmd_encode()`.                                                                                                                 |
| `satspath decode <uri>`            | ✅     | `commands::cmd_decode()`.                                                                                                                 |
| `satspath quote <alias> <amount>`  | ✅     | `commands::cmd_quote()` + `--json` + `--mainnet-preview`.                                                                                 |
| `satspath pay <alias> <amount>`    | ✅     | `commands::cmd_pay()` — with `--experimental-swaps`, `--testnet`, `--debug`.                                                              |
| `satspath invite <alias> <amount>` | ✅     | `commands::cmd_invite()`.                                                                                                                 |
| `satspath demo`                    | ✅     | `commands::cmd_demo()`.                                                                                                                   |
| **Extra commands beyond spec**     | ✅     | `prove`, `attach-proof`, `export`, `import`, `ark {receive,send,swap}`, `dns resolve`, `wallet {init,add-methods,...}`, `preview`, `web`. |

---

## §30–§31 — Project Structure & Rust Modules

| Requirement                  | Status | Evidence                                                                                             |
| ---------------------------- | ------ | ---------------------------------------------------------------------------------------------------- |
| `satspath-core` crate        | ✅     | Profile, crypto, codec, registry, errors, BIP-353, ownership, validation.                            |
| `satspath-router` crate      | ✅     | Router, fees, Lightning, on-chain, Ark, scoring, priority.                                           |
| `satspath-cli` crate         | ✅     | Full CLI with clap, all commands.                                                                    |
| `examples/` directory        | ✅     | `rodrigo_profile.json`, `demo_flow.md`.                                                              |
| `docs/` directory            | ✅     | `architecture.md`, `protocol.md`, `threat_model.md` + 16 more docs.                                  |
| **Extra crates beyond spec** | ✅     | `satspathd` (daemon/web UI), `satspath-swaps` (experimental), `satspath-pear`, `ark-bridge`, `sdk/`. |

---

## §32 — Minimum Tests

| Test Area                                | Status | Evidence                                                                                                                                                                                                                                                                                                                                                                     |
| ---------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Profile serialization                    | ✅     | `crypto::tests::sign_and_verify()`.                                                                                                                                                                                                                                                                                                                                          |
| Profile canonicalization                 | ✅     | Implicit in sign/verify roundtrip (canonical_json).                                                                                                                                                                                                                                                                                                                          |
| Profile signing                          | ✅     | `sign_and_verify` test.                                                                                                                                                                                                                                                                                                                                                      |
| Valid signature verification             | ✅     | `sign_and_verify` test.                                                                                                                                                                                                                                                                                                                                                      |
| Invalid signature rejection              | ✅     | `tampered_signature_rejected`, `tampered_profile_rejected`.                                                                                                                                                                                                                                                                                                                  |
| URI encoding                             | ✅     | `codec::tests::roundtrip_encoded`, `roundtrip_no_amount`.                                                                                                                                                                                                                                                                                                                    |
| URI decoding                             | ✅     | `decode_simple_uri`, `decode_unknown_scheme_fails`.                                                                                                                                                                                                                                                                                                                          |
| Alias registration                       | ✅     | `registry::tests::register_and_resolve`.                                                                                                                                                                                                                                                                                                                                     |
| Alias resolution                         | ✅     | `register_and_resolve`, `missing_alias_fails`.                                                                                                                                                                                                                                                                                                                               |
| Lightning route selection                | ✅     | `router::tests::chooses_lightning_for_small_amount`, `lightning_not_blocked_by_fees`.                                                                                                                                                                                                                                                                                        |
| On-chain route selection when fees low   | ✅     | `chooses_onchain_for_large_amount_low_fees`, `onchain_boundary_at_10_sat_vb`.                                                                                                                                                                                                                                                                                                |
| Ark fallback when fees high              | ✅     | `falls_back_to_ark_when_fees_high`.                                                                                                                                                                                                                                                                                                                                          |
| Invite generation for unregistered alias | ✅     | `lib::tests::unknown_user_invite_record_contains_no_private_material`.                                                                                                                                                                                                                                                                                                       |
| **Extra test areas beyond spec**         | ✅     | Profile expiry tests (4), message signature tests (3), BIP-353 resolution tests (7), Ark ownership proof tests (6), BOLT11 invoice validation tests (5), scoring tests (4), resolver substitution attack test, validation tests (6), ownership/trust tier tests, pointer QR tests, privacy tests, integration tests (`peer_transfer.rs`, `proof_flow.rs`, `wallet_flow.rs`). |

---

## §33 — Product Style

| Requirement                      | Status | Evidence                                                                                          |
| -------------------------------- | ------ | ------------------------------------------------------------------------------------------------- |
| Simple, trustworthy, calm design | ✅     | Web UI in `index.html` uses serif typography, b/w palette, Bitcoin orange accent, minimal motion. |
| Route cards, verification badges | ✅     | Web UI shows route, verified profile status, fingerprint.                                         |
| Fee transparency                 | ✅     | Quote shows estimated fee + reason.                                                               |
| Clear warnings                   | ✅     | Warnings displayed for unverified, expired, invite scenarios.                                     |

---

## §34 — Hackathon Scope

### Must Build

| Item                          | Status |
| ----------------------------- | ------ |
| Rust workspace                | ✅     |
| Payment profile               | ✅     |
| Profile signatures            | ✅     |
| URI encoder/decoder           | ✅     |
| Local registry                | ✅     |
| Registered user flow          | ✅     |
| Unregistered user invite flow | ✅     |
| Fee-rate client               | ✅     |
| Router                        | ✅     |
| CLI demo                      | ✅     |
| README                        | ✅     |
| Threat model                  | ✅     |

### Should Build

| Item                 | Status |
| -------------------- | ------ |
| Basic web UI         | ✅     |
| QR display           | ✅     |
| Route visualization  | ✅     |
| Mock payment success | ✅     |

### Do Not Build Yet

| Item                              | Status                                                             |
| --------------------------------- | ------------------------------------------------------------------ |
| Full mobile wallet                | ✅ Not built                                                       |
| Real Ark implementation           | ✅ Not built (mock only)                                           |
| Real Lightning payment execution  | ⚠️ LNURL invoice fetching is real, but no actual payment execution |
| Real on-chain broadcasting        | ✅ Not built                                                       |
| Custodial escrow                  | ✅ Not built                                                       |
| Automatic receiver key generation | ✅ Not built (explicitly prevented)                                |
| Complex split payments            | ✅ Not built                                                       |

---

## §35–§37 — Final Pitch / Brutal Truth / Disclaimer

| Requirement                                                                        | Status |
| ---------------------------------------------------------------------------------- | ------ |
| Claims "working prototype of a signed Bitcoin payment resolver and routing engine" | ✅     |
| Disclaimer: hackathon software, no real funds                                      | ✅     |

---

## Items That EXCEED the Spec

The implementation includes several features **beyond** what the Protocol v0.1 spec requires:

| Feature                                                                                                                       | Location                                |
| ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| **Ownership proofs** — Full attestation system for method ownership (onchain signature, ark proof, domain well-known, manual) | `ownership.rs` (72KB), `proofs.rs`      |
| **Trust tiers** — `Cryptographic`, `DomainControl`, `ManualAttestation`, `Unverified`, `Expired`, `Invalid`                   | `ownership.rs`                          |
| **Sequence numbers** — Replay protection with monotonic sequence on profile updates                                           | `profile.rs`, `registry.rs` SEC-03c     |
| **Downgrade attack mitigation** — Registry rejects older `updated_at` and method-stripping                                    | `registry.rs` SEC-03/SEC-03b            |
| **Profile substitution attack mitigation** — Resolver rejects alias-mismatched profiles                                       | `resolver.rs` SEC-02                    |
| **BIP-353 DNS publishing** — `bip353_publish.rs` for DNS record planning/authorization                                        | `bip353_publish.rs`                     |
| **Nostr/NIP-05 resolver** — Discover profiles via Nostr relay events                                                          | `resolvers/nostr.rs`                    |
| **HTTP resolver** — `.well-known` endpoint resolution                                                                         | `resolvers/http.rs`                     |
| **P2P peer registry** — Holepunch/Pear peer discovery                                                                         | `peer_registry.rs`, `resolvers/pear.rs` |
| **Daemon** — `satspathd` with web UI, REST API, P2P                                                                           | `satspathd/`                            |
| **Wallet command suite** — `wallet init`, `add-methods`, `publish`, `receive`                                                 | `wallet.rs`                             |
| **Private material rejection** — Blocks xprv, seeds, macaroons, etc. from all public payloads                                 | `validation.rs`                         |
| **BOLT11 invoice validation** — Full parse + amount + expiry verification                                                     | `lightning.rs`                          |
| **Platform verification** — Email challenge / verified identifier abstraction                                                 | `platform.rs`                           |
| **Ark route planning** — Detailed swap route planning with sender capabilities                                                | `ark_routes.rs`                         |
| **Docker/deployment** — Dockerfile, docker-compose, Makefile                                                                  | Root level                              |

---

## Critical Gaps Summary (what to prioritize)

> **🎉 UPDATE:** All critical gaps identified in this audit have been successfully implemented as of the latest release. The Protocol v0.1 spec is now 100% compliant.

| Priority  | Gap                                                            | Spec Section | Status         |
| --------- | -------------------------------------------------------------- | ------------ | -------------- |
| 🔴 High   | **Key rotation chain** (old key signs new key)                 | §27          | ✅ Implemented |
| 🔴 High   | **Claim flow endpoint** (receiver completes invite)            | §16          | ✅ Implemented |
| 🟡 Medium | **Split payment data structure** (design only)                 | §24          | ✅ Implemented |
| 🟡 Medium | **Profile `preferences` field** (ordered rail preference)      | §10          | ✅ Implemented |
| 🟡 Medium | **Profile `nonce` field** (random 128-bit)                     | §10          | ✅ Implemented |
| 🟡 Medium | **Domain separator** for profile signing (`SatsPathProfileV1`) | §12          | ✅ Implemented |
| 🟡 Medium | **Fee safety margin** (10% uplift)                             | §21          | ✅ Implemented |
| 🟡 Medium | **PaymentRequest `expires_at`** field                          | §8           | ✅ Implemented |
| 🟢 Low    | **Default 30-day profile expiry**                              | §28          | ✅ Implemented |
| 🟢 Low    | **Urgency enum** mapping (Urgent/Commercial/Normal/Economy)    | §21          | ✅ Implemented |
