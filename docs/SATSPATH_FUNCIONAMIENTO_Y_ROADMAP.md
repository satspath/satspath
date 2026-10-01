# SatsPath Architecture, Operation, and Production Roadmap

**Repository:** `Truja503/satspath`  
**Purpose:** Explain what SatsPath is, how it operates, its current architectural capabilities, and the exact steps required to transition it into production-grade infrastructure for wallets and applications.

---

## 1. Executive Summary

SatsPath is an open-source, non-custodial protocol and toolset designed to discover, verify, and select Bitcoin payment methods from human-readable identifiers, for example:

```text
alice@satspath.dev
```

Instead of requiring the sender to know in advance whether the recipient uses Lightning, an on-chain address, Ark, or BOLT12, SatsPath publishes a cryptographically signed profile containing all available public receiving methods.

The end-to-end resolution pipeline operates as follows:

```text
Human-Readable Identifier
    ↓
Resolver Chain (Local, BIP-353, HTTPS S2S v2, Nostr, P2P)
    ↓
Signed Payment Profile
    ↓
Cryptographic Verification (secp256k1 Schnorr, Merkle Inclusion, Checkpoint)
    ↓
Multi-Rail Smart Routing (satspath-router)
    ↓
Payable Instruction (BOLT11/12, Ark URI, BIP-21 URI) → Host Wallet Handoff
```

SatsPath operates strictly on public data and constructs instructions that any compliant Bitcoin wallet can execute. For example, it resolves a BOLT11 invoice via LNURL-pay, generates a BIP-21 URI for on-chain addresses, or returns a standard Ark pointer.

SatsPath **never stores seeds, xprv keys, or spending secrets**. Identity keypairs are used exclusively to sign public profiles and prove message integrity. Bitcoin spending keys remain isolated within the host wallet.

> **Core Value Proposition:** SatsPath transforms a human-readable identity into a cryptographically verified payment instruction and selects the optimal rail for host wallet settlement.

---

## 2. The Multi-Rail Fragmented Problem

Bitcoin no longer possesses a single settlement method. Users and merchants accept payments across diverse rails:

- Lightning Address
- LNURL-pay
- BOLT11 Invoices
- BOLT12 Offers
- Standard On-Chain Addresses (BIP-84, Taproot)
- Silent Payments (BIP-352)
- Ark Protocol (VTXOs)

Each rail exhibits different trade-offs across speed, fees, privacy, availability, liquidity, and infrastructure dependencies.

SatsPath acts as a zero-trust cryptographic layer answering three fundamental questions:
1. **Who is the recipient?**
2. **What public receiving methods do they accept?**
3. **Which method is optimal for this specific transaction?**

---

## 3. The Signed Payment Profile

The primary cryptographic artifact is `SignedPaymentProfile`. A profile payload contains:

```json
{
  "alias": "alice@satspath.dev",
  "identity_pubkey": "03e0fa79bc28965724d3eee52d58cf0cd11f712462582f42e79a545d13d85aac0b",
  "methods": [
    {
      "type": "Lightning",
      "lightning_address": "alice@getalby.com"
    },
    {
      "type": "Onchain",
      "network": "Mainnet",
      "address": "bc1q..."
    },
    {
      "type": "Ark",
      "server": "https://ark.example.com",
      "pubkey": "02..."
    }
  ],
  "updated_at": 1782810000,
  "expires_at": 1785402000,
  "sequence": 4
}
```

The profile is canonicalized and signed using `secp256k1` Schnorr signatures:

```text
PaymentProfile
    ↓ RFC-8785 Canonical JSON
SHA-256 (with domain separator "SatsPathProfileV1")
    ↓
secp256k1 Schnorr Signature
```

Verification guarantees that:
- The profile was not modified in transit.
- Payment methods were not substituted or stripped during resolution.
- The identity public key corresponds to the signature.
- The payload maintains complete cryptographic integrity.

---

## 4. End-to-End System Operation

### 4.1 Identity Derivation
The identity keypair is derived deterministically from the wallet seed using HMAC-SHA512 with domain separator `b"SatsPath Identity Key m/9737'/0'"` and the account index. It signs public profiles and rotation proofs without accessing spending keys.

### 4.2 Profile Assembly & Signing
The user or wallet configures public receive methods (Lightning, On-chain, Ark). The profile is canonicalized, timestamped, assigned a monotonic sequence number, and signed.

### 4.3 Multi-Transport Distribution
Profiles can be distributed across neutral transports:
- Authoritative S2S v2 daemon (`satspathd`) with RFC 6962 Merkle transparency logs.
- HTTPS `.well-known` endpoints.
- BIP-353 via DNSSEC.
- Nostr relays via NIP-05.
- P2P swarms via Holepunch / Pear.

### 4.4 Resolution & Verification
The payer inputs an alias (e.g. `alice@domain.com`). SatsPath queries the resolver chain, validates the exact alias match, verifies the Schnorr signature, inspects expiration and sequence freshness, and checks Merkle inclusion proofs.

### 4.5 Multi-Rail Smart Routing
`satspath-router` scores available methods based on:
- Live `mempool.space` fee rates.
- Payment amount thresholds (micro-payments prefer Lightning; large settlements select On-Chain).
- Transport health and user preferences.

### 4.6 Payment Handoff
SatsPath outputs a standardized payload (`BOLT11 invoice`, `BIP-21 URI`, or `Ark pointer`) and passes it to the host wallet for execution.

---

## 5. Production Architectural Boundary

```text
┌─────────────────────────────────────────────────────────────┐
│ Host Wallet or Client Application                           │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ SatsPath SDK (@satspath/wasm & @satspath/router)            │
│  • Resolver Chain (Local, BIP-353, S2S v2, Nostr)           │
│  • Cryptographic Verifier (Schnorr, Merkle Proofs)          │
│  • Smart Routing & Fee Engine                               │
│  • Payment Payload Builder                                  │
└──────────────┬───────────────────────────────┬──────────────┘
               │                               │
               ▼                               ▼
┌──────────────────────────────┐ ┌────────────────────────────┐
│ Transports & Networks        │ │ Host Wallet Execution      │
│  • S2S v2 HTTPS / DNSSEC     │ │  • Lightning Node / LDK    │
│  • Nostr / P2P Swarms        │ │  • Bitcoin Core / PSBT     │
│  • Merkle Transparency Logs  │ │  • Ark ASP Client          │
└──────────────────────────────┘ └────────────────────────────┘
```

---

## 6. Production Milestone Checklist (v0.2)

### Security & Cryptography
- [x] Fail-closed verification for invalid or expired profiles.
- [x] Replay protection via monotonic sequence and timestamp validation.
- [x] SSRF hardening with strict port allowlists (80, 443, 8080, 8443) and metadata IP blocking.
- [x] Merkle tree transparency with Bitcoin on-chain checkpoint anchoring (`OP_RETURN`).
- [ ] Production-grade distributed witness quorum cosigning ($K$-of-$N$).

### Integration & Tooling
- [x] Standardized `QuoteResponse` UX contract (`ok`, `invalid_signature`, `no_route`, `not_registered`).
- [x] Fast WebAssembly client bindings (`@satspath/wasm`).
- [x] Complete developer quickstart with `pnpm` ([`docs/SDK_QUICKSTART.md`](SDK_QUICKSTART.md)).
- [ ] Mobile bindings for React Native and Flutter.
- [ ] End-to-end payment settlement in reference wallet.

---

## 7. Conclusion

SatsPath establishes a sovereign, zero-trust discovery and routing layer for the Bitcoin ecosystem. By separating identity resolution from financial custody, it enables seamless multi-rail interoperability across all modern wallets and services.
