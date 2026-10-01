# SatsPath v2 Authoritative Server

## Overview

The SatsPath v2 server is an authoritative, network-facing identity resolution service that hosts one or more namespaces and returns proof-carrying resolution envelopes. It is strictly a discovery layer: it does not sign or broadcast payments and accepts no wallet spending secrets. Every `ResolutionEnvelope` delivers mandatory cryptographic evidence (`signed_profile`, `name_events`, `inclusion_proof`, and `checkpoint`), while optional extended proofs (`consistency_proof`, `current_state_proof`, and `witness_cosignatures`) are populated when requested by the client or configured by the namespace operator.

## V2 API Endpoints

### `GET /.well-known/satspath-authority`

Returns the signed `NamespaceDescriptor` for the hosted domain, including the operator public key, witness quorum policy, and endpoint list.

### `GET /v2/resolve` / `POST /v2/resolve`

Accepts `identifier` query parameter (or POST body `{"identifier": "..."}` to avoid placing sub-identifiers directly into URL query parameters) and returns a `ResolutionEnvelope` containing:

- The signed payment profile (`signed_profile`).
- All name events for the identifier (`name_events`).
- Merkle inclusion proof binding the event to the log (`inclusion_proof`).
- The latest signed checkpoint (`checkpoint`).
- Consistency proof (if requested or pinned) (`consistency_proof`).
- Current-state map proof (when configured) (`current_state_proof`).
- Witness cosignatures (when witness quorum is configured) (`witness_cosignatures`).

### `GET /v2/checkpoint/latest`

Returns the latest signed `TransparencyCheckpoint` with its attached witness cosignatures.

### `GET /v2/health`

Returns readiness status, version, checkpoint age, witness quorum health, and replica lag metrics.

## Resolution Pipeline

```text
canonical identifier
-> discover authoritative namespace
-> fetch proof envelope
-> verify namespace binding
-> verify owner event/profile
-> verify current-state proof
-> verify append-only inclusion + consistency
-> verify operator continuity + witness policy
-> verify method ownership
-> route
```

Every quote/pay/preview path must consume the same verified result. Legacy data or transport responses must not bypass this composition.

## Security Requirements

- HTTPS required in deployment; strict origin/redirect rules in the client.
- Atomic SQLite persistence remains fail-closed under crashes.
- Bounded request/response bodies, proof depths, histories, concurrency, and timeouts.
- Rate limits per namespace/IP without changing cryptographic truth.
- SSRF prevention through descriptors, payment-method metadata, redirects, and replica URLs.
- No logging of auth tokens, challenges, full sensitive request metadata, or any private keys.
- Multi-tenant namespace separation prevents cross-namespace reads, writes, proof reuse, and key confusion.
