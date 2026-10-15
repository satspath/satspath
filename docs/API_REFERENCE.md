# `satspathd` REST API Reference (`/v1` & `/v2`)

This reference documents the HTTP endpoints served by `satspathd` (`crates/satspathd/src/router.rs`). For the machine-readable OpenAPI 3.0 specification, see [`docs/openapi.yaml`](openapi.yaml).

---

## 1. Security, Authentication & Rate Limiting

### Authentication
- **Public Read Endpoints** (`/v2/resolve`, `/v2/namespace`, `/.well-known/satspath-authority`, `/health`, `/v1/transparency/*` GET endpoints) do not require authentication.
- **Admin / Mutating Endpoints** (`/v1/profile`, `/v1/profile/rotate-key`, `/v1/profile/recover`, `/v1/control`, `/v1/transparency/anchors`, `/v1/transparency/catena/anchor`) require a Bearer token matching `SATSPATH_API_TOKEN`:
  ```http
  Authorization: Bearer <SATSPATH_API_TOKEN>
  ```

### Rate Limiting & Payload Guards
- **Per-IP Token Bucket:** Default burst capacity of `60` requests and refill rate of `10.0` requests/sec per IP (`crates/satspathd/src/rate_limit.rs`).
- **Response Headers:**
  - `X-Request-ID`: Correlation UUID for structured logs.
  - `Retry-After`: Seconds to wait before retrying when `HTTP 429 Too Many Requests` is returned.
- **Payload Cap:** Request bodies exceeding `65,536` bytes (`64 KB`) are rejected with `HTTP 413 Payload Too Large`.

---

## 2. S2S v2 Authoritative Endpoints

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/.well-known/satspath-authority` | Public | Returns the signed `NamespaceDescriptor` for domain authority discovery. |
| `GET` | `/v2/namespace` | Public | Alias for `/.well-known/satspath-authority`. |
| `GET` | `/v2/resolve?id=<alias>&pinned_size=<n>` | Public | Returns a full `ResolutionEnvelope` containing the signed profile, `NameEvent`, RFC 6962 inclusion proof, optional consistency proof from `pinned_size`, `StateMapProof` (inclusion or non-inclusion), signed `TransparencyCheckpoint`, and witness cosignatures. |
| `GET` | `/v2/health` | Public | Deep dependency health check (`sqlite`, `fee_api`, `transparency_log`). |

---

## 3. Core Discovery, Quote & Transparency Endpoints (`/v1`)

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/health`, `/v1/health` | Public | Deep health status (`200 OK` or `503 Service Unavailable`). |
| `GET` | `/metrics` | Public | Prometheus metrics exposition (`text/plain; version=0.0.4`). |
| `GET` | `/v1/diagnostics/rate_limit` | Public | Returns `RateLimiterStats` (`tracked_ips`, `total_allowed`, `total_blocked`). |
| `POST` | `/v1/resolve` | Public | Resolves an `{"alias": "alice@example.com"}` through the mandatory transparency + ownership verifier. |
| `POST` | `/v1/quote` | Public | Resolves recipient, verifies transparency & method ownership, and returns a `QuoteResponse` (`{"alias": "...", "amount_sats": 21000}`). |
| `POST` | `/v1/preview` | Public | Mainnet-safe route and handoff preview without moving funds. |
| `POST` | `/v1/dns/resolve` | Public | Resolves a BIP-353 DNS name (`₿user@domain`) under `DnssecPolicy::Strict`. |
| `GET` | `/v1/transparency/status` | Public | Returns `TransparencyStatus` (`log_size`, `log_root`, `map_root`, `consistency_status`). |
| `GET` | `/v1/transparency/checkpoints` | Public | Paginated list of signed operator checkpoints (`?offset=0&limit=50`). |
| `GET` | `/v1/transparency/events` | Public | Paginated list of append-only `NameEvent` entries. |
| `GET` | `/v1/transparency/inclusion/:hash` | Public | Returns the RFC 6962 `MerkleInclusionProof` for an event hash. |
| `GET` | `/v1/transparency/consistency?old_size=M&new_size=N` | Public | Returns compact RFC 6962 `MerkleConsistencyProof` between tree sizes `M` and `N`. |
| `GET` | `/v1/transparency/catena/chain` | Public | Returns the `CatenaChainProof` of UTXO-linked Bitcoin `OP_RETURN` anchors. |
| `POST` | `/v1/transparency/anchors` | Bearer | Anchors the latest checkpoint on Bitcoin Core regtest (`SATSPATH_BITCOIN_NETWORK=regtest`). |
| `POST` | `/v1/profile` | Bearer | Registers or updates a signed `PaymentProfile` in the transparency log. |
| `POST` | `/v1/profile/rotate-key` | Bearer | Submits a dual-signed `RotateKey` transition event. |
| `POST` | `/v1/profile/recover` | Bearer | Submits an $M$-of-$N$ guardian `RecoverKey` transition event. |

---

## 4. Standard Error Codes

| HTTP Status | Meaning | Common Cause |
| :--- | :--- | :--- |
| `400 Bad Request` | Malformed request or validation failure | Invalid signature, untrusted `Host` header, or failed proof verification. |
| `401 Unauthorized` | Missing or invalid Bearer token | Mutating `/v1/*` call without valid `Authorization: Bearer <token>`. |
| `404 Not Found` | Resource or identifier not found | Unknown route or unregistered identifier. |
| `413 Payload Too Large` | Request body exceeds `64 KB` | Oversized JSON body blocked by `rate_limit.rs`. |
| `429 Too Many Requests` | IP token bucket exhausted | Client exceeded burst/refill limits; inspect `Retry-After` header. |
| `503 Service Unavailable` | Subsystem unhealthy | SQLite store unwritable or transparency log corrupted. |
