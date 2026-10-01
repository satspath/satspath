# Experimental daemon Hyperswarm bridge

`satspathd --p2p` optionally manages the Node >=20 SDK from this source checkout.
Run `npm ci` in `sdk/satspath-p2p` first. Without `--p2p`, no Node process or
Hyperswarm discovery is started. Packaged binary distribution/relocatable script
installation is not implemented; the fixed build-time source script must exist.

## Identity and authority

An alias is a namespace pointer, not a cryptographic identity. The durable anchor
is the identity public key, fingerprint and authorized continuity history.
Changing an alias does not require changing keys. A valid signature proves that
the key holder signed the profile, not that they control its domain or inbox.
`truja@binance.com` remains self-asserted without independent authority evidence.
`.test`/`.local` names are local development names, never global ownership proof.
The daemon's mock email challenge is not a real identifier attestation.

Existing `VerificationStates`, attestation verification, method trust evaluation,
transactional transparency storage and authorized rotation are reused. No new
generic verified flag or namespace ownership cryptography is introduced.
Namespace operators (including satspath.com when chosen) can allocate/delist
their own names; they cannot acquire users' identity/spending keys or authorize
identity rotation alone. satspath.com is not mandatory.

## Publication and lifecycle

The daemon supervises one public snapshot for its wallet's **active alias**.
It checks that the snapshot belongs to the local identity and passes existing
Rust signature, canonical alias and private-material validation. Revoked and
expired profiles are withdrawn. Changes are detected every two seconds; the
old sidecar is shut down before a replacement starts. Normal updates/revocations
can take two seconds to withdraw; a pending startup can delay polling by its
20-second timeout. Withdrawal is not instantaneous. Expiry is also checked on
peer requests, including peers that connected before expiry.
The sidecar has no daemon home path or auth token. Only typed public profile JSON
is written to stdin. Unknown/private daemon configuration is never serialized.
It uses the standalone SDK topic and GET_PROFILE protocol without format changes.

The executable is Node from the operator's PATH; the script path is fixed to the
trusted checkout. There is no shell interpolation. Environment inheritance is
cleared except OS runtime/PATH/temp variables. This is a secret-minimizing process
boundary, **not an OS sandbox**: Node still runs with the user's filesystem rights.
The daemon must run trusted SDK dependencies/code. Transport Noise keys are not
SatsPath identity keys. Peer input never selects paths, executables or modules.

Status: disabled, starting, active, degraded, stopped. Active means the supervisor
is ready; `announcements` distinguishes whether a profile is actually announced.
No profile means zero announcements. Errors degrade transport without changing
wallet/registry state. Ctrl+C (and SIGTERM on Unix) unblocks the HTTP server, closes sidecar stdin and
waits up to three seconds, then kills/reaps the process if necessary. Dropped or
timed-out child operations also use kill-on-drop. IPC EOF also stops the sidecar
when its parent exits unexpectedly. No daemon secrets enter logs.
Network stalls are bounded; failed startup is retried with a two-second interval.

## Resolution and routing

Authenticated `POST /v1/p2p/resolve` with `{"alias":"alice@example.com"}` downloads
a **candidate**. The existing HTTP body/rate limits apply, and at most one P2P
resolution per daemon runs concurrently. Rust checks bounded UTF-8/JSON, private
material, canonical alias binding, signature, expiry and revocation. If a local
transparency profile exists, its identity cannot be replaced and timestamp/sequence
rollback and conflicting equal sequences are rejected. An identical equal-sequence
profile can be returned. Candidates are not persisted, so no TOFU pin is created.
Profiles lacking expiry remain replayable when no prior state exists.

**Bare SignedPaymentProfile does not contain remote transparency proofs.** The
response therefore always has `routing_eligible: false`, `identifier_verified:
false`, `key_continuity_verified: false` and `transparency_verified: false`.
It reports signature validity and payment-method proof states separately.
Even a legitimate key change cannot be accepted through this candidate endpoint:
use the existing transparent rotation flow. Existing routing/resolver priorities
remain unchanged; the P2P candidate source cannot override a stronger authority.
P2P routing integration requires a separate protocol design for remote proofs.

## Abuse, privacy and control center

Profiles/responses are bounded to 51,200 bytes, peer exchanges to ten seconds,
discovery to 25 seconds and the Rust operation to 30 seconds. Publication allows
16 peers and at most 32 incoming sessions per ten seconds. One request per stream;
malformed/oversized/repeated requests disconnect. SDK status logs contain no raw
aliases, profiles, keys or peer addresses. Deterministic hashed aliases permit
dictionary attacks: pseudonymity/transit obfuscation is not anonymity. Exported
profiles are public and may inherently contain receiving addresses or domains.
No wallet-provider metadata was added; no spending authority or Bitcoin signing
is involved.

The dashboard defaults to Node Control. `/v1/control` exposes a local fingerprint,
active alias count, capability names, separate trust booleans and transport status.
It does not expose profile contents or payment-method descriptors. Peer count is
unknown (`null`), not a fabricated zero. Nostr is an on-demand resolver, not an
exclusive P2P layer or a claimed active broadcast service. Existing wallet and
transparency tools remain accessible. A multi-alias catalog, per-resolver telemetry
and event stream are deliberately deferred rather than populated with inferred data.

## Manual Rodrigo / Marcelo test

1. Both: `cd sdk/satspath-p2p && npm ci`; build Rust binaries from the repository.
2. Rodrigo: run `satspathd --p2p --no-open` with his existing home and active signed
   public profile. Open the control center: announcement count should reach one.
3. Marcelo: run his own daemon on another network. Read its local admin token
   privately and use it as a Bearer header for `POST /v1/p2p/resolve` with Rodrigo's
   exact profile alias. Never send the token to a peer or paste it into shared logs.
4. Inspect separate result fields: signature true, authority/continuity/transparency
   false, routing eligibility false. Compare fingerprints over a trusted channel.
5. Update Rodrigo's profile through the normal authenticated daemon flow; retry
   resolution after the refreshed announcement. Revoke/expire it and check withdrawal.
6. Ctrl+C on both nodes; verify no bridge Node process remains. Restart without
   `--p2p`: Hyperswarm must report disabled.

Standalone publish/resolve examples remain supported. Their previously tested
cross-network behavior does not validate daemon supervision; the above two-peer
daemon procedure still needs operator validation.
