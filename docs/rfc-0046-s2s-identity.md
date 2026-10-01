# RFC-0046: SatsPath v2 - Authoritative Server-to-Server Identity Resolution

## Objective

Move SatsPath from a transport-neutral/P2P-oriented prototype to an **authoritative Server-to-Server (S2S) resolution protocol** for identifiers such as `alice@example.com`.

A domain owner should be able to run a SatsPath authority for its own namespace, publish a DNS-discoverable endpoint, and let wallets or other SatsPath servers resolve proof-carrying payment profiles. A hosted provider may also issue identifiers under its own domain.

## Implementation Phases

### Phase 0 — Freeze the security contract

- **Issues:** #47, #48
- Define the v2 trust model and S2S wire protocol.

### Phase 1 — Establish authority and immutable state

- **Issues:** #49, #50, #45, #51, #52
- Integrate compact consistency proofs.
- Develop append-only Merkle logs.
- Support current-state and non-inclusion proofs.

### Phase 2 — Build the S2S system

- **Issues:** #53, #54, #55
- DNS namespace delegation and authoritative server mutation API.
- Replication and failover support.

### Phase 3 — Sovereignty and payment-method parity

- **Issues:** #56, #57, #59
- BOLT12 binding.
- Self-hosting UX and migration tools.

### Phase 4 — Cutover and production gate

- **Issues:** #58, #60
- Security conformance suites.
- Retire Pear/Holepunch P2P architecture.

## Non-negotiable security invariant

The server stores, logs, replicates, and serves identity data; it is **not allowed to author identity changes**.
A valid S2S response must let a verifier establish all criteria without trusting the serving server.

## Trust Composition

```text
DNSSEC / explicit namespace pin
        |
        v
domain namespace descriptor + authority key
        |
        v
owner-authorized name-event chain
        |
        v
append-only Merkle log + current-state proof
        |
        v
signed checkpoint + witness quorum
        |
        v
proof-carrying S2S response
        |
        v
local verification -> route selection
```
