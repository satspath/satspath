# SatsPath v2 Authenticated State Map

## Overview

An append-only Merkle log efficiently proves that an event exists in history, but it cannot efficiently prove non-inclusion (i.e. that an identifier is NOT registered) or that an event is the _latest_ state. To prevent malicious log operators from selectively hiding identifiers via omission, SatsPath utilizes a dual authenticated structure.

## Dual Authenticated Structure

1. **History Log**: The server-wide append-only Merkle tree containing every signed `NameEvent`.
2. **Current-State Map**: A verifiable Sparse Merkle Tree (SMT) mapping a domain-separated `identifier_hash` to a leaf value containing `{latest_event_hash, sequence, status}`.

A checkpoint commits to BOTH structures simultaneously (`log_root` and `map_root`). Any mutation updates both atomically.

## Current-State Map Design

We employ a Sparse Merkle Tree (SMT) with a 256-bit key space (the `identifier_hash`).

### Cryptographic Properties

- **Leaf Hashing**: `H(domain_separator || key || value)`
- **Internal Node Hashing**: `H(domain_separator || left_child || right_child)`
- **Domain Separation**: Explicit 32-byte domain tags to prevent internal nodes from being treated as leaves, and to separate map hashing from log hashing.

### Proof Formats

1. **Inclusion Proof**: A path of sibling nodes from the leaf to the root. Verifies that the specific `(key, value)` exists at the leaf index.
2. **Non-Inclusion Proof**: A path of sibling nodes to an empty leaf or a leaf with a different key. Verifies that the requested key does not have an entry in the map.

## Verification Rules

- **Positive Resolution**: Must include a valid inclusion proof binding the requested identifier's latest state to the `map_root` of a fresh checkpoint.
- **Negative Resolution (`not_registered`)**: Must include a valid non-inclusion proof against the same `map_root`.
- **Revoked**: Revocation is an included state, NOT a non-inclusion. A revoked identifier has an inclusion proof showing `status = Revoked`.
- **Cross-binding**: The map proof, log proof, roots, sizes, and checkpoint must be cross-bound in the `ResolutionEnvelope`.

## Security Considerations

- **Dictionary Attacks**: Hashing identifiers reduces disclosure in the tree, but does not stop offline dictionary enumeration of short or predictable aliases.
- **Atomic Commits**: Rollbacks must leave neither the log nor the map partially advanced.
