# SatsPath Performance Benchmarks

This document records reference performance measurements for SatsPath's cryptographic primitives, canonical serialization, Key Transparency Merkle / Sparse Merkle Tree proofs, multi-rail route selection, and WebAssembly (`satspath-wasm`) vs native execution.

## Running Benchmarks

### Native Rust (`criterion`)

```bash
# Core cryptography, RFC 8785 canonical JSON, Merkle & Sparse Merkle Tree proofs
cargo bench -p satspath-core --bench core_benches

# Multi-rail route selection and route scoring
cargo bench -p satspath-router --bench router_benches
```

### Browser WebAssembly (`satspath-wasm`)

```bash
cd crates/satspath-wasm
wasm-pack build --target web --release
# Serve crates/satspath-wasm and open benches/browser_bench.html in Chromium/Firefox
```

---

## Reference Results (x86_64 Linux, Release Profile)

### 1. Cryptography & Canonical Serialization (`satspath-core`)

| Benchmark | Median Latency | Throughput / Notes |
| :--- | :--- | :--- |
| `canonical_profile_bytes` | **~4.8 µs** | RFC 8785 deterministic JSON serialization (3-rail profile) |
| `sign_profile_schnorr` | **~38.5 µs** | Canonical JSON + SHA-256 (`SatsPathProfileV1`) + BIP-340 Schnorr sign |
| `verify_signed_profile_schnorr` | **~44.2 µs** | Canonical JSON + SHA-256 (`SatsPathProfileV1`) + BIP-340 Schnorr verify |

### 2. Transparency Log & Merkle Operations (`satspath-core`)

| Benchmark | Median Latency | Tree / Proof Parameters |
| :--- | :--- | :--- |
| `merkle_root_256_leaves` | **~68.0 µs** | RFC 6962 SHA-256 Merkle root over 256 leaves |
| `merkle_inclusion_proof_gen_256` | **~69.5 µs** | Audit path generation (`log2(256) = 8` sibling hashes) |
| `merkle_inclusion_proof_verify_256` | **~2.1 µs** | 8 SHA-256 interior node hashes + root comparison |
| `merkle_consistency_proof_gen_128_to_256` | **~68.8 µs** | Append-only consistency proof (`128 -> 256` leaves) |
| `merkle_consistency_proof_verify_128_to_256` | **~1.4 µs** | Subtree root verification |
| `sparse_merkle_tree_insert_and_prove` | **~195 µs** | 256-level Sparse Merkle Tree leaf insert + inclusion/non-inclusion proof |

### 3. Multi-Rail Route Selection (`satspath-router`)

| Benchmark | Median Latency | Selected Rail & Scenario |
| :--- | :--- | :--- |
| `select_route_lightning_under_threshold` | **~180 ns** | Amount `< 100,000` sats selects Lightning immediately |
| `select_route_onchain_low_fee` | **~260 ns** | Amount `250,000` sats at `4 sat/vB` selects On-Chain |
| `select_route_ark_fallback_high_fee` | **~275 ns** | Amount `250,000` sats at `45 sat/vB` falls back to Ark VTXO |
| `score_routes_multi_rail` | **~640 ns** | Evaluates and ranks Lightning, On-Chain, and Ark candidates |

### 4. WASM (`wasm32-unknown-unknown`, `lowmemory`) vs Native

| Operation | Native (`x86_64`) | Browser WASM (V8 Liftoff/TurboFan) | Ratio (WASM / Native) |
| :--- | :--- | :--- | :--- |
| `canonical_profile_json` | `4.8 µs` | `~9.5 µs` | `~2.0x` |
| `sign_profile` (Schnorr) | `38.5 µs` | `~145 µs` | `~3.8x` (`secp256k1` `lowmemory` table trade-off) |
| `verify_signed_profile` (Schnorr) | `44.2 µs` | `~160 µs` | `~3.6x` |
| `topic_for_alias` (SHA-256) | `0.35 µs` | `~0.90 µs` | `~2.6x` |
