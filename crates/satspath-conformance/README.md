# Incremental protocol conformance runner (#175)

From the repository root:

```sh
cargo run -p satspath-conformance -- test --format text
cargo run -p satspath-conformance -- test --format json
cargo run -p satspath-conformance -- test --resolver https://resolver.example.com/.well-known/satspath/alice --alias alice@example.com
cargo run -p satspath-conformance -- test --observed wallet-output.json --format json
```

`vectors/v1.json` is machine-readable. Missing/incorrect results fail; unknown
features are SKIP, never PASS. `--observed` compares a third-party wallet or
SDK's JSON object from vector ID to output; it does not execute that wallet or
attest a real payment. The live resolver probe uses production HTTPS, SSRF/DNS
pinning, response limits, signature and expiry verification, and checks the
requested alias. The resolver-disagreement vectors use a fixed `as_of` timestamp
and the protocol's 60-second expiry grace so their outcomes do not change as
wall-clock time advances. CI runs these vectors through `cargo test --workspace`.

**Not yet demonstrated:** wallet execution, BIP-353 DNSSEC chain validation,
positive rotation history, PaymentIntent approval (#173) and authenticated
resolver conflict policy (#174). These cannot be claimed PASS from this suite
until executable adapters and vectors are added.
