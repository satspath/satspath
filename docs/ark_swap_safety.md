# Ark Swap Safety

Ark swap support is intentionally conservative.

## Safety Rules

- Mainnet execution is unavailable.
- Preview mode never moves funds.
- SatsPath never stores seed phrases, private keys, macaroons, certs, API keys,
  or passwords in plaintext.
- Swap execution must use encrypted `SwapStore`.
- Plaintext swap storage is only available through an explicit test/dev API.
- Claim/refund builders are required before executing a route that can strand
  funds.

## Execution Gates

Commands that can move testnet funds require:

- `--testnet`,
- `--execute-testnet`,
- `--confirm "execute testnet ark intent"`,
- valid signed profile,
- fresh profile,
- valid Ark server URL,
- compressed secp256k1 receiver pubkey,
- verified Ark ownership proof,
- supported Ark bridge method,
- available claim/refund builder for swap routes.

If any gate fails, execution is blocked and the command remains preview-only.

## Not Implemented

- Mainnet Ark execution.
- Ark funding for Boltz submarine swaps.
- Lightning-to-Ark delivery if Boltz can only deliver to a BTC address.
- Ark onboard address creation and VTXO claiming.
- Ark offboard execution to arbitrary BTC destinations.
- Reverse/chain claim transaction builders.
- Submarine refund transaction builder.
