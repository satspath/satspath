# Ark Routes

SatsPath treats Ark as a public payment rail and keeps execution separate from
route planning.

## Direct Ark Receive

An Ark receiver can publish an Ark public pointer:

- Ark server URL,
- compressed receiver public key,
- optional VTXO pointer,
- optional ownership proof.

If the sender is compatible with the same Ark server, the route planner can
produce an `ArkToArk` intent. This does not require Boltz, Lightning, or an
on-chain swap. Current SatsPath CLI output is preview/intents unless explicitly
testnet-executed and supported by the local bridge.

## Ark Swap Routes

Ark swaps are different from direct Ark receive:

- `ArkToLightning` requires an offboard/submarine-style path.
- `LightningToArk` requires an onboard/reverse path.
- `ArkToOnchain` requires Ark offboard support.
- `OnchainToArk` requires Ark onboard support.

SatsPath does not call a normal Bitcoin address an Ark receive. If the Ark bridge
cannot create or claim the required Ark-side object, the route is intent-only and
fails closed for execution.

## Current Status

- Ark route planning and scoring are implemented.
- Live Ark ASP client connector (`LiveArkAspClient`) queries real ASP public keys, round intervals, dust limits, and fee schedules (`/v1/info`).
- VTXO covenant tree DAG verification (`verify_ark_vtxo_dag`) and non-custodial host-wallet settlement handoff structures (`ArkBoardingHandoff`, `ArkForfeitHandoff`, `ArkOorPaymentRequest`) are implemented in `crates/satspath-router/src/ark.rs`.
- Ownership proof verification exists.
- Mainnet execution by SatsPath is disabled; all signing and settlement execution is delegated to compatible host wallets (e.g. Arkade Money).
