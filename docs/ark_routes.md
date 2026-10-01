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

- Ark route planning exists.
- Ark direct receive/send previews exist.
- Ownership proof verification exists.
- Mainnet execution is disabled.
- Testnet execution is gated by `--testnet`, `--execute-testnet`, exact
  confirmation text, profile validation, Ark ownership proof validation, bridge
  availability, encrypted swap storage, and claim/refund builder availability.
- Boltz Ark swap settlement is not implemented end to end.
