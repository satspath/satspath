# Routing Model

SatsPath compares Lightning, on-chain Bitcoin, and Ark using public profile
data, fee estimates, and user preferences.

`RouteCandidate` includes:

- rail,
- estimated fee,
- estimated time,
- privacy score,
- reliability score,
- user action requirement,
- availability,
- reason.

## MVP Rules

Lightning:

- preferred for small and medium amounts when available,
- uses conservative fee heuristics,
- does not query private node data unless explicitly configured.

On-chain:

- estimates fee as vbytes multiplied by sat/vB,
- rejects dust or economically irrational outputs,
- preferred for large amounts or when Lightning is unavailable.

Ark:

- experimental,
- considered when an Ark public pointer exists,
- selected only when experimental Ark is allowed,
- no mainnet settlement in SatsPath.

## Execution Boundary

Route selection produces a payment pointer and explanation. It does not sign,
broadcast, settle, or move funds.
