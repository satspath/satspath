# SatsPath Mainnet Preview Checklist

SatsPath Preview Mode is a public payment pointer resolver and QR preview.

It is safe to test with real mainnet public identifiers, public keys, Lightning
Addresses, LNURL metadata, BOLT11 invoices, Ark public pointers, and Bitcoin
addresses because this mode only touches public data.

Required CLI language:

```txt
SatsPath Preview Mode
No funds moved.
No signing performed.
No private keys touched.
Public payment pointer only.
```

Mainnet preview mode:

- Resolves an identifier to a signed public payment profile or local peer record.
- Verifies the signed profile before routing.
- Selects the best public route.
- Returns a public payment pointer.
- Builds a QR payload for Lightning, on-chain, or Ark public pointers.
- Uses mainnet address rules when `--mainnet-preview` is passed.
- Rejects QR payloads that appear to contain private material.

Mainnet preview mode does not:

- Sign transactions.
- Broadcast transactions.
- Pay invoices.
- Execute swaps.
- Generate seeds.
- Store seeds.
- Touch wallet private keys.
- Touch wallet signing keys.
- Read LND macaroons or node certs.
- Use API secrets.
- Auto-create wallets for unknown users.

Unknown user flow remains:

```txt
unknown identifier -> invite required -> receiver generates keys locally -> receiver publishes signed profile -> sender re-resolves
```

Actual mainnet payment execution must be implemented as a separate future
feature with stronger confirmation gates. Do not call a preview "payment sent"
or "payment complete".
