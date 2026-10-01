# BOLT12 Offers in SatsPath

SatsPath supports BOLT12 offers as a first-class, identity-bound payment method. This allows users to publish reusable payment instructions while ensuring SatsPath remains strictly a discovery and routing layer rather than executing payments itself.

## Data Model

The `PaymentMethod` enum includes the `Bolt12(Bolt12Offer)` variant:

```json
{
  "type": "Bolt12",
  "label": "Donation Offer",
  "offer": "lno1...",
  "network": "mainnet",
  "issuer_pubkey": "03..."
}
```

The exact BOLT12 string (`lno1...`) is preserved and signed directly within the user's profile.

## Validation & Parsing

SatsPath validates offers before allowing them into the profile:

- **Prefix validation**: Verifies that BOLT12 offer strings start with the `lno1` Bech32 prefix.

_Future extensions will decode full TLV trees to validate expiry, unknown required feature bits, and amount constraints directly._

## Routing & Handoff

When resolving a SatsPath identifier that prefers BOLT12, the server returns the raw offer payload to the client. The client/wallet then decides whether to:

1. Parse the BOLT12 offer directly.
2. Rely on a `bitcoin:?lno=...` (BIP-321) URI handoff to trigger a standard wallet payment flow.

SatsPath servers **never** attempt to fetch an invoice (e.g. `invoice_request`) on behalf of the user, preserving the privacy and non-custodial nature of the S2S routing layer.
