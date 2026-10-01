# Identity Ownership Model

SatsPath maps human identifiers to signed public payment profiles. The proof
attached to an identifier depends on the identifier type.

## Domain-Owned Identifier

Example:

```txt
₿rodrigo@satspath.dev
```

A domain-owned identifier can be verified through DNS-based mechanisms such as
BIP-353 and DNSSEC when the domain owner publishes payment instructions. This is
the preferred protocol-native ownership model because the user or wallet
operator controls the domain namespace.

SatsPath must fail closed when DNSSEC validation is required but not available.
The current BIP-353 resolver is a scaffold and does not claim full DNSSEC
validation.

## Platform-Verified Email

Example:

```txt
rodrigo@gmail.com
```

For Gmail-style addresses, SatsPath cannot prove domain ownership through DNS.
A hosted SatsPath platform can only prove inbox access by sending a code or magic
link to that email address.

Email verification means:

- the receiver accessed the inbox,
- the receiver can proceed to create or connect a wallet,
- the receiver wallet can publish a signed public profile.

Email verification does not mean:

- SatsPath controls the domain,
- SatsPath owns the wallet,
- custody moved,
- private keys or seed phrases were transferred.

## Local Contact

A local contact is an alias stored on the local device. It is trusted only by
that local user/device. It is useful for demos, contacts, and local registry
fallbacks, but it is not global identity proof.

## Privacy Note

Identifier hashes are used where possible, but hashed emails are not strong
anonymity because emails are guessable. Platform layers should avoid storing raw
emails except where delivery is required.
