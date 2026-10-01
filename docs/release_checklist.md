# Release Readiness Checklist for SatsPath v0

## Security and Privacy

- [ ] All cryptographic implementations reviewed.
- [ ] No private material (seeds, keys) included in profiles or payment pointers.
- [ ] Sensitive user data masked in preview modes.

## Functional Testing

- [ ] All unit tests pass across workspaces.
- [ ] Integration tests for HTTP resolver and LNURL pass.
- [ ] Testnet execution paths enabled; mainnet execution paths strictly disabled.

## Code Quality

- [ ] CI workflows in place for formatting, linting, and testing.
- [ ] PR template and branch protection guidelines established.

## Documentation

- [ ] README reflects experimental nature of swap engine.
- [ ] Core architecture and protocol concepts fully documented.
