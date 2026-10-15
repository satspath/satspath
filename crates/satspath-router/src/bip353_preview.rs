//! Map a resolved BIP-353 record into a Mainnet-Preview [`QuoteResponse`].
//!
//! BIP-353 resolution yields a public `bitcoin:` URI (and a DNSSEC verdict) but
//! no signed SatsPath profile, so the resulting recipient has `fingerprint: None`.
//! Only a DNSSEC-validated, strictly checked on-chain URI becomes a payable QR.

use satspath_core::{
    bip321::{parse_bip321, Bip321Instruction},
    validation::validate_amount_sats,
    Bip353Resolution, BitcoinNetwork, PaymentMethod,
};

use crate::handoff::validate_payload;
use crate::quote_response::{QuoteRecipient, QuoteResponse};

/// Convert a BIP-353 resolution into a preview `QuoteResponse`.
///
/// Picks a representative payment method (on-chain → Lightning BOLT12 → Lightning
/// BOLT11) and permits only a verified, amount-bound on-chain URI as a QR.
pub fn quote_from_bip353_resolution(
    resolution: &Bip353Resolution,
    amount_sats: u64,
) -> QuoteResponse {
    if !resolution.dnssec_validated {
        return QuoteResponse::NoRoute {
            reason: "BIP-353 payment instructions require validated DNSSEC".into(),
        };
    }
    if let Err(e) = validate_amount_sats(amount_sats) {
        return QuoteResponse::NoRoute {
            reason: e.to_string(),
        };
    }
    let parsed = match parse_bip321(&resolution.bitcoin_uri) {
        Ok(p) => p,
        Err(e) => {
            return QuoteResponse::NoRoute {
                reason: format!("BIP-353 record is not a valid bitcoin: URI: {e}"),
            }
        }
    };

    let recipient = QuoteRecipient {
        alias: resolution.name.display.clone(),
        // Backward compatibility: for direct BIP-353 previews, `verified`
        // historically meant DNSSEC validation rather than profile signature.
        verified: resolution.dnssec_validated,
        profile_signature_verified: false,
        identifier_verified: resolution.dnssec_validated,
        identifier_verification: if resolution.dnssec_validated {
            "dnssec-bip353"
        } else {
            "dnssec-not-validated"
        }
        .into(),
        fingerprint: None,
    };

    // Choose a representative rail: on-chain, then BOLT12 offer, then BOLT11.
    let (selected_method, rail) = if let Some(addr) = &parsed.address {
        (
            PaymentMethod::Onchain {
                label: "BIP-353 on-chain".into(),
                network: BitcoinNetwork::Mainnet,
                address: Some(addr.clone()),
                silent_payment_pubkey: None,
                pubkey_hint: None,
                descriptor_hint: None,
                address_list: vec![],
            },
            "on-chain",
        )
    } else if let Some(offer) = parsed.instructions.iter().find_map(|i| match i {
        Bip321Instruction::Bolt12Offer { offer } => Some(offer.clone()),
        _ => None,
    }) {
        (
            PaymentMethod::Lightning {
                label: "BIP-353 BOLT12 offer".into(),
                lightning_address: None,
                lnurl: None,
                bolt12: Some(offer),
                receiver_pubkey: None,
            },
            "lightning (BOLT12)",
        )
    } else if parsed
        .instructions
        .iter()
        .any(|i| matches!(i, Bip321Instruction::LightningBolt11 { .. }))
    {
        (
            PaymentMethod::Lightning {
                label: "BIP-353 BOLT11 invoice".into(),
                lightning_address: None,
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            },
            "lightning (BOLT11)",
        )
    } else {
        return QuoteResponse::NoRoute {
            reason: "BIP-353 record carries no on-chain, BOLT12, or BOLT11 instruction".into(),
        };
    };

    if let Err(e) = validate_payload(
        &selected_method,
        &resolution.bitcoin_uri,
        "mainnet",
        Some(amount_sats),
    ) {
        return QuoteResponse::NoRoute {
            reason: format!("unsafe BIP-353 payment instruction: {e}"),
        };
    }

    QuoteResponse::Ok {
        recipient,
        selected_method,
        fee_sats: None,
        eta: None,
        reason: format!(
            "Resolved via BIP-353 (DNSSEC validated); {rail} preview for {amount_sats} sats. \
             Mainnet preview only — no funds moved."
        ),
        // The authoritative payable is the strictly checked BIP-353 URI itself.
        qr: resolution.bitcoin_uri.clone(),
        execution: None,
        wallet_hint: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::bip353::{
        resolve_bip353_with, Bip353Name, DnsTxtRecord, DnssecPolicy, MockDnsTxtResolver,
    };

    fn resolution(uri: &str, dnssec: bool) -> Bip353Resolution {
        let mut resolver = MockDnsTxtResolver::new();
        let name = Bip353Name {
            user: "rodrigo".into(),
            domain: "satspath.dev".into(),
            display: "₿rodrigo@satspath.dev".into(),
            dns_name: "rodrigo.user._bitcoin-payment.satspath.dev".into(),
        };
        resolver.insert(
            &name.dns_name,
            DnsTxtRecord {
                strings: vec![uri.to_string()],
                dnssec_validated: dnssec,
                ttl_seconds: Some(1800),
            },
        );
        let policy = if dnssec {
            DnssecPolicy::Strict
        } else {
            DnssecPolicy::DevInsecure
        };
        // Block on the async resolver in a small runtime.
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(resolve_bip353_with(
                &resolver,
                "rodrigo@satspath.dev",
                policy,
                1_700_000_000,
            ))
            .unwrap()
    }

    #[test]
    fn bip353_bolt12_offer_cannot_be_used_as_payment_qr() {
        let res = resolution("bitcoin:?lno=lno1qoffer", true);
        let quote = quote_from_bip353_resolution(&res, 1000);
        assert!(matches!(quote, QuoteResponse::NoRoute { .. }));
    }

    #[test]
    fn bip353_onchain_maps_to_onchain_method() {
        let res = resolution(
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00001000",
            true,
        );
        let quote = quote_from_bip353_resolution(&res, 1000);
        match quote {
            QuoteResponse::Ok {
                selected_method,
                qr,
                ..
            } => {
                assert!(matches!(selected_method, PaymentMethod::Onchain { .. }));
                assert_eq!(
                    qr,
                    "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00001000"
                );
            }
            other => panic!("expected Ok, got {}", other.status()),
        }
    }

    #[test]
    fn bip353_unvalidated_dnssec_never_returns_payable_uri() {
        let res = resolution(
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00001000",
            false,
        );
        let quote = quote_from_bip353_resolution(&res, 1000);
        assert!(matches!(quote, QuoteResponse::NoRoute { .. }));
    }

    #[test]
    fn bip353_rejects_conflicts_wrong_network_and_amountless_uri() {
        for uri in [
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00002000",
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00001000&amount=0.00001000",
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00001000&lno=lno1qoffer",
            "bitcoin:mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn?amount=0.00001000",
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
        ] {
            let res = resolution(uri, true);
            assert!(
                matches!(
                    quote_from_bip353_resolution(&res, 1000),
                    QuoteResponse::NoRoute { .. }
                ),
                "accepted unsafe URI: {uri}"
            );
        }
    }
}
