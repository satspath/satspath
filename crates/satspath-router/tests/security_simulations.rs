use satspath_core::{BitcoinNetwork, PaymentMethod};
use satspath_router::fees::FeeEstimate;
use satspath_router::priority::select_priority_route;

// Helper to quickly build the 3 methods
fn build_methods() -> Vec<PaymentMethod> {
    vec![
        PaymentMethod::Onchain {
            label: "btc".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some("bc1q_onchain".into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        },
        PaymentMethod::Lightning {
            label: "ln".into(),
            lightning_address: Some("alice@lightning.node".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        },
        PaymentMethod::Ark {
            label: "ark".into(),
            opaque_uri: None,
            server: "https://ark.node".into(),
            pubkey: "02ark".into(),
            vtxo_pointer: None,
            proof: None,
            expires_at: None,
        },
    ]
}

#[test]
fn test_attack_fee_oracle_manipulation() {
    let methods = build_methods();

    // SETUP: Normally, a payment of 50k sats would go on-chain if fees are low (e.g. 10 sats/vb).
    let normal_fee = FeeEstimate {
        fastest_fee: 10,
        half_hour_fee: 10,
        hour_fee: 10,
        economy_fee: 5,
        minimum_fee: 1,
    };
    let decision = select_priority_route(50_000, &normal_fee, &methods, true).unwrap();
    assert_eq!(decision.rail, "onchain");
    println!("✅ SETUP: Normal network conditions correctly prioritize On-chain.");

    // ATTACK 3: Fee Oracle Manipulation
    println!("⚔️ ATTACK 3: Malicious oracle reports catastrophically high fees (1000 sat/vB) to drain user funds...");
    let malicious_fee = FeeEstimate {
        fastest_fee: 1000,
        half_hour_fee: 1000,
        hour_fee: 1000,
        economy_fee: 1000,
        minimum_fee: 1000,
    };

    // VALIDATION
    let attack_decision = select_priority_route(50_000, &malicious_fee, &methods, true).unwrap();

    assert_ne!(
        attack_decision.rail, "onchain",
        "SECURITY FAILURE: Router attempted on-chain transaction during massive fee spike!"
    );
    assert_eq!(
        attack_decision.rail, "lightning",
        "Router should fallback to Lightning."
    );
    println!(
        "🛡️ DEFENSE SUCCESS: Router automatically abandoned On-chain due to high fees. Reason: {}",
        attack_decision.reason
    );
}

#[test]
fn test_attack_routing_blackhole() {
    let methods = build_methods();

    // ATTACK 4: Routing Blackhole & L2 Censorship
    // Attacker spoofs high on-chain fees AND blocks/censors Lightning routes.
    println!("⚔️ ATTACK 4: Malicious node fakes high fees AND censors Lightning routes...");
    let malicious_fee = FeeEstimate {
        fastest_fee: 200,
        half_hour_fee: 200,
        hour_fee: 200,
        economy_fee: 200,
        minimum_fee: 200,
    };
    let routing_ok = false; // Attacker blocks Lightning path

    // VALIDATION
    let attack_decision =
        select_priority_route(50_000, &malicious_fee, &methods, routing_ok).unwrap();

    assert_ne!(
        attack_decision.rail, "onchain",
        "SECURITY FAILURE: Fell into high fee trap."
    );
    assert_ne!(
        attack_decision.rail, "lightning",
        "SECURITY FAILURE: Attempted censored Lightning route."
    );
    assert_eq!(
        attack_decision.rail, "ark",
        "Router should fallback to Ark layer 3."
    );
    println!(
        "🛡️ DEFENSE SUCCESS: Router safely fell back to Ark (L3). Reason: {}",
        attack_decision.reason
    );
}

#[test]
fn test_attack_extreme_value_liquidity() {
    let methods = build_methods();

    // ATTACK 5: Extreme Value Liquidity Attack
    // Attacker crafts a massive payment invoice to trap funds in L2 HTLCs.
    println!("⚔️ ATTACK 5: Attacker attempts to route massive payment (10 BTC) via Lightning...");
    let massive_payment_sats = 10_000_000_000; // 100 BTC (exceeds LARGE_PAYMENT_SATS threshold)

    // Even if fees are manipulated to be high, forcing the router out of on-chain
    let malicious_fee = FeeEstimate {
        fastest_fee: 500,
        half_hour_fee: 500,
        hour_fee: 500,
        economy_fee: 500,
        minimum_fee: 500,
    };

    // VALIDATION
    let attack_decision =
        select_priority_route(massive_payment_sats, &malicious_fee, &methods, true).unwrap();

    assert_ne!(
        attack_decision.rail, "lightning",
        "SECURITY FAILURE: Router attempted to send a massive amount via Lightning!"
    );
    assert_eq!(attack_decision.rail, "ark", "Router should skip Lightning for massive amounts and use Ark (or On-chain if fees were normal).");
    println!(
        "🛡️ DEFENSE SUCCESS: Router blocked massive L2 payment to protect liquidity. Reason: {}",
        attack_decision.reason
    );
}
