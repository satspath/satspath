//! Integration tests for live Ark Service Provider (ASP) connector, VTXO covenant tree DAG
//! verification, and settlement handoff structures (Issue #155).

use satspath_router::ark::{
    verify_ark_vtxo_dag, ArkAspInfo, ArkBoardingHandoff, ArkFeeSchedule, ArkForfeitHandoff,
    ArkRoundSubmissionReceipt, ArkSettlementHandoff, ArkVtxoTreeNode, LiveArkAspClient,
};

const ASP_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const RECEIVER_PUBKEY: &str = "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

fn sample_asp_info() -> ArkAspInfo {
    ArkAspInfo {
        pubkey: ASP_PUBKEY.to_string(),
        network: "signet".to_string(),
        round_interval_secs: 10,
        vtxo_tree_expiry: 604_800,
        unilateral_exit_delay: 512,
        dust_limit_sats: 330,
        boarding_descriptor_template: Some(
            "tr(ASP_KEY,{and_v(v:pk(ASP_KEY),pk(USER_KEY)),older(512)})".to_string(),
        ),
        fees: ArkFeeSchedule {
            base_fee_sats: 15,
            ppm_rate: 500, // 0.05%
            onboard_fee_sats: 250,
            offboard_fee_sats: 350,
        },
    }
}

#[tokio::test]
async fn test_live_ark_asp_connector_info_oor_and_forfeit_round_submission() {
    let mut server = mockito::Server::new_async().await;
    let asp_info = sample_asp_info();

    let info_mock = server
        .mock("GET", "/v1/info")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&asp_info).unwrap())
        .expect(2)
        .create_async()
        .await;

    let oor_receipt = ArkRoundSubmissionReceipt {
        submission_id: "oor_pkg_8f7a2c".to_string(),
        status: "cosigned".to_string(),
        vtxo_txid: Some("11".repeat(32)),
    };
    let oor_mock = server
        .mock("POST", "/v1/oor/submit")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&oor_receipt).unwrap())
        .create_async()
        .await;

    let round_receipt = ArkRoundSubmissionReceipt {
        submission_id: "round_42_reg".to_string(),
        status: "registered".to_string(),
        vtxo_txid: Some("22".repeat(32)),
    };
    let round_mock = server
        .mock("POST", "/v1/round/register")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&round_receipt).unwrap())
        .create_async()
        .await;

    let client = LiveArkAspClient::new_for_test(server.url());

    // 1. Fetch live ASP info
    let fetched_info = client.get_asp_info().await.unwrap();
    assert_eq!(fetched_info, asp_info);
    assert_eq!(fetched_info.estimate_transfer_fee(100_000), 15 + 50); // 15 base + 50 ppm

    // 2. Build and submit an Out-of-Round (OOR) payment handoff
    let sender_vtxo = format!("{}:0", "aa".repeat(32));
    let (info, oor_handoff) = client
        .build_oor_handoff(&sender_vtxo, RECEIVER_PUBKEY, 100_000)
        .await
        .unwrap();
    let submitted_oor = client
        .submit_settlement_handoff(&info, &oor_handoff)
        .await
        .unwrap();
    assert_eq!(submitted_oor, oor_receipt);

    // 3. Build and submit an In-Round Forfeit settlement handoff (Arkade Money compatible)
    let forfeit_handoff = ArkSettlementHandoff::InRoundForfeit(ArkForfeitHandoff {
        server_url: client.server_url().to_string(),
        round_id: "round_42".to_string(),
        input_vtxo_outpoint: sender_vtxo,
        connector_outpoint: format!("{}:1", "bb".repeat(32)),
        forfeit_psbt_base64: "cHNidP8BAHECAAAAAQ==".to_string(),
        new_vtxo_tree_root: "22".repeat(32),
        asp_pubkey: ASP_PUBKEY.to_string(),
        receiver_pubkey: RECEIVER_PUBKEY.to_string(),
        amount_sats: 50_000,
    });
    let submitted_round = client
        .submit_settlement_handoff(&info, &forfeit_handoff)
        .await
        .unwrap();
    assert_eq!(submitted_round, round_receipt);

    info_mock.assert_async().await;
    oor_mock.assert_async().await;
    round_mock.assert_async().await;
}

#[test]
fn test_ark_settlement_handoff_fail_closed_validation() {
    let asp_info = sample_asp_info();

    // Valid Boarding handoff passes
    let valid_boarding = ArkSettlementHandoff::Boarding(ArkBoardingHandoff {
        server_url: "https://ark.satspath.dev".to_string(),
        boarding_address: "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
            .to_string(),
        asp_pubkey: ASP_PUBKEY.to_string(),
        user_pubkey: RECEIVER_PUBKEY.to_string(),
        exit_delay: 512,
        amount_sats: 10_000,
        bip21_uri:
            "bitcoin:tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0?amount=0.0001"
                .to_string(),
    });
    assert!(valid_boarding.validate(&asp_info).is_ok());

    // Below dust limit fails closed
    let dust_boarding = ArkSettlementHandoff::Boarding(ArkBoardingHandoff {
        server_url: "https://ark.satspath.dev".to_string(),
        boarding_address: "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
            .to_string(),
        asp_pubkey: ASP_PUBKEY.to_string(),
        user_pubkey: RECEIVER_PUBKEY.to_string(),
        exit_delay: 512,
        amount_sats: 100, // < 330 dust limit
        bip21_uri: "bitcoin:tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
            .to_string(),
    });
    assert!(dust_boarding.validate(&asp_info).is_err());

    // Mismatched ASP pubkey fails closed
    let wrong_asp = ArkSettlementHandoff::Boarding(ArkBoardingHandoff {
        server_url: "https://ark.satspath.dev".to_string(),
        boarding_address: "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
            .to_string(),
        asp_pubkey: RECEIVER_PUBKEY.to_string(),
        user_pubkey: RECEIVER_PUBKEY.to_string(),
        exit_delay: 512,
        amount_sats: 10_000,
        bip21_uri: "bitcoin:tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
            .to_string(),
    });
    assert!(wrong_asp.validate(&asp_info).is_err());
}

#[test]
fn test_ark_vtxo_covenant_tree_dag_verification() {
    let root_txid = "01".repeat(32);
    let branch_left = "02".repeat(32);
    let branch_right = "03".repeat(32);
    let leaf_alice = "04".repeat(32);
    let leaf_bob = "05".repeat(32);

    let dag = vec![
        ArkVtxoTreeNode {
            txid: root_txid.clone(),
            parent_txid: None,
            vout: 0,
            amount_sats: 100_000,
            asp_cosign_pubkey: ASP_PUBKEY.to_string(),
            receiver_pubkey: None,
            expiry_sequence: 1008,
            children: vec![branch_left.clone(), branch_right.clone()],
        },
        ArkVtxoTreeNode {
            txid: branch_left.clone(),
            parent_txid: Some(root_txid.clone()),
            vout: 0,
            amount_sats: 60_000,
            asp_cosign_pubkey: ASP_PUBKEY.to_string(),
            receiver_pubkey: None,
            expiry_sequence: 1008,
            children: vec![leaf_alice.clone(), leaf_bob.clone()],
        },
        ArkVtxoTreeNode {
            txid: branch_right.clone(),
            parent_txid: Some(root_txid.clone()),
            vout: 1,
            amount_sats: 40_000,
            asp_cosign_pubkey: ASP_PUBKEY.to_string(),
            receiver_pubkey: Some(RECEIVER_PUBKEY.to_string()),
            expiry_sequence: 1008,
            children: Vec::new(),
        },
        ArkVtxoTreeNode {
            txid: leaf_alice.clone(),
            parent_txid: Some(branch_left.clone()),
            vout: 0,
            amount_sats: 35_000,
            asp_cosign_pubkey: ASP_PUBKEY.to_string(),
            receiver_pubkey: Some(RECEIVER_PUBKEY.to_string()),
            expiry_sequence: 1008,
            children: Vec::new(),
        },
        ArkVtxoTreeNode {
            txid: leaf_bob.clone(),
            parent_txid: Some(branch_left.clone()),
            vout: 1,
            amount_sats: 25_000,
            asp_cosign_pubkey: ASP_PUBKEY.to_string(),
            receiver_pubkey: Some(RECEIVER_PUBKEY.to_string()),
            expiry_sequence: 1008,
            children: Vec::new(),
        },
    ];

    // 1. Valid path from root -> branch_left -> leaf_alice passes
    verify_ark_vtxo_dag(&dag, &root_txid, ASP_PUBKEY, &leaf_alice, 35_000)
        .expect("valid VTXO covenant tree DAG must verify");

    // 2. Under-funded target leaf fails closed
    assert!(verify_ark_vtxo_dag(&dag, &root_txid, ASP_PUBKEY, &leaf_alice, 36_000).is_err());

    // 3. Value inflation (children sum > parent amount) fails closed
    let mut inflated = dag.clone();
    inflated[4].amount_sats = 30_000; // 35_000 + 30_000 = 65_000 > 60_000
    assert!(verify_ark_vtxo_dag(&inflated, &root_txid, ASP_PUBKEY, &leaf_alice, 35_000).is_err());
}
