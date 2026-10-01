#[tokio::test]
#[ignore = "requires an explicitly configured Bitcoin Core regtest node"]
async fn checkpoint_op_return_round_trip_on_bitcoin_core_regtest() {
    let checkpoint_hash = "42".repeat(32);
    let client = satspath_core::transparency::RegtestAnchorClient::from_env().unwrap();
    let receipt = client.anchor_checkpoint(&checkpoint_hash).await.unwrap();
    assert_eq!(receipt.network, satspath_core::BitcoinNetwork::Regtest);
    assert!(receipt.verified);
    assert!(receipt.confirmations > 0);
    let fetched = client
        .verify_anchor(&receipt.txid, &receipt.commitment)
        .await
        .unwrap();
    assert!(fetched.verified);
    assert_eq!(fetched.commitment, receipt.commitment);
}
