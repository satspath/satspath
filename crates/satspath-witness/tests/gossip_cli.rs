use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use satspath_core::{
    crypto::{generate_identity_keypair, IdentityKeypair},
    transparency::{
        consistency_proof, leaf_hash, merkle_root, MerkleConsistencyProof, TransparencyCheckpoint,
    },
};

fn binary(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_satspath-gossip"))
        .args(args)
        .output()
        .unwrap()
}

fn checkpoint(operator: &IdentityKeypair, size: u64, root: &str) -> TransparencyCheckpoint {
    let mut cp = TransparencyCheckpoint {
        version: 1,
        log_id: "cli-test".into(),
        log_size: size,
        log_root: root.into(),
        map_root: None,
        previous_checkpoint_hash: None,
        created_at: chrono::Utc::now().timestamp(),
        operator_pubkey: hex::encode(operator.public_key.serialize()),
        operator_sequence: 0,
        operator_rotation: None,
        operator_signature: String::new(),
        bitcoin_anchor: None,
    };
    cp.sign(&operator.secret_key).unwrap();
    cp
}

fn save(path: &Path, item: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(item).unwrap()).unwrap();
}

#[test]
fn cli_observes_with_consistency_and_reads_persisted_alerts() {
    let temp = tempfile::tempdir().unwrap();
    let key_path = temp.path().join("observer.key");
    let key = key_path.to_str().unwrap();
    let result = binary(&["keygen", "--key-file", key]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let observer = String::from_utf8(result.stdout).unwrap().trim().to_owned();
    let other = hex::encode(generate_identity_keypair().public_key.serialize());
    assert!(!binary(&["keygen", "--key-file", key]).status.success());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let operator = generate_identity_keypair();
    let op = hex::encode(operator.public_key.serialize());
    let state = temp.path().join("state");
    let state_dir = state.to_str().unwrap();
    let first_path = temp.path().join("first.json");
    let second_path = temp.path().join("second.json");
    let proof_path = temp.path().join("proof.json");
    let leaves = [leaf_hash(b"one"), leaf_hash(b"two")];
    let root1 = hex::encode(merkle_root(&leaves[..1]));
    let root2 = hex::encode(merkle_root(&leaves));
    save(&first_path, &checkpoint(&operator, 1, &root1));
    save(&second_path, &checkpoint(&operator, 2, &root2));
    let base = [
        "--state-dir",
        state_dir,
        "--log-id",
        "cli-test",
        "--operator-pubkey",
        &op,
        "--observer-pubkey",
        &observer,
        "--observer-pubkey",
        &other,
    ];
    let observe = |path: &Path, proof: Option<&Path>| {
        let mut args = vec!["observe"];
        args.extend(base);
        args.extend([
            "--key-file",
            key,
            "--checkpoint-file",
            path.to_str().unwrap(),
        ]);
        if let Some(proof) = proof {
            args.extend(["--consistency-file", proof.to_str().unwrap()]);
        }
        binary(&args)
    };

    assert!(observe(&first_path, None).status.success());
    assert!(
        !observe(&second_path, None).status.success(),
        "advance requires a consistency proof"
    );
    let proof = MerkleConsistencyProof {
        version: 2,
        old_tree_size: 1,
        new_tree_size: 2,
        old_root: root1,
        new_root: root2,
        audit_path: consistency_proof(&leaves, 1)
            .unwrap()
            .into_iter()
            .map(hex::encode)
            .collect(),
    };
    save(&proof_path, &proof);
    let advanced = observe(&second_path, Some(&proof_path));
    assert!(
        advanced.status.success(),
        "{}",
        String::from_utf8_lossy(&advanced.stderr)
    );
    let mut args = vec!["alerts"];
    args.extend(base);
    let alerts = binary(&args);
    assert!(alerts.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&alerts.stdout).unwrap(),
        serde_json::json!([])
    );
}
