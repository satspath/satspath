use super::tree::{consistency_proof, leaf_hash, merkle_root, verify_consistency};
use super::verifier::verify_consistency_proof;
use super::{MerkleConsistencyProof, TransparencyError};

// Published SHA-256 Merkle leaf hashes from Certificate Transparency (RFC 6962 / Chromium)
const RFC6962_LEAF_HASHES: &[&str] = &[
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
    "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
    "07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
    "4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658",
    "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
    "46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1",
];

// Published SHA-256 Merkle root hashes for trees of size 1..8
const RFC6962_ROOT_HASHES: &[&str] = &[
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", // size 1
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", // size 2
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77", // size 3
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", // size 4
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4", // size 5
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef", // size 6
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c", // size 7
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328", // size 8
];

fn rfc6962_leaves() -> Vec<[u8; 32]> {
    RFC6962_LEAF_HASHES
        .iter()
        .map(|hex_str| {
            let bytes = hex::decode(hex_str).expect("valid hex leaf");
            bytes.try_into().expect("32-byte hash")
        })
        .collect()
}

#[test]
fn test_rfc6962_leaves_and_roots() {
    let leaves = rfc6962_leaves();

    for size in 1..=8 {
        let root = merkle_root(&leaves[..size]);
        assert_eq!(
            hex::encode(root),
            RFC6962_ROOT_HASHES[size - 1],
            "Root mismatch at size {}",
            size
        );
    }
}

#[test]
fn test_rfc6962_published_consistency_proof_vectors() {
    let leaves = rfc6962_leaves();

    // Published specific consistency proof vectors from RFC 6962 / Chromium CT test suite
    let test_cases = vec![
        (1, 1, vec![]),
        (
            1,
            8,
            vec![
                "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
            ],
        ),
        (
            6,
            8,
            vec![
                "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            ],
        ),
        (
            2,
            5,
            vec![
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            ],
        ),
    ];

    for (old_size, new_size, expected_path) in test_cases {
        let proof =
            consistency_proof(&leaves[..new_size], old_size).expect("consistency proof generation");
        let hex_proof: Vec<String> = proof.iter().map(hex::encode).collect();
        assert_eq!(
            hex_proof, expected_path,
            "Consistency proof mismatch for ({}, {})",
            old_size, new_size
        );

        let old_root = merkle_root(&leaves[..old_size]);
        let new_root = merkle_root(&leaves[..new_size]);
        let valid = verify_consistency(
            old_size as u64,
            new_size as u64,
            &old_root,
            &new_root,
            &proof,
        )
        .expect("verify consistency");
        assert!(
            valid,
            "Failed verify_consistency for ({}, {})",
            old_size, new_size
        );

        let wire_proof = MerkleConsistencyProof {
            version: 2,
            old_tree_size: old_size as u64,
            new_tree_size: new_size as u64,
            old_root: hex::encode(old_root),
            new_root: hex::encode(new_root),
            audit_path: hex_proof,
        };
        assert!(
            verify_consistency_proof(&wire_proof).expect("verify wire proof"),
            "Failed verify_consistency_proof for ({}, {})",
            old_size,
            new_size
        );
    }
}

#[test]
fn test_rfc6962_all_subtrees_consistency_proof_vectors() {
    let leaves = rfc6962_leaves();

    for old_size in 1..=8 {
        for new_size in old_size..=8 {
            let old_root = merkle_root(&leaves[..old_size]);
            let new_root = merkle_root(&leaves[..new_size]);

            let proof = consistency_proof(&leaves[..new_size], old_size).expect("valid proof");

            // Verify using low-level verifier
            let valid = verify_consistency(
                old_size as u64,
                new_size as u64,
                &old_root,
                &new_root,
                &proof,
            )
            .expect("verification succeeds without error");
            assert!(
                valid,
                "RFC 6962 consistency check failed for ({}, {})",
                old_size, new_size
            );

            // Verify using wire-format V2 proof structure
            let v2_wire_proof = MerkleConsistencyProof {
                version: 2,
                old_tree_size: old_size as u64,
                new_tree_size: new_size as u64,
                old_root: hex::encode(old_root),
                new_root: hex::encode(new_root),
                audit_path: proof.iter().map(hex::encode).collect(),
            };

            let wire_valid =
                verify_consistency_proof(&v2_wire_proof).expect("wire verification ok");
            assert!(
                wire_valid,
                "V2 wire proof verification failed for ({}, {})",
                old_size, new_size
            );

            // Proof path length is strictly O(log n)
            let max_expected_len = (new_size as f64).log2().ceil() as usize + 1;
            assert!(
                proof.len() <= max_expected_len,
                "Proof length {} exceeded O(log n) bound {} for ({}, {})",
                proof.len(),
                max_expected_len,
                old_size,
                new_size
            );
        }
    }
}

#[test]
fn test_property_consistency_proofs_arbitrary_sizes() {
    // Generate simulated leaves (33 covers power-of-2 boundaries while keeping O(n²) manageable)
    let total_leaves = 33;
    let leaves: Vec<[u8; 32]> = (0..total_leaves)
        .map(|i| leaf_hash(&format!("leaf-data-{}", i).into_bytes()))
        .collect();

    for new_size in 1..=total_leaves {
        for old_size in 1..=new_size {
            let old_root = merkle_root(&leaves[..old_size]);
            let new_root = merkle_root(&leaves[..new_size]);

            let proof = consistency_proof(&leaves[..new_size], old_size)
                .expect("consistency proof generation");

            let valid = verify_consistency(
                old_size as u64,
                new_size as u64,
                &old_root,
                &new_root,
                &proof,
            )
            .expect("consistency verification");
            assert!(
                valid,
                "Failed consistency property test for m={}, n={}",
                old_size, new_size
            );

            let wire_proof = MerkleConsistencyProof {
                version: 2,
                old_tree_size: old_size as u64,
                new_tree_size: new_size as u64,
                old_root: hex::encode(old_root),
                new_root: hex::encode(new_root),
                audit_path: proof.iter().map(hex::encode).collect(),
            };
            assert!(
                verify_consistency_proof(&wire_proof).expect("wire proof ok"),
                "Wire proof failed for m={}, n={}",
                old_size,
                new_size
            );
        }
    }
}

#[test]
fn test_adversarial_bit_flips() {
    let leaves: Vec<[u8; 32]> = (0..16).map(|i| leaf_hash(&[i as u8])).collect();

    let old_size = 7;
    let new_size = 15;
    let old_root = merkle_root(&leaves[..old_size]);
    let new_root = merkle_root(&leaves[..new_size]);
    let proof = consistency_proof(&leaves[..new_size], old_size).unwrap();
    assert!(!proof.is_empty());

    for (node_idx, _node) in proof.iter().enumerate() {
        for byte_idx in 0..32 {
            let mut corrupted_proof = proof.clone();
            corrupted_proof[node_idx][byte_idx] ^= 0x01; // flip 1 bit

            let result = verify_consistency(
                old_size as u64,
                new_size as u64,
                &old_root,
                &new_root,
                &corrupted_proof,
            );
            assert!(
                matches!(result, Ok(false)),
                "Bit flip in node {} byte {} must fail closed",
                node_idx,
                byte_idx
            );
        }
    }
}

#[test]
fn test_adversarial_reordered_and_truncated_path() {
    let leaves: Vec<[u8; 32]> = (0..16).map(|i| leaf_hash(&[i as u8])).collect();

    let old_size = 3;
    let new_size = 11;
    let old_root = merkle_root(&leaves[..old_size]);
    let new_root = merkle_root(&leaves[..new_size]);
    let proof = consistency_proof(&leaves[..new_size], old_size).unwrap();
    assert!(proof.len() >= 2);

    // 1. Truncated path
    let mut truncated = proof.clone();
    truncated.pop();
    let res = verify_consistency(
        old_size as u64,
        new_size as u64,
        &old_root,
        &new_root,
        &truncated,
    );
    assert!(!res.unwrap(), "Truncated proof must fail");

    // 2. Extended path (garbage node added)
    let mut extended = proof.clone();
    extended.push([0xaa; 32]);
    let res = verify_consistency(
        old_size as u64,
        new_size as u64,
        &old_root,
        &new_root,
        &extended,
    );
    assert!(!res.unwrap(), "Extended proof with trailing node must fail");

    // 3. Reordered path
    let mut reordered = proof.clone();
    reordered.swap(0, 1);
    let res = verify_consistency(
        old_size as u64,
        new_size as u64,
        &old_root,
        &new_root,
        &reordered,
    );
    assert!(!res.unwrap(), "Reordered proof must fail");
}

#[test]
fn test_adversarial_tampered_roots_and_invalid_sizes() {
    let leaves: Vec<[u8; 32]> = (0..16).map(|i| leaf_hash(&[i as u8])).collect();

    let old_size = 4;
    let new_size = 8;
    let mut old_root = merkle_root(&leaves[..old_size]);
    let mut new_root = merkle_root(&leaves[..new_size]);
    let proof = consistency_proof(&leaves[..new_size], old_size).unwrap();

    // Tampered old root
    old_root[0] ^= 0xff;
    let res = verify_consistency(
        old_size as u64,
        new_size as u64,
        &old_root,
        &new_root,
        &proof,
    );
    assert!(!res.unwrap(), "Tampered old root must fail");

    // Restore old root, tamper new root
    old_root[0] ^= 0xff;
    new_root[0] ^= 0xff;
    let res = verify_consistency(
        old_size as u64,
        new_size as u64,
        &old_root,
        &new_root,
        &proof,
    );
    assert!(!res.unwrap(), "Tampered new root must fail");

    // Invalid sizes: old_size == 0
    let res = verify_consistency(0, 8, &old_root, &new_root, &proof);
    assert!(matches!(
        res,
        Err(TransparencyError::InvalidConsistencyProof)
    ));

    // Invalid sizes: old_size > new_size
    let res = verify_consistency(9, 8, &old_root, &new_root, &proof);
    assert!(matches!(
        res,
        Err(TransparencyError::InvalidConsistencyProof)
    ));

    // Wire proof with invalid version
    let invalid_version_proof = MerkleConsistencyProof {
        version: 3,
        old_tree_size: old_size as u64,
        new_tree_size: new_size as u64,
        old_root: hex::encode(old_root),
        new_root: hex::encode(merkle_root(&leaves[..new_size])),
        audit_path: proof.iter().map(hex::encode).collect(),
    };
    assert!(verify_consistency_proof(&invalid_version_proof).is_err());
}

#[test]
fn test_large_tree_scalability_above_16384() {
    // Generate tree with 16,500 leaves — just above the V1 cap of 16,384
    let total_leaves: usize = 16_500;
    let old_size: usize = 8_000;

    let leaves: Vec<[u8; 32]> = (0..total_leaves)
        .map(|i| leaf_hash(&(i as u64).to_be_bytes()))
        .collect();

    let old_root = merkle_root(&leaves[..old_size]);
    let new_root = merkle_root(&leaves);

    let proof = consistency_proof(&leaves, old_size)
        .expect("consistency proof generation for 16.5k leaves");

    // O(log 16500) is <= 15 nodes
    assert!(
        proof.len() <= 15,
        "Audit path length {} should be <= 15",
        proof.len()
    );

    let v2_proof = MerkleConsistencyProof {
        version: 2,
        old_tree_size: old_size as u64,
        new_tree_size: total_leaves as u64,
        old_root: hex::encode(old_root),
        new_root: hex::encode(new_root),
        audit_path: proof.iter().map(hex::encode).collect(),
    };

    // Verifier must succeed and not reject due to old 16,384 cap
    let verified =
        verify_consistency_proof(&v2_proof).expect("verification of large V2 proof above V1 cap");
    assert!(verified, "V2 proof for 16.5k leaves must be valid");
}

#[test]
fn test_v1_backward_compatibility() {
    let leaves: Vec<[u8; 32]> = (0..8).map(|i| leaf_hash(&[i as u8])).collect();

    let old_size = 3;
    let new_size = 8;
    let old_root = merkle_root(&leaves[..old_size]);
    let new_root = merkle_root(&leaves[..new_size]);

    // Construct valid V1 proof (audit_path contains all new_tree_size leaves)
    let v1_proof = MerkleConsistencyProof {
        version: 1,
        old_tree_size: old_size as u64,
        new_tree_size: new_size as u64,
        old_root: hex::encode(old_root),
        new_root: hex::encode(new_root),
        audit_path: leaves.iter().map(hex::encode).collect(),
    };

    assert!(
        verify_consistency_proof(&v1_proof).expect("valid V1 verification"),
        "Valid V1 proof under 16,384 leaves should verify"
    );

    // V1 proof with truncated audit path must fail
    let mut bad_v1 = v1_proof.clone();
    bad_v1.audit_path.pop();
    assert!(verify_consistency_proof(&bad_v1).is_err());

    // V1 proof exceeding MAX_V1_CONSISTENCY_LEAVES (16,384) must be rejected
    let oversized_v1 = MerkleConsistencyProof {
        version: 1,
        old_tree_size: 100,
        new_tree_size: 16_385,
        old_root: hex::encode(old_root),
        new_root: hex::encode(new_root),
        audit_path: vec![hex::encode([0u8; 32]); 16_385],
    };
    assert!(
        verify_consistency_proof(&oversized_v1).is_err(),
        "V1 proofs exceeding 16,384 leaves must be rejected"
    );
}
