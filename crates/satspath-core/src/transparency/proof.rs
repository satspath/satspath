use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleInclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub leaf_hash: String,
    pub audit_path: Vec<String>,
    pub root_hash: String,
}

/// Consistency proofs support two versions:
/// * **V1**: Intentionally carries the complete new-tree leaf-hash sequence. This is bandwidth-heavy but
///   independently proves that the first `old_tree_size` leaves produce `old_root` and all leaves produce `new_root`.
///   V1 proofs are bounded to 16,384 leaves to prevent unbounded memory growth.
/// * **V2**: A compact RFC 6962-style proof using `O(log n)` bandwidth containing only the necessary sub-tree hashes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleConsistencyProof {
    pub version: u16,
    pub old_tree_size: u64,
    pub new_tree_size: u64,
    pub old_root: String,
    pub new_root: String,
    pub audit_path: Vec<String>,
}
