use sha2::{Digest, Sha256};

use super::{MerkleInclusionProof, TransparencyError};

pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let split = largest_power_of_two_less_than(n);
            node_hash(
                &merkle_root(&leaves[..split]),
                &merkle_root(&leaves[split..]),
            )
        }
    }
}

pub fn inclusion_proof(
    leaves: &[[u8; 32]],
    index: usize,
) -> Result<MerkleInclusionProof, TransparencyError> {
    if index >= leaves.len() {
        return Err(TransparencyError::InvalidInclusionProof);
    }
    let mut path = Vec::new();
    inclusion_path(leaves, index, &mut path);
    Ok(MerkleInclusionProof {
        leaf_index: index as u64,
        tree_size: leaves.len() as u64,
        leaf_hash: hex::encode(leaves[index]),
        audit_path: path.into_iter().map(hex::encode).collect(),
        root_hash: hex::encode(merkle_root(leaves)),
    })
}

fn inclusion_path(leaves: &[[u8; 32]], index: usize, out: &mut Vec<[u8; 32]>) {
    if leaves.len() <= 1 {
        return;
    }
    let split = largest_power_of_two_less_than(leaves.len());
    if index < split {
        inclusion_path(&leaves[..split], index, out);
        out.push(merkle_root(&leaves[split..]));
    } else {
        inclusion_path(&leaves[split..], index - split, out);
        out.push(merkle_root(&leaves[..split]));
    }
}

fn largest_power_of_two_less_than(n: usize) -> usize {
    debug_assert!(n > 1);
    let p = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
    if p == n {
        p / 2
    } else {
        p
    }
}

pub fn consistency_proof(
    leaves: &[[u8; 32]],
    old_size: usize,
) -> Result<Vec<[u8; 32]>, TransparencyError> {
    let new_size = leaves.len();
    if old_size == 0 || old_size > new_size {
        return Err(TransparencyError::InvalidConsistencyProof);
    }
    if old_size == new_size {
        return Ok(Vec::new());
    }
    let mut path = Vec::new();
    sub_proof(leaves, old_size, true, &mut path);
    Ok(path)
}

fn sub_proof(leaves: &[[u8; 32]], m: usize, b: bool, out: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if m == n {
        if !b {
            out.push(merkle_root(leaves));
        }
        return;
    }
    let k = largest_power_of_two_less_than(n);
    if m <= k {
        sub_proof(&leaves[..k], m, b, out);
        out.push(merkle_root(&leaves[k..]));
    } else {
        sub_proof(&leaves[k..], m - k, false, out);
        out.push(merkle_root(&leaves[..k]));
    }
}

pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> Result<bool, TransparencyError> {
    if old_size == 0 || old_size > new_size {
        return Err(TransparencyError::InvalidConsistencyProof);
    }
    if old_size == new_size {
        return Ok(old_root == new_root && proof.is_empty());
    }
    if proof.is_empty() {
        return Ok(false);
    }

    let mut fn_ = old_size - 1;
    let mut sn = new_size - 1;
    while fn_ % 2 == 1 {
        fn_ /= 2;
        sn /= 2;
    }

    let (mut fr, mut sr, mut p) = if fn_ == 0 {
        (*old_root, *old_root, 0)
    } else {
        (proof[0], proof[0], 1)
    };

    while fn_ > 0 {
        if fn_ % 2 == 1 {
            if p >= proof.len() {
                return Ok(false);
            }
            let pr = proof[p];
            p += 1;
            fr = node_hash(&pr, &fr);
            sr = node_hash(&pr, &sr);
        } else if fn_ < sn {
            if p >= proof.len() {
                return Ok(false);
            }
            let pr = proof[p];
            p += 1;
            sr = node_hash(&sr, &pr);
        }
        fn_ /= 2;
        sn /= 2;
    }

    while sn > 0 {
        if p >= proof.len() {
            return Ok(false);
        }
        let pr = proof[p];
        p += 1;
        sr = node_hash(&sr, &pr);
        sn /= 2;
    }

    Ok(&fr == old_root && &sr == new_root && p == proof.len())
}
