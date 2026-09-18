extern crate alloc;

use auths_model::Digest;
use sha2::{Digest as _, Sha256};

pub fn leaf_hash(body: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update([0]);
    hasher.update(body);
    Digest::new(hasher.finalize().into())
}

pub fn fold(index: u64, tree_size: u64, leaf: Digest, hashes: &[Digest]) -> Result<Digest, ()> {
    if tree_size == 0 || index >= tree_size || hashes.len() != path_length(index, tree_size)? {
        return Err(());
    }
    let mut node = leaf;
    let mut position = index;
    let mut last = tree_size - 1;
    for sibling in hashes {
        if position & 1 == 1 || position == last {
            node = branch(*sibling, node);
            while position & 1 == 0 && position != 0 {
                position >>= 1;
                last >>= 1;
            }
        } else {
            node = branch(node, *sibling);
        }
        position >>= 1;
        last >>= 1;
    }
    if last != 0 {
        return Err(());
    }
    Ok(node)
}

pub fn path_length(index: u64, tree_size: u64) -> Result<usize, ()> {
    if tree_size == 0 || index >= tree_size {
        return Err(());
    }
    let mut length = 0usize;
    let mut position = index;
    let mut last = tree_size - 1;
    while last != 0 {
        if position & 1 == 1 || position < last {
            length = length.checked_add(1).ok_or(())?;
        }
        position >>= 1;
        last >>= 1;
    }
    Ok(length)
}

fn branch(left: Digest, right: Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    Digest::new(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_and_two_leaf_trees_match_rfc6962_shape() {
        let left = leaf_hash(b"left");
        let right = leaf_hash(b"right");
        assert_eq!(fold(0, 1, left, &[]), Ok(left));
        assert_eq!(fold(0, 2, left, &[right]), Ok(branch(left, right)));
        assert_eq!(fold(1, 2, right, &[left]), Ok(branch(left, right)));
        assert!(fold(0, 2, left, &[]).is_err());
    }
}
