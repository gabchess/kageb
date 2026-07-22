use sha2::{Digest, Sha256};

const LEAF_TAG: &[u8] = b"KAGEB_LEAF_V1\0";
const ROOT_TAG: &[u8] = b"KAGEB_ROOT_V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentDomain {
    BalanceSet,
    MemberSet,
    ResultSet,
}

impl CommitmentDomain {
    const fn tag(self) -> &'static [u8] {
        match self {
            Self::BalanceSet => b"KAGEB_BALANCE_SET_V1\0",
            Self::MemberSet => b"KAGEB_MEMBER_SET_V1\0",
            Self::ResultSet => b"KAGEB_RESULT_SET_V1\0",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentError {
    DuplicateLeaf,
}

/// Hashes an unordered set under a fixed protocol domain.
pub fn content_root(
    domain: CommitmentDomain,
    leaves: &[&[u8]],
) -> Result<[u8; 32], CommitmentError> {
    let domain = domain.tag();
    let mut leaf_hashes: Vec<[u8; 32]> = leaves
        .iter()
        .map(|leaf| {
            let mut hasher = Sha256::new();
            hasher.update(LEAF_TAG);
            hasher.update((domain.len() as u64).to_le_bytes());
            hasher.update(domain);
            hasher.update((leaf.len() as u64).to_le_bytes());
            hasher.update(leaf);
            hasher.finalize().into()
        })
        .collect();
    leaf_hashes.sort_unstable();
    if leaf_hashes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CommitmentError::DuplicateLeaf);
    }

    let mut hasher = Sha256::new();
    hasher.update(ROOT_TAG);
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update((leaf_hashes.len() as u64).to_le_bytes());
    for leaf_hash in leaf_hashes {
        hasher.update(leaf_hash);
    }
    Ok(hasher.finalize().into())
}
