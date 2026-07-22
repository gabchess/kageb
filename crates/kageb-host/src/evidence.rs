use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use kageb_program::wire::SettlementPayloadV1;
use sha2::{Digest, Sha256};

use crate::{
    content_root, BatchConfig, ConfirmedLock, FundedOrder, LockPackageV1, PoolBalance,
    ReferenceKeyper, ReleasedShareV1, Residual, SignedIntentV1, MAX_BATCH_MEMBERS,
};

const RESULT_COMMITMENT_DOMAIN: &[u8] = b"KAGEB_RESULT_COMMITMENT_V1\0";
const RECOVERED_INTENTS_DOMAIN: &[u8] = b"KAGEB_RECOVERED_INTENTS_V1\0";
const MAX_RELEASED_SHARE_WIRE_LEN: usize = 512;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SettlementBalanceV1 {
    pub participant_id: [u8; 32],
    pub base_atoms: u64,
    pub quote_atoms: u64,
}

impl std::fmt::Debug for SettlementBalanceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SettlementBalanceV1(..redacted)")
    }
}

#[derive(Clone)]
pub struct DecryptionEvidenceV1 {
    shares: [ReleasedShareV1; 2],
}

impl std::fmt::Debug for DecryptionEvidenceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DecryptionEvidenceV1(..redacted)")
    }
}

impl DecryptionEvidenceV1 {
    pub fn new(
        first: ReleasedShareV1,
        second: ReleasedShareV1,
    ) -> Result<Self, SettlementValidationError> {
        if first.index() == second.index() {
            return Err(SettlementValidationError::InvalidBatch);
        }
        Ok(Self {
            shares: [first, second],
        })
    }

    fn shares(&self) -> [&ReleasedShareV1; 2] {
        [&self.shares[0], &self.shares[1]]
    }
}

#[derive(Clone)]
pub struct SettlementRequestV1 {
    pub package: LockPackageV1,
    pub decryption_evidence: Vec<DecryptionEvidenceV1>,
    pub post_balances: Vec<SettlementBalanceV1>,
    pub pre_balance_root: [u8; 32],
    pub post_balance_root: [u8; 32],
    pub residual: Residual,
    pub result_root: [u8; 32],
    pub result_commitment: [u8; 32],
    pub settlement_nonce: [u8; 32],
    pub settlement_digest: [u8; 32],
}

impl std::fmt::Debug for SettlementRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SettlementRequestV1(..redacted)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementValidationError {
    InvalidLock,
    InvalidBatch,
    InvalidBalance,
    InvalidResult,
    InvalidNonce,
    WrongKeyper,
    MemberLimitExceeded,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SettlementApprovalV1 {
    keyper_key: [u8; 32],
    payload: SettlementPayloadV1,
    digest: [u8; 32],
    signature: [u8; 64],
}

impl std::fmt::Debug for SettlementApprovalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SettlementApprovalV1(..redacted)")
    }
}

impl SettlementApprovalV1 {
    #[must_use]
    pub const fn payload(&self) -> SettlementPayloadV1 {
        self.payload
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.keyper_key) else {
            return false;
        };
        self.digest == self.payload.digest()
            && key
                .verify(&self.digest, &Signature::from_bytes(&self.signature))
                .is_ok()
    }

    pub(crate) const fn keyper_key(&self) -> [u8; 32] {
        self.keyper_key
    }

    pub(crate) const fn signature(&self) -> [u8; 64] {
        self.signature
    }

    pub(crate) fn encode_wire(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(503);
        bytes.push(1);
        bytes.extend_from_slice(&self.keyper_key);
        bytes.extend_from_slice(&self.payload.encode());
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub(crate) fn decode_wire(bytes: &[u8]) -> Result<Self, SettlementValidationError> {
        if bytes.len() != 503 || bytes[0] != 1 {
            return Err(SettlementValidationError::InvalidResult);
        }
        let payload = SettlementPayloadV1::decode(&bytes[33..407])
            .ok_or(SettlementValidationError::InvalidResult)?;
        Ok(Self {
            keyper_key: bytes[1..33]
                .try_into()
                .map_err(|_| SettlementValidationError::InvalidResult)?,
            payload,
            digest: bytes[407..439]
                .try_into()
                .map_err(|_| SettlementValidationError::InvalidResult)?,
            signature: bytes[439..503]
                .try_into()
                .map_err(|_| SettlementValidationError::InvalidResult)?,
        })
    }
}

struct RecomputedSettlement {
    post_balances: Vec<SettlementBalanceV1>,
    pre_balance_root: [u8; 32],
    post_balance_root: [u8; 32],
    residual: Residual,
    result_root: [u8; 32],
    result_commitment: [u8; 32],
    payload: SettlementPayloadV1,
}

impl SettlementRequestV1 {
    pub fn build(
        package: LockPackageV1,
        decryption_evidence: Vec<DecryptionEvidenceV1>,
        settlement_nonce: [u8; 32],
        confirmed: &ConfirmedLock,
    ) -> Result<Self, SettlementValidationError> {
        let recomputed = recompute(&package, &decryption_evidence, settlement_nonce, confirmed)?;
        let settlement_digest = recomputed.payload.digest();
        Ok(Self {
            package,
            decryption_evidence,
            post_balances: recomputed.post_balances,
            pre_balance_root: recomputed.pre_balance_root,
            post_balance_root: recomputed.post_balance_root,
            residual: recomputed.residual,
            result_root: recomputed.result_root,
            result_commitment: recomputed.result_commitment,
            settlement_nonce,
            settlement_digest,
        })
    }

    pub(crate) fn encode_wire(&self) -> Result<Vec<u8>, SettlementValidationError> {
        let package = self
            .package
            .encode_wire()
            .map_err(|_| SettlementValidationError::InvalidBatch)?;
        let mut bytes = Vec::new();
        bytes.push(1);
        bytes.extend_from_slice(
            &u32::try_from(package.len())
                .map_err(|_| SettlementValidationError::InvalidBatch)?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&package);
        bytes.extend_from_slice(
            &u32::try_from(self.decryption_evidence.len())
                .map_err(|_| SettlementValidationError::InvalidBatch)?
                .to_le_bytes(),
        );
        for evidence in &self.decryption_evidence {
            for share in &evidence.shares {
                let encoded = share
                    .encode_wire()
                    .map_err(|_| SettlementValidationError::InvalidBatch)?;
                if encoded.len() > MAX_RELEASED_SHARE_WIRE_LEN {
                    return Err(SettlementValidationError::InvalidBatch);
                }
                bytes.extend_from_slice(
                    &u32::try_from(encoded.len())
                        .map_err(|_| SettlementValidationError::InvalidBatch)?
                        .to_le_bytes(),
                );
                bytes.extend_from_slice(&encoded);
            }
        }
        bytes.extend_from_slice(
            &u32::try_from(self.post_balances.len())
                .map_err(|_| SettlementValidationError::InvalidBalance)?
                .to_le_bytes(),
        );
        for balance in &self.post_balances {
            bytes.extend_from_slice(&encode_settlement_balance(balance));
        }
        bytes.extend_from_slice(&self.pre_balance_root);
        bytes.extend_from_slice(&self.post_balance_root);
        let (side, lots) = residual_wire(self.residual);
        bytes.push(side);
        bytes.extend_from_slice(&lots.to_le_bytes());
        bytes.extend_from_slice(&self.result_root);
        bytes.extend_from_slice(&self.result_commitment);
        bytes.extend_from_slice(&self.settlement_nonce);
        bytes.extend_from_slice(&self.settlement_digest);
        Ok(bytes)
    }

    pub(crate) fn decode_wire(bytes: &[u8]) -> Result<Self, SettlementValidationError> {
        if bytes.len() < 1 + 4 || bytes[0] != 1 {
            return Err(SettlementValidationError::InvalidBatch);
        }
        let mut offset = 1_usize;
        let package_len = take_u32(bytes, &mut offset)? as usize;
        let package_end = offset
            .checked_add(package_len)
            .ok_or(SettlementValidationError::InvalidBatch)?;
        let package = LockPackageV1::decode_wire(
            bytes
                .get(offset..package_end)
                .ok_or(SettlementValidationError::InvalidBatch)?,
        )
        .map_err(|_| SettlementValidationError::InvalidBatch)?;
        offset = package_end;
        let evidence_count = take_u32(bytes, &mut offset)? as usize;
        if evidence_count > MAX_BATCH_MEMBERS
            || evidence_count != package.submissions.len()
            || evidence_count != package.member_count as usize
        {
            return Err(SettlementValidationError::MemberLimitExceeded);
        }
        let mut decryption_evidence = Vec::with_capacity(evidence_count);
        for _ in 0..evidence_count {
            let mut shares = Vec::with_capacity(2);
            for _ in 0..2 {
                let share_len = take_u32(bytes, &mut offset)? as usize;
                if share_len > MAX_RELEASED_SHARE_WIRE_LEN {
                    return Err(SettlementValidationError::InvalidBatch);
                }
                let end = offset
                    .checked_add(share_len)
                    .ok_or(SettlementValidationError::InvalidBatch)?;
                shares.push(
                    ReleasedShareV1::decode_wire(
                        bytes
                            .get(offset..end)
                            .ok_or(SettlementValidationError::InvalidBatch)?,
                    )
                    .map_err(|_| SettlementValidationError::InvalidBatch)?,
                );
                offset = end;
            }
            decryption_evidence.push(DecryptionEvidenceV1::new(
                shares.remove(0),
                shares.remove(0),
            )?);
        }
        let post_count = take_u32(bytes, &mut offset)? as usize;
        if post_count > MAX_BATCH_MEMBERS || post_count != package.balances.len() {
            return Err(SettlementValidationError::MemberLimitExceeded);
        }
        let mut post_balances = Vec::with_capacity(post_count);
        for _ in 0..post_count {
            let encoded = take_array::<48>(bytes, &mut offset)?;
            post_balances.push(SettlementBalanceV1 {
                participant_id: encoded[0..32]
                    .try_into()
                    .map_err(|_| SettlementValidationError::InvalidBalance)?,
                base_atoms: u64::from_le_bytes(
                    encoded[32..40]
                        .try_into()
                        .map_err(|_| SettlementValidationError::InvalidBalance)?,
                ),
                quote_atoms: u64::from_le_bytes(
                    encoded[40..48]
                        .try_into()
                        .map_err(|_| SettlementValidationError::InvalidBalance)?,
                ),
            });
        }
        let pre_balance_root = take_array(bytes, &mut offset)?;
        let post_balance_root = take_array(bytes, &mut offset)?;
        let side = *bytes
            .get(offset)
            .ok_or(SettlementValidationError::InvalidResult)?;
        offset += 1;
        let lots = take_u32(bytes, &mut offset)?;
        let residual = match (side, lots) {
            (0, 0) => Residual::None,
            (1, 1..=u32::MAX) => Residual::Buy { lots },
            (2, 1..=u32::MAX) => Residual::Sell { lots },
            _ => return Err(SettlementValidationError::InvalidResult),
        };
        let result_root = take_array(bytes, &mut offset)?;
        let result_commitment = take_array(bytes, &mut offset)?;
        let settlement_nonce = take_array(bytes, &mut offset)?;
        let settlement_digest = take_array(bytes, &mut offset)?;
        if offset != bytes.len() {
            return Err(SettlementValidationError::InvalidBatch);
        }
        Ok(Self {
            package,
            decryption_evidence,
            post_balances,
            pre_balance_root,
            post_balance_root,
            residual,
            result_root,
            result_commitment,
            settlement_nonce,
            settlement_digest,
        })
    }
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, SettlementValidationError> {
    Ok(u32::from_le_bytes(take_array(bytes, offset)?))
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], SettlementValidationError> {
    let end = offset
        .checked_add(N)
        .ok_or(SettlementValidationError::InvalidBatch)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(SettlementValidationError::InvalidBatch)?
        .try_into()
        .map_err(|_| SettlementValidationError::InvalidBatch)?;
    *offset = end;
    Ok(value)
}

impl ReferenceKeyper {
    pub fn sign_settlement(
        &self,
        request: &SettlementRequestV1,
        confirmed: &ConfirmedLock,
        secret: &crate::KeyperSecretShare,
    ) -> Result<SettlementApprovalV1, SettlementValidationError> {
        let recomputed = recompute(
            &request.package,
            &request.decryption_evidence,
            request.settlement_nonce,
            confirmed,
        )?;
        let digest = recomputed.payload.digest();
        if request.post_balances != recomputed.post_balances
            || request.pre_balance_root != recomputed.pre_balance_root
            || request.post_balance_root != recomputed.post_balance_root
            || request.residual != recomputed.residual
            || request.result_root != recomputed.result_root
            || request.result_commitment != recomputed.result_commitment
            || request.settlement_digest != digest
        {
            return Err(SettlementValidationError::InvalidResult);
        }
        let pool = confirmed
            .pool
            .as_ref()
            .ok_or(SettlementValidationError::InvalidLock)?;
        let configured = pool
            .keypers
            .get(self.index)
            .ok_or(SettlementValidationError::WrongKeyper)?;
        let keyper_key = self.signing_key.verifying_key().to_bytes();
        if configured.to_bytes() != keyper_key
            || secret.index() != self.index
            || secret.epoch_account() != request.package.epoch_account()
            || !request.package.epoch_public_keys.matches_share(secret)
            || self.journal.digest(confirmed.epoch_account()) != Some(confirmed.lock_digest())
        {
            return Err(SettlementValidationError::WrongKeyper);
        }
        Ok(SettlementApprovalV1 {
            keyper_key,
            payload: recomputed.payload,
            digest,
            signature: self.signing_key.sign(&digest).to_bytes(),
        })
    }
}

fn recompute(
    package: &LockPackageV1,
    decryption_evidence: &[DecryptionEvidenceV1],
    settlement_nonce: [u8; 32],
    confirmed: &ConfirmedLock,
) -> Result<RecomputedSettlement, SettlementValidationError> {
    package
        .validate_locked(confirmed)
        .map_err(|_| SettlementValidationError::InvalidLock)?;
    if settlement_nonce == [0; 32] || settlement_nonce == confirmed.state.lock_nonce {
        return Err(SettlementValidationError::InvalidNonce);
    }
    if decryption_evidence.len() != package.submissions.len()
        || decryption_evidence.len() > MAX_BATCH_MEMBERS
    {
        return Err(SettlementValidationError::InvalidBatch);
    }
    let mut recovered = Vec::with_capacity(decryption_evidence.len());
    for (submission, evidence) in package.submissions.iter().zip(decryption_evidence) {
        if evidence.shares.iter().any(|share| {
            share.epoch_account() != confirmed.epoch_account()
                || share.lock_digest() != confirmed.lock_digest()
        }) {
            return Err(SettlementValidationError::InvalidBatch);
        }
        recovered.push(
            package
                .epoch_public_keys
                .recover_submission(submission, evidence.shares())
                .map_err(|_| SettlementValidationError::InvalidBatch)?,
        );
    }
    let mut submissions = BTreeMap::new();
    for submission in &package.submissions {
        let participant = submission.authorization.participant_id;
        if submissions.insert(participant, submission).is_some() {
            return Err(SettlementValidationError::InvalidBatch);
        }
    }
    let mut seen = BTreeSet::new();
    let mut orders = Vec::with_capacity(recovered.len());
    for intent in &recovered {
        let participant = intent.body().participant_id();
        let submission = submissions
            .get(&participant)
            .ok_or(SettlementValidationError::InvalidBatch)?;
        if !seen.insert(participant) {
            return Err(SettlementValidationError::InvalidBatch);
        }
        let trading_key = VerifyingKey::from_bytes(&submission.authorization.trading_key)
            .map_err(|_| SettlementValidationError::InvalidBatch)?;
        intent
            .verify(&trading_key, package.configuration.epoch_id, participant)
            .map_err(|_| SettlementValidationError::InvalidBatch)?;
        orders.push(
            FundedOrder::new(
                participant,
                intent.body().side(),
                intent.body().limit_price(),
            )
            .map_err(|_| SettlementValidationError::InvalidBatch)?,
        );
    }
    let before: BTreeMap<[u8; 32], PoolBalance> = package
        .balances
        .iter()
        .map(|balance| (balance.participant_id(), balance.pool_balance()))
        .collect();
    if before.len() != package.balances.len() {
        return Err(SettlementValidationError::InvalidBalance);
    }
    let result = crate::net_batch(
        BatchConfig::new(
            package.configuration.base_lot_atoms,
            package.configuration.quote_atoms_per_lot,
        )
        .map_err(|_| SettlementValidationError::InvalidBatch)?,
        &before,
        &orders,
    )
    .map_err(|_| SettlementValidationError::InvalidBatch)?;
    if !result.conserves(&before) {
        return Err(SettlementValidationError::InvalidBalance);
    }
    let post_balances: Vec<_> = result
        .balances()
        .iter()
        .map(|(participant_id, balance)| SettlementBalanceV1 {
            participant_id: *participant_id,
            base_atoms: balance.base_atoms,
            quote_atoms: balance.quote_atoms,
        })
        .collect();
    let post_balance_root = settlement_balance_root(&post_balances)?;
    let result_root = per_participant_result_root(&before, &post_balances)?;
    let recovered_root = recovered_intents_root(&recovered);
    let pre_balance_root = package.pre_balance_root;
    let result_commitment = result_commitment(
        confirmed,
        recovered_root,
        pre_balance_root,
        post_balance_root,
        result.residual(),
        result_root,
    );
    let pool = confirmed
        .pool
        .as_ref()
        .ok_or(SettlementValidationError::InvalidLock)?;
    let (residual_side, residual_lots) = residual_wire(result.residual());
    let payload = SettlementPayloadV1 {
        epoch_account: confirmed.epoch_account(),
        lock_digest: confirmed.lock_digest(),
        result_commitment,
        residual_side,
        residual_lots,
        base_lot_atoms: confirmed.state.base_lot_atoms,
        quote_atoms_per_lot: confirmed.state.quote_atoms_per_lot,
        base_mint: pool.base_mint,
        quote_mint: pool.quote_mint,
        pool_base_vault: pool.pool_base_vault,
        pool_quote_vault: pool.pool_quote_vault,
        venue_base_account: pool.venue_base_account,
        venue_quote_account: pool.venue_quote_account,
        venue_authority: pool.venue_authority,
        settlement_nonce,
    };
    Ok(RecomputedSettlement {
        post_balances,
        pre_balance_root,
        post_balance_root,
        residual: result.residual(),
        result_root,
        result_commitment,
        payload,
    })
}

fn settlement_balance_root(
    balances: &[SettlementBalanceV1],
) -> Result<[u8; 32], SettlementValidationError> {
    let leaves: Vec<_> = balances.iter().map(encode_settlement_balance).collect();
    let refs: Vec<_> = leaves.iter().map(<[u8; 48]>::as_slice).collect();
    content_root(crate::CommitmentDomain::BalanceSet, &refs)
        .map_err(|_| SettlementValidationError::InvalidBalance)
}

fn per_participant_result_root(
    before: &BTreeMap<[u8; 32], PoolBalance>,
    after: &[SettlementBalanceV1],
) -> Result<[u8; 32], SettlementValidationError> {
    let mut leaves = Vec::with_capacity(after.len());
    for balance in after {
        let prior = before
            .get(&balance.participant_id)
            .ok_or(SettlementValidationError::InvalidBalance)?;
        let mut leaf = [0_u8; 64];
        leaf[0..32].copy_from_slice(&balance.participant_id);
        leaf[32..40].copy_from_slice(&prior.base_atoms.to_le_bytes());
        leaf[40..48].copy_from_slice(&prior.quote_atoms.to_le_bytes());
        leaf[48..56].copy_from_slice(&balance.base_atoms.to_le_bytes());
        leaf[56..64].copy_from_slice(&balance.quote_atoms.to_le_bytes());
        leaves.push(leaf);
    }
    let refs: Vec<_> = leaves.iter().map(<[u8; 64]>::as_slice).collect();
    content_root(crate::CommitmentDomain::ResultSet, &refs)
        .map_err(|_| SettlementValidationError::InvalidResult)
}

fn encode_settlement_balance(balance: &SettlementBalanceV1) -> [u8; 48] {
    let mut bytes = [0_u8; 48];
    bytes[0..32].copy_from_slice(&balance.participant_id);
    bytes[32..40].copy_from_slice(&balance.base_atoms.to_le_bytes());
    bytes[40..48].copy_from_slice(&balance.quote_atoms.to_le_bytes());
    bytes
}

fn recovered_intents_root(recovered: &[SignedIntentV1]) -> [u8; 32] {
    let mut leaves: Vec<[u8; 32]> = recovered
        .iter()
        .map(|intent| Sha256::digest(intent.encode()).into())
        .collect();
    leaves.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(RECOVERED_INTENTS_DOMAIN);
    hasher.update((leaves.len() as u64).to_le_bytes());
    for leaf in leaves {
        hasher.update(leaf);
    }
    hasher.finalize().into()
}

fn result_commitment(
    confirmed: &ConfirmedLock,
    recovered_root: [u8; 32],
    pre_balance_root: [u8; 32],
    post_balance_root: [u8; 32],
    residual: Residual,
    result_root: [u8; 32],
) -> [u8; 32] {
    let (side, lots) = residual_wire(residual);
    let mut hasher = Sha256::new();
    hasher.update(RESULT_COMMITMENT_DOMAIN);
    hasher.update(confirmed.epoch_account().as_ref());
    hasher.update(confirmed.lock_digest());
    hasher.update(recovered_root);
    hasher.update(pre_balance_root);
    hasher.update(post_balance_root);
    hasher.update([side]);
    hasher.update(lots.to_le_bytes());
    hasher.update(result_root);
    hasher.finalize().into()
}

const fn residual_wire(residual: Residual) -> (u8, u32) {
    match residual {
        Residual::None => (0, 0),
        Residual::Buy { lots } => (1, lots),
        Residual::Sell { lots } => (2, lots),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use kageb_program::wire::EpochConfigurationV1;
    use solana_program::pubkey::Pubkey;

    use super::*;
    use crate::{EpochDealer, SignedBalanceSnapshotV1};

    #[test]
    fn settlement_wire_rejects_coordinator_counts_before_allocating() {
        let epoch = Pubkey::new_unique();
        let epoch_id = [1; 32];
        let operator = SigningKey::from_bytes(&[2; 32]);
        let package = LockPackageV1::new(
            epoch,
            EpochConfigurationV1 {
                pool: Pubkey::new_unique(),
                epoch_id,
                base_mint: Pubkey::new_unique(),
                quote_mint: Pubkey::new_unique(),
                base_lot_atoms: 1,
                quote_atoms_per_lot: 100,
                minimum_count: 4,
                lock_threshold: 2,
                settlement_threshold: 2,
                keypers: [
                    Pubkey::new_unique(),
                    Pubkey::new_unique(),
                    Pubkey::new_unique(),
                ],
                lock_deadline: 900,
                abort_deadline: 1_000,
            },
            EpochDealer::random().unwrap().public_keys().clone(),
            Vec::new(),
            Vec::new(),
            SignedBalanceSnapshotV1::sign(epoch_id, &[], &operator).unwrap(),
            [3; 32],
        )
        .unwrap();
        let encoded_package = package.encode_wire().unwrap();
        let mut bytes = vec![1];
        bytes.extend_from_slice(&(encoded_package.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&encoded_package);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            SettlementRequestV1::decode_wire(&bytes),
            Err(SettlementValidationError::MemberLimitExceeded)
        ));
    }
}
