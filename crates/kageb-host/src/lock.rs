use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use kageb_program::{
    epoch_address, pool_address,
    state::{EpochStateV1, EpochTerminalState, PoolStateV1},
    vault_authority_address,
    wire::{EpochConfigurationV1, LockPayloadV1},
    ID,
};
use sha2::{Digest, Sha256};
use solana_commitment_config::CommitmentConfig;
use solana_program::{
    pubkey::Pubkey,
    sysvar::{self, clock::Clock},
};
use solana_rpc_client::rpc_client::RpcClient;

use crate::{
    content_root, AdmissionPolicyV1, CommitmentDomain, EncryptedSubmissionV1, EpochPublicKeys,
    KeyperSecretShare, ReleasedShareV1,
};

const SNAPSHOT_DOMAIN: &[u8] = b"KAGEB_BALANCE_SNAPSHOT_V1\0";
const JOURNAL_HEADER: &[u8; 8] = b"KGBLCK1\0";
const JOURNAL_INITIALIZED: &[u8; 8] = b"KGBINI1\0";
const JOURNAL_RECORD_LEN: usize = 64;
const JOURNAL_CHECKSUM_LEN: usize = 32;
const LOCK_ATTEMPTS: usize = 100;
pub const MAX_BATCH_MEMBERS: usize = 64;
const MAX_EPOCH_PUBLIC_KEYS_LEN: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockValidationError {
    InvalidBalance,
    InvalidSnapshot,
    InvalidConfiguration,
    InvalidSubmission,
    DuplicateParticipant,
    DuplicateAuthorization,
    DuplicateReceipt,
    MemberCountMismatch,
    MemberLimitExceeded,
    CrowdBelowMinimum,
    MemberRootMismatch,
    DeadlinePassed,
    WrongKeyper,
    ConflictingLock,
    CorruptJournal,
    JournalBusy,
    Io(io::ErrorKind),
    Rpc,
    MissingAccount,
    InvalidOnchainEpoch,
    InvalidOnchainLock,
}

impl From<io::Error> for LockValidationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BalanceRecordV1 {
    participant_id: [u8; 32],
    base_atoms: u64,
    quote_atoms: u64,
    reserved_base_atoms: u64,
    reserved_quote_atoms: u64,
}

impl std::fmt::Debug for BalanceRecordV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BalanceRecordV1(..redacted)")
    }
}

impl BalanceRecordV1 {
    pub fn new(
        participant_id: [u8; 32],
        base_atoms: u64,
        quote_atoms: u64,
        reserved_base_atoms: u64,
        reserved_quote_atoms: u64,
    ) -> Result<Self, LockValidationError> {
        if participant_id == [0; 32]
            || reserved_base_atoms == 0
            || reserved_quote_atoms == 0
            || base_atoms < reserved_base_atoms
            || quote_atoms < reserved_quote_atoms
        {
            return Err(LockValidationError::InvalidBalance);
        }
        Ok(Self {
            participant_id,
            base_atoms,
            quote_atoms,
            reserved_base_atoms,
            reserved_quote_atoms,
        })
    }

    fn encode(self) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[0..32].copy_from_slice(&self.participant_id);
        bytes[32..40].copy_from_slice(&self.base_atoms.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.quote_atoms.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.reserved_base_atoms.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.reserved_quote_atoms.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, LockValidationError> {
        if bytes.len() != 64 {
            return Err(LockValidationError::InvalidBalance);
        }
        Self::new(
            bytes[0..32]
                .try_into()
                .map_err(|_| LockValidationError::InvalidBalance)?,
            u64::from_le_bytes(
                bytes[32..40]
                    .try_into()
                    .map_err(|_| LockValidationError::InvalidBalance)?,
            ),
            u64::from_le_bytes(
                bytes[40..48]
                    .try_into()
                    .map_err(|_| LockValidationError::InvalidBalance)?,
            ),
            u64::from_le_bytes(
                bytes[48..56]
                    .try_into()
                    .map_err(|_| LockValidationError::InvalidBalance)?,
            ),
            u64::from_le_bytes(
                bytes[56..64]
                    .try_into()
                    .map_err(|_| LockValidationError::InvalidBalance)?,
            ),
        )
    }

    pub(crate) const fn participant_id(&self) -> [u8; 32] {
        self.participant_id
    }

    pub(crate) const fn pool_balance(&self) -> crate::PoolBalance {
        crate::PoolBalance::new(self.base_atoms, self.quote_atoms)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SignedBalanceSnapshotV1 {
    epoch_id: [u8; 32],
    record_count: u32,
    balance_root: [u8; 32],
    operator_key: [u8; 32],
    signature: [u8; 64],
}

impl std::fmt::Debug for SignedBalanceSnapshotV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SignedBalanceSnapshotV1(..redacted)")
    }
}

impl SignedBalanceSnapshotV1 {
    pub fn sign(
        epoch_id: [u8; 32],
        records: &[BalanceRecordV1],
        operator: &SigningKey,
    ) -> Result<Self, LockValidationError> {
        let record_count =
            u32::try_from(records.len()).map_err(|_| LockValidationError::InvalidSnapshot)?;
        let balance_root = balance_root(records)?;
        let operator_key = operator.verifying_key().to_bytes();
        let signature = operator
            .sign(&snapshot_message(epoch_id, record_count, balance_root))
            .to_bytes();
        Ok(Self {
            epoch_id,
            record_count,
            balance_root,
            operator_key,
            signature,
        })
    }

    fn verify(
        &self,
        epoch_id: [u8; 32],
        records: &[BalanceRecordV1],
        operator_key: [u8; 32],
    ) -> Result<(), LockValidationError> {
        let count =
            u32::try_from(records.len()).map_err(|_| LockValidationError::InvalidSnapshot)?;
        if self.epoch_id != epoch_id
            || self.record_count != count
            || self.operator_key != operator_key
            || self.balance_root != balance_root(records)?
        {
            return Err(LockValidationError::InvalidSnapshot);
        }
        let key = VerifyingKey::from_bytes(&self.operator_key)
            .map_err(|_| LockValidationError::InvalidSnapshot)?;
        key.verify(
            &snapshot_message(self.epoch_id, self.record_count, self.balance_root),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| LockValidationError::InvalidSnapshot)
    }

    fn encode(&self) -> [u8; 164] {
        let mut bytes = [0_u8; 164];
        bytes[0..32].copy_from_slice(&self.epoch_id);
        bytes[32..36].copy_from_slice(&self.record_count.to_le_bytes());
        bytes[36..68].copy_from_slice(&self.balance_root);
        bytes[68..100].copy_from_slice(&self.operator_key);
        bytes[100..164].copy_from_slice(&self.signature);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, LockValidationError> {
        if bytes.len() != 164 {
            return Err(LockValidationError::InvalidSnapshot);
        }
        Ok(Self {
            epoch_id: bytes[0..32]
                .try_into()
                .map_err(|_| LockValidationError::InvalidSnapshot)?,
            record_count: u32::from_le_bytes(
                bytes[32..36]
                    .try_into()
                    .map_err(|_| LockValidationError::InvalidSnapshot)?,
            ),
            balance_root: bytes[36..68]
                .try_into()
                .map_err(|_| LockValidationError::InvalidSnapshot)?,
            operator_key: bytes[68..100]
                .try_into()
                .map_err(|_| LockValidationError::InvalidSnapshot)?,
            signature: bytes[100..164]
                .try_into()
                .map_err(|_| LockValidationError::InvalidSnapshot)?,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct LockPackageV1 {
    pub epoch_account: Pubkey,
    pub configuration: EpochConfigurationV1,
    pub epoch_public_keys: EpochPublicKeys,
    pub submissions: Vec<EncryptedSubmissionV1>,
    pub balances: Vec<BalanceRecordV1>,
    pub balance_snapshot: SignedBalanceSnapshotV1,
    pub pre_balance_root: [u8; 32],
    pub member_root: [u8; 32],
    pub member_count: u32,
    pub lock_nonce: [u8; 32],
}

impl std::fmt::Debug for LockPackageV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LockPackageV1(..redacted)")
    }
}

impl LockPackageV1 {
    pub fn new(
        epoch_account: Pubkey,
        configuration: EpochConfigurationV1,
        epoch_public_keys: EpochPublicKeys,
        submissions: Vec<EncryptedSubmissionV1>,
        balances: Vec<BalanceRecordV1>,
        balance_snapshot: SignedBalanceSnapshotV1,
        lock_nonce: [u8; 32],
    ) -> Result<Self, LockValidationError> {
        if submissions.len() > MAX_BATCH_MEMBERS || balances.len() > MAX_BATCH_MEMBERS {
            return Err(LockValidationError::MemberLimitExceeded);
        }
        let member_count = u32::try_from(submissions.len())
            .map_err(|_| LockValidationError::MemberCountMismatch)?;
        let member_root = member_root(&epoch_public_keys, &submissions)?;
        let pre_balance_root = balance_root(&balances)?;
        Ok(Self {
            epoch_account,
            configuration,
            epoch_public_keys,
            submissions,
            balances,
            balance_snapshot,
            pre_balance_root,
            member_root,
            member_count,
            lock_nonce,
        })
    }

    #[must_use]
    pub const fn epoch_account(&self) -> Pubkey {
        self.epoch_account
    }

    #[must_use]
    pub fn lock_payload(&self) -> LockPayloadV1 {
        LockPayloadV1 {
            epoch_account: self.epoch_account,
            configuration_hash: self.configuration.digest(),
            pre_balance_root: self.pre_balance_root,
            member_root: self.member_root,
            member_count: self.member_count,
            lock_deadline: self.configuration.lock_deadline,
            lock_nonce: self.lock_nonce,
        }
    }

    fn validate(&self, confirmed: &ConfirmedOpenEpoch) -> Result<[u8; 32], LockValidationError> {
        if self.epoch_account != confirmed.epoch_account
            || self.configuration != confirmed.configuration
            || self.configuration.minimum_count < 4
            || self.configuration.lock_threshold != 2
            || self.configuration.settlement_threshold != 2
            || self.configuration.pool == Pubkey::default()
            || self.configuration.base_mint == Pubkey::default()
            || self.configuration.quote_mint == Pubkey::default()
            || self.configuration.base_mint == self.configuration.quote_mint
            || self
                .configuration
                .keypers
                .iter()
                .any(|keyper| *keyper == Pubkey::default())
            || self.configuration.keypers[0] == self.configuration.keypers[1]
            || self.configuration.keypers[0] == self.configuration.keypers[2]
            || self.configuration.keypers[1] == self.configuration.keypers[2]
            || self.configuration.abort_deadline <= self.configuration.lock_deadline
            || self.lock_nonce == [0; 32]
        {
            return Err(LockValidationError::InvalidConfiguration);
        }
        if confirmed.current_timestamp >= self.configuration.lock_deadline {
            return Err(LockValidationError::DeadlinePassed);
        }
        if self.submissions.len() > MAX_BATCH_MEMBERS || self.balances.len() > MAX_BATCH_MEMBERS {
            return Err(LockValidationError::MemberLimitExceeded);
        }
        if self.member_count as usize != self.submissions.len() {
            return Err(LockValidationError::MemberCountMismatch);
        }
        if self.member_count < self.configuration.minimum_count {
            return Err(LockValidationError::CrowdBelowMinimum);
        }

        let mut participants = BTreeSet::new();
        let mut nonces = BTreeSet::new();
        let mut receipts = BTreeSet::new();
        for submission in &self.submissions {
            submission
                .verify_admission(&confirmed.policy)
                .map_err(|_| LockValidationError::InvalidSubmission)?;
            if !participants.insert(submission.authorization.participant_id) {
                return Err(LockValidationError::DuplicateParticipant);
            }
            if !nonces.insert(submission.authorization.nonce) {
                return Err(LockValidationError::DuplicateAuthorization);
            }
            if !receipts.insert(submission.receipt) {
                return Err(LockValidationError::DuplicateReceipt);
            }
        }
        if member_root(&self.epoch_public_keys, &self.submissions)? != self.member_root {
            return Err(LockValidationError::MemberRootMismatch);
        }

        self.balance_snapshot.verify(
            self.configuration.epoch_id,
            &self.balances,
            confirmed.policy.operator_key,
        )?;
        if balance_root(&self.balances)? != self.pre_balance_root {
            return Err(LockValidationError::InvalidBalance);
        }
        if self.balances.len() != self.submissions.len() {
            return Err(LockValidationError::InvalidBalance);
        }
        let balances: BTreeMap<_, _> = self
            .balances
            .iter()
            .map(|balance| (balance.participant_id, balance))
            .collect();
        if balances.len() != self.balances.len() {
            return Err(LockValidationError::InvalidBalance);
        }
        for submission in &self.submissions {
            let balance = balances
                .get(&submission.authorization.participant_id)
                .ok_or(LockValidationError::InvalidBalance)?;
            if balance.reserved_base_atoms != submission.authorization.base_atoms
                || balance.reserved_quote_atoms != submission.authorization.quote_atoms
                || balance.base_atoms < balance.reserved_base_atoms
                || balance.quote_atoms < balance.reserved_quote_atoms
            {
                return Err(LockValidationError::InvalidBalance);
            }
        }
        Ok(self.lock_payload().digest())
    }

    pub(crate) fn validate_locked(
        &self,
        confirmed: &ConfirmedLock,
    ) -> Result<[u8; 32], LockValidationError> {
        let pool = confirmed
            .pool
            .as_ref()
            .ok_or(LockValidationError::InvalidOnchainLock)?;
        let configuration = EpochConfigurationV1 {
            pool: confirmed.state.pool,
            epoch_id: confirmed.state.epoch_id,
            base_mint: pool.base_mint,
            quote_mint: pool.quote_mint,
            base_lot_atoms: pool.base_lot_atoms,
            quote_atoms_per_lot: confirmed.state.quote_atoms_per_lot,
            minimum_count: confirmed.state.minimum_count,
            lock_threshold: pool.lock_threshold,
            settlement_threshold: pool.settlement_threshold,
            keypers: pool.keypers,
            lock_deadline: confirmed.state.lock_deadline,
            abort_deadline: confirmed.state.abort_deadline,
        };
        let operator = VerifyingKey::from_bytes(&pool.operator.to_bytes())
            .map_err(|_| LockValidationError::InvalidOnchainLock)?;
        let policy = AdmissionPolicyV1::new(
            configuration.epoch_id,
            operator,
            configuration.minimum_count as usize,
            configuration.base_lot_atoms,
            configuration.quote_atoms_per_lot,
            confirmed.confirmation_slot,
        )
        .map_err(|_| LockValidationError::InvalidOnchainLock)?;
        let open = ConfirmedOpenEpoch {
            epoch_account: confirmed.epoch_account,
            configuration,
            policy,
            current_timestamp: configuration.lock_deadline.saturating_sub(1),
            confirmation_slot: confirmed.confirmation_slot,
        };
        let digest = self.validate(&open)?;
        if digest != confirmed.state.lock_digest
            || self.pre_balance_root != confirmed.state.pre_balance_root
            || self.member_root != confirmed.state.member_root
            || self.member_count != confirmed.state.member_count
        {
            return Err(LockValidationError::InvalidOnchainLock);
        }
        Ok(digest)
    }

    pub(crate) fn encode_wire(&self) -> Result<Vec<u8>, LockValidationError> {
        if self.submissions.len() > MAX_BATCH_MEMBERS || self.balances.len() > MAX_BATCH_MEMBERS {
            return Err(LockValidationError::MemberLimitExceeded);
        }
        let public_keys = self
            .epoch_public_keys
            .encode_wire()
            .map_err(|_| LockValidationError::InvalidConfiguration)?;
        if public_keys.len() > MAX_EPOCH_PUBLIC_KEYS_LEN {
            return Err(LockValidationError::InvalidConfiguration);
        }
        let public_keys_len = u32::try_from(public_keys.len())
            .map_err(|_| LockValidationError::InvalidConfiguration)?;
        let submission_count = u32::try_from(self.submissions.len())
            .map_err(|_| LockValidationError::MemberCountMismatch)?;
        let balance_count =
            u32::try_from(self.balances.len()).map_err(|_| LockValidationError::InvalidBalance)?;
        let mut bytes = Vec::new();
        bytes.push(1);
        bytes.extend_from_slice(self.epoch_account.as_ref());
        bytes.extend_from_slice(&self.configuration.encode());
        bytes.extend_from_slice(&public_keys_len.to_le_bytes());
        bytes.extend_from_slice(&public_keys);
        bytes.extend_from_slice(&submission_count.to_le_bytes());
        for submission in &self.submissions {
            bytes.extend_from_slice(&submission.encode_wire());
        }
        bytes.extend_from_slice(&balance_count.to_le_bytes());
        for balance in &self.balances {
            bytes.extend_from_slice(&balance.encode());
        }
        bytes.extend_from_slice(&self.balance_snapshot.encode());
        bytes.extend_from_slice(&self.pre_balance_root);
        bytes.extend_from_slice(&self.member_root);
        bytes.extend_from_slice(&self.member_count.to_le_bytes());
        bytes.extend_from_slice(&self.lock_nonce);
        Ok(bytes)
    }

    pub(crate) fn decode_wire(bytes: &[u8]) -> Result<Self, LockValidationError> {
        use crate::crypto::ENCRYPTED_SUBMISSION_V1_LEN;

        const FIXED_PREFIX: usize = 1 + 32 + EpochConfigurationV1::ENCODED_LEN + 4 + 4;
        const FIXED_SUFFIX: usize = 4 + 164 + 32 + 32 + 4 + 32;
        if bytes.len() < FIXED_PREFIX + FIXED_SUFFIX || bytes[0] != 1 {
            return Err(LockValidationError::InvalidSubmission);
        }
        let epoch_account = Pubkey::new_from_array(
            bytes[1..33]
                .try_into()
                .map_err(|_| LockValidationError::InvalidConfiguration)?,
        );
        let configuration_end = 33 + EpochConfigurationV1::ENCODED_LEN;
        let configuration = EpochConfigurationV1::decode(&bytes[33..configuration_end])
            .ok_or(LockValidationError::InvalidConfiguration)?;
        let public_keys_len = u32::from_le_bytes(
            bytes[configuration_end..configuration_end + 4]
                .try_into()
                .map_err(|_| LockValidationError::InvalidConfiguration)?,
        ) as usize;
        if public_keys_len > MAX_EPOCH_PUBLIC_KEYS_LEN {
            return Err(LockValidationError::InvalidConfiguration);
        }
        let public_keys_start = configuration_end + 4;
        let public_keys_end = public_keys_start
            .checked_add(public_keys_len)
            .ok_or(LockValidationError::InvalidConfiguration)?;
        let epoch_public_keys = EpochPublicKeys::decode_wire(
            bytes
                .get(public_keys_start..public_keys_end)
                .ok_or(LockValidationError::InvalidConfiguration)?,
        )
        .map_err(|_| LockValidationError::InvalidConfiguration)?;
        let count_end = public_keys_end
            .checked_add(4)
            .ok_or(LockValidationError::InvalidSubmission)?;
        let submission_count = u32::from_le_bytes(
            bytes
                .get(public_keys_end..count_end)
                .ok_or(LockValidationError::InvalidSubmission)?
                .try_into()
                .map_err(|_| LockValidationError::InvalidSubmission)?,
        ) as usize;
        if submission_count > MAX_BATCH_MEMBERS {
            return Err(LockValidationError::MemberLimitExceeded);
        }
        let submissions_len = submission_count
            .checked_mul(ENCRYPTED_SUBMISSION_V1_LEN)
            .ok_or(LockValidationError::InvalidSubmission)?;
        let submissions_start = count_end;
        let submissions_end = submissions_start
            .checked_add(submissions_len)
            .ok_or(LockValidationError::InvalidSubmission)?;
        if submissions_end + FIXED_SUFFIX > bytes.len() {
            return Err(LockValidationError::InvalidSubmission);
        }
        let mut submissions = Vec::with_capacity(submission_count);
        for encoded in
            bytes[submissions_start..submissions_end].chunks_exact(ENCRYPTED_SUBMISSION_V1_LEN)
        {
            submissions.push(
                EncryptedSubmissionV1::decode_wire(encoded)
                    .map_err(|_| LockValidationError::InvalidSubmission)?,
            );
        }
        let balance_count = u32::from_le_bytes(
            bytes[submissions_end..submissions_end + 4]
                .try_into()
                .map_err(|_| LockValidationError::InvalidBalance)?,
        ) as usize;
        if balance_count > MAX_BATCH_MEMBERS {
            return Err(LockValidationError::MemberLimitExceeded);
        }
        let balances_start = submissions_end + 4;
        let balances_end = balances_start
            .checked_add(
                balance_count
                    .checked_mul(64)
                    .ok_or(LockValidationError::InvalidBalance)?,
            )
            .ok_or(LockValidationError::InvalidBalance)?;
        let expected_len = balances_end
            .checked_add(164 + 32 + 32 + 4 + 32)
            .ok_or(LockValidationError::InvalidSubmission)?;
        if expected_len != bytes.len() {
            return Err(LockValidationError::InvalidSubmission);
        }
        let mut balances = Vec::with_capacity(balance_count);
        for encoded in bytes[balances_start..balances_end].chunks_exact(64) {
            balances.push(BalanceRecordV1::decode(encoded)?);
        }
        let snapshot_end = balances_end + 164;
        let balance_snapshot = SignedBalanceSnapshotV1::decode(&bytes[balances_end..snapshot_end])?;
        let pre_balance_root = bytes[snapshot_end..snapshot_end + 32]
            .try_into()
            .map_err(|_| LockValidationError::InvalidBalance)?;
        let member_root = bytes[snapshot_end + 32..snapshot_end + 64]
            .try_into()
            .map_err(|_| LockValidationError::MemberRootMismatch)?;
        let member_count = u32::from_le_bytes(
            bytes[snapshot_end + 64..snapshot_end + 68]
                .try_into()
                .map_err(|_| LockValidationError::MemberCountMismatch)?,
        );
        let lock_nonce = bytes[snapshot_end + 68..snapshot_end + 100]
            .try_into()
            .map_err(|_| LockValidationError::InvalidConfiguration)?;
        Ok(Self {
            epoch_account,
            configuration,
            epoch_public_keys,
            submissions,
            balances,
            balance_snapshot,
            pre_balance_root,
            member_root,
            member_count,
            lock_nonce,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct LockApprovalV1 {
    keyper_key: [u8; 32],
    digest: [u8; 32],
    signature: [u8; 64],
}

impl std::fmt::Debug for LockApprovalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LockApprovalV1(..redacted)")
    }
}

impl LockApprovalV1 {
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.keyper_key) else {
            return false;
        };
        key.verify(&self.digest, &Signature::from_bytes(&self.signature))
            .is_ok()
    }

    pub(crate) const fn from_parts(
        keyper_key: [u8; 32],
        digest: [u8; 32],
        signature: [u8; 64],
    ) -> Self {
        Self {
            keyper_key,
            digest,
            signature,
        }
    }

    pub(crate) const fn keyper_key(&self) -> [u8; 32] {
        self.keyper_key
    }

    pub(crate) const fn signature(&self) -> [u8; 64] {
        self.signature
    }
}

pub struct ReferenceKeyper {
    pub(crate) index: usize,
    pub(crate) signing_key: SigningKey,
    pub(crate) journal: LockJournal,
}

impl ReferenceKeyper {
    #[must_use]
    pub const fn new(index: usize, signing_key: SigningKey, journal: LockJournal) -> Self {
        Self {
            index,
            signing_key,
            journal,
        }
    }

    pub fn sign_lock(
        &mut self,
        package: &LockPackageV1,
        confirmed: &ConfirmedOpenEpoch,
        secret: &KeyperSecretShare,
    ) -> Result<LockApprovalV1, LockValidationError> {
        let configured = confirmed
            .configuration
            .keypers
            .get(self.index)
            .ok_or(LockValidationError::WrongKeyper)?;
        let keyper_key = self.signing_key.verifying_key().to_bytes();
        if configured.to_bytes() != keyper_key
            || secret.index() != self.index
            || secret.epoch_account() != package.epoch_account
            || !package.epoch_public_keys.matches_share(secret)
        {
            return Err(LockValidationError::WrongKeyper);
        }
        let digest = package.validate(confirmed)?;
        self.journal.record(package.epoch_account, digest)?;
        Ok(LockApprovalV1 {
            keyper_key,
            digest,
            signature: self.signing_key.sign(&digest).to_bytes(),
        })
    }

    pub fn release_share(
        &self,
        package: &LockPackageV1,
        confirmed: &ConfirmedLock,
        secret: &KeyperSecretShare,
        member_index: usize,
    ) -> Result<ReleasedShareV1, LockValidationError> {
        let digest = package.validate_locked(confirmed)?;
        let configured = confirmed
            .pool
            .as_ref()
            .and_then(|pool| pool.keypers.get(self.index))
            .ok_or(LockValidationError::WrongKeyper)?;
        if configured.to_bytes() != self.signing_key.verifying_key().to_bytes()
            || self.journal.digest(package.epoch_account) != Some(digest)
            || self.index != secret.index()
            || secret.epoch_account() != package.epoch_account
            || !package.epoch_public_keys.matches_share(secret)
        {
            return Err(LockValidationError::WrongKeyper);
        }
        let submission = package
            .submissions
            .get(member_index)
            .ok_or(LockValidationError::InvalidSubmission)?;
        let mut ciphertexts = BTreeSet::new();
        if package
            .submissions
            .iter()
            .any(|member| !ciphertexts.insert(Sha256::digest(&member.ciphertext)))
        {
            return Err(LockValidationError::InvalidSubmission);
        }
        secret
            .release(
                package.epoch_account,
                confirmed.lock_digest(),
                &submission.ciphertext,
            )
            .map_err(|_| LockValidationError::InvalidSubmission)
    }
}

/// A capability proving that an epoch, its pool, and the clock were read at confirmed commitment.
///
/// Its fields are private so signing code cannot construct trusted epoch context from caller data.
pub struct ConfirmedOpenEpoch {
    epoch_account: Pubkey,
    configuration: EpochConfigurationV1,
    policy: AdmissionPolicyV1,
    current_timestamp: i64,
    confirmation_slot: u64,
}

impl ConfirmedOpenEpoch {
    #[must_use]
    pub const fn epoch_account(&self) -> Pubkey {
        self.epoch_account
    }

    #[must_use]
    pub const fn confirmation_slot(&self) -> u64 {
        self.confirmation_slot
    }

    #[must_use]
    pub fn configuration_hash(&self) -> [u8; 32] {
        self.configuration.digest()
    }
}

#[derive(Debug)]
pub struct LockJournal {
    path: PathBuf,
    records: BTreeMap<Pubkey, [u8; 32]>,
}

impl LockJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LockValidationError> {
        let path = path.as_ref().to_path_buf();
        let _lock = JournalFileLock::acquire(&path)?;
        let initialized = initialized_path(&path);
        match (path.exists(), initialized.exists()) {
            (false, false) => {
                persist_initialization_marker(&initialized)?;
                persist_journal(&path, &BTreeMap::new())?;
            }
            (true, true) => validate_initialization_marker(&initialized)?,
            (false, true) | (true, false) => {
                return Err(LockValidationError::CorruptJournal);
            }
        }
        let records = load_journal(&path)?;
        Ok(Self { path, records })
    }

    #[must_use]
    pub fn digest(&self, epoch: Pubkey) -> Option<[u8; 32]> {
        self.records.get(&epoch).copied()
    }

    fn record(&mut self, epoch: Pubkey, digest: [u8; 32]) -> Result<(), LockValidationError> {
        let _lock = JournalFileLock::acquire(&self.path)?;
        if !self.path.exists() {
            return Err(LockValidationError::CorruptJournal);
        }
        let mut records = load_journal(&self.path)?;
        if let Some(existing) = records.get(&epoch) {
            if *existing == digest {
                self.records = records;
                return Ok(());
            }
            return Err(LockValidationError::ConflictingLock);
        }
        records.insert(epoch, digest);
        persist_journal(&self.path, &records)?;
        self.records = records;
        Ok(())
    }
}

/// A lock capability that can only be produced by fetching a confirmed program account.
pub struct ConfirmedLock {
    pub(crate) epoch_account: Pubkey,
    pub(crate) state: EpochStateV1,
    pub(crate) pool: Option<PoolStateV1>,
    pub(crate) confirmation_slot: u64,
}

impl ConfirmedLock {
    #[must_use]
    pub const fn epoch_account(&self) -> Pubkey {
        self.epoch_account
    }

    #[must_use]
    pub const fn lock_digest(&self) -> [u8; 32] {
        self.state.lock_digest
    }

    #[must_use]
    pub const fn member_root(&self) -> [u8; 32] {
        self.state.member_root
    }

    #[must_use]
    pub const fn confirmation_slot(&self) -> u64 {
        self.confirmation_slot
    }
}

pub struct ProgramClient {
    rpc: RpcClient,
}

impl ProgramClient {
    #[must_use]
    pub fn new(rpc_url: impl ToString) -> Self {
        Self {
            rpc: RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed()),
        }
    }

    pub fn fetch_confirmed_lock(
        &self,
        epoch_account: Pubkey,
    ) -> Result<ConfirmedLock, LockValidationError> {
        let response = self
            .rpc
            .get_account_with_commitment(&epoch_account, CommitmentConfig::confirmed())
            .map_err(|_| LockValidationError::Rpc)?;
        let account = response.value.ok_or(LockValidationError::MissingAccount)?;
        let initial_lock = confirmed_lock_from_account(
            epoch_account,
            account.owner,
            &account.data,
            response.context.slot,
        )?;
        let response = self
            .rpc
            .get_multiple_accounts_with_commitment(
                &[epoch_account, initial_lock.state.pool],
                CommitmentConfig::confirmed(),
            )
            .map_err(|_| LockValidationError::Rpc)?;
        if response.context.slot < initial_lock.confirmation_slot || response.value.len() != 2 {
            return Err(LockValidationError::Rpc);
        }
        let mut accounts = response.value.into_iter();
        let epoch = accounts
            .next()
            .flatten()
            .ok_or(LockValidationError::MissingAccount)?;
        let pool = accounts
            .next()
            .flatten()
            .ok_or(LockValidationError::MissingAccount)?;
        confirmed_lock_from_accounts(
            epoch_account,
            RpcAccountData::new(epoch.owner, &epoch.data),
            RpcAccountData::new(pool.owner, &pool.data),
            response.context.slot,
        )
    }

    pub fn fetch_confirmed_open_epoch(
        &self,
        epoch_account: Pubkey,
    ) -> Result<ConfirmedOpenEpoch, LockValidationError> {
        let initial = self
            .rpc
            .get_account_with_commitment(&epoch_account, CommitmentConfig::confirmed())
            .map_err(|_| LockValidationError::Rpc)?;
        let initial_epoch = initial.value.ok_or(LockValidationError::MissingAccount)?;
        let initial_state =
            decode_program_epoch(epoch_account, initial_epoch.owner, &initial_epoch.data)?;
        let response = self
            .rpc
            .get_multiple_accounts_with_commitment(
                &[epoch_account, initial_state.pool, sysvar::clock::ID],
                CommitmentConfig::confirmed(),
            )
            .map_err(|_| LockValidationError::Rpc)?;
        if response.context.slot < initial.context.slot || response.value.len() != 3 {
            return Err(LockValidationError::Rpc);
        }
        let mut accounts = response.value.into_iter();
        let epoch = accounts
            .next()
            .flatten()
            .ok_or(LockValidationError::MissingAccount)?;
        let pool = accounts
            .next()
            .flatten()
            .ok_or(LockValidationError::MissingAccount)?;
        let clock = accounts
            .next()
            .flatten()
            .ok_or(LockValidationError::MissingAccount)?;
        confirmed_open_epoch_from_accounts(
            epoch_account,
            RpcAccountData::new(epoch.owner, &epoch.data),
            initial_state.pool,
            RpcAccountData::new(pool.owner, &pool.data),
            RpcAccountData::new(clock.owner, &clock.data),
            response.context.slot,
        )
    }
}

struct RpcAccountData<'a> {
    owner: Pubkey,
    data: &'a [u8],
}

impl<'a> RpcAccountData<'a> {
    const fn new(owner: Pubkey, data: &'a [u8]) -> Self {
        Self { owner, data }
    }
}

fn confirmed_open_epoch_from_accounts(
    epoch_account: Pubkey,
    epoch_account_data: RpcAccountData<'_>,
    pool_address_from_initial_read: Pubkey,
    pool_account_data: RpcAccountData<'_>,
    clock_account_data: RpcAccountData<'_>,
    confirmation_slot: u64,
) -> Result<ConfirmedOpenEpoch, LockValidationError> {
    let state = decode_program_epoch(
        epoch_account,
        epoch_account_data.owner,
        epoch_account_data.data,
    )?;
    if state.pool != pool_address_from_initial_read {
        return Err(LockValidationError::InvalidOnchainEpoch);
    }
    if pool_account_data.owner != ID || clock_account_data.owner != sysvar::ID {
        return Err(LockValidationError::InvalidOnchainEpoch);
    }
    let pool = PoolStateV1::decode(pool_account_data.data)
        .map_err(|_| LockValidationError::InvalidOnchainEpoch)?;
    let clock: Clock = bincode::deserialize(clock_account_data.data)
        .map_err(|_| LockValidationError::InvalidOnchainEpoch)?;
    let (expected_pool, pool_bump) =
        pool_address(&pool.operator, &pool.base_mint, &pool.quote_mint);
    let (_, vault_bump) = vault_authority_address(&state.pool);
    let configuration = EpochConfigurationV1 {
        pool: state.pool,
        epoch_id: state.epoch_id,
        base_mint: pool.base_mint,
        quote_mint: pool.quote_mint,
        base_lot_atoms: pool.base_lot_atoms,
        quote_atoms_per_lot: state.quote_atoms_per_lot,
        minimum_count: state.minimum_count,
        lock_threshold: pool.lock_threshold,
        settlement_threshold: pool.settlement_threshold,
        keypers: pool.keypers,
        lock_deadline: state.lock_deadline,
        abort_deadline: state.abort_deadline,
    };
    if expected_pool != state.pool
        || pool.pool_bump != pool_bump
        || pool.vault_bump != vault_bump
        || pool.lock_threshold != 2
        || pool.settlement_threshold != 2
        || pool.base_lot_atoms == 0
        || pool.base_mint == pool.quote_mint
        || pool.keypers.iter().any(|key| *key == Pubkey::default())
        || pool.keypers[0] == pool.keypers[1]
        || pool.keypers[0] == pool.keypers[2]
        || pool.keypers[1] == pool.keypers[2]
        || state.terminal_state != EpochTerminalState::Open
        || state.residual_side != 0
        || state.configuration_hash != configuration.digest()
        || state.pre_balance_root != [0; 32]
        || state.member_root != [0; 32]
        || state.lock_digest != [0; 32]
        || state.result_commitment != [0; 32]
        || state.settlement_digest != [0; 32]
        || state.lock_nonce != [0; 32]
        || state.settlement_nonce != [0; 32]
        || state.member_count != 0
        || state.minimum_count < 4
        || state.residual_lots != 0
        || state.base_lot_atoms != pool.base_lot_atoms
        || state.quote_atoms_per_lot == 0
        || state.abort_deadline <= state.lock_deadline
        || clock.slot > confirmation_slot
        || clock.unix_timestamp >= state.lock_deadline
    {
        return Err(LockValidationError::InvalidOnchainEpoch);
    }
    let operator = VerifyingKey::from_bytes(&pool.operator.to_bytes())
        .map_err(|_| LockValidationError::InvalidOnchainEpoch)?;
    let policy = AdmissionPolicyV1::new(
        state.epoch_id,
        operator,
        state.minimum_count as usize,
        state.base_lot_atoms,
        state.quote_atoms_per_lot,
        clock.slot,
    )
    .map_err(|_| LockValidationError::InvalidOnchainEpoch)?;
    Ok(ConfirmedOpenEpoch {
        epoch_account,
        configuration,
        policy,
        current_timestamp: clock.unix_timestamp,
        confirmation_slot,
    })
}

fn decode_program_epoch(
    epoch_account: Pubkey,
    owner: Pubkey,
    data: &[u8],
) -> Result<EpochStateV1, LockValidationError> {
    if owner != ID {
        return Err(LockValidationError::InvalidOnchainEpoch);
    }
    let state = EpochStateV1::decode(data).map_err(|_| LockValidationError::InvalidOnchainEpoch)?;
    let (expected, bump) = epoch_address(&state.pool, &state.epoch_id);
    if expected != epoch_account || state.epoch_bump != bump {
        return Err(LockValidationError::InvalidOnchainEpoch);
    }
    Ok(state)
}

fn confirmed_lock_from_account(
    epoch_account: Pubkey,
    owner: Pubkey,
    data: &[u8],
    confirmation_slot: u64,
) -> Result<ConfirmedLock, LockValidationError> {
    if owner != ID {
        return Err(LockValidationError::InvalidOnchainLock);
    }
    let state = EpochStateV1::decode(data).map_err(|_| LockValidationError::InvalidOnchainLock)?;
    let (expected, bump) = epoch_address(&state.pool, &state.epoch_id);
    let expected_lock_digest = LockPayloadV1 {
        epoch_account,
        configuration_hash: state.configuration_hash,
        pre_balance_root: state.pre_balance_root,
        member_root: state.member_root,
        member_count: state.member_count,
        lock_deadline: state.lock_deadline,
        lock_nonce: state.lock_nonce,
    }
    .digest();
    if expected != epoch_account
        || state.epoch_bump != bump
        || state.terminal_state != EpochTerminalState::Locked
        || state.minimum_count < 4
        || state.member_count < state.minimum_count
        || state.base_lot_atoms == 0
        || state.quote_atoms_per_lot == 0
        || state.abort_deadline <= state.lock_deadline
        || state.configuration_hash == [0; 32]
        || state.lock_nonce == [0; 32]
        || state.pre_balance_root == [0; 32]
        || state.member_root == [0; 32]
        || state.lock_digest != expected_lock_digest
    {
        return Err(LockValidationError::InvalidOnchainLock);
    }
    Ok(ConfirmedLock {
        epoch_account,
        state,
        pool: None,
        confirmation_slot,
    })
}

fn confirmed_lock_from_accounts(
    epoch_account: Pubkey,
    epoch_account_data: RpcAccountData<'_>,
    pool_account_data: RpcAccountData<'_>,
    confirmation_slot: u64,
) -> Result<ConfirmedLock, LockValidationError> {
    let mut confirmed = confirmed_lock_from_account(
        epoch_account,
        epoch_account_data.owner,
        epoch_account_data.data,
        confirmation_slot,
    )?;
    if pool_account_data.owner != ID {
        return Err(LockValidationError::InvalidOnchainLock);
    }
    let pool = PoolStateV1::decode(pool_account_data.data)
        .map_err(|_| LockValidationError::InvalidOnchainLock)?;
    let (expected_pool, pool_bump) =
        pool_address(&pool.operator, &pool.base_mint, &pool.quote_mint);
    let (_, vault_bump) = vault_authority_address(&confirmed.state.pool);
    let configuration = EpochConfigurationV1 {
        pool: confirmed.state.pool,
        epoch_id: confirmed.state.epoch_id,
        base_mint: pool.base_mint,
        quote_mint: pool.quote_mint,
        base_lot_atoms: pool.base_lot_atoms,
        quote_atoms_per_lot: confirmed.state.quote_atoms_per_lot,
        minimum_count: confirmed.state.minimum_count,
        lock_threshold: pool.lock_threshold,
        settlement_threshold: pool.settlement_threshold,
        keypers: pool.keypers,
        lock_deadline: confirmed.state.lock_deadline,
        abort_deadline: confirmed.state.abort_deadline,
    };
    if expected_pool != confirmed.state.pool
        || pool.pool_bump != pool_bump
        || pool.vault_bump != vault_bump
        || pool.lock_threshold != 2
        || pool.settlement_threshold != 2
        || pool.base_lot_atoms == 0
        || pool.base_mint == pool.quote_mint
        || configuration.digest() != confirmed.state.configuration_hash
    {
        return Err(LockValidationError::InvalidOnchainLock);
    }
    confirmed.pool = Some(pool);
    Ok(confirmed)
}

fn member_root(
    public_keys: &EpochPublicKeys,
    submissions: &[EncryptedSubmissionV1],
) -> Result<[u8; 32], LockValidationError> {
    let mut leaves = Vec::with_capacity(submissions.len() + 1);
    leaves.push(
        public_keys
            .commitment_leaf()
            .map_err(|_| LockValidationError::InvalidConfiguration)?,
    );
    leaves.extend(
        submissions
            .iter()
            .map(EncryptedSubmissionV1::commitment_bytes),
    );
    let refs: Vec<_> = leaves.iter().map(Vec::as_slice).collect();
    content_root(CommitmentDomain::MemberSet, &refs)
        .map_err(|_| LockValidationError::InvalidSubmission)
}

fn balance_root(records: &[BalanceRecordV1]) -> Result<[u8; 32], LockValidationError> {
    let leaves: Vec<_> = records
        .iter()
        .copied()
        .map(BalanceRecordV1::encode)
        .collect();
    let refs: Vec<_> = leaves.iter().map(<[u8; 64]>::as_slice).collect();
    content_root(CommitmentDomain::BalanceSet, &refs)
        .map_err(|_| LockValidationError::InvalidBalance)
}

fn snapshot_message(epoch_id: [u8; 32], count: u32, root: [u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SNAPSHOT_DOMAIN.len() + 68);
    message.extend_from_slice(SNAPSHOT_DOMAIN);
    message.extend_from_slice(&epoch_id);
    message.extend_from_slice(&count.to_le_bytes());
    message.extend_from_slice(&root);
    message
}

fn load_journal(path: &Path) -> Result<BTreeMap<Pubkey, [u8; 32]>, LockValidationError> {
    let bytes = fs::read(path)?;
    if bytes.len() < JOURNAL_HEADER.len() + 4 + JOURNAL_CHECKSUM_LEN
        || &bytes[..JOURNAL_HEADER.len()] != JOURNAL_HEADER
    {
        return Err(LockValidationError::CorruptJournal);
    }
    let payload_len = bytes.len() - JOURNAL_CHECKSUM_LEN;
    if Sha256::digest(&bytes[..payload_len]).as_slice() != &bytes[payload_len..] {
        return Err(LockValidationError::CorruptJournal);
    }
    let count = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| LockValidationError::CorruptJournal)?,
    ) as usize;
    let expected = 12_usize
        .checked_add(
            count
                .checked_mul(JOURNAL_RECORD_LEN)
                .ok_or(LockValidationError::CorruptJournal)?,
        )
        .and_then(|value| value.checked_add(JOURNAL_CHECKSUM_LEN))
        .ok_or(LockValidationError::CorruptJournal)?;
    if bytes.len() != expected {
        return Err(LockValidationError::CorruptJournal);
    }
    let mut records = BTreeMap::new();
    for record in bytes[12..payload_len].chunks_exact(JOURNAL_RECORD_LEN) {
        let epoch = Pubkey::new_from_array(
            record[0..32]
                .try_into()
                .map_err(|_| LockValidationError::CorruptJournal)?,
        );
        let digest = record[32..64]
            .try_into()
            .map_err(|_| LockValidationError::CorruptJournal)?;
        if records.insert(epoch, digest).is_some() {
            return Err(LockValidationError::CorruptJournal);
        }
    }
    Ok(records)
}

fn persist_journal(
    path: &Path,
    records: &BTreeMap<Pubkey, [u8; 32]>,
) -> Result<(), LockValidationError> {
    let mut bytes =
        Vec::with_capacity(12 + records.len() * JOURNAL_RECORD_LEN + JOURNAL_CHECKSUM_LEN);
    bytes.extend_from_slice(JOURNAL_HEADER);
    bytes.extend_from_slice(
        &u32::try_from(records.len())
            .map_err(|_| LockValidationError::CorruptJournal)?
            .to_le_bytes(),
    );
    for (epoch, digest) in records {
        bytes.extend_from_slice(epoch.as_ref());
        bytes.extend_from_slice(digest);
    }
    let checksum = Sha256::digest(&bytes);
    bytes.extend_from_slice(&checksum);

    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    if let Err(error) = (|| -> io::Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
        Ok(())
    })() {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

fn initialized_path(journal: &Path) -> PathBuf {
    journal.with_extension("initialized")
}

fn persist_initialization_marker(path: &Path) -> Result<(), LockValidationError> {
    let mut bytes = Vec::with_capacity(JOURNAL_INITIALIZED.len() + JOURNAL_CHECKSUM_LEN);
    bytes.extend_from_slice(JOURNAL_INITIALIZED);
    bytes.extend_from_slice(&Sha256::digest(JOURNAL_INITIALIZED));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    Ok(())
}

fn validate_initialization_marker(path: &Path) -> Result<(), LockValidationError> {
    let bytes = fs::read(path)?;
    if bytes.len() != JOURNAL_INITIALIZED.len() + JOURNAL_CHECKSUM_LEN
        || &bytes[..JOURNAL_INITIALIZED.len()] != JOURNAL_INITIALIZED
        || Sha256::digest(&bytes[..JOURNAL_INITIALIZED.len()]).as_slice()
            != &bytes[JOURNAL_INITIALIZED.len()..]
    {
        return Err(LockValidationError::CorruptJournal);
    }
    Ok(())
}

struct JournalFileLock {
    file: File,
}

impl JournalFileLock {
    fn acquire(journal: &Path) -> Result<Self, LockValidationError> {
        let path = journal.with_extension("lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(path)?;
        for _ in 0..LOCK_ATTEMPTS {
            match file.try_lock() {
                Ok(()) => return Ok(Self { file }),
                Err(std::fs::TryLockError::WouldBlock) => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
            }
        }
        Err(LockValidationError::JournalBusy)
    }
}

impl Drop for JournalFileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked_state() -> (Pubkey, EpochStateV1) {
        let pool = Pubkey::new_from_array([1; 32]);
        let epoch_id = [2; 32];
        let (epoch, epoch_bump) = epoch_address(&pool, &epoch_id);
        let mut state = EpochStateV1 {
            epoch_bump,
            terminal_state: EpochTerminalState::Locked,
            residual_side: 0,
            pool,
            epoch_id,
            configuration_hash: [3; 32],
            pre_balance_root: [6; 32],
            member_root: [4; 32],
            lock_digest: [0; 32],
            result_commitment: [0; 32],
            settlement_digest: [0; 32],
            lock_nonce: [5; 32],
            settlement_nonce: [0; 32],
            member_count: 4,
            minimum_count: 4,
            residual_lots: 0,
            base_lot_atoms: 1,
            quote_atoms_per_lot: 100,
            lock_deadline: 900,
            abort_deadline: 1_000,
        };
        state.lock_digest = LockPayloadV1 {
            epoch_account: epoch,
            configuration_hash: state.configuration_hash,
            pre_balance_root: state.pre_balance_root,
            member_root: state.member_root,
            member_count: state.member_count,
            lock_deadline: state.lock_deadline,
            lock_nonce: state.lock_nonce,
        }
        .digest();
        (epoch, state)
    }

    #[test]
    fn confirmed_lock_requires_exact_program_owned_locked_state() {
        let (epoch, state) = locked_state();
        let confirmed = confirmed_lock_from_account(epoch, ID, &state.encode(), 42).unwrap();
        assert_eq!(confirmed.epoch_account(), epoch);
        assert_eq!(confirmed.lock_digest(), state.lock_digest);
        assert_eq!(confirmed.member_root(), state.member_root);
        assert_eq!(confirmed.confirmation_slot(), 42);

        assert!(
            confirmed_lock_from_account(epoch, Pubkey::new_unique(), &state.encode(), 42).is_err()
        );

        let mut invalid = state;
        invalid.lock_digest[0] ^= 1;
        assert!(confirmed_lock_from_account(epoch, ID, &invalid.encode(), 42).is_err());

        let mut invalid = state;
        invalid.member_count = 3;
        assert!(confirmed_lock_from_account(epoch, ID, &invalid.encode(), 42).is_err());

        let mut invalid = state;
        invalid.terminal_state = EpochTerminalState::Open;
        assert!(confirmed_lock_from_account(epoch, ID, &invalid.encode(), 42).is_err());

        assert!(confirmed_lock_from_account(epoch, ID, &state.encode()[..383], 42).is_err());
    }

    #[test]
    fn lock_wire_rejects_coordinator_counts_before_allocating() {
        let configuration = EpochConfigurationV1 {
            pool: Pubkey::new_unique(),
            epoch_id: [1; 32],
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
        };
        let dealer = crate::EpochDealer::random().unwrap();
        let encoded_keys = dealer.public_keys().encode_wire().unwrap();
        let mut bytes = Vec::new();
        bytes.push(1);
        bytes.extend_from_slice(Pubkey::new_unique().as_ref());
        bytes.extend_from_slice(&configuration.encode());
        bytes.extend_from_slice(&(encoded_keys.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&encoded_keys);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.resize(bytes.len() + 264, 0);
        assert_eq!(
            LockPackageV1::decode_wire(&bytes),
            Err(LockValidationError::MemberLimitExceeded)
        );
    }
}
