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

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{crypto::FundedAuthorizationV1, PoolBalance};

const HEADER: [u8; 8] = *b"KGBRSV1\0";
const RECORD_LEN: usize = 81;
const CHECKSUM_LEN: usize = 32;
const LOCK_ATTEMPTS: usize = 100;
const SUSPENSION_HEADER: [u8; 8] = *b"KGBSUS1\0";
const TRADING_KEY_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReservationState {
    Reserved = 1,
    Used = 2,
    Released = 3,
}

impl TryFrom<u8> for ReservationState {
    type Error = JournalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Reserved),
            2 => Ok(Self::Used),
            3 => Ok(Self::Released),
            _ => Err(JournalError::Corrupt),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationRecord {
    nonce: [u8; 32],
    participant_id: [u8; 32],
    base_atoms: u64,
    quote_atoms: u64,
    state: ReservationState,
}

/// Capability returned only after its backing reservation is durable.
#[derive(Debug, PartialEq, Eq)]
pub struct UnsignedFundedAuthorizationV1 {
    nonce: [u8; 32],
    participant_id: [u8; 32],
    base_atoms: u64,
    quote_atoms: u64,
}

impl UnsignedFundedAuthorizationV1 {
    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    #[must_use]
    pub const fn participant_id(&self) -> [u8; 32] {
        self.participant_id
    }

    pub(crate) const fn into_parts(self) -> ([u8; 32], [u8; 32], u64, u64) {
        (
            self.nonce,
            self.participant_id,
            self.base_atoms,
            self.quote_atoms,
        )
    }
}

/// Unsigned envelope that Task 2 will authenticate and encrypt.
#[derive(Debug, PartialEq, Eq)]
pub struct SubmissionV1 {
    authorization: UnsignedFundedAuthorizationV1,
    ciphertext_hash: [u8; 32],
}

impl SubmissionV1 {
    #[must_use]
    pub const fn new(
        authorization: UnsignedFundedAuthorizationV1,
        ciphertext_hash: [u8; 32],
    ) -> Self {
        Self {
            authorization,
            ciphertext_hash,
        }
    }

    #[must_use]
    pub const fn ciphertext_hash(&self) -> [u8; 32] {
        self.ciphertext_hash
    }
}

impl ReservationRecord {
    pub const fn new(
        nonce: [u8; 32],
        participant_id: [u8; 32],
        base_atoms: u64,
        quote_atoms: u64,
    ) -> Result<Self, JournalError> {
        if base_atoms == 0 || quote_atoms == 0 {
            return Err(JournalError::InvalidAmount);
        }
        Ok(Self {
            nonce,
            participant_id,
            base_atoms,
            quote_atoms,
            state: ReservationState::Reserved,
        })
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != RECORD_LEN {
            return Err(JournalError::Corrupt);
        }
        let nonce = bytes[0..32].try_into().map_err(|_| JournalError::Corrupt)?;
        let participant_id = bytes[32..64]
            .try_into()
            .map_err(|_| JournalError::Corrupt)?;
        let base_atoms = u64::from_le_bytes(
            bytes[64..72]
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        );
        let quote_atoms = u64::from_le_bytes(
            bytes[72..80]
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        );
        let mut record = Self::new(nonce, participant_id, base_atoms, quote_atoms)
            .map_err(|_| JournalError::Corrupt)?;
        record.state = ReservationState::try_from(bytes[80])?;
        Ok(record)
    }

    fn encode_into(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.participant_id);
        bytes.extend_from_slice(&self.base_atoms.to_le_bytes());
        bytes.extend_from_slice(&self.quote_atoms.to_le_bytes());
        bytes.push(self.state as u8);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    Io(io::ErrorKind),
    Busy,
    Corrupt,
    DuplicateNonce,
    UnknownNonce,
    InvalidTransition,
    InvalidAmount,
    InsufficientBalance,
    ArithmeticOverflow,
}

impl From<io::Error> for JournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

#[derive(Debug)]
pub struct ReservationJournal {
    path: PathBuf,
    records: BTreeMap<[u8; 32], ReservationRecord>,
}

impl ReservationJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let _lock = acquire_journal_lock(&path)?;
        if !path.exists() {
            persist_records(&path, &BTreeMap::new())?;
        }
        let records = load_records(&path)?;
        Ok(Self { path, records })
    }

    pub fn reserve(
        &mut self,
        record: ReservationRecord,
        available: PoolBalance,
    ) -> Result<UnsignedFundedAuthorizationV1, JournalError> {
        self.mutate(|records| {
            if records.contains_key(&record.nonce) {
                return Err(JournalError::DuplicateNonce);
            }

            let (reserved_base, reserved_quote) = records
                .values()
                .filter(|existing| {
                    existing.participant_id == record.participant_id
                        && existing.state == ReservationState::Reserved
                })
                .try_fold((0_u64, 0_u64), |totals, existing| {
                    Some((
                        totals.0.checked_add(existing.base_atoms)?,
                        totals.1.checked_add(existing.quote_atoms)?,
                    ))
                })
                .ok_or(JournalError::ArithmeticOverflow)?;
            let required_base = reserved_base
                .checked_add(record.base_atoms)
                .ok_or(JournalError::ArithmeticOverflow)?;
            let required_quote = reserved_quote
                .checked_add(record.quote_atoms)
                .ok_or(JournalError::ArithmeticOverflow)?;
            if available.base_atoms < required_base || available.quote_atoms < required_quote {
                return Err(JournalError::InsufficientBalance);
            }

            records.insert(record.nonce, record);
            Ok(())
        })?;
        Ok(UnsignedFundedAuthorizationV1 {
            nonce: record.nonce,
            participant_id: record.participant_id,
            base_atoms: record.base_atoms,
            quote_atoms: record.quote_atoms,
        })
    }

    pub fn mark_used(&mut self, nonce: [u8; 32]) -> Result<(), JournalError> {
        self.transition(nonce, ReservationState::Used)
    }

    pub fn release(&mut self, nonce: [u8; 32]) -> Result<(), JournalError> {
        self.transition(nonce, ReservationState::Released)
    }

    #[must_use]
    pub fn state(&self, nonce: [u8; 32]) -> Option<ReservationState> {
        self.records.get(&nonce).map(|record| record.state)
    }

    fn transition(&mut self, nonce: [u8; 32], next: ReservationState) -> Result<(), JournalError> {
        self.mutate(|records| {
            let record = records.get_mut(&nonce).ok_or(JournalError::UnknownNonce)?;
            if record.state != ReservationState::Reserved {
                return Err(JournalError::InvalidTransition);
            }
            record.state = next;
            Ok(())
        })
    }

    fn mutate(
        &mut self,
        operation: impl FnOnce(&mut BTreeMap<[u8; 32], ReservationRecord>) -> Result<(), JournalError>,
    ) -> Result<(), JournalError> {
        let _lock = acquire_journal_lock(&self.path)?;
        let mut current = load_records(&self.path)?;
        operation(&mut current)?;
        persist_records(&self.path, &current)?;
        self.records = current;
        Ok(())
    }
}

fn acquire_journal_lock(journal_path: &Path) -> Result<AdvisoryLock, JournalError> {
    AdvisoryLock::acquire(&journal_path.with_extension("lock")).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            JournalError::Busy
        } else {
            error.into()
        }
    })
}

fn load_records(path: &Path) -> Result<BTreeMap<[u8; 32], ReservationRecord>, JournalError> {
    let bytes = fs::read(path)?;
    if bytes.len() < HEADER.len() + 4 + CHECKSUM_LEN || bytes[..HEADER.len()] != HEADER {
        return Err(JournalError::Corrupt);
    }
    let payload_len = bytes.len() - CHECKSUM_LEN;
    let expected_checksum = Sha256::digest(&bytes[..payload_len]);
    if expected_checksum.as_slice() != &bytes[payload_len..] {
        return Err(JournalError::Corrupt);
    }

    let count = u32::from_le_bytes(
        bytes[HEADER.len()..HEADER.len() + 4]
            .try_into()
            .map_err(|_| JournalError::Corrupt)?,
    ) as usize;
    let expected_len = HEADER
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(count.checked_mul(RECORD_LEN)?))
        .and_then(|length| length.checked_add(CHECKSUM_LEN))
        .ok_or(JournalError::Corrupt)?;
    if bytes.len() != expected_len {
        return Err(JournalError::Corrupt);
    }

    let mut records = BTreeMap::new();
    let mut offset = HEADER.len() + 4;
    for _ in 0..count {
        let record = ReservationRecord::decode(&bytes[offset..offset + RECORD_LEN])?;
        offset += RECORD_LEN;
        if records.insert(record.nonce, record).is_some() {
            return Err(JournalError::Corrupt);
        }
    }
    Ok(records)
}

fn persist_records(
    path: &Path,
    records: &BTreeMap<[u8; 32], ReservationRecord>,
) -> Result<(), JournalError> {
    let mut bytes =
        Vec::with_capacity(HEADER.len() + 4 + records.len() * RECORD_LEN + CHECKSUM_LEN);
    bytes.extend_from_slice(&HEADER);
    let count = u32::try_from(records.len()).map_err(|_| JournalError::ArithmeticOverflow)?;
    bytes.extend_from_slice(&count.to_le_bytes());
    for record in records.values() {
        record.encode_into(&mut bytes);
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
        sync_parent(path)?;
        Ok(())
    })() {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuspensionError {
    Io(io::ErrorKind),
    Busy,
    Corrupt,
    Suspended,
    Capacity,
}

impl From<io::Error> for SuspensionError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

/// Durable denylist consulted by the supported funded-authorization issuer.
#[derive(Debug)]
pub struct SuspensionRegistry {
    path: PathBuf,
    trading_keys: BTreeSet<[u8; TRADING_KEY_LEN]>,
}

impl SuspensionRegistry {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SuspensionError> {
        let path = path.as_ref().to_path_buf();
        let _lock = acquire_suspension_lock(&path)?;
        if !path.exists() {
            persist_suspensions(&path, &BTreeSet::new())?;
        }
        let trading_keys = load_suspensions(&path)?;
        Ok(Self { path, trading_keys })
    }

    pub fn suspend(&mut self, trading_key: [u8; TRADING_KEY_LEN]) -> Result<(), SuspensionError> {
        let _lock = acquire_suspension_lock(&self.path)?;
        let mut current = load_suspensions(&self.path)?;
        current.insert(trading_key);
        persist_suspensions(&self.path, &current)?;
        self.trading_keys = current;
        Ok(())
    }

    #[must_use]
    pub fn is_suspended(&self, trading_key: [u8; TRADING_KEY_LEN]) -> bool {
        self.trading_keys.contains(&trading_key)
    }

    pub fn issue_authorization(
        &self,
        reserved: UnsignedFundedAuthorizationV1,
        epoch_id: [u8; 32],
        trading_key: VerifyingKey,
        operator: &SigningKey,
        expiry_slot: u64,
    ) -> Result<FundedAuthorizationV1, SuspensionError> {
        let _lock = acquire_suspension_lock(&self.path)?;
        if load_suspensions(&self.path)?.contains(&trading_key.to_bytes()) {
            return Err(SuspensionError::Suspended);
        }
        Ok(FundedAuthorizationV1::sign(
            reserved,
            epoch_id,
            trading_key,
            operator,
            expiry_slot,
        ))
    }
}

fn acquire_suspension_lock(registry_path: &Path) -> Result<AdvisoryLock, SuspensionError> {
    AdvisoryLock::acquire(&registry_path.with_extension("suspension-lock")).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            SuspensionError::Busy
        } else {
            error.into()
        }
    })
}

struct AdvisoryLock {
    file: File,
}

impl AdvisoryLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(path)?;
        for _ in 0..LOCK_ATTEMPTS {
            match file.try_lock() {
                Ok(()) => return Ok(Self { file }),
                Err(error) => {
                    let error: io::Error = error.into();
                    if error.kind() != io::ErrorKind::WouldBlock {
                        return Err(error);
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "advisory lock remained busy",
        ))
    }
}

impl Drop for AdvisoryLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn load_suspensions(path: &Path) -> Result<BTreeSet<[u8; TRADING_KEY_LEN]>, SuspensionError> {
    let bytes = fs::read(path)?;
    let minimum = SUSPENSION_HEADER.len() + 4 + CHECKSUM_LEN;
    if bytes.len() < minimum || bytes[..SUSPENSION_HEADER.len()] != SUSPENSION_HEADER {
        return Err(SuspensionError::Corrupt);
    }
    let payload_len = bytes.len() - CHECKSUM_LEN;
    if Sha256::digest(&bytes[..payload_len]).as_slice() != &bytes[payload_len..] {
        return Err(SuspensionError::Corrupt);
    }
    let count = u32::from_le_bytes(
        bytes[SUSPENSION_HEADER.len()..SUSPENSION_HEADER.len() + 4]
            .try_into()
            .map_err(|_| SuspensionError::Corrupt)?,
    ) as usize;
    let expected_len = SUSPENSION_HEADER
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(count.checked_mul(TRADING_KEY_LEN)?))
        .and_then(|length| length.checked_add(CHECKSUM_LEN))
        .ok_or(SuspensionError::Corrupt)?;
    if bytes.len() != expected_len {
        return Err(SuspensionError::Corrupt);
    }
    let mut trading_keys = BTreeSet::new();
    for encoded in bytes[SUSPENSION_HEADER.len() + 4..payload_len].chunks_exact(TRADING_KEY_LEN) {
        let trading_key = encoded.try_into().map_err(|_| SuspensionError::Corrupt)?;
        if !trading_keys.insert(trading_key) {
            return Err(SuspensionError::Corrupt);
        }
    }
    Ok(trading_keys)
}

fn persist_suspensions(
    path: &Path,
    trading_keys: &BTreeSet<[u8; TRADING_KEY_LEN]>,
) -> Result<(), SuspensionError> {
    let count = u32::try_from(trading_keys.len()).map_err(|_| SuspensionError::Capacity)?;
    let mut bytes = Vec::with_capacity(
        SUSPENSION_HEADER.len() + 4 + trading_keys.len() * TRADING_KEY_LEN + CHECKSUM_LEN,
    );
    bytes.extend_from_slice(&SUSPENSION_HEADER);
    bytes.extend_from_slice(&count.to_le_bytes());
    for trading_key in trading_keys {
        bytes.extend_from_slice(trading_key);
    }
    bytes.extend_from_slice(&Sha256::digest(&bytes));

    let temporary = path.with_extension(format!("suspension-tmp.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    if let Err(error) = (|| -> io::Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_parent(path)?;
        Ok(())
    })() {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}
