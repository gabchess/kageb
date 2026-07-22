use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use sha2::{Digest, Sha256};

use crate::PoolBalance;

const HEADER: [u8; 8] = *b"KGBRSV1\0";
const RECORD_LEN: usize = 81;
const CHECKSUM_LEN: usize = 32;
const LOCK_ATTEMPTS: usize = 100;

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
        let _lock = FileLock::acquire(&path)?;
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
        let _lock = FileLock::acquire(&self.path)?;
        let mut current = load_records(&self.path)?;
        operation(&mut current)?;
        persist_records(&self.path, &current)?;
        self.records = current;
        Ok(())
    }
}

struct FileLock {
    path: PathBuf,
    _file: File,
}

impl FileLock {
    fn acquire(journal_path: &Path) -> Result<Self, JournalError> {
        let path = journal_path.with_extension("lock");
        for _ in 0..LOCK_ATTEMPTS {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            match options.open(&path) {
                Ok(file) => return Ok(Self { path, _file: file }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(JournalError::Busy)
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
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
