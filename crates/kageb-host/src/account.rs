use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::{
    admission::{sync_parent, AdvisoryLock},
    BatchResult, ConfirmedTerminalEpoch, JournalError, PoolBalance, ReservationJournal,
};

const HEADER: [u8; 8] = *b"KGBACC2\0";
const RECORD_LEN: usize = 112;
const CHECKSUM_LEN: usize = 32;
type AccountState = (
    BTreeMap<[u8; 32], AccountRecord>,
    BTreeMap<[u8; 32], [u8; 32]>,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AccountRecord {
    participant_id: [u8; 32],
    trading_key: [u8; 32],
    balance: PoolBalance,
    last_epoch: [u8; 32],
}

impl AccountRecord {
    fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        if bytes.len() != RECORD_LEN {
            return Err(AccountError::Corrupt);
        }
        let participant_id = bytes[0..32].try_into().map_err(|_| AccountError::Corrupt)?;
        let trading_key = bytes[32..64]
            .try_into()
            .map_err(|_| AccountError::Corrupt)?;
        VerifyingKey::from_bytes(&trading_key).map_err(|_| AccountError::Corrupt)?;
        let base_atoms = u64::from_le_bytes(
            bytes[64..72]
                .try_into()
                .map_err(|_| AccountError::Corrupt)?,
        );
        let quote_atoms = u64::from_le_bytes(
            bytes[72..80]
                .try_into()
                .map_err(|_| AccountError::Corrupt)?,
        );
        let last_epoch = bytes[80..112]
            .try_into()
            .map_err(|_| AccountError::Corrupt)?;
        if participant_id == [0; 32] || (base_atoms == 0 && quote_atoms == 0) {
            return Err(AccountError::Corrupt);
        }
        Ok(Self {
            participant_id,
            trading_key,
            balance: PoolBalance::new(base_atoms, quote_atoms),
            last_epoch,
        })
    }

    fn encode_into(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.participant_id);
        bytes.extend_from_slice(&self.trading_key);
        bytes.extend_from_slice(&self.balance.base_atoms.to_le_bytes());
        bytes.extend_from_slice(&self.balance.quote_atoms.to_le_bytes());
        bytes.extend_from_slice(&self.last_epoch);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountResultV1 {
    epoch_id: [u8; 32],
    balance: PoolBalance,
}

impl AccountResultV1 {
    #[must_use]
    pub const fn epoch_id(self) -> [u8; 32] {
        self.epoch_id
    }

    #[must_use]
    pub const fn balance(self) -> PoolBalance {
        self.balance
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountError {
    Io(io::ErrorKind),
    Busy,
    Corrupt,
    InvalidAccount,
    DuplicateAccount,
    UnknownAccount,
    Unauthorized,
    ResultPending,
    StaleSettlement,
    ArithmeticOverflow,
    Reservation(JournalError),
}

impl From<io::Error> for AccountError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AccountJournal {
    path: PathBuf,
    records: BTreeMap<[u8; 32], AccountRecord>,
    applied_epochs: BTreeMap<[u8; 32], [u8; 32]>,
}

impl AccountJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AccountError> {
        let path = path.as_ref().to_path_buf();
        let _lock = acquire_lock(&path)?;
        if !path.exists() {
            persist(&path, &BTreeMap::new(), &BTreeMap::new())?;
        }
        let (records, applied_epochs) = load(&path)?;
        Ok(Self {
            path,
            records,
            applied_epochs,
        })
    }

    pub fn register(
        &mut self,
        participant_id: [u8; 32],
        trading_key: VerifyingKey,
        balance: PoolBalance,
    ) -> Result<(), AccountError> {
        if participant_id == [0; 32] || (balance.base_atoms == 0 && balance.quote_atoms == 0) {
            return Err(AccountError::InvalidAccount);
        }
        self.mutate(|records, _| {
            if records.contains_key(&participant_id) {
                return Err(AccountError::DuplicateAccount);
            }
            records.insert(
                participant_id,
                AccountRecord {
                    participant_id,
                    trading_key: trading_key.to_bytes(),
                    balance,
                    last_epoch: [0; 32],
                },
            );
            Ok(())
        })
    }

    pub fn query_result(
        &mut self,
        participant_id: [u8; 32],
        trading_key: VerifyingKey,
    ) -> Result<AccountResultV1, AccountError> {
        self.reload()?;
        let record = self
            .records
            .get(&participant_id)
            .ok_or(AccountError::UnknownAccount)?;
        if record.trading_key != trading_key.to_bytes() {
            return Err(AccountError::Unauthorized);
        }
        if record.last_epoch == [0; 32] {
            return Err(AccountError::ResultPending);
        }
        Ok(AccountResultV1 {
            epoch_id: record.last_epoch,
            balance: record.balance,
        })
    }

    fn apply_settlement(
        &mut self,
        epoch_id: [u8; 32],
        result: &BatchResult,
    ) -> Result<(), AccountError> {
        if epoch_id == [0; 32] {
            return Err(AccountError::StaleSettlement);
        }
        self.mutate(|records, applied_epochs| {
            for participant_id in result.balances().keys() {
                if !records.contains_key(participant_id) {
                    return Err(AccountError::UnknownAccount);
                }
            }
            let result_digest = settlement_digest(result);
            if let Some(applied_digest) = applied_epochs.get(&epoch_id) {
                let matches = *applied_digest == result_digest
                    && settlement_matches(records, epoch_id, result);
                return if matches {
                    Ok(())
                } else {
                    Err(AccountError::StaleSettlement)
                };
            }
            if result
                .before_balances()
                .iter()
                .any(|(participant_id, balance)| {
                    records
                        .get(participant_id)
                        .is_none_or(|record| record.balance != *balance)
                })
            {
                return Err(AccountError::StaleSettlement);
            }
            for (participant_id, balance) in result.balances() {
                let record = records
                    .get_mut(participant_id)
                    .ok_or(AccountError::UnknownAccount)?;
                record.balance = *balance;
                record.last_epoch = epoch_id;
            }
            applied_epochs.insert(epoch_id, result_digest);
            Ok(())
        })
    }

    fn settlement_matches(
        &mut self,
        epoch_id: [u8; 32],
        result: &BatchResult,
    ) -> Result<bool, AccountError> {
        self.reload()?;
        Ok(
            self.applied_epochs.get(&epoch_id) == Some(&settlement_digest(result))
                && settlement_matches(&self.records, epoch_id, result),
        )
    }

    fn has_applied_epoch(&mut self, epoch_id: [u8; 32]) -> Result<bool, AccountError> {
        self.reload()?;
        Ok(self.applied_epochs.contains_key(&epoch_id))
    }

    fn reload(&mut self) -> Result<(), AccountError> {
        let _lock = acquire_lock(&self.path)?;
        let (records, applied_epochs) = load(&self.path)?;
        self.records = records;
        self.applied_epochs = applied_epochs;
        Ok(())
    }

    fn mutate(
        &mut self,
        operation: impl FnOnce(
            &mut BTreeMap<[u8; 32], AccountRecord>,
            &mut BTreeMap<[u8; 32], [u8; 32]>,
        ) -> Result<(), AccountError>,
    ) -> Result<(), AccountError> {
        let _lock = acquire_lock(&self.path)?;
        let (mut records, mut applied_epochs) = load(&self.path)?;
        operation(&mut records, &mut applied_epochs)?;
        persist(&self.path, &records, &applied_epochs)?;
        self.records = records;
        self.applied_epochs = applied_epochs;
        Ok(())
    }
}

pub fn finalize_settlement(
    accounts: &mut AccountJournal,
    reservations: &mut ReservationJournal,
    epoch_id: [u8; 32],
    result: &BatchResult,
    reservation_nonces: &[[u8; 32]],
) -> Result<(), AccountError> {
    let result_members: BTreeSet<_> = result.balances().keys().copied().collect();
    reservations
        .finalize_epoch(epoch_id, reservation_nonces, &result_members, |had_used| {
            if had_used && !accounts.settlement_matches(epoch_id, result)? {
                return Err(AccountError::StaleSettlement);
            }
            accounts.apply_settlement(epoch_id, result)
        })
        .map_err(AccountError::Reservation)?
}

/// Releases one reservation batch only with a confirmed capability for the same aborted or
/// expired onchain epoch.
pub fn release_reservations(
    accounts: &mut AccountJournal,
    reservations: &mut ReservationJournal,
    terminal_epoch: &ConfirmedTerminalEpoch,
    reservation_nonces: &[[u8; 32]],
) -> Result<(), AccountError> {
    let epoch_id = terminal_epoch.epoch_id();
    reservations
        .release_epoch_checked(epoch_id, reservation_nonces, || {
            if accounts.has_applied_epoch(epoch_id)? {
                Err(AccountError::StaleSettlement)
            } else {
                Ok(())
            }
        })
        .map_err(AccountError::Reservation)?
}

fn acquire_lock(path: &Path) -> Result<AdvisoryLock, AccountError> {
    AdvisoryLock::acquire(&path.with_extension("account-lock")).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            AccountError::Busy
        } else {
            error.into()
        }
    })
}

fn settlement_matches(
    records: &BTreeMap<[u8; 32], AccountRecord>,
    epoch_id: [u8; 32],
    result: &BatchResult,
) -> bool {
    result.balances().iter().all(|(participant_id, balance)| {
        records
            .get(participant_id)
            .is_some_and(|record| record.last_epoch == epoch_id && record.balance == *balance)
    })
}

fn settlement_digest(result: &BatchResult) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"kageb-account-settlement-v1");
    for balances in [result.before_balances(), result.balances()] {
        digest.update(
            u32::try_from(balances.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for (participant_id, balance) in balances {
            digest.update(participant_id);
            digest.update(balance.base_atoms.to_le_bytes());
            digest.update(balance.quote_atoms.to_le_bytes());
        }
    }
    digest.finalize().into()
}

fn load(path: &Path) -> Result<AccountState, AccountError> {
    let bytes = fs::read(path)?;
    let minimum = HEADER.len() + 8 + CHECKSUM_LEN;
    if bytes.len() < minimum || bytes[..HEADER.len()] != HEADER {
        return Err(AccountError::Corrupt);
    }
    let payload_len = bytes.len() - CHECKSUM_LEN;
    if Sha256::digest(&bytes[..payload_len]).as_slice() != &bytes[payload_len..] {
        return Err(AccountError::Corrupt);
    }
    let account_count = u32::from_le_bytes(
        bytes[HEADER.len()..HEADER.len() + 4]
            .try_into()
            .map_err(|_| AccountError::Corrupt)?,
    ) as usize;
    let epoch_count = u32::from_le_bytes(
        bytes[HEADER.len() + 4..HEADER.len() + 8]
            .try_into()
            .map_err(|_| AccountError::Corrupt)?,
    ) as usize;
    let expected_len = HEADER
        .len()
        .checked_add(8)
        .and_then(|length| length.checked_add(account_count.checked_mul(RECORD_LEN)?))
        .and_then(|length| length.checked_add(epoch_count.checked_mul(64)?))
        .and_then(|length| length.checked_add(CHECKSUM_LEN))
        .ok_or(AccountError::Corrupt)?;
    if bytes.len() != expected_len {
        return Err(AccountError::Corrupt);
    }

    let mut records = BTreeMap::new();
    let mut offset = HEADER.len() + 8;
    for _ in 0..account_count {
        let record = AccountRecord::decode(&bytes[offset..offset + RECORD_LEN])?;
        offset += RECORD_LEN;
        if records.insert(record.participant_id, record).is_some() {
            return Err(AccountError::Corrupt);
        }
    }
    let mut applied_epochs = BTreeMap::new();
    for _ in 0..epoch_count {
        let epoch = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| AccountError::Corrupt)?;
        offset += 32;
        let result_digest = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| AccountError::Corrupt)?;
        offset += 32;
        if epoch == [0; 32]
            || result_digest == [0; 32]
            || applied_epochs.insert(epoch, result_digest).is_some()
        {
            return Err(AccountError::Corrupt);
        }
    }
    Ok((records, applied_epochs))
}

fn persist(
    path: &Path,
    records: &BTreeMap<[u8; 32], AccountRecord>,
    applied_epochs: &BTreeMap<[u8; 32], [u8; 32]>,
) -> Result<(), AccountError> {
    let account_count =
        u32::try_from(records.len()).map_err(|_| AccountError::ArithmeticOverflow)?;
    let epoch_count =
        u32::try_from(applied_epochs.len()).map_err(|_| AccountError::ArithmeticOverflow)?;
    let mut bytes = Vec::with_capacity(
        HEADER.len() + 8 + records.len() * RECORD_LEN + applied_epochs.len() * 64 + CHECKSUM_LEN,
    );
    bytes.extend_from_slice(&HEADER);
    bytes.extend_from_slice(&account_count.to_le_bytes());
    bytes.extend_from_slice(&epoch_count.to_le_bytes());
    for record in records.values() {
        record.encode_into(&mut bytes);
    }
    for (epoch, result_digest) in applied_epochs {
        bytes.extend_from_slice(epoch);
        bytes.extend_from_slice(result_digest);
    }
    bytes.extend_from_slice(&Sha256::digest(&bytes));

    let temporary = path.with_extension(format!("account-tmp.{}", std::process::id()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{net_batch, BatchConfig, FundedOrder, ReservationRecord, Side};
    use ed25519_dalek::SigningKey;
    use kageb_program::state::EpochTerminalState;
    use solana_program::pubkey::Pubkey;
    use tempfile::tempdir;

    fn terminal_epoch(epoch_id: [u8; 32]) -> ConfirmedTerminalEpoch {
        ConfirmedTerminalEpoch {
            epoch_account: Pubkey::new_unique(),
            epoch_id,
            terminal_state: EpochTerminalState::Aborted,
            confirmation_slot: 42,
        }
    }

    #[test]
    fn confirmed_terminal_epoch_releases_only_its_own_batch_and_is_idempotent() {
        let directory = tempdir().unwrap();
        let mut accounts = AccountJournal::open(directory.path().join("accounts.bin")).unwrap();
        let mut reservations =
            ReservationJournal::open(directory.path().join("reservations.bin")).unwrap();
        let epoch_id = [92; 32];
        let nonce = [24; 32];
        reservations
            .reserve(
                ReservationRecord::new(nonce, epoch_id, [2; 32], 1, 100).unwrap(),
                PoolBalance::new(1, 100),
            )
            .unwrap();

        assert_eq!(
            release_reservations(
                &mut accounts,
                &mut reservations,
                &terminal_epoch([93; 32]),
                &[nonce],
            ),
            Err(AccountError::Reservation(JournalError::InvalidTransition))
        );
        assert_eq!(
            reservations.state(nonce),
            Some(crate::ReservationState::Reserved)
        );

        let terminal = terminal_epoch(epoch_id);
        release_reservations(&mut accounts, &mut reservations, &terminal, &[nonce]).unwrap();
        release_reservations(&mut accounts, &mut reservations, &terminal, &[nonce]).unwrap();
        assert_eq!(
            reservations.state(nonce),
            Some(crate::ReservationState::Released)
        );
    }

    #[test]
    fn release_checks_the_commit_marker_while_holding_the_reservation_lock() {
        let directory = tempdir().unwrap();
        let account_path = directory.path().join("accounts.bin");
        let reservation_path = directory.path().join("reservations.bin");
        let epoch_id = [91; 32];
        let members = [[1; 32], [2; 32]];
        let nonces = [[71; 32], [72; 32]];
        let before = BTreeMap::from([
            (members[0], PoolBalance::new(1, 100)),
            (members[1], PoolBalance::new(1, 100)),
        ]);
        let result = net_batch(
            BatchConfig::new(1, 100).unwrap(),
            &before,
            &[
                FundedOrder::new(members[0], Side::Buy, 100).unwrap(),
                FundedOrder::new(members[1], Side::Sell, 100).unwrap(),
            ],
        )
        .unwrap();
        let mut accounts = AccountJournal::open(&account_path).unwrap();
        let mut reservations = ReservationJournal::open(&reservation_path).unwrap();
        for (index, (member, nonce)) in members.into_iter().zip(nonces).enumerate() {
            accounts
                .register(
                    member,
                    SigningKey::from_bytes(&[index as u8 + 11; 32]).verifying_key(),
                    before[&member],
                )
                .unwrap();
            reservations
                .reserve(
                    ReservationRecord::new(nonce, epoch_id, member, 1, 100).unwrap(),
                    before[&member],
                )
                .unwrap();
        }

        // Fault injection: the account commit landed, then the process stopped before
        // the reservation journal could record consumption.
        accounts.apply_settlement(epoch_id, &result).unwrap();
        let release = reservations
            .release_epoch_checked(epoch_id, &nonces, || {
                assert!(matches!(
                    ReservationJournal::open(&reservation_path),
                    Err(JournalError::Busy)
                ));
                if accounts.has_applied_epoch(epoch_id)? {
                    Err(AccountError::StaleSettlement)
                } else {
                    Ok(())
                }
            })
            .unwrap();

        assert_eq!(release, Err(AccountError::StaleSettlement));
        assert_eq!(
            reservations.state(nonces[0]),
            Some(crate::ReservationState::Reserved)
        );
        assert_eq!(
            reservations.state(nonces[1]),
            Some(crate::ReservationState::Reserved)
        );
        finalize_settlement(&mut accounts, &mut reservations, epoch_id, &result, &nonces).unwrap();
        assert_eq!(
            reservations.state(nonces[0]),
            Some(crate::ReservationState::Used)
        );
        assert_eq!(
            reservations.state(nonces[1]),
            Some(crate::ReservationState::Used)
        );
    }
}
