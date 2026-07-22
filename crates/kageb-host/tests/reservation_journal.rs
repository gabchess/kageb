use std::{fs, sync::Arc, thread};

use ed25519_dalek::SigningKey;
use kageb::{
    JournalError, PoolBalance, ReservationJournal, ReservationRecord, ReservationState,
    SubmissionV1, SuspensionError, SuspensionRegistry,
};
use tempfile::tempdir;

fn record(nonce: u8) -> ReservationRecord {
    ReservationRecord::new([nonce; 32], [7; 32], 2, 100).expect("funded reservation")
}

#[test]
fn reservation_requires_both_sides_funded() {
    assert_eq!(
        ReservationRecord::new([1; 32], [7; 32], 0, 100),
        Err(JournalError::InvalidAmount)
    );
    assert_eq!(
        ReservationRecord::new([1; 32], [7; 32], 2, 0),
        Err(JournalError::InvalidAmount)
    );
}

#[test]
fn reservation_is_durable_before_success_and_cannot_replay() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("reservations.bin");
    let balance = PoolBalance::new(10, 1_000);

    let mut journal = ReservationJournal::open(&path).expect("create journal");
    journal.reserve(record(1), balance).expect("reserve");

    let mut restarted = ReservationJournal::open(&path).expect("restart journal");
    assert_eq!(restarted.state([1; 32]), Some(ReservationState::Reserved));
    assert_eq!(
        restarted.reserve(record(1), balance),
        Err(JournalError::DuplicateNonce)
    );

    restarted.mark_used([1; 32]).expect("consume reservation");
    assert_eq!(
        restarted.release([1; 32]),
        Err(JournalError::InvalidTransition)
    );
    assert_eq!(
        ReservationJournal::open(&path)
            .expect("second restart")
            .state([1; 32]),
        Some(ReservationState::Used)
    );
}

#[test]
fn stale_reservation_lock_inode_does_not_block_restart() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("reservations.bin");
    let mut journal = ReservationJournal::open(&path).expect("create journal");
    journal
        .reserve(record(1), PoolBalance::new(10, 1_000))
        .expect("reserve");
    fs::write(path.with_extension("lock"), b"stale process marker").expect("stale lock inode");

    let restarted = ReservationJournal::open(&path).expect("restart after stale lock inode");
    assert_eq!(restarted.state([1; 32]), Some(ReservationState::Reserved));
}

#[test]
fn durable_reservation_is_the_only_path_to_an_unsigned_submission() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("reservations.bin");
    let mut journal = ReservationJournal::open(&path).expect("create journal");

    let authorization = journal
        .reserve(record(1), PoolBalance::new(10, 1_000))
        .expect("durably reserve");
    assert_eq!(authorization.nonce(), [1; 32]);
    assert_eq!(authorization.participant_id(), [7; 32]);
    assert_eq!(
        ReservationJournal::open(&path)
            .expect("restart after capability returned")
            .state([1; 32]),
        Some(ReservationState::Reserved)
    );

    let submission = SubmissionV1::new(authorization, [9; 32]);
    assert_eq!(submission.ciphertext_hash(), [9; 32]);
}

#[test]
fn concurrent_duplicate_reservation_has_one_winner() {
    let directory = tempdir().expect("tempdir");
    let path = Arc::new(directory.path().join("reservations.bin"));
    ReservationJournal::open(path.as_ref()).expect("create journal");

    let handles: Vec<_> = (0..2)
        .map(|_| {
            let path = Arc::clone(&path);
            thread::spawn(move || {
                let mut journal = ReservationJournal::open(path.as_ref()).expect("open journal");
                journal.reserve(record(1), PoolBalance::new(10, 1_000))
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(JournalError::DuplicateNonce))
            .count(),
        1
    );
}

#[test]
fn concurrent_use_has_one_winner_and_terminal_states_cannot_cross() {
    let directory = tempdir().expect("tempdir");
    let path = Arc::new(directory.path().join("reservations.bin"));
    let mut journal = ReservationJournal::open(path.as_ref()).expect("create journal");
    journal
        .reserve(record(1), PoolBalance::new(10, 1_000))
        .expect("reserve for concurrent use");

    let handles: Vec<_> = (0..2)
        .map(|_| {
            let path = Arc::clone(&path);
            thread::spawn(move || {
                let mut journal = ReservationJournal::open(path.as_ref()).expect("open journal");
                journal.mark_used([1; 32])
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(JournalError::InvalidTransition))
            .count(),
        1
    );

    journal
        .reserve(record(2), PoolBalance::new(10, 1_000))
        .expect("reserve for release");
    journal.release([2; 32]).expect("release");
    assert_eq!(
        journal.mark_used([2; 32]),
        Err(JournalError::InvalidTransition)
    );
    assert_eq!(
        journal.release([1; 32]),
        Err(JournalError::InvalidTransition)
    );
}

#[test]
fn insufficient_or_overcommitted_balance_never_changes_disk_state() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("reservations.bin");
    let mut journal = ReservationJournal::open(&path).expect("create journal");

    assert_eq!(
        journal.reserve(record(1), PoolBalance::new(1, 99)),
        Err(JournalError::InsufficientBalance)
    );
    assert_eq!(journal.state([1; 32]), None);

    journal
        .reserve(record(1), PoolBalance::new(2, 100))
        .expect("first reservation");
    assert_eq!(
        journal.reserve(record(2), PoolBalance::new(2, 100)),
        Err(JournalError::InsufficientBalance)
    );
    assert_eq!(journal.state([2; 32]), None);

    journal.release([1; 32]).expect("release first");
    journal
        .reserve(record(2), PoolBalance::new(2, 100))
        .expect("released capacity can be reserved");
}

#[test]
fn truncated_or_tampered_journal_fails_closed() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("reservations.bin");
    let mut journal = ReservationJournal::open(&path).expect("create journal");
    journal
        .reserve(record(1), PoolBalance::new(10, 1_000))
        .expect("reserve");

    let mut bytes = fs::read(&path).expect("read journal");
    bytes.truncate(bytes.len() - 1);
    fs::write(&path, bytes).expect("truncate journal");

    assert!(matches!(
        ReservationJournal::open(&path),
        Err(JournalError::Corrupt)
    ));
}

#[test]
fn suspended_trading_key_survives_restart_and_blocks_later_authorization() {
    let directory = tempdir().expect("tempdir");
    let suspension_path = directory.path().join("suspensions.bin");
    let reservation_path = directory.path().join("reservations.bin");
    let trading = SigningKey::from_bytes(&[41; 32]);
    let operator = SigningKey::from_bytes(&[90; 32]);
    let trading_key = trading.verifying_key();

    let mut reservations = ReservationJournal::open(&reservation_path).expect("reservations");
    let first = reservations
        .reserve(record(1), PoolBalance::new(10, 1_000))
        .expect("first reservation");
    let mut suspensions = SuspensionRegistry::open(&suspension_path).expect("registry");
    assert!(suspensions
        .issue_authorization(first, [42; 32], trading_key, &operator, 1_000)
        .is_ok());

    suspensions
        .suspend(trading_key.to_bytes())
        .expect("suspend");
    let reopened = SuspensionRegistry::open(&suspension_path).expect("reopen registry");
    assert!(reopened.is_suspended(trading_key.to_bytes()));

    let later = reservations
        .reserve(record(2), PoolBalance::new(10, 1_000))
        .expect("later reservation");
    assert_eq!(
        reopened.issue_authorization(later, [43; 32], trading_key, &operator, 2_000),
        Err(SuspensionError::Suspended)
    );
}

#[test]
fn stale_suspension_lock_inode_does_not_block_restart() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("suspensions.bin");
    let mut registry = SuspensionRegistry::open(&path).expect("create registry");
    registry.suspend([41; 32]).expect("suspend");
    fs::write(
        path.with_extension("suspension-lock"),
        b"stale process marker",
    )
    .expect("stale lock inode");

    let restarted = SuspensionRegistry::open(&path).expect("restart after stale lock inode");
    assert!(restarted.is_suspended([41; 32]));
}

#[test]
fn tampered_suspension_registry_fails_closed() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("suspensions.bin");
    let mut registry = SuspensionRegistry::open(&path).expect("registry");
    registry.suspend([41; 32]).expect("suspend");

    let mut bytes = fs::read(&path).expect("read registry");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&path, bytes).expect("tamper registry");
    assert!(matches!(
        SuspensionRegistry::open(&path),
        Err(SuspensionError::Corrupt)
    ));
}
