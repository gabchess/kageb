use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use kageb::{
    finalize_settlement, net_batch, AccountError, AccountJournal, BatchConfig, FundedOrder,
    JournalError, PoolBalance, ReservationJournal, ReservationRecord, ReservationState, Side,
};
use tempfile::tempdir;

fn participant(value: u8) -> [u8; 32] {
    [value; 32]
}

fn settled_batch() -> (BTreeMap<[u8; 32], PoolBalance>, kageb::BatchResult) {
    let before = BTreeMap::from([
        (participant(1), PoolBalance::new(1, 100)),
        (participant(2), PoolBalance::new(1, 100)),
    ]);
    let orders = [
        FundedOrder::new(participant(1), Side::Buy, 100).unwrap(),
        FundedOrder::new(participant(2), Side::Sell, 100).unwrap(),
    ];
    let result = net_batch(BatchConfig::new(1, 100).unwrap(), &before, &orders).unwrap();
    (before, result)
}

#[test]
fn accounts_persist_and_only_the_local_trading_key_can_read_a_settled_result() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("accounts.bin");
    let trader_one = SigningKey::from_bytes(&[11; 32]);
    let trader_two = SigningKey::from_bytes(&[12; 32]);
    let outsider = SigningKey::from_bytes(&[13; 32]);
    let (before, result) = settled_batch();
    let epoch_id = [91; 32];

    let mut accounts = AccountJournal::open(&path).unwrap();
    let reservation_path = directory.path().join("reservations.bin");
    let mut reservations = ReservationJournal::open(&reservation_path).unwrap();
    accounts
        .register(
            participant(1),
            trader_one.verifying_key(),
            before[&participant(1)],
        )
        .unwrap();
    for (id, nonce) in [(participant(1), [11; 32]), (participant(2), [12; 32])] {
        reservations
            .reserve(
                ReservationRecord::new(nonce, epoch_id, id, 1, 100).unwrap(),
                before[&id],
            )
            .unwrap();
    }
    accounts
        .register(
            participant(2),
            trader_two.verifying_key(),
            before[&participant(2)],
        )
        .unwrap();
    assert_eq!(
        accounts.query_result(participant(1), trader_one.verifying_key()),
        Err(AccountError::ResultPending)
    );
    assert_eq!(
        accounts.query_result(participant(1), outsider.verifying_key()),
        Err(AccountError::Unauthorized)
    );

    finalize_settlement(
        &mut accounts,
        &mut reservations,
        epoch_id,
        &result,
        &[[11; 32], [12; 32]],
    )
    .unwrap();
    drop(accounts);
    drop(reservations);
    let mut restarted = AccountJournal::open(&path).unwrap();
    let mut restarted_reservations = ReservationJournal::open(&reservation_path).unwrap();
    let result_one = restarted
        .query_result(participant(1), trader_one.verifying_key())
        .unwrap();
    assert_eq!(result_one.epoch_id(), epoch_id);
    assert_eq!(result_one.balance(), PoolBalance::new(2, 0));
    let result_two = restarted
        .query_result(participant(2), trader_two.verifying_key())
        .unwrap();
    assert_eq!(result_two.balance(), PoolBalance::new(0, 200));

    finalize_settlement(
        &mut restarted,
        &mut restarted_reservations,
        epoch_id,
        &result,
        &[[11; 32], [12; 32]],
    )
    .unwrap();
    let subset_before = BTreeMap::from([(participant(1), PoolBalance::new(1, 100))]);
    let subset_result = net_batch(
        BatchConfig::new(1, 100).unwrap(),
        &subset_before,
        &[FundedOrder::new(participant(1), Side::Buy, 100).unwrap()],
    )
    .unwrap();
    assert_eq!(
        finalize_settlement(
            &mut restarted,
            &mut restarted_reservations,
            epoch_id,
            &subset_result,
            &[[11; 32]],
        ),
        Err(AccountError::StaleSettlement)
    );
    let before = BTreeMap::from([
        (participant(1), PoolBalance::new(1, 100)),
        (participant(2), PoolBalance::new(1, 100)),
    ]);
    let conflicting = net_batch(
        BatchConfig::new(1, 100).unwrap(),
        &before,
        &[
            FundedOrder::new(participant(1), Side::Sell, 100).unwrap(),
            FundedOrder::new(participant(2), Side::Buy, 100).unwrap(),
        ],
    )
    .unwrap();
    assert_eq!(
        finalize_settlement(
            &mut restarted,
            &mut restarted_reservations,
            [92; 32],
            &conflicting,
            &[[11; 32], [12; 32]],
        ),
        Err(AccountError::Reservation(JournalError::InvalidTransition))
    );
    assert_eq!(
        finalize_settlement(
            &mut restarted,
            &mut restarted_reservations,
            epoch_id,
            &conflicting,
            &[[11; 32], [12; 32]],
        ),
        Err(AccountError::StaleSettlement)
    );
}

#[test]
fn settlement_finishes_reservations_without_changing_unrelated_balances() {
    let directory = tempdir().unwrap();
    let mut accounts = AccountJournal::open(directory.path().join("accounts.bin")).unwrap();
    let mut reservations =
        ReservationJournal::open(directory.path().join("reservations.bin")).unwrap();
    let trader_one = SigningKey::from_bytes(&[11; 32]);
    let trader_two = SigningKey::from_bytes(&[12; 32]);
    let (before, result) = settled_batch();
    for (id, trader, nonce) in [
        (participant(1), &trader_one, [21; 32]),
        (participant(2), &trader_two, [22; 32]),
    ] {
        accounts
            .register(id, trader.verifying_key(), before[&id])
            .unwrap();
        reservations
            .reserve(
                ReservationRecord::new(nonce, [91; 32], id, 1, 100).unwrap(),
                before[&id],
            )
            .unwrap();
    }

    finalize_settlement(
        &mut accounts,
        &mut reservations,
        [91; 32],
        &result,
        &[[21; 32], [22; 32]],
    )
    .unwrap();
    finalize_settlement(
        &mut accounts,
        &mut reservations,
        [91; 32],
        &result,
        &[[21; 32], [22; 32]],
    )
    .unwrap();
    assert_eq!(reservations.state([21; 32]), Some(ReservationState::Used));
    assert_eq!(reservations.state([22; 32]), Some(ReservationState::Used));
    assert_eq!(
        finalize_settlement(
            &mut accounts,
            &mut reservations,
            [92; 32],
            &result,
            &[[21; 32], [22; 32]],
        ),
        Err(AccountError::Reservation(JournalError::InvalidTransition))
    );
    assert_eq!(
        accounts
            .query_result(participant(1), trader_one.verifying_key())
            .unwrap()
            .epoch_id(),
        [91; 32]
    );

    assert_eq!(
        accounts
            .query_result(participant(2), trader_two.verifying_key())
            .unwrap()
            .balance(),
        PoolBalance::new(0, 200)
    );
}

#[test]
fn released_reservation_rejects_before_any_result_is_committed() {
    let directory = tempdir().unwrap();
    let mut accounts = AccountJournal::open(directory.path().join("accounts.bin")).unwrap();
    let mut reservations =
        ReservationJournal::open(directory.path().join("reservations.bin")).unwrap();
    let trader_one = SigningKey::from_bytes(&[11; 32]);
    let trader_two = SigningKey::from_bytes(&[12; 32]);
    let (before, result) = settled_batch();
    for (id, trader, nonce) in [
        (participant(1), &trader_one, [41; 32]),
        (participant(2), &trader_two, [42; 32]),
    ] {
        accounts
            .register(id, trader.verifying_key(), before[&id])
            .unwrap();
        reservations
            .reserve(
                ReservationRecord::new(nonce, [91; 32], id, 1, 100).unwrap(),
                before[&id],
            )
            .unwrap();
    }
    reservations.release([42; 32]).unwrap();

    assert_eq!(
        finalize_settlement(
            &mut accounts,
            &mut reservations,
            [91; 32],
            &result,
            &[[41; 32], [42; 32]],
        ),
        Err(AccountError::Reservation(JournalError::InvalidTransition))
    );
    assert_eq!(
        accounts.query_result(participant(1), trader_one.verifying_key()),
        Err(AccountError::ResultPending)
    );
    assert_eq!(
        accounts.query_result(participant(2), trader_two.verifying_key()),
        Err(AccountError::ResultPending)
    );
    assert_eq!(
        reservations.state([41; 32]),
        Some(ReservationState::Reserved)
    );
}

#[test]
fn prematurely_used_or_unknown_reservations_do_not_commit_a_result() {
    let directory = tempdir().unwrap();
    let mut accounts = AccountJournal::open(directory.path().join("accounts.bin")).unwrap();
    let mut reservations =
        ReservationJournal::open(directory.path().join("reservations.bin")).unwrap();
    let trader_one = SigningKey::from_bytes(&[11; 32]);
    let trader_two = SigningKey::from_bytes(&[12; 32]);
    let (before, result) = settled_batch();
    for (id, trader, nonce) in [
        (participant(1), &trader_one, [51; 32]),
        (participant(2), &trader_two, [52; 32]),
    ] {
        accounts
            .register(id, trader.verifying_key(), before[&id])
            .unwrap();
        reservations
            .reserve(
                ReservationRecord::new(nonce, [91; 32], id, 1, 100).unwrap(),
                before[&id],
            )
            .unwrap();
    }
    reservations.mark_used([51; 32]).unwrap();

    assert_eq!(
        finalize_settlement(
            &mut accounts,
            &mut reservations,
            [91; 32],
            &result,
            &[[51; 32], [52; 32]],
        ),
        Err(AccountError::StaleSettlement)
    );
    assert_eq!(
        finalize_settlement(
            &mut accounts,
            &mut reservations,
            [91; 32],
            &result,
            &[[51; 32], [99; 32]],
        ),
        Err(AccountError::Reservation(JournalError::UnknownNonce))
    );
    assert_eq!(
        accounts.query_result(participant(1), trader_one.verifying_key()),
        Err(AccountError::ResultPending)
    );
    assert_eq!(
        reservations.state([52; 32]),
        Some(ReservationState::Reserved)
    );
}

#[test]
fn account_journal_rejects_duplicates_missing_accounts_and_corruption() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("accounts.bin");
    let trader = SigningKey::from_bytes(&[11; 32]);
    let mut accounts = AccountJournal::open(&path).unwrap();
    accounts
        .register(
            participant(1),
            trader.verifying_key(),
            PoolBalance::new(1, 100),
        )
        .unwrap();
    assert_eq!(
        accounts.register(
            participant(1),
            trader.verifying_key(),
            PoolBalance::new(1, 100),
        ),
        Err(AccountError::DuplicateAccount)
    );
    let (_, result) = settled_batch();
    let mut reservations =
        ReservationJournal::open(directory.path().join("reservations.bin")).unwrap();
    for (id, nonce) in [(participant(1), [61; 32]), (participant(2), [62; 32])] {
        reservations
            .reserve(
                ReservationRecord::new(nonce, [91; 32], id, 1, 100).unwrap(),
                PoolBalance::new(1, 100),
            )
            .unwrap();
    }
    assert_eq!(
        finalize_settlement(
            &mut accounts,
            &mut reservations,
            [91; 32],
            &result,
            &[[61; 32], [62; 32]],
        ),
        Err(AccountError::UnknownAccount)
    );

    drop(accounts);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(AccountJournal::open(&path), Err(AccountError::Corrupt));
}

#[test]
fn settlement_rejects_reservations_that_do_not_match_the_result_members() {
    let directory = tempdir().unwrap();
    let mut accounts = AccountJournal::open(directory.path().join("accounts.bin")).unwrap();
    let mut reservations =
        ReservationJournal::open(directory.path().join("reservations.bin")).unwrap();
    let trader_one = SigningKey::from_bytes(&[11; 32]);
    let trader_two = SigningKey::from_bytes(&[12; 32]);
    let (before, result) = settled_batch();
    accounts
        .register(
            participant(1),
            trader_one.verifying_key(),
            before[&participant(1)],
        )
        .unwrap();
    accounts
        .register(
            participant(2),
            trader_two.verifying_key(),
            before[&participant(2)],
        )
        .unwrap();
    for nonce in [[31; 32], [32; 32]] {
        reservations
            .reserve(
                ReservationRecord::new(nonce, [91; 32], participant(1), 1, 100).unwrap(),
                PoolBalance::new(2, 200),
            )
            .unwrap();
    }

    assert_eq!(
        finalize_settlement(
            &mut accounts,
            &mut reservations,
            [91; 32],
            &result,
            &[[31; 32], [32; 32]],
        ),
        Err(AccountError::Reservation(JournalError::InvalidTransition))
    );
    assert_eq!(
        reservations.state([31; 32]),
        Some(ReservationState::Reserved)
    );
    assert_eq!(
        reservations.state([32; 32]),
        Some(ReservationState::Reserved)
    );
    assert_eq!(
        accounts.query_result(participant(1), trader_one.verifying_key()),
        Err(AccountError::ResultPending)
    );
}
