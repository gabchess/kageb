use std::collections::BTreeMap;

use kageb::{
    net_batch, BatchConfig, FundedOrder, LedgerError, PoolBalance, Residual, Side, VaultDelta,
};

fn participant(value: u8) -> [u8; 32] {
    [value; 32]
}

fn funded_balances(ids: &[u8]) -> BTreeMap<[u8; 32], PoolBalance> {
    ids.iter()
        .map(|id| (participant(*id), PoolBalance::new(10, 1_000)))
        .collect()
}

fn config() -> BatchConfig {
    BatchConfig::new(2, 100).expect("valid config")
}

fn order(participant_id: [u8; 32], side: Side, limit_price: u64) -> FundedOrder {
    FundedOrder::new(participant_id, side, limit_price).expect("valid funded order")
}

#[test]
fn funded_order_rejects_an_invalid_limit_before_it_reaches_the_ledger() {
    assert_eq!(
        FundedOrder::new(participant(1), Side::Buy, 0),
        Err(LedgerError::InvalidLimit)
    );
}

#[test]
fn balanced_orders_match_internally_and_conserve_both_vaults() {
    let before = funded_balances(&[1, 2]);
    let orders = vec![
        order(participant(1), Side::Buy, 100),
        order(participant(2), Side::Sell, 100),
    ];

    let result = net_batch(config(), &before, &orders).expect("balanced batch");

    assert_eq!(result.residual(), Residual::None);
    assert_eq!(result.vault_delta(), VaultDelta::ZERO);
    assert_eq!(
        result.balance(participant(1)),
        Some(PoolBalance::new(12, 900))
    );
    assert_eq!(
        result.balance(participant(2)),
        Some(PoolBalance::new(8, 1_100))
    );
    assert!(result.conserves(&before));
}

#[test]
fn buy_heavy_orders_create_one_aggregate_vault_delta() {
    let before = funded_balances(&[1, 2, 3]);
    let orders = vec![
        order(participant(1), Side::Buy, 100),
        order(participant(2), Side::Buy, 100),
        order(participant(3), Side::Sell, 100),
    ];

    let result = net_batch(config(), &before, &orders).expect("buy-heavy batch");

    assert_eq!(result.residual(), Residual::Buy { lots: 1 });
    assert_eq!(
        result.vault_delta(),
        VaultDelta {
            base_atoms: 2,
            quote_atoms: -100,
        }
    );
    assert!(result.conserves(&before));
}

#[test]
fn sell_heavy_orders_create_one_aggregate_vault_delta() {
    let before = funded_balances(&[1, 2, 3]);
    let orders = vec![
        order(participant(1), Side::Sell, 100),
        order(participant(2), Side::Sell, 100),
        order(participant(3), Side::Buy, 100),
    ];

    let result = net_batch(config(), &before, &orders).expect("sell-heavy batch");

    assert_eq!(result.residual(), Residual::Sell { lots: 1 });
    assert_eq!(
        result.vault_delta(),
        VaultDelta {
            base_atoms: -2,
            quote_atoms: 100,
        }
    );
    assert!(result.conserves(&before));
}

#[test]
fn every_order_requires_both_sides_reserved_before_reveal() {
    let mut before = funded_balances(&[1]);
    before.insert(participant(1), PoolBalance::new(0, 1_000));

    let error = net_batch(config(), &before, &[order(participant(1), Side::Buy, 100)])
        .expect_err("missing base reservation must fail");

    assert_eq!(error, LedgerError::InsufficientReservation(participant(1)));
}

#[test]
fn limits_duplicates_and_overflow_fail_without_a_result() {
    let before = funded_balances(&[1, 2]);

    assert_eq!(
        net_batch(config(), &before, &[order(participant(1), Side::Buy, 99)],),
        Err(LedgerError::LimitViolated(participant(1)))
    );
    assert_eq!(
        net_batch(config(), &before, &[order(participant(1), Side::Sell, 101)],),
        Err(LedgerError::LimitViolated(participant(1)))
    );
    assert_eq!(
        net_batch(
            config(),
            &before,
            &[
                order(participant(1), Side::Buy, 100),
                order(participant(1), Side::Sell, 100),
            ],
        ),
        Err(LedgerError::DuplicateParticipant(participant(1)))
    );

    let overflowing = BTreeMap::from([(participant(1), PoolBalance::new(u64::MAX, u64::MAX))]);
    assert_eq!(
        net_batch(
            BatchConfig::new(2, 1).expect("valid config"),
            &overflowing,
            &[order(participant(1), Side::Buy, 1)],
        ),
        Err(LedgerError::ArithmeticOverflow)
    );
}
