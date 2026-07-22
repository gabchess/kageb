use std::collections::BTreeMap;

use crate::{
    content_root, net_batch, BatchConfig, CommitmentDomain, DirectOrder, FundedOrder, LedgerError,
    PoolBalance, PublicTrace, Side,
};

pub fn trace_fixture() -> Result<String, LedgerError> {
    let participants = [[1_u8; 32], [2_u8; 32], [3_u8; 32], [4_u8; 32]];
    let balances: BTreeMap<_, _> = participants
        .iter()
        .map(|participant| (*participant, PoolBalance::new(10, 1_000)))
        .collect();
    let orders = vec![
        FundedOrder::new(participants[0], Side::Buy, 100)?,
        FundedOrder::new(participants[1], Side::Sell, 100)?,
        FundedOrder::new(participants[2], Side::Buy, 100)?,
        FundedOrder::new(participants[3], Side::Buy, 100)?,
    ];
    let result = net_batch(BatchConfig::new(2, 100)?, &balances, &orders)?;
    let participant_leaves: Vec<&[u8]> = participants
        .iter()
        .map(|participant| participant.as_slice())
        .collect();
    let member_root = content_root(CommitmentDomain::MemberSet, &participant_leaves)
        .expect("fixture participants are unique");
    let result_root = content_root(CommitmentDomain::ResultSet, &[b"fixture-result"])
        .expect("fixture result is unique");
    let direct = PublicTrace::direct(&[
        DirectOrder::one_lot([11; 32], Side::Buy),
        DirectOrder::one_lot([12; 32], Side::Sell),
        DirectOrder::one_lot([13; 32], Side::Buy),
        DirectOrder::one_lot([14; 32], Side::Buy),
    ]);
    let pooled = PublicTrace::pooled(
        [9; 32],
        [8; 32],
        result.residual(),
        member_root,
        result_root,
    );

    Ok(format!(
        "DIRECT: {} wallet-linked orders visible\n{}\n\nKAGEB: {} individual orders visible\n{}\n\n4 real orders, one pooled result, no decoy trades.\n",
        direct.individual_order_count(),
        direct.render(),
        pooled.individual_order_count(),
        pooled.render()
    ))
}
