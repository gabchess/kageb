use kageb::{
    content_root, CommitmentDomain, CommitmentError, DirectOrder, PublicTrace, Residual, Side,
};

#[test]
fn direct_trace_names_wallets_while_pooled_trace_names_only_the_aggregate() {
    let wallets = [[11_u8; 32], [12_u8; 32], [13_u8; 32], [14_u8; 32]];
    let orders = vec![
        DirectOrder::one_lot(wallets[0], Side::Buy),
        DirectOrder::one_lot(wallets[1], Side::Sell),
        DirectOrder::one_lot(wallets[2], Side::Buy),
        DirectOrder::one_lot(wallets[3], Side::Buy),
    ];
    let direct = PublicTrace::direct(&orders);
    let pooled = PublicTrace::pooled(
        [9; 32],
        [8; 32],
        Residual::Buy { lots: 2 },
        [6; 32],
        [5; 32],
    );

    assert_eq!(direct.visible_participant_wallets(), wallets);
    assert_eq!(direct.individual_order_count(), 4);
    assert_eq!(direct.aggregate_count(), 0);
    assert!(pooled.visible_participant_wallets().is_empty());
    assert_eq!(pooled.individual_order_count(), 0);
    assert_eq!(pooled.aggregate_count(), 1);
    assert!(pooled.render().contains("pool aggregate: BUY 2 lots"));
    assert!(!pooled.render().contains("participant"));
}

#[test]
fn content_roots_are_order_independent_and_domain_separated() {
    let forward = content_root(CommitmentDomain::MemberSet, &[&b"alice"[..], &b"bob"[..]])
        .expect("unique members");
    let reverse = content_root(CommitmentDomain::MemberSet, &[&b"bob"[..], &b"alice"[..]])
        .expect("unique members");
    let other_domain = content_root(CommitmentDomain::BalanceSet, &[&b"alice"[..], &b"bob"[..]])
        .expect("unique balances");

    assert_eq!(forward, reverse);
    assert_ne!(forward, other_domain);
    assert_ne!(
        forward,
        content_root(CommitmentDomain::MemberSet, &[&b"alicebob"[..]]).expect("unique member")
    );
    assert_eq!(
        content_root(CommitmentDomain::MemberSet, &[&b"alice"[..], &b"alice"[..]]),
        Err(CommitmentError::DuplicateLeaf)
    );
}
