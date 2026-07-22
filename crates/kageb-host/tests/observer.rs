use kageb::{
    content_root, CommitmentDomain, CommitmentError, DirectMarketAccounts, DirectOrder,
    KagebObserverAccounts, PublicTrace, Residual, Side,
};
use kageb_program::{
    instruction::{lock_instruction, settle_instruction, SettleAccounts},
    wire::{LockPayloadV1, SettlementPayloadV1},
};
use solana_keypair::Keypair;
use solana_program::pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
    EncodedTransaction, EncodedTransactionWithStatusMeta, TransactionBinaryEncoding,
    UiCompiledInstruction, UiInnerInstructions, UiInstruction, UiTransactionStatusMeta,
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
    let public_view = pooled.render();
    assert!(public_view.contains("pool aggregate: BUY 2 lots"));
    for private_field in [
        "participant wallet",
        "participant identifier",
        "individual order",
        "ciphertext",
        "share",
        "private balance",
    ] {
        assert!(!public_view.contains(private_field));
    }
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

#[test]
fn confirmed_kageb_decoder_uses_exact_public_instructions_accounts_and_inner_token_effects() {
    let fee_payer = Keypair::new();
    let payer = Keypair::new();
    let venue_authority = Keypair::new();
    let pool = Pubkey::new_unique();
    let epoch = Pubkey::new_unique();
    let vault_authority = Pubkey::new_unique();
    let pool_base_vault = Pubkey::new_unique();
    let pool_quote_vault = Pubkey::new_unique();
    let venue_base_account = Pubkey::new_unique();
    let venue_quote_account = Pubkey::new_unique();
    let base_mint = Pubkey::new_unique();
    let quote_mint = Pubkey::new_unique();
    let lock_payload = LockPayloadV1 {
        epoch_account: epoch,
        configuration_hash: [1; 32],
        pre_balance_root: [2; 32],
        member_root: [3; 32],
        member_count: 4,
        lock_deadline: 900,
        lock_nonce: [4; 32],
    };
    let settlement_payload = SettlementPayloadV1 {
        epoch_account: epoch,
        lock_digest: lock_payload.digest(),
        result_commitment: [5; 32],
        residual_side: 1,
        residual_lots: 4,
        base_lot_atoms: 7,
        quote_atoms_per_lot: 113,
        base_mint,
        quote_mint,
        pool_base_vault,
        pool_quote_vault,
        venue_base_account,
        venue_quote_account,
        venue_authority: venue_authority.pubkey(),
        settlement_nonce: [6; 32],
    };
    let lock = confirmed_transaction(
        Transaction::new_signed_with_payer(
            &[
                approval_instruction(),
                approval_instruction(),
                lock_instruction(payer.pubkey(), pool, epoch, lock_payload),
            ],
            Some(&fee_payer.pubkey()),
            &[&fee_payer, &payer],
            Default::default(),
        ),
        Vec::new(),
    );
    let settlement_transaction = Transaction::new_signed_with_payer(
        &[
            approval_instruction(),
            approval_instruction(),
            settle_instruction(
                SettleAccounts {
                    payer: payer.pubkey(),
                    pool,
                    epoch,
                    vault_authority,
                    pool_base_vault,
                    pool_quote_vault,
                    venue_authority: venue_authority.pubkey(),
                    venue_base_account,
                    venue_quote_account,
                    base_mint,
                    quote_mint,
                },
                settlement_payload,
            ),
        ],
        Some(&fee_payer.pubkey()),
        &[&fee_payer, &payer, &venue_authority],
        Default::default(),
    );
    assert!(bincode::serialize(&settlement_transaction).unwrap().len() <= 1_232);
    let keys = &settlement_transaction.message.account_keys;
    let token_index = key_index(keys, kageb_program::TOKEN_PROGRAM_ID);
    let transfer = |accounts: [Pubkey; 4], amount: u64| {
        UiInstruction::Compiled(UiCompiledInstruction {
            program_id_index: token_index,
            accounts: accounts.map(|account| key_index(keys, account)).to_vec(),
            data: bs58::encode(
                spl_token_interface::instruction::TokenInstruction::TransferChecked {
                    amount,
                    decimals: 0,
                }
                .pack(),
            )
            .into_string(),
            stack_height: Some(2),
        })
    };
    let settlement = confirmed_transaction(
        settlement_transaction.clone(),
        vec![UiInnerInstructions {
            index: 2,
            instructions: vec![
                transfer(
                    [
                        pool_quote_vault,
                        quote_mint,
                        venue_quote_account,
                        vault_authority,
                    ],
                    452,
                ),
                transfer(
                    [
                        venue_base_account,
                        base_mint,
                        pool_base_vault,
                        venue_authority.pubkey(),
                    ],
                    28,
                ),
            ],
        }],
    );

    let observer_accounts = KagebObserverAccounts {
        fee_payer: fee_payer.pubkey(),
        payer: payer.pubkey(),
        pool,
        epoch,
        vault_authority,
        pool_base_vault,
        pool_quote_vault,
        venue_authority: venue_authority.pubkey(),
        venue_base_account,
        venue_quote_account,
        base_mint,
        quote_mint,
        base_lot_atoms: settlement_payload.base_lot_atoms,
        quote_atoms_per_lot: settlement_payload.quote_atoms_per_lot,
    };
    let trace = PublicTrace::from_confirmed_kageb(&lock, &settlement, observer_accounts)
        .expect("strict public decode");
    assert_eq!(trace.aggregate_count(), 1);
    assert!(trace.visible_participant_wallets().is_empty());
    assert!(trace.render().contains("pool aggregate: BUY 4 lots"));

    let participant_payer_lock = confirmed_transaction(
        Transaction::new_signed_with_payer(
            &[
                approval_instruction(),
                approval_instruction(),
                lock_instruction(payer.pubkey(), pool, epoch, lock_payload),
            ],
            Some(&payer.pubkey()),
            &[&payer],
            Default::default(),
        ),
        Vec::new(),
    );
    assert!(PublicTrace::from_confirmed_kageb(
        &participant_payer_lock,
        &settlement,
        observer_accounts,
    )
    .is_err());

    let participant_payer_settlement_transaction = Transaction::new_signed_with_payer(
        &[
            approval_instruction(),
            approval_instruction(),
            settle_instruction(
                SettleAccounts {
                    payer: payer.pubkey(),
                    pool,
                    epoch,
                    vault_authority,
                    pool_base_vault,
                    pool_quote_vault,
                    venue_authority: venue_authority.pubkey(),
                    venue_base_account,
                    venue_quote_account,
                    base_mint,
                    quote_mint,
                },
                settlement_payload,
            ),
        ],
        Some(&payer.pubkey()),
        &[&payer, &venue_authority],
        Default::default(),
    );
    let keys = &participant_payer_settlement_transaction
        .message
        .account_keys;
    let token_index = key_index(keys, kageb_program::TOKEN_PROGRAM_ID);
    let transfer = |accounts: [Pubkey; 4], amount: u64| {
        UiInstruction::Compiled(UiCompiledInstruction {
            program_id_index: token_index,
            accounts: accounts.map(|account| key_index(keys, account)).to_vec(),
            data: bs58::encode(
                spl_token_interface::instruction::TokenInstruction::TransferChecked {
                    amount,
                    decimals: 0,
                }
                .pack(),
            )
            .into_string(),
            stack_height: Some(2),
        })
    };
    let participant_payer_inner = vec![UiInnerInstructions {
        index: 2,
        instructions: vec![
            transfer(
                [
                    pool_quote_vault,
                    quote_mint,
                    venue_quote_account,
                    vault_authority,
                ],
                452,
            ),
            transfer(
                [
                    venue_base_account,
                    base_mint,
                    pool_base_vault,
                    venue_authority.pubkey(),
                ],
                28,
            ),
        ],
    }];
    let participant_payer_settlement = confirmed_transaction(
        participant_payer_settlement_transaction,
        participant_payer_inner,
    );
    assert!(PublicTrace::from_confirmed_kageb(
        &lock,
        &participant_payer_settlement,
        observer_accounts,
    )
    .is_err());

    let mut extra_key_settlement = settlement.clone();
    let mut transaction = settlement_transaction.clone();
    transaction.message.account_keys.push(Pubkey::new_unique());
    extra_key_settlement.transaction.transaction = encode_transaction(transaction);
    assert!(
        PublicTrace::from_confirmed_kageb(&lock, &extra_key_settlement, observer_accounts,)
            .is_err()
    );

    let mut wrong_settlement = settlement.clone();
    let mut transaction = settlement_transaction;
    transaction.message.instructions[2].accounts.swap(1, 2);
    wrong_settlement.transaction.transaction = encode_transaction(transaction);
    assert!(
        PublicTrace::from_confirmed_kageb(&lock, &wrong_settlement, observer_accounts,).is_err()
    );
}

#[test]
fn confirmed_direct_decoder_rejects_participant_as_undeclared_fee_payer() {
    let fee_payer = Keypair::new();
    let participant = Keypair::new();
    let source = Pubkey::new_unique();
    let base_mint = Pubkey::new_unique();
    let quote_mint = Pubkey::new_unique();
    let venue_base_account = Pubkey::new_unique();
    let venue_quote_account = Pubkey::new_unique();
    let instruction = spl_token_interface::instruction::transfer_checked(
        &kageb_program::TOKEN_PROGRAM_ID,
        &source,
        &quote_mint,
        &venue_quote_account,
        &participant.pubkey(),
        &[],
        100,
        0,
    )
    .unwrap();
    let market = DirectMarketAccounts {
        fee_payer: fee_payer.pubkey(),
        base_mint,
        quote_mint,
        venue_base_account,
        venue_quote_account,
        base_lot_atoms: 1,
        quote_atoms_per_lot: 100,
    };
    let neutral = confirmed_transaction(
        Transaction::new_signed_with_payer(
            std::slice::from_ref(&instruction),
            Some(&fee_payer.pubkey()),
            &[&fee_payer, &participant],
            Default::default(),
        ),
        Vec::new(),
    );
    PublicTrace::from_confirmed_direct(&[neutral], market).expect("declared neutral fee payer");

    let participant_paid = confirmed_transaction(
        Transaction::new_signed_with_payer(
            &[instruction],
            Some(&participant.pubkey()),
            &[&participant],
            Default::default(),
        ),
        Vec::new(),
    );
    assert!(PublicTrace::from_confirmed_direct(&[participant_paid], market).is_err());
}

fn approval_instruction() -> solana_program::instruction::Instruction {
    let mut data = vec![0_u8; 144];
    data[0] = 1;
    data[2..4].copy_from_slice(&48_u16.to_le_bytes());
    data[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
    data[6..8].copy_from_slice(&16_u16.to_le_bytes());
    data[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    data[10..12].copy_from_slice(&112_u16.to_le_bytes());
    data[12..14].copy_from_slice(&32_u16.to_le_bytes());
    data[14..16].copy_from_slice(&u16::MAX.to_le_bytes());
    solana_program::instruction::Instruction {
        program_id: solana_program::ed25519_program::ID,
        accounts: Vec::new(),
        data,
    }
}

fn key_index(keys: &[Pubkey], key: Pubkey) -> u8 {
    keys.iter().position(|candidate| *candidate == key).unwrap() as u8
}

fn encode_transaction(transaction: Transaction) -> EncodedTransaction {
    use base64::{engine::general_purpose::STANDARD, Engine};
    EncodedTransaction::Binary(
        STANDARD.encode(bincode::serialize(&transaction).expect("serialize transaction")),
        TransactionBinaryEncoding::Base64,
    )
}

fn confirmed_transaction(
    transaction: Transaction,
    inner: Vec<UiInnerInstructions>,
) -> EncodedConfirmedTransactionWithStatusMeta {
    EncodedConfirmedTransactionWithStatusMeta {
        slot: 1,
        transaction: EncodedTransactionWithStatusMeta {
            transaction: encode_transaction(transaction),
            meta: Some(UiTransactionStatusMeta {
                err: None,
                status: Ok(()),
                fee: 0,
                pre_balances: Vec::new(),
                post_balances: Vec::new(),
                inner_instructions: OptionSerializer::Some(inner),
                log_messages: OptionSerializer::Skip,
                pre_token_balances: OptionSerializer::Skip,
                post_token_balances: OptionSerializer::Skip,
                rewards: OptionSerializer::Skip,
                loaded_addresses: OptionSerializer::Skip,
                return_data: OptionSerializer::Skip,
                compute_units_consumed: OptionSerializer::Skip,
                cost_units: OptionSerializer::Skip,
            }),
            version: None,
        },
        block_time: None,
        transaction_index: None,
    }
}
