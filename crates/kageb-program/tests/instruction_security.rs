use kageb_program::{
    ed25519::{count_matching_keypers, parse_strict_ed25519},
    error::KagebError,
    instruction::{
        settle_instruction, CreateEpochArgs, InitializePoolArgs, KagebInstruction, SettleAccounts,
    },
    processor::process_instruction,
    wire::SettlementPayloadV1,
    ID, TOKEN_PROGRAM_ID,
};
use solana_program::{instruction::AccountMeta, instruction::Instruction, pubkey::Pubkey};

fn key(byte: u8) -> Pubkey {
    Pubkey::new_from_array([byte; 32])
}

fn verifier_instruction(signer: Pubkey, digest: [u8; 32], signature: [u8; 64]) -> Instruction {
    let mut data = vec![0_u8; 144];
    data[0] = 1;
    data[2..4].copy_from_slice(&48_u16.to_le_bytes());
    data[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
    data[6..8].copy_from_slice(&16_u16.to_le_bytes());
    data[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    data[10..12].copy_from_slice(&112_u16.to_le_bytes());
    data[12..14].copy_from_slice(&32_u16.to_le_bytes());
    data[14..16].copy_from_slice(&u16::MAX.to_le_bytes());
    data[16..48].copy_from_slice(signer.as_ref());
    data[48..112].copy_from_slice(&signature);
    data[112..144].copy_from_slice(&digest);
    Instruction {
        program_id: solana_program::ed25519_program::ID,
        accounts: vec![],
        data,
    }
}

#[test]
fn instruction_codecs_reject_trailing_or_malformed_data() {
    let initialize = InitializePoolArgs {
        lock_threshold: 2,
        settlement_threshold: 2,
        base_lot_atoms: 1,
        keypers: [key(1), key(2), key(3)],
    };
    let encoded = KagebInstruction::InitializePool(initialize).encode();
    assert_eq!(
        KagebInstruction::decode(&encoded).unwrap(),
        KagebInstruction::InitializePool(initialize)
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(KagebInstruction::decode(&trailing).is_err());

    let create = CreateEpochArgs {
        epoch_id: [4; 32],
        minimum_count: 4,
        quote_atoms_per_lot: 100,
        lock_deadline: 500,
        abort_deadline: 700,
    };
    let encoded = KagebInstruction::CreateEpoch(create).encode();
    assert_eq!(
        KagebInstruction::decode(&encoded).unwrap(),
        KagebInstruction::CreateEpoch(create)
    );
    assert!(KagebInstruction::decode(&encoded[..encoded.len() - 1]).is_err());
    assert_eq!(KagebInstruction::Expire.encode(), vec![4]);
    assert_eq!(KagebInstruction::Abort.encode(), vec![5]);
}

#[test]
fn settlement_has_exact_wire_codec_and_account_builder() {
    let payload = SettlementPayloadV1 {
        epoch_account: key(22),
        lock_digest: [2; 32],
        result_commitment: [3; 32],
        residual_side: 1,
        residual_lots: 2,
        base_lot_atoms: 3,
        quote_atoms_per_lot: 4,
        base_mint: key(29),
        quote_mint: key(30),
        pool_base_vault: key(24),
        pool_quote_vault: key(25),
        venue_base_account: key(27),
        venue_quote_account: key(28),
        venue_authority: key(26),
        settlement_nonce: [12; 32],
    };
    let compact = payload.into();
    let encoded = KagebInstruction::Settle(compact).encode();
    assert_eq!(encoded.len(), 70);
    assert_eq!(encoded[0], 3);
    assert_eq!(
        KagebInstruction::decode(&encoded).unwrap(),
        KagebInstruction::Settle(compact)
    );
    assert!(KagebInstruction::decode(&encoded[..encoded.len() - 1]).is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(KagebInstruction::decode(&trailing).is_err());

    let accounts = SettleAccounts {
        payer: key(20),
        pool: key(21),
        epoch: key(22),
        vault_authority: key(23),
        pool_base_vault: key(24),
        pool_quote_vault: key(25),
        venue_authority: key(26),
        venue_base_account: key(27),
        venue_quote_account: key(28),
        base_mint: key(29),
        quote_mint: key(30),
    };
    let instruction = settle_instruction(accounts, payload);
    assert_eq!(instruction.program_id, ID);
    assert_eq!(instruction.data, encoded);
    let mut removed_route = encoded.clone();
    removed_route[0] = 6;
    assert!(KagebInstruction::decode(&removed_route).is_err());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(key(20), true),
            AccountMeta::new_readonly(key(21), false),
            AccountMeta::new(key(22), false),
            AccountMeta::new_readonly(key(23), false),
            AccountMeta::new(key(24), false),
            AccountMeta::new(key(25), false),
            AccountMeta::new_readonly(key(26), true),
            AccountMeta::new(key(27), false),
            AccountMeta::new(key(28), false),
            AccountMeta::new_readonly(key(29), false),
            AccountMeta::new_readonly(key(30), false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(solana_sdk_ids::sysvar::instructions::ID, false),
            AccountMeta::new_readonly(solana_sdk_ids::sysvar::clock::ID, false),
        ]
    );
    assert_eq!(
        process_instruction(&ID, &[], &encoded),
        Err(KagebError::InvalidAccounts.into())
    );
}

#[test]
fn ed25519_parser_accepts_only_exact_internal_layout() {
    let digest = [9; 32];
    let signer = key(1);
    let valid = verifier_instruction(signer, digest, [8; 64]);
    let parsed = parse_strict_ed25519(&valid).unwrap();
    assert_eq!(parsed.signer, signer);
    assert_eq!(parsed.digest, digest);

    let mut external_offsets = valid.clone();
    external_offsets.data[4..6].copy_from_slice(&0_u16.to_le_bytes());
    assert!(parse_strict_ed25519(&external_offsets).is_err());

    let mut trailing = valid.clone();
    trailing.data.push(0);
    assert!(parse_strict_ed25519(&trailing).is_err());

    let mut account_meta = valid.clone();
    account_meta
        .accounts
        .push(solana_program::instruction::AccountMeta::new_readonly(
            key(2),
            false,
        ));
    assert!(parse_strict_ed25519(&account_meta).is_err());
}

#[test]
fn quorum_counts_distinct_configured_keys_only() {
    let digest = [9; 32];
    let keypers = [key(1), key(2), key(3)];
    let first = verifier_instruction(keypers[0], digest, [4; 64]);
    let duplicate = verifier_instruction(keypers[0], digest, [5; 64]);
    let second = verifier_instruction(keypers[1], digest, [6; 64]);
    let wrong_digest = verifier_instruction(keypers[2], [10; 32], [7; 64]);
    let outsider = verifier_instruction(key(4), digest, [8; 64]);

    assert_eq!(
        count_matching_keypers(
            [&first, &duplicate, &second, &wrong_digest, &outsider],
            &keypers,
            &digest
        ),
        2
    );
}
