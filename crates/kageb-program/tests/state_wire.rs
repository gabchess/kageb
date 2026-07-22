use kageb_program::state::{EpochStateV1, EpochTerminalState, PoolStateV1, STATE_LEN};
use kageb_program::wire::{LockPayloadV1, SettlementPayloadV1};
use solana_program::pubkey::Pubkey;

fn key(byte: u8) -> Pubkey {
    Pubkey::new_from_array([byte; 32])
}

#[test]
fn pool_state_has_exact_384_byte_canonical_layout() {
    let state = PoolStateV1 {
        pool_bump: 2,
        vault_bump: 3,
        lock_threshold: 2,
        settlement_threshold: 2,
        operator: key(1),
        base_mint: key(2),
        quote_mint: key(3),
        pool_base_vault: key(4),
        pool_quote_vault: key(5),
        venue_authority: key(6),
        venue_base_account: key(7),
        venue_quote_account: key(8),
        keypers: [key(9), key(10), key(11)],
        base_lot_atoms: 42,
    };

    let encoded = state.encode();
    assert_eq!(encoded.len(), STATE_LEN);
    assert_eq!(&encoded[0..8], b"KAGEPOOL");
    assert_eq!(encoded[8], 1);
    assert_eq!(encoded[9], 2);
    assert_eq!(encoded[10], 3);
    assert_eq!(encoded[11], 2);
    assert_eq!(encoded[12], 2);
    assert_eq!(&encoded[13..16], &[0; 3]);
    assert_eq!(&encoded[16..48], key(1).as_ref());
    assert_eq!(&encoded[48..80], key(2).as_ref());
    assert_eq!(&encoded[80..112], key(3).as_ref());
    assert_eq!(&encoded[112..144], key(4).as_ref());
    assert_eq!(&encoded[144..176], key(5).as_ref());
    assert_eq!(&encoded[176..208], key(6).as_ref());
    assert_eq!(&encoded[208..240], key(7).as_ref());
    assert_eq!(&encoded[240..272], key(8).as_ref());
    assert_eq!(&encoded[272..304], key(9).as_ref());
    assert_eq!(&encoded[304..336], key(10).as_ref());
    assert_eq!(&encoded[336..368], key(11).as_ref());
    assert_eq!(&encoded[368..376], &42_u64.to_le_bytes());
    assert_eq!(&encoded[376..384], &[0; 8]);
    assert_eq!(PoolStateV1::decode(&encoded).unwrap(), state);

    let mut wrong_discriminator = encoded;
    wrong_discriminator[0] ^= 1;
    assert!(PoolStateV1::decode(&wrong_discriminator).is_err());
    let mut wrong_version = encoded;
    wrong_version[8] = 2;
    assert!(PoolStateV1::decode(&wrong_version).is_err());
    let mut non_zero_reserved = encoded;
    non_zero_reserved[383] = 1;
    assert!(PoolStateV1::decode(&non_zero_reserved).is_err());
    assert!(PoolStateV1::decode(&encoded[..383]).is_err());
}

#[test]
fn epoch_state_has_exact_384_byte_canonical_layout() {
    let state = EpochStateV1 {
        epoch_bump: 7,
        terminal_state: EpochTerminalState::Locked,
        residual_side: 0,
        pool: key(1),
        epoch_id: [2; 32],
        configuration_hash: [3; 32],
        pre_balance_root: [4; 32],
        member_root: [5; 32],
        lock_digest: [6; 32],
        result_commitment: [7; 32],
        settlement_digest: [8; 32],
        lock_nonce: [9; 32],
        settlement_nonce: [10; 32],
        member_count: 4,
        minimum_count: 4,
        residual_lots: 0,
        base_lot_atoms: 1,
        quote_atoms_per_lot: 100,
        lock_deadline: 500,
        abort_deadline: 700,
    };

    let encoded = state.encode();
    assert_eq!(encoded.len(), STATE_LEN);
    assert_eq!(&encoded[0..8], b"KAGEEPCH");
    assert_eq!(encoded[8], 1);
    assert_eq!(encoded[9], 7);
    assert_eq!(encoded[10], EpochTerminalState::Locked as u8);
    assert_eq!(encoded[11], 0);
    assert_eq!(&encoded[12..16], &[0; 4]);
    assert_eq!(&encoded[16..48], key(1).as_ref());
    assert_eq!(&encoded[48..80], &[2; 32]);
    assert_eq!(&encoded[80..112], &[3; 32]);
    assert_eq!(&encoded[112..144], &[4; 32]);
    assert_eq!(&encoded[144..176], &[5; 32]);
    assert_eq!(&encoded[176..208], &[6; 32]);
    assert_eq!(&encoded[208..240], &[7; 32]);
    assert_eq!(&encoded[240..272], &[8; 32]);
    assert_eq!(&encoded[272..304], &[9; 32]);
    assert_eq!(&encoded[304..336], &[10; 32]);
    assert_eq!(&encoded[336..340], &4_u32.to_le_bytes());
    assert_eq!(&encoded[340..344], &4_u32.to_le_bytes());
    assert_eq!(&encoded[344..348], &0_u32.to_le_bytes());
    assert_eq!(&encoded[348..356], &1_u64.to_le_bytes());
    assert_eq!(&encoded[356..364], &100_u64.to_le_bytes());
    assert_eq!(&encoded[364..372], &500_i64.to_le_bytes());
    assert_eq!(&encoded[372..380], &700_i64.to_le_bytes());
    assert_eq!(&encoded[380..384], &[0; 4]);
    assert_eq!(EpochStateV1::decode(&encoded).unwrap(), state);

    let mut wrong_discriminator = encoded;
    wrong_discriminator[0] ^= 1;
    assert!(EpochStateV1::decode(&wrong_discriminator).is_err());
    let mut wrong_version = encoded;
    wrong_version[8] = 2;
    assert!(EpochStateV1::decode(&wrong_version).is_err());
    let mut invalid_state = encoded;
    invalid_state[10] = 99;
    assert!(EpochStateV1::decode(&invalid_state).is_err());
    let mut non_zero_reserved = encoded;
    non_zero_reserved[383] = 1;
    assert!(EpochStateV1::decode(&non_zero_reserved).is_err());
    assert!(EpochStateV1::decode(&encoded[..383]).is_err());
}

#[test]
fn lock_wire_and_digest_bind_balance_root_count_deadline_and_nonce() {
    let payload = LockPayloadV1 {
        epoch_account: key(1),
        configuration_hash: [2; 32],
        pre_balance_root: [3; 32],
        member_root: [4; 32],
        member_count: 4,
        lock_deadline: 500,
        lock_nonce: [5; 32],
    };

    let encoded = payload.encode();
    assert_eq!(encoded.len(), LockPayloadV1::ENCODED_LEN);
    assert_eq!(LockPayloadV1::decode(&encoded), Some(payload));
    assert_eq!(encoded[0], 1);
    assert_eq!(&encoded[1..33], key(1).as_ref());
    assert_eq!(&encoded[33..65], &[2; 32]);
    assert_eq!(&encoded[65..97], &[3; 32]);
    assert_eq!(&encoded[97..129], &[4; 32]);
    assert_eq!(&encoded[129..133], &4_u32.to_le_bytes());
    assert_eq!(&encoded[133..141], &500_i64.to_le_bytes());
    assert_eq!(&encoded[141..173], &[5; 32]);
    assert!(LockPayloadV1::decode(&encoded[..172]).is_none());
    let mut wrong_version = encoded;
    wrong_version[0] = 2;
    assert!(LockPayloadV1::decode(&wrong_version).is_none());
    assert_ne!(
        payload.digest(),
        LockPayloadV1 {
            pre_balance_root: [6; 32],
            ..payload
        }
        .digest()
    );
    assert_ne!(
        payload.digest(),
        LockPayloadV1 {
            member_count: 5,
            ..payload
        }
        .digest()
    );
    assert_ne!(
        payload.digest(),
        LockPayloadV1 {
            lock_deadline: 501,
            ..payload
        }
        .digest()
    );
    assert_ne!(
        payload.digest(),
        LockPayloadV1 {
            lock_nonce: [6; 32],
            ..payload
        }
        .digest()
    );
}

#[test]
fn settlement_digest_binds_every_market_facing_field() {
    let payload = SettlementPayloadV1 {
        epoch_account: key(1),
        lock_digest: [2; 32],
        result_commitment: [3; 32],
        residual_side: 1,
        residual_lots: 2,
        base_lot_atoms: 3,
        quote_atoms_per_lot: 4,
        base_mint: key(5),
        quote_mint: key(6),
        pool_base_vault: key(7),
        pool_quote_vault: key(8),
        venue_base_account: key(9),
        venue_quote_account: key(10),
        venue_authority: key(11),
        settlement_nonce: [12; 32],
    };

    let encoded = payload.encode();
    assert_eq!(encoded.len(), SettlementPayloadV1::ENCODED_LEN);
    assert_eq!(SettlementPayloadV1::decode(&encoded), Some(payload));
    assert_eq!(encoded[0], 1);
    assert_eq!(&encoded[1..33], key(1).as_ref());
    assert_eq!(&encoded[33..65], &[2; 32]);
    assert_eq!(&encoded[65..97], &[3; 32]);
    assert_eq!(encoded[97], 1);
    assert_eq!(&encoded[98..102], &2_u32.to_le_bytes());
    assert_eq!(&encoded[102..110], &3_u64.to_le_bytes());
    assert_eq!(&encoded[110..118], &4_u64.to_le_bytes());
    assert_eq!(&encoded[118..150], key(5).as_ref());
    assert_eq!(&encoded[150..182], key(6).as_ref());
    assert_eq!(&encoded[182..214], key(7).as_ref());
    assert_eq!(&encoded[214..246], key(8).as_ref());
    assert_eq!(&encoded[246..278], key(9).as_ref());
    assert_eq!(&encoded[278..310], key(10).as_ref());
    assert_eq!(&encoded[310..342], key(11).as_ref());
    assert_eq!(&encoded[342..374], &[12; 32]);
    assert!(SettlementPayloadV1::decode(&encoded[..373]).is_none());
    let mut wrong_version = encoded;
    wrong_version[0] = 2;
    assert!(SettlementPayloadV1::decode(&wrong_version).is_none());
    assert_ne!(
        payload.digest(),
        SettlementPayloadV1 {
            residual_lots: 3,
            ..payload
        }
        .digest()
    );
    assert_ne!(
        payload.digest(),
        SettlementPayloadV1 {
            venue_authority: key(13),
            ..payload
        }
        .digest()
    );
}
