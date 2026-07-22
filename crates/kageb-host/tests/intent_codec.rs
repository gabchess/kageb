use kageb::{IntentBodyV1, Side};

#[test]
fn intent_v1_round_trips_through_exactly_128_bytes() {
    let intent =
        IntentBodyV1::new(Side::Buy, 1, 100, [1; 32], [2; 32], [3; 16]).expect("valid intent");

    let encoded = intent.encode();
    let expected = [
        1, 0, 1, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, // header
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // epoch
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, // participant
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, // nonce
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // padding
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    assert_eq!(encoded.len(), 128);
    assert_eq!(encoded, expected);
    assert_eq!(IntentBodyV1::decode(&encoded), Ok(intent));
}

#[test]
fn intent_v1_rejects_every_noncanonical_field() {
    let canonical = IntentBodyV1::new(Side::Buy, 1, 100, [1; 32], [2; 32], [3; 16])
        .expect("valid intent")
        .encode();

    assert!(IntentBodyV1::decode(&canonical[..127]).is_err());

    let mut wrong_version = canonical;
    wrong_version[0] = 2;
    assert!(IntentBodyV1::decode(&wrong_version).is_err());

    let mut wrong_side = canonical;
    wrong_side[1] = 2;
    assert!(IntentBodyV1::decode(&wrong_side).is_err());

    let mut wrong_lots = canonical;
    wrong_lots[2..6].copy_from_slice(&2_u32.to_le_bytes());
    assert!(IntentBodyV1::decode(&wrong_lots).is_err());

    let mut zero_limit = canonical;
    zero_limit[6..14].fill(0);
    assert!(IntentBodyV1::decode(&zero_limit).is_err());

    let mut nonzero_padding = canonical;
    nonzero_padding[127] = 1;
    assert!(IntentBodyV1::decode(&nonzero_padding).is_err());
}
