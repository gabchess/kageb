use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use kageb::{
    admit_batch, AdmissionPolicyV1, CryptoError, EncryptedSubmissionV1, EpochDealer,
    FundedAuthorizationV1, IntentBodyV1, PoolBalance, ReservationJournal, ReservationRecord, Side,
    SignedIntentV1, SuspensionRegistry, ENCRYPTED_INTENT_V1_LEN, FUNDED_AUTHORIZATION_V1_LEN,
};
use tempfile::tempdir;

fn trading_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[derive(Clone, Copy)]
struct TestMember {
    participant: u8,
    nonce: u8,
    receipt: u8,
    base_atoms: u64,
    quote_atoms: u64,
    expiry: u64,
}

impl TestMember {
    const fn standard(participant: u8) -> Self {
        Self {
            participant,
            nonce: participant,
            receipt: participant + 20,
            base_atoms: 2,
            quote_atoms: 100,
            expiry: 1_000,
        }
    }
}

fn authorization(
    participant: u8,
    epoch: [u8; 32],
    trading: &SigningKey,
    operator: &SigningKey,
) -> FundedAuthorizationV1 {
    authorization_with(TestMember::standard(participant), epoch, trading, operator)
}

fn authorization_with(
    member: TestMember,
    epoch: [u8; 32],
    trading: &SigningKey,
    operator: &SigningKey,
) -> FundedAuthorizationV1 {
    let directory = tempdir().expect("tempdir");
    let mut journal =
        ReservationJournal::open(directory.path().join("reservations.bin")).expect("journal");
    let reserved = journal
        .reserve(
            ReservationRecord::new(
                [member.nonce; 32],
                [member.participant; 32],
                member.base_atoms,
                member.quote_atoms,
            )
            .expect("funded record"),
            PoolBalance::new(member.base_atoms, member.quote_atoms),
        )
        .expect("reserve");
    SuspensionRegistry::open(directory.path().join("suspensions.bin"))
        .expect("suspensions")
        .issue_authorization(
            reserved,
            epoch,
            trading.verifying_key(),
            operator,
            member.expiry,
        )
        .expect("authorization")
}

fn policy(epoch: [u8; 32], operator: &SigningKey) -> AdmissionPolicyV1 {
    AdmissionPolicyV1::new(epoch, operator.verifying_key(), 4, 2, 100, 500)
        .expect("valid admission policy")
}

fn signed_intent(participant: u8, epoch: [u8; 32], trading: &SigningKey) -> SignedIntentV1 {
    let body = IntentBodyV1::new(
        Side::Buy,
        1,
        100,
        epoch,
        [participant; 32],
        [participant; 16],
    )
    .expect("intent");
    SignedIntentV1::sign(body, trading)
}

fn submission(
    member: TestMember,
    epoch: [u8; 32],
    dealer: &EpochDealer,
    operator: &SigningKey,
) -> EncryptedSubmissionV1 {
    let trader = trading_key(member.participant);
    let authorization = authorization_with(member, epoch, &trader, operator);
    let encrypted = dealer
        .public_keys()
        .encrypt(&signed_intent(member.participant, epoch, &trader))
        .expect("encrypt");
    EncryptedSubmissionV1::sign(authorization, encrypted, [member.receipt; 32], &trader)
        .expect("submission")
}

#[test]
fn inner_and_outer_signatures_bind_every_context() {
    let epoch = [42; 32];
    let operator = trading_key(90);
    let trader = trading_key(7);
    let policy = policy(epoch, &operator);
    let funded_authorization = authorization(7, epoch, &trader, &operator);
    assert_eq!(
        format!("{funded_authorization:?}"),
        "FundedAuthorizationV1(..redacted)"
    );
    assert_eq!(
        funded_authorization.encode().len(),
        FUNDED_AUTHORIZATION_V1_LEN
    );
    assert_eq!(FUNDED_AUTHORIZATION_V1_LEN, 249);
    let mut wrong_version = funded_authorization.encode().to_vec();
    wrong_version[0] = 2;
    assert_eq!(
        FundedAuthorizationV1::decode(&wrong_version),
        Err(CryptoError::InvalidAuthorization)
    );
    let mut trailing_authorization = funded_authorization.encode().to_vec();
    trailing_authorization.push(0);
    assert_eq!(
        FundedAuthorizationV1::decode(&trailing_authorization),
        Err(CryptoError::InvalidAuthorization)
    );
    let signed = signed_intent(7, epoch, &trader);
    assert_eq!(signed.encode().len(), 192);
    let mut signed_with_trailing = signed.encode().to_vec();
    signed_with_trailing.push(0);
    assert_eq!(
        SignedIntentV1::decode(&signed_with_trailing),
        Err(CryptoError::InvalidSignedIntent)
    );
    assert!(signed
        .verify(&trader.verifying_key(), epoch, [7; 32])
        .is_ok());
    assert_eq!(
        signed.verify(&trader.verifying_key(), [41; 32], [7; 32]),
        Err(CryptoError::WrongEpoch)
    );
    assert_eq!(
        signed.verify(&trader.verifying_key(), epoch, [6; 32]),
        Err(CryptoError::WrongParticipant)
    );
    assert_eq!(
        signed.verify(&trading_key(6).verifying_key(), epoch, [7; 32]),
        Err(CryptoError::InvalidInnerSignature)
    );

    let dealer = EpochDealer::random().expect("OS-backed dealer");
    let encrypted = dealer.public_keys().encrypt(&signed).expect("encrypt");
    assert_eq!(encrypted.as_bytes().len(), ENCRYPTED_INTENT_V1_LEN);
    assert_eq!(ENCRYPTED_INTENT_V1_LEN, 344);
    assert_eq!(
        EncryptedSubmissionV1::sign(
            funded_authorization.clone(),
            encrypted.clone(),
            [0; 32],
            &trader,
        ),
        Err(CryptoError::InvalidReceipt)
    );
    let submission = EncryptedSubmissionV1::sign(funded_authorization, encrypted, [8; 32], &trader)
        .expect("submit");

    assert!(submission.verify_admission(&policy).is_ok());
    let wrong_epoch_policy =
        AdmissionPolicyV1::new([41; 32], operator.verifying_key(), 4, 2, 100, 500).expect("policy");
    assert_eq!(
        submission.verify_admission(&wrong_epoch_policy),
        Err(CryptoError::WrongEpoch)
    );
    let wrong_operator_policy =
        AdmissionPolicyV1::new(epoch, trading_key(89).verifying_key(), 4, 2, 100, 500)
            .expect("policy");
    assert_eq!(
        submission.verify_admission(&wrong_operator_policy),
        Err(CryptoError::InvalidAuthorization)
    );

    let (auth, ciphertext, mut receipt, signature) = submission.into_wire_parts();
    receipt[0] ^= 1;
    let tampered = EncryptedSubmissionV1::from_wire_parts(auth, ciphertext, receipt, signature);
    assert_eq!(
        tampered.verify_admission(&policy),
        Err(CryptoError::InvalidOuterSignature)
    );

    let authorization = authorization(7, epoch, &trader, &operator);
    let encrypted = dealer.public_keys().encrypt(&signed).expect("encrypt");
    assert_eq!(
        EncryptedSubmissionV1::sign(authorization, encrypted, [9; 32], &trading_key(6)),
        Err(CryptoError::WrongTradingKey)
    );
}

#[test]
fn crowd_gate_counts_only_four_valid_unique_structural_members() {
    let epoch = [42; 32];
    let operator = trading_key(90);
    let policy = policy(epoch, &operator);
    let dealer = EpochDealer::random().expect("dealer");
    let submissions: Vec<_> = (1..=4)
        .map(|id| {
            let trader = trading_key(id);
            let auth = authorization(id, epoch, &trader, &operator);
            let encrypted = dealer
                .public_keys()
                .encrypt(&signed_intent(id, epoch, &trader))
                .expect("encrypt");
            EncryptedSubmissionV1::sign(auth, encrypted, [id + 20; 32], &trader).expect("submit")
        })
        .collect();

    assert_eq!(
        admit_batch(&submissions[..3], &policy),
        Err(CryptoError::InsufficientCrowd {
            valid: 3,
            minimum: 4
        })
    );
    let batch = admit_batch(&submissions, &policy).expect("four unique members");
    assert_eq!(batch.member_count(), 4);

    let mut duplicate = submissions.clone();
    duplicate[3] = duplicate[0].clone();
    assert_eq!(
        admit_batch(&duplicate, &policy),
        Err(CryptoError::InsufficientCrowd {
            valid: 3,
            minimum: 4
        })
    );

    let mut invalid = submissions.clone();
    let (auth, mut ciphertext, receipt, signature) = invalid[3].clone().into_wire_parts();
    ciphertext[ENCRYPTED_INTENT_V1_LEN / 2] ^= 1;
    invalid[3] = EncryptedSubmissionV1::from_wire_parts(auth, ciphertext, receipt, signature);
    assert_eq!(
        admit_batch(&invalid, &policy),
        Err(CryptoError::InsufficientCrowd {
            valid: 3,
            minimum: 4
        })
    );
}

#[test]
fn encrypted_wire_rejects_trailing_or_changed_bytes() {
    let dealer = EpochDealer::random().expect("dealer");
    let encrypted = dealer
        .public_keys()
        .encrypt(&signed_intent(7, [42; 32], &trading_key(7)))
        .expect("encrypt");

    let mut trailing = encrypted.as_bytes().to_vec();
    trailing.push(0);
    assert!(matches!(
        dealer.public_keys().decode_ciphertext(&trailing),
        Err(CryptoError::InvalidCiphertext)
    ));

    let mut changed = encrypted.as_bytes().to_vec();
    changed[ENCRYPTED_INTENT_V1_LEN / 2] ^= 1;
    assert!(matches!(
        dealer.public_keys().decode_ciphertext(&changed),
        Err(CryptoError::InvalidCiphertext)
    ));
}

#[test]
fn admission_order_is_deterministic_by_participant() {
    let epoch = [42; 32];
    let operator = trading_key(90);
    let policy = policy(epoch, &operator);
    let dealer = EpochDealer::random().expect("dealer");
    let mut by_id = BTreeMap::new();
    for id in [4, 2, 1, 3] {
        let trader = trading_key(id);
        let auth = authorization(id, epoch, &trader, &operator);
        let encrypted = dealer
            .public_keys()
            .encrypt(&signed_intent(id, epoch, &trader))
            .expect("encrypt");
        by_id.insert(
            id,
            EncryptedSubmissionV1::sign(auth, encrypted, [id + 20; 32], &trader).expect("submit"),
        );
    }
    let unordered = [
        by_id[&4].clone(),
        by_id[&2].clone(),
        by_id[&1].clone(),
        by_id[&3].clone(),
    ];
    let batch = admit_batch(&unordered, &policy).expect("batch");
    assert_eq!(
        batch.participant_ids(),
        vec![[1; 32], [2; 32], [3; 32], [4; 32]]
    );
    assert_eq!(
        AdmissionPolicyV1::new(epoch, operator.verifying_key(), 0, 2, 100, 500),
        Err(CryptoError::InvalidMinimum)
    );
}

#[test]
fn crowd_gate_rejects_reused_nonce_receipt_underfunding_and_expiry() {
    let epoch = [42; 32];
    let operator = trading_key(90);
    let policy = policy(epoch, &operator);
    let dealer = EpochDealer::random().expect("dealer");
    let first_three = [
        submission(TestMember::standard(1), epoch, &dealer, &operator),
        submission(TestMember::standard(2), epoch, &dealer, &operator),
        submission(TestMember::standard(3), epoch, &dealer, &operator),
    ];

    let assert_fourth_rejected = |fourth| {
        let candidates = [
            first_three[0].clone(),
            first_three[1].clone(),
            first_three[2].clone(),
            fourth,
        ];
        assert_eq!(
            admit_batch(&candidates, &policy),
            Err(CryptoError::InsufficientCrowd {
                valid: 3,
                minimum: 4,
            })
        );
    };

    assert_fourth_rejected(submission(
        TestMember {
            nonce: 1,
            ..TestMember::standard(4)
        },
        epoch,
        &dealer,
        &operator,
    ));
    assert_fourth_rejected(submission(
        TestMember {
            receipt: 21,
            ..TestMember::standard(4)
        },
        epoch,
        &dealer,
        &operator,
    ));
    assert_fourth_rejected(submission(
        TestMember {
            base_atoms: 1,
            ..TestMember::standard(4)
        },
        epoch,
        &dealer,
        &operator,
    ));
    assert_fourth_rejected(submission(
        TestMember {
            expiry: 400,
            ..TestMember::standard(4)
        },
        epoch,
        &dealer,
        &operator,
    ));
}
