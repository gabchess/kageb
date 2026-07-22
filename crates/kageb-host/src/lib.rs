//! Host-side KageB protocol types.

mod admission;
mod commitment;
mod crypto;
mod demo;
mod domain;
mod keyper;
mod ledger;
mod observer;

pub use admission::{
    JournalError, ReservationJournal, ReservationRecord, ReservationState, SubmissionV1,
    UnsignedFundedAuthorizationV1,
};
pub use commitment::{content_root, CommitmentDomain, CommitmentError};
pub use crypto::{
    admit_batch, AdmissionPolicyV1, AdmittedBatch, CryptoError, EncryptedIntentV1,
    EncryptedSubmissionV1, EpochDealer, EpochPublicKeys, FundedAuthorizationV1, KeyperSecretShare,
    SignedIntentV1, ENCRYPTED_INTENT_V1_LEN, FUNDED_AUTHORIZATION_V1_LEN,
};
pub use demo::trace_fixture;
pub use domain::{IntentBodyV1, ProtocolError, Side};
pub use keyper::{
    handle_keyper_self_test, run_keyper_self_test, KeyperProcessError, KeyperSelfTestResponse,
};
pub use ledger::{
    net_batch, BatchConfig, BatchResult, FundedOrder, LedgerError, PoolBalance, Residual,
    VaultDelta,
};
pub use observer::{DirectOrder, PublicTrace};
