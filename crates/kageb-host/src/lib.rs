//! Host-side KageB protocol types.

mod admission;
mod commitment;
mod crypto;
mod demo;
mod domain;
mod evidence;
mod keyper;
mod ledger;
mod lock;
mod observer;

pub use admission::{
    JournalError, ReservationJournal, ReservationRecord, ReservationState, SubmissionV1,
    SuspensionError, SuspensionRegistry, UnsignedFundedAuthorizationV1,
};
pub use commitment::{content_root, CommitmentDomain, CommitmentError};
pub use crypto::{
    admit_batch, AdmissionPolicyV1, AdmittedBatch, CryptoError, EncryptedIntentV1,
    EncryptedSubmissionV1, EpochDealer, EpochPublicKeys, FundedAuthorizationV1, KeyperSecretShare,
    ReleasedShareV1, SignedIntentV1, ENCRYPTED_INTENT_V1_LEN, FUNDED_AUTHORIZATION_V1_LEN,
};
pub use demo::{devnet_proof, local_proof, trace_fixture};
pub use domain::{IntentBodyV1, ProtocolError, Side};
pub use evidence::{
    extract_upgradeable_program, fetch_devnet_public_snapshot, verify_devnet_evidence,
    verify_devnet_evidence_at_rpc, verify_evidence_file, DecodedInstructionEvidenceV1,
    DecryptionEvidenceV1, DevnetEvidenceBundleV1, DevnetEvidenceContentV1, DevnetEvidenceError,
    DevnetPublicSnapshotV1, EvidenceAccountsV1, EvidenceCommitmentsV1, EvidenceConfigurationV1,
    EvidenceDeploymentV1, EvidenceTokenBalancesV1, EvidenceTransactionV1, EvidenceTransactionsV1,
    ExtractedUpgradeableProgramV1, FinalizedTransactionSnapshotV1, FundingTransactionEvidenceV1,
    PublicAccountSnapshotV1, SettlementApprovalV1, SettlementBalanceV1, SettlementRequestV1,
    SettlementValidationError, DEVNET_GENESIS_HASH, UPGRADEABLE_LOADER_ID,
};
pub use keyper::{
    handle_keyper_release_share, handle_keyper_self_test, handle_keyper_sign_settlement,
    run_keyper_release_share, run_keyper_self_test, run_keyper_sign_settlement, KeyperProcessError,
    KeyperSelfTestResponse,
};
pub use keyper::{handle_keyper_sign_lock, run_keyper_sign_lock};
pub use ledger::{
    net_batch, BatchConfig, BatchResult, FundedOrder, LedgerError, PoolBalance, Residual,
    VaultDelta,
};
pub use lock::{
    BalanceRecordV1, ConfirmedLock, ConfirmedOpenEpoch, LockApprovalV1, LockJournal, LockPackageV1,
    LockValidationError, ProgramClient, ReferenceKeyper, SignedBalanceSnapshotV1,
    MAX_BATCH_MEMBERS,
};
pub use observer::{
    DirectMarketAccounts, DirectOrder, KagebObserverAccounts, ObserverError, PublicTrace,
};
