use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Read,
    path::Path,
    str::FromStr,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use kageb_program::wire::SettlementPayloadV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_program::{instruction::Instruction, program_pack::Pack, pubkey::Pubkey};
use solana_rpc_client::{api::config::RpcTransactionConfig, rpc_client::RpcClient};
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta, UiInstruction,
    UiTransactionEncoding, UiTransactionTokenBalance,
};

use crate::{
    content_root, BatchConfig, ConfirmedLock, FundedOrder, KagebObserverAccounts, LockPackageV1,
    PoolBalance, PublicTrace, ReferenceKeyper, ReleasedShareV1, Residual, SignedIntentV1,
    MAX_BATCH_MEMBERS,
};

const RESULT_COMMITMENT_DOMAIN: &[u8] = b"KAGEB_RESULT_COMMITMENT_V1\0";
const RECOVERED_INTENTS_DOMAIN: &[u8] = b"KAGEB_RECOVERED_INTENTS_V1\0";
const MAX_RELEASED_SHARE_WIRE_LEN: usize = 512;
const EVIDENCE_BUNDLE_DOMAIN: &[u8] = b"KAGEB_EVIDENCE_BUNDLE_V1\0";

pub const UPGRADEABLE_LOADER_ID: Pubkey =
    solana_program::pubkey!("BPFLoaderUpgradeab1e11111111111111111111111");
pub const DEVNET_GENESIS_HASH: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
pub(crate) const CANONICAL_REPOSITORY: &str = "https://github.com/gabchess/kageb.git";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevnetEvidenceBundleV1 {
    pub schema_version: u8,
    pub content: DevnetEvidenceContentV1,
    pub evidence_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevnetEvidenceContentV1 {
    pub cluster: String,
    pub public_commit: String,
    pub build_toolchain: EvidenceBuildToolchainV1,
    pub checkpoint_artifact_len: usize,
    pub checkpoint_artifact_sha256: String,
    pub deployment: EvidenceDeploymentV1,
    pub transactions: EvidenceTransactionsV1,
    pub accounts: EvidenceAccountsV1,
    pub configuration: EvidenceConfigurationV1,
    pub commitments: EvidenceCommitmentsV1,
    pub token_balances: EvidenceTokenBalancesV1,
    pub decoded_allowlist: Vec<DecodedInstructionEvidenceV1>,
    pub explorer_links: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBuildToolchainV1 {
    pub solana_verify: String,
    pub build_image: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiableBuildConfigV1 {
    schema_version: u8,
    solana_verify: String,
    build_image: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDeploymentV1 {
    pub program: String,
    pub loader: String,
    pub programdata: String,
    pub deployment_slot: u64,
    pub upgrade_authority: Option<String>,
    pub deployed_executable_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceTransactionV1 {
    pub signature: String,
    pub slot: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundingTransactionEvidenceV1 {
    pub authority: String,
    pub base_source: String,
    pub quote_source: String,
    pub transaction: EvidenceTransactionV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceTransactionsV1 {
    pub funding: [FundingTransactionEvidenceV1; 4],
    pub lock: EvidenceTransactionV1,
    pub settlement: EvidenceTransactionV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAccountsV1 {
    pub fee_payer: String,
    pub operator: String,
    pub pool: String,
    pub epoch: String,
    pub vault_authority: String,
    pub base_mint: String,
    pub quote_mint: String,
    pub pool_base_vault: String,
    pub pool_quote_vault: String,
    pub venue_authority: String,
    pub venue_base_account: String,
    pub venue_quote_account: String,
    pub token_program: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceConfigurationV1 {
    pub epoch_id: String,
    pub minimum_count: u32,
    pub member_count: u32,
    pub lock_threshold: u8,
    pub settlement_threshold: u8,
    pub keypers: [String; 3],
    pub base_lot_atoms: u64,
    pub quote_atoms_per_lot: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCommitmentsV1 {
    pub configuration_hash: String,
    pub pre_balance_root: String,
    pub member_set: String,
    pub lock_digest: String,
    pub result: String,
    pub settlement_digest: String,
    pub local_transcript_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceTokenBalancesV1 {
    pub pool_base_before: u64,
    pub pool_base_after: u64,
    pub pool_quote_before: u64,
    pub pool_quote_after: u64,
    pub venue_base_before: u64,
    pub venue_base_after: u64,
    pub venue_quote_before: u64,
    pub venue_quote_after: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodedInstructionEvidenceV1 {
    pub transaction: String,
    pub position: u16,
    pub program: String,
    pub kind: String,
    pub digest: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevnetEvidenceError {
    InvalidSchema,
    ContentHashMismatch,
    WrongLoader,
    WrongProgramDataOwner,
    WrongProgramDataAddress,
    MalformedLoaderMetadata,
    TruncatedExecutable,
    InvalidElf,
    NonZeroProgramDataTail,
    InvalidPublicField,
    WrongCluster,
    WrongProgram,
    DeploymentMismatch,
    MissingTransaction,
    UnfinalizedTransaction,
    FailedTransaction,
    TransactionSlotMismatch,
    RepeatedFundingAuthority,
    WrongAccountOwner,
    WrongState,
    WrongMemberCount,
    WrongKeyper,
    ChangedCommitment,
    WrongTokenDelta,
    UnexpectedInstruction,
    SecondSettlement,
    WrongGenesis,
    RpcUnavailable,
    InvalidTransaction,
    InvalidTokenAccount,
    InvalidChronology,
    RepeatedFundingSource,
}

impl DevnetEvidenceBundleV1 {
    pub fn seal(content: DevnetEvidenceContentV1) -> Result<Self, DevnetEvidenceError> {
        let evidence_sha256 = evidence_content_hash(&content)?;
        Ok(Self {
            schema_version: 1,
            content,
            evidence_sha256,
        })
    }

    pub fn from_json(json: &str) -> Result<Self, DevnetEvidenceError> {
        serde_json::from_str(json).map_err(|_| DevnetEvidenceError::InvalidSchema)
    }

    pub fn to_json_pretty(&self) -> Result<String, DevnetEvidenceError> {
        serde_json::to_string_pretty(self).map_err(|_| DevnetEvidenceError::InvalidSchema)
    }

    pub fn verify_content_hash(&self) -> Result<(), DevnetEvidenceError> {
        if self.schema_version != 1 || evidence_content_hash(&self.content)? != self.evidence_sha256
        {
            return Err(DevnetEvidenceError::ContentHashMismatch);
        }
        Ok(())
    }
}

fn evidence_content_hash(content: &DevnetEvidenceContentV1) -> Result<String, DevnetEvidenceError> {
    let encoded = serde_json::to_vec(content).map_err(|_| DevnetEvidenceError::InvalidSchema)?;
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_BUNDLE_DOMAIN);
    hasher.update(encoded);
    Ok(hex_digest(hasher.finalize()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicAccountSnapshotV1 {
    pub owner: Pubkey,
    pub executable: bool,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractedUpgradeableProgramV1 {
    pub deployment_slot: u64,
    pub upgrade_authority: Option<Pubkey>,
    pub executable: Vec<u8>,
    pub executable_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedTransactionSnapshotV1 {
    pub signature: String,
    pub slot: u64,
    pub status_slot: u64,
    pub finalized: bool,
    pub succeeded: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevnetPublicSnapshotV1 {
    pub program: PublicAccountSnapshotV1,
    pub programdata_address: Pubkey,
    pub programdata: PublicAccountSnapshotV1,
    pub pool: PublicAccountSnapshotV1,
    pub epoch: PublicAccountSnapshotV1,
    pub base_mint: PublicAccountSnapshotV1,
    pub quote_mint: PublicAccountSnapshotV1,
    pub current_token_accounts: [PublicAccountSnapshotV1; 4],
    pub transactions: Vec<FinalizedTransactionSnapshotV1>,
    pub token_balances: EvidenceTokenBalancesV1,
    pub decoded_allowlist: Vec<DecodedInstructionEvidenceV1>,
}

pub(crate) struct CanonicalCheckpointV1 {
    pub artifact: Vec<u8>,
    pub build_toolchain: EvidenceBuildToolchainV1,
}

pub fn extract_upgradeable_program(
    program: &PublicAccountSnapshotV1,
    expected_programdata: Pubkey,
    programdata: &PublicAccountSnapshotV1,
    checkpoint_artifact_len: usize,
) -> Result<ExtractedUpgradeableProgramV1, DevnetEvidenceError> {
    if program.owner != UPGRADEABLE_LOADER_ID || !program.executable {
        return Err(DevnetEvidenceError::WrongLoader);
    }
    let program_state: UpgradeableLoaderState = bincode::deserialize(&program.data)
        .map_err(|_| DevnetEvidenceError::MalformedLoaderMetadata)?;
    let UpgradeableLoaderState::Program {
        programdata_address,
    } = program_state
    else {
        return Err(DevnetEvidenceError::MalformedLoaderMetadata);
    };
    if programdata_address.to_bytes() != expected_programdata.to_bytes() {
        return Err(DevnetEvidenceError::WrongProgramDataAddress);
    }
    if programdata.owner != UPGRADEABLE_LOADER_ID || programdata.executable {
        return Err(DevnetEvidenceError::WrongProgramDataOwner);
    }
    let metadata_len = UpgradeableLoaderState::size_of_programdata_metadata();
    let metadata = programdata
        .data
        .get(..metadata_len)
        .ok_or(DevnetEvidenceError::MalformedLoaderMetadata)?;
    let programdata_state: UpgradeableLoaderState =
        bincode::deserialize(metadata).map_err(|_| DevnetEvidenceError::MalformedLoaderMetadata)?;
    let UpgradeableLoaderState::ProgramData {
        slot,
        upgrade_authority_address,
    } = programdata_state
    else {
        return Err(DevnetEvidenceError::MalformedLoaderMetadata);
    };
    let executable_end = metadata_len
        .checked_add(checkpoint_artifact_len)
        .ok_or(DevnetEvidenceError::TruncatedExecutable)?;
    let executable = programdata
        .data
        .get(metadata_len..executable_end)
        .ok_or(DevnetEvidenceError::TruncatedExecutable)?;
    if !executable.starts_with(b"\x7fELF") {
        return Err(DevnetEvidenceError::InvalidElf);
    }
    if programdata.data[executable_end..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(DevnetEvidenceError::NonZeroProgramDataTail);
    }
    Ok(ExtractedUpgradeableProgramV1 {
        deployment_slot: slot,
        upgrade_authority: upgrade_authority_address
            .map(|address| Pubkey::new_from_array(address.to_bytes())),
        executable: executable.to_vec(),
        executable_sha256: hex_digest(Sha256::digest(executable)),
    })
}

pub fn verify_devnet_evidence(
    bundle: &DevnetEvidenceBundleV1,
    snapshot: &DevnetPublicSnapshotV1,
    checkpoint_artifact: &[u8],
) -> Result<(), DevnetEvidenceError> {
    bundle.verify_content_hash()?;
    let evidence = &bundle.content;
    validate_public_fields(evidence, checkpoint_artifact)?;
    validate_deployment(evidence, snapshot, checkpoint_artifact)?;
    validate_transactions(evidence, &snapshot.transactions)?;
    validate_distinct_funding_authorities(evidence)?;
    let (pool, epoch) = validate_program_state(evidence, snapshot)?;
    validate_token_deltas(evidence, snapshot, &epoch)?;
    validate_allowlist(evidence, snapshot, pool.settlement_threshold)?;
    Ok(())
}

fn validate_public_fields(
    evidence: &DevnetEvidenceContentV1,
    checkpoint_artifact: &[u8],
) -> Result<(), DevnetEvidenceError> {
    if evidence.cluster != "devnet" {
        return Err(DevnetEvidenceError::WrongCluster);
    }
    if evidence.public_commit.len() != 40
        || !evidence
            .public_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || evidence.checkpoint_artifact_len != checkpoint_artifact.len()
        || parse_digest(&evidence.checkpoint_artifact_sha256)?
            != Sha256::digest(checkpoint_artifact).as_slice()
    {
        return Err(DevnetEvidenceError::InvalidPublicField);
    }
    for identity in [
        &evidence.build_toolchain.solana_verify,
        &evidence.build_toolchain.build_image,
    ] {
        if identity.is_empty()
            || identity.len() > 128
            || !identity
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        {
            return Err(DevnetEvidenceError::InvalidPublicField);
        }
    }
    if parse_pubkey(&evidence.deployment.program)? != kageb_program::ID
        || parse_pubkey(&evidence.accounts.token_program)? != kageb_program::TOKEN_PROGRAM_ID
    {
        return Err(DevnetEvidenceError::WrongProgram);
    }
    if parse_pubkey(&evidence.deployment.loader)? != UPGRADEABLE_LOADER_ID {
        return Err(DevnetEvidenceError::WrongLoader);
    }
    let canonical_programdata =
        Pubkey::find_program_address(&[kageb_program::ID.as_ref()], &UPGRADEABLE_LOADER_ID).0;
    if parse_pubkey(&evidence.deployment.programdata)? != canonical_programdata {
        return Err(DevnetEvidenceError::WrongProgramDataAddress);
    }
    let transactions = evidence
        .transactions
        .funding
        .iter()
        .map(|funding| &funding.transaction)
        .chain([
            &evidence.transactions.lock,
            &evidence.transactions.settlement,
        ]);
    if evidence.explorer_links.len() != 6
        || !evidence
            .explorer_links
            .iter()
            .zip(transactions)
            .all(|(link, transaction)| {
                link == &format!(
                    "https://explorer.solana.com/tx/{}?cluster=devnet",
                    transaction.signature
                )
            })
    {
        return Err(DevnetEvidenceError::InvalidPublicField);
    }
    Ok(())
}

fn validate_deployment(
    evidence: &DevnetEvidenceContentV1,
    snapshot: &DevnetPublicSnapshotV1,
    checkpoint_artifact: &[u8],
) -> Result<(), DevnetEvidenceError> {
    let programdata = parse_pubkey(&evidence.deployment.programdata)?;
    if programdata != snapshot.programdata_address {
        return Err(DevnetEvidenceError::WrongProgramDataAddress);
    }
    let extracted = extract_upgradeable_program(
        &snapshot.program,
        programdata,
        &snapshot.programdata,
        evidence.checkpoint_artifact_len,
    )?;
    let upgrade_authority = evidence
        .deployment
        .upgrade_authority
        .as_deref()
        .map(parse_pubkey)
        .transpose()?;
    if extracted.deployment_slot != evidence.deployment.deployment_slot
        || extracted.upgrade_authority != upgrade_authority
        || extracted.executable.as_slice() != checkpoint_artifact
        || extracted.executable_sha256 != evidence.deployment.deployed_executable_sha256
        || extracted.executable_sha256 != evidence.checkpoint_artifact_sha256
    {
        return Err(DevnetEvidenceError::DeploymentMismatch);
    }
    Ok(())
}

fn validate_transactions(
    evidence: &DevnetEvidenceContentV1,
    snapshots: &[FinalizedTransactionSnapshotV1],
) -> Result<(), DevnetEvidenceError> {
    let expected = evidence
        .transactions
        .funding
        .iter()
        .map(|funding| &funding.transaction)
        .chain([
            &evidence.transactions.lock,
            &evidence.transactions.settlement,
        ]);
    let mut signatures = BTreeSet::new();
    for transaction in expected {
        solana_signature::Signature::from_str(&transaction.signature)
            .map_err(|_| DevnetEvidenceError::InvalidPublicField)?;
        if !signatures.insert(transaction.signature.as_str()) {
            return Err(DevnetEvidenceError::UnexpectedInstruction);
        }
        let fetched = snapshots
            .iter()
            .find(|snapshot| snapshot.signature == transaction.signature)
            .ok_or(DevnetEvidenceError::MissingTransaction)?;
        if !fetched.finalized {
            return Err(DevnetEvidenceError::UnfinalizedTransaction);
        }
        if !fetched.succeeded {
            return Err(DevnetEvidenceError::FailedTransaction);
        }
        if fetched.slot != transaction.slot {
            return Err(DevnetEvidenceError::TransactionSlotMismatch);
        }
        if fetched.status_slot != transaction.slot {
            return Err(DevnetEvidenceError::TransactionSlotMismatch);
        }
    }
    if snapshots.len() != signatures.len() {
        return Err(DevnetEvidenceError::UnexpectedInstruction);
    }
    let deployment_slot = evidence.deployment.deployment_slot;
    let lock_slot = evidence.transactions.lock.slot;
    let settlement_slot = evidence.transactions.settlement.slot;
    if deployment_slot >= lock_slot
        || lock_slot >= settlement_slot
        || evidence.transactions.funding.iter().any(|funding| {
            funding.transaction.slot <= deployment_slot || funding.transaction.slot >= lock_slot
        })
    {
        return Err(DevnetEvidenceError::InvalidChronology);
    }
    Ok(())
}

fn validate_distinct_funding_authorities(
    evidence: &DevnetEvidenceContentV1,
) -> Result<(), DevnetEvidenceError> {
    let mut authorities = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for funding in &evidence.transactions.funding {
        let authority = parse_pubkey(&funding.authority)?;
        if authority == Pubkey::default() || !authorities.insert(authority) {
            return Err(DevnetEvidenceError::RepeatedFundingAuthority);
        }
        for source in [&funding.base_source, &funding.quote_source] {
            if !sources.insert(parse_pubkey(source)?) {
                return Err(DevnetEvidenceError::RepeatedFundingSource);
            }
        }
    }
    Ok(())
}

fn validate_program_state(
    evidence: &DevnetEvidenceContentV1,
    snapshot: &DevnetPublicSnapshotV1,
) -> Result<
    (
        kageb_program::state::PoolStateV1,
        kageb_program::state::EpochStateV1,
    ),
    DevnetEvidenceError,
> {
    if snapshot.pool.owner != kageb_program::ID
        || snapshot.pool.executable
        || snapshot.epoch.owner != kageb_program::ID
        || snapshot.epoch.executable
    {
        return Err(DevnetEvidenceError::WrongAccountOwner);
    }
    let pool = kageb_program::state::PoolStateV1::decode(&snapshot.pool.data)
        .map_err(|_| DevnetEvidenceError::WrongState)?;
    let epoch = kageb_program::state::EpochStateV1::decode(&snapshot.epoch.data)
        .map_err(|_| DevnetEvidenceError::WrongState)?;
    let operator = parse_pubkey(&evidence.accounts.operator)?;
    let base_mint = parse_pubkey(&evidence.accounts.base_mint)?;
    let quote_mint = parse_pubkey(&evidence.accounts.quote_mint)?;
    let expected_pool = parse_pubkey(&evidence.accounts.pool)?;
    let expected_epoch = parse_pubkey(&evidence.accounts.epoch)?;
    let expected_vault_authority = parse_pubkey(&evidence.accounts.vault_authority)?;
    let (derived_pool, pool_bump) = kageb_program::pool_address(&operator, &base_mint, &quote_mint);
    let (derived_vault_authority, vault_bump) =
        kageb_program::vault_authority_address(&derived_pool);
    let epoch_id = parse_digest(&evidence.configuration.epoch_id)?;
    let (derived_epoch, epoch_bump) = kageb_program::epoch_address(&derived_pool, &epoch_id);
    if expected_pool != derived_pool
        || expected_epoch != derived_epoch
        || expected_vault_authority != derived_vault_authority
        || pool.pool_bump != pool_bump
        || pool.vault_bump != vault_bump
        || epoch.epoch_bump != epoch_bump
        || pool.operator != operator
        || pool.base_mint != base_mint
        || pool.quote_mint != quote_mint
        || pool.pool_base_vault != parse_pubkey(&evidence.accounts.pool_base_vault)?
        || pool.pool_quote_vault != parse_pubkey(&evidence.accounts.pool_quote_vault)?
        || pool.venue_authority != parse_pubkey(&evidence.accounts.venue_authority)?
        || pool.venue_base_account != parse_pubkey(&evidence.accounts.venue_base_account)?
        || pool.venue_quote_account != parse_pubkey(&evidence.accounts.venue_quote_account)?
        || epoch.pool != expected_pool
        || epoch.epoch_id != epoch_id
        || epoch.terminal_state != kageb_program::state::EpochTerminalState::Settled
        || epoch.settlement_nonce == [0; 32]
        || epoch.lock_nonce == [0; 32]
    {
        return Err(DevnetEvidenceError::WrongState);
    }
    if evidence.configuration.member_count != 4
        || evidence.configuration.minimum_count != 4
        || epoch.member_count != evidence.configuration.member_count
        || epoch.minimum_count != evidence.configuration.minimum_count
        || epoch.member_count < epoch.minimum_count
    {
        return Err(DevnetEvidenceError::WrongMemberCount);
    }
    let mut keypers = [Pubkey::default(); 3];
    for (slot, encoded) in keypers.iter_mut().zip(&evidence.configuration.keypers) {
        *slot = parse_pubkey(encoded)?;
    }
    if keypers != pool.keypers
        || keypers.iter().collect::<BTreeSet<_>>().len() != keypers.len()
        || evidence.configuration.lock_threshold != pool.lock_threshold
        || evidence.configuration.settlement_threshold != pool.settlement_threshold
        || pool.lock_threshold != 2
        || pool.settlement_threshold != 2
    {
        return Err(DevnetEvidenceError::WrongKeyper);
    }
    if evidence.configuration.base_lot_atoms != pool.base_lot_atoms
        || evidence.configuration.base_lot_atoms != epoch.base_lot_atoms
        || evidence.configuration.quote_atoms_per_lot != epoch.quote_atoms_per_lot
    {
        return Err(DevnetEvidenceError::WrongState);
    }
    if epoch.configuration_hash != parse_digest(&evidence.commitments.configuration_hash)?
        || epoch.pre_balance_root != parse_digest(&evidence.commitments.pre_balance_root)?
        || epoch.member_root != parse_digest(&evidence.commitments.member_set)?
        || epoch.lock_digest != parse_digest(&evidence.commitments.lock_digest)?
        || epoch.result_commitment != parse_digest(&evidence.commitments.result)?
        || epoch.settlement_digest != parse_digest(&evidence.commitments.settlement_digest)?
    {
        return Err(DevnetEvidenceError::ChangedCommitment);
    }
    parse_digest(&evidence.commitments.local_transcript_sha256)?;
    Ok((pool, epoch))
}

fn validate_token_deltas(
    evidence: &DevnetEvidenceContentV1,
    snapshot: &DevnetPublicSnapshotV1,
    epoch: &kageb_program::state::EpochStateV1,
) -> Result<(), DevnetEvidenceError> {
    validate_public_mint(&snapshot.base_mint)?;
    validate_public_mint(&snapshot.quote_mint)?;
    validate_current_token_accounts(evidence, &snapshot.current_token_accounts)?;
    let balances = &evidence.token_balances;
    let base_before = balances
        .pool_base_before
        .checked_add(balances.venue_base_before)
        .ok_or(DevnetEvidenceError::WrongTokenDelta)?;
    let base_after = balances
        .pool_base_after
        .checked_add(balances.venue_base_after)
        .ok_or(DevnetEvidenceError::WrongTokenDelta)?;
    let quote_before = balances
        .pool_quote_before
        .checked_add(balances.venue_quote_before)
        .ok_or(DevnetEvidenceError::WrongTokenDelta)?;
    let quote_after = balances
        .pool_quote_after
        .checked_add(balances.venue_quote_after)
        .ok_or(DevnetEvidenceError::WrongTokenDelta)?;
    if balances != &snapshot.token_balances
        || base_before != base_after
        || quote_before != quote_after
    {
        return Err(DevnetEvidenceError::WrongTokenDelta);
    }
    let lots = u64::from(epoch.residual_lots);
    let base = epoch
        .base_lot_atoms
        .checked_mul(lots)
        .ok_or(DevnetEvidenceError::WrongTokenDelta)?;
    let quote = epoch
        .quote_atoms_per_lot
        .checked_mul(lots)
        .ok_or(DevnetEvidenceError::WrongTokenDelta)?;
    let deltas = (
        i128::from(balances.pool_base_after) - i128::from(balances.pool_base_before),
        i128::from(balances.pool_quote_after) - i128::from(balances.pool_quote_before),
        i128::from(balances.venue_base_after) - i128::from(balances.venue_base_before),
        i128::from(balances.venue_quote_after) - i128::from(balances.venue_quote_before),
    );
    let expected = match (epoch.residual_side, epoch.residual_lots) {
        (0, 0) => (0, 0, 0, 0),
        (1, 1..=u32::MAX) => (
            i128::from(base),
            -i128::from(quote),
            -i128::from(base),
            i128::from(quote),
        ),
        (2, 1..=u32::MAX) => (
            -i128::from(base),
            i128::from(quote),
            i128::from(base),
            -i128::from(quote),
        ),
        _ => return Err(DevnetEvidenceError::WrongTokenDelta),
    };
    if deltas != expected {
        return Err(DevnetEvidenceError::WrongTokenDelta);
    }
    Ok(())
}

fn validate_public_mint(mint: &PublicAccountSnapshotV1) -> Result<(), DevnetEvidenceError> {
    if mint.owner != kageb_program::TOKEN_PROGRAM_ID || mint.executable {
        return Err(DevnetEvidenceError::InvalidTokenAccount);
    }
    let mint = spl_token_interface::state::Mint::unpack(&mint.data)
        .map_err(|_| DevnetEvidenceError::InvalidTokenAccount)?;
    if mint.decimals != 0 || mint.mint_authority.is_some() || mint.freeze_authority.is_some() {
        return Err(DevnetEvidenceError::InvalidTokenAccount);
    }
    Ok(())
}

fn validate_current_token_accounts(
    evidence: &DevnetEvidenceContentV1,
    accounts: &[PublicAccountSnapshotV1; 4],
) -> Result<(), DevnetEvidenceError> {
    let expected = [
        (
            &evidence.accounts.base_mint,
            &evidence.accounts.vault_authority,
        ),
        (
            &evidence.accounts.quote_mint,
            &evidence.accounts.vault_authority,
        ),
        (
            &evidence.accounts.base_mint,
            &evidence.accounts.venue_authority,
        ),
        (
            &evidence.accounts.quote_mint,
            &evidence.accounts.venue_authority,
        ),
    ];
    for (account, (mint, authority)) in accounts.iter().zip(expected) {
        if account.owner != kageb_program::TOKEN_PROGRAM_ID || account.executable {
            return Err(DevnetEvidenceError::InvalidTokenAccount);
        }
        let token = spl_token_interface::state::Account::unpack(&account.data)
            .map_err(|_| DevnetEvidenceError::InvalidTokenAccount)?;
        if token.mint != parse_pubkey(mint)?
            || token.owner != parse_pubkey(authority)?
            || token.state != spl_token_interface::state::AccountState::Initialized
        {
            return Err(DevnetEvidenceError::InvalidTokenAccount);
        }
    }
    Ok(())
}

fn validate_allowlist(
    evidence: &DevnetEvidenceContentV1,
    snapshot: &DevnetPublicSnapshotV1,
    settlement_threshold: u8,
) -> Result<(), DevnetEvidenceError> {
    let aggregate_count = snapshot
        .decoded_allowlist
        .iter()
        .filter(|instruction| instruction.kind == "aggregate-settlement")
        .count();
    if aggregate_count > 1 {
        return Err(DevnetEvidenceError::SecondSettlement);
    }
    if aggregate_count != 1 {
        return Err(DevnetEvidenceError::UnexpectedInstruction);
    }
    let lock_approvals = snapshot
        .decoded_allowlist
        .iter()
        .filter(|instruction| instruction.kind == "keyper-lock-approval")
        .count();
    let settlement_approvals = snapshot
        .decoded_allowlist
        .iter()
        .filter(|instruction| instruction.kind == "keyper-settlement-approval")
        .count();
    if lock_approvals != usize::from(evidence.configuration.lock_threshold)
        || settlement_approvals != usize::from(settlement_threshold)
        || snapshot.decoded_allowlist != evidence.decoded_allowlist
    {
        return Err(DevnetEvidenceError::UnexpectedInstruction);
    }
    for instruction in &snapshot.decoded_allowlist {
        let expected_digest = match instruction.kind.as_str() {
            "keyper-lock-approval" | "epoch-lock" => Some(&evidence.commitments.lock_digest),
            "keyper-settlement-approval" | "aggregate-settlement" => {
                Some(&evidence.commitments.settlement_digest)
            }
            "pool-funding-base"
            | "pool-funding-quote"
            | "aggregate-base-leg"
            | "aggregate-quote-leg" => None,
            _ => return Err(DevnetEvidenceError::UnexpectedInstruction),
        };
        if instruction.digest.as_ref() != expected_digest {
            return Err(DevnetEvidenceError::UnexpectedInstruction);
        }
        if let Some(digest) = &instruction.digest {
            parse_digest(digest)?;
        }
    }
    Ok(())
}

fn parse_pubkey(encoded: &str) -> Result<Pubkey, DevnetEvidenceError> {
    Pubkey::from_str(encoded).map_err(|_| DevnetEvidenceError::InvalidPublicField)
}

fn parse_digest(encoded: &str) -> Result<[u8; 32], DevnetEvidenceError> {
    let encoded = encoded.as_bytes();
    if encoded.len() != 64 || !encoded.iter().all(u8::is_ascii_hexdigit) {
        return Err(DevnetEvidenceError::InvalidPublicField);
    }
    let mut decoded = [0_u8; 32];
    for (pair, byte) in encoded.chunks_exact(2).zip(&mut decoded) {
        *byte = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Result<u8, DevnetEvidenceError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(DevnetEvidenceError::InvalidPublicField),
    }
}

fn validate_rpc_response_len(actual: usize, expected: usize) -> Result<(), DevnetEvidenceError> {
    if actual != expected {
        return Err(DevnetEvidenceError::RpcUnavailable);
    }
    Ok(())
}

fn verify_queried_transaction(
    transaction: &solana_transaction::versioned::VersionedTransaction,
    expected: &solana_signature::Signature,
) -> Result<(), DevnetEvidenceError> {
    if transaction.signatures.first() != Some(expected) {
        return Err(DevnetEvidenceError::InvalidTransaction);
    }
    transaction
        .verify_and_hash_message()
        .map(|_| ())
        .map_err(|_| DevnetEvidenceError::InvalidTransaction)
}

fn verify_ed25519_instruction(
    instruction: &Instruction,
) -> Result<kageb_program::ed25519::StrictEd25519, DevnetEvidenceError> {
    let parsed = kageb_program::ed25519::parse_strict_ed25519(instruction)
        .map_err(|_| DevnetEvidenceError::InvalidTransaction)?;
    let signature = Signature::from_slice(
        instruction
            .data
            .get(48..112)
            .ok_or(DevnetEvidenceError::InvalidTransaction)?,
    )
    .map_err(|_| DevnetEvidenceError::InvalidTransaction)?;
    let key = VerifyingKey::from_bytes(parsed.signer.as_array())
        .map_err(|_| DevnetEvidenceError::InvalidTransaction)?;
    key.verify_strict(&parsed.digest, &signature)
        .map_err(|_| DevnetEvidenceError::InvalidTransaction)?;
    Ok(parsed)
}

pub fn fetch_devnet_public_snapshot(
    bundle: &DevnetEvidenceBundleV1,
    rpc_url: &str,
) -> Result<DevnetPublicSnapshotV1, DevnetEvidenceError> {
    bundle.verify_content_hash()?;
    let rpc = RpcClient::new_with_commitment(
        rpc_url.to_owned(),
        solana_commitment_config::CommitmentConfig::finalized(),
    );
    if rpc
        .get_genesis_hash()
        .map_err(|_| DevnetEvidenceError::RpcUnavailable)?
        .to_string()
        != DEVNET_GENESIS_HASH
    {
        return Err(DevnetEvidenceError::WrongGenesis);
    }
    let evidence = &bundle.content;
    let program_address = parse_pubkey(&evidence.deployment.program)?;
    let programdata_address = parse_pubkey(&evidence.deployment.programdata)?;
    let pool_address = parse_pubkey(&evidence.accounts.pool)?;
    let epoch_address = parse_pubkey(&evidence.accounts.epoch)?;
    let base_mint_address = parse_pubkey(&evidence.accounts.base_mint)?;
    let quote_mint_address = parse_pubkey(&evidence.accounts.quote_mint)?;
    let program = fetch_finalized_account(&rpc, program_address)?;
    let programdata = fetch_finalized_account(&rpc, programdata_address)?;
    let pool = fetch_finalized_account(&rpc, pool_address)?;
    let epoch = fetch_finalized_account(&rpc, epoch_address)?;
    let base_mint = fetch_finalized_account(&rpc, base_mint_address)?;
    let quote_mint = fetch_finalized_account(&rpc, quote_mint_address)?;

    let expected_transactions: Vec<&EvidenceTransactionV1> = evidence
        .transactions
        .funding
        .iter()
        .map(|funding| &funding.transaction)
        .chain([
            &evidence.transactions.lock,
            &evidence.transactions.settlement,
        ])
        .collect();
    let signatures: Vec<_> = expected_transactions
        .iter()
        .map(|transaction| {
            solana_signature::Signature::from_str(&transaction.signature)
                .map_err(|_| DevnetEvidenceError::InvalidPublicField)
        })
        .collect::<Result<_, _>>()?;
    let statuses = rpc
        .get_signature_statuses_with_history(&signatures)
        .map_err(|_| DevnetEvidenceError::RpcUnavailable)?
        .value;
    validate_rpc_response_len(statuses.len(), signatures.len())?;
    let mut transaction_snapshots = Vec::with_capacity(signatures.len());
    let mut fetched_transactions = Vec::with_capacity(signatures.len());
    for index in 0..signatures.len() {
        let expected = expected_transactions
            .get(index)
            .ok_or(DevnetEvidenceError::RpcUnavailable)?;
        let signature = signatures
            .get(index)
            .ok_or(DevnetEvidenceError::RpcUnavailable)?;
        let status = statuses
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(DevnetEvidenceError::MissingTransaction)?;
        let finalized =
            status.satisfies_commitment(solana_commitment_config::CommitmentConfig::finalized());
        let succeeded = status.err.is_none() && status.status.is_ok();
        let fetched = rpc
            .get_transaction_with_config(
                signature,
                RpcTransactionConfig {
                    encoding: Some(UiTransactionEncoding::Base64),
                    commitment: Some(solana_commitment_config::CommitmentConfig::finalized()),
                    max_supported_transaction_version: Some(0),
                },
            )
            .map_err(|_| DevnetEvidenceError::MissingTransaction)?;
        let decoded = fetched
            .transaction
            .transaction
            .decode()
            .ok_or(DevnetEvidenceError::InvalidTransaction)?;
        verify_queried_transaction(&decoded, signature)?;
        transaction_snapshots.push(FinalizedTransactionSnapshotV1 {
            signature: expected.signature.clone(),
            slot: fetched.slot,
            status_slot: status.slot,
            finalized,
            succeeded,
        });
        fetched_transactions.push(fetched);
    }

    let mut decoded_allowlist = Vec::new();
    let mut funding_sources = BTreeSet::new();
    for index in 0..4 {
        let funding = evidence
            .transactions
            .funding
            .get(index)
            .ok_or(DevnetEvidenceError::InvalidTransaction)?;
        let transaction = fetched_transactions
            .get(index)
            .ok_or(DevnetEvidenceError::InvalidTransaction)?;
        decoded_allowlist.extend(decode_funding_transaction(
            transaction,
            index,
            funding,
            evidence,
            &mut funding_sources,
        )?);
    }
    let lock = fetched_transactions
        .get(4)
        .ok_or(DevnetEvidenceError::InvalidTransaction)?;
    let settlement = fetched_transactions
        .get(5)
        .ok_or(DevnetEvidenceError::InvalidTransaction)?;
    let observer_accounts = observer_accounts(evidence)?;
    PublicTrace::from_confirmed_kageb(lock, settlement, observer_accounts)
        .map_err(|_| DevnetEvidenceError::InvalidTransaction)?;
    decoded_allowlist.extend(decode_kageb_transaction(lock, "lock", evidence)?);
    decoded_allowlist.extend(decode_kageb_transaction(
        settlement,
        "settlement",
        evidence,
    )?);
    let token_balances = transaction_token_balances(settlement, evidence)?;
    let current_token_accounts = fetch_live_token_accounts(&rpc, evidence)?;
    Ok(DevnetPublicSnapshotV1 {
        program,
        programdata_address,
        programdata,
        pool,
        epoch,
        base_mint,
        quote_mint,
        current_token_accounts,
        transactions: transaction_snapshots,
        token_balances,
        decoded_allowlist,
    })
}

pub fn verify_devnet_evidence_at_rpc(
    bundle: &DevnetEvidenceBundleV1,
    checkpoint_artifact: &[u8],
    rpc_url: &str,
) -> Result<(), DevnetEvidenceError> {
    let snapshot = fetch_devnet_public_snapshot(bundle, rpc_url)?;
    verify_devnet_evidence(bundle, &snapshot, checkpoint_artifact)
}

pub(crate) fn build_canonical_checkpoint(commit: &str) -> Result<CanonicalCheckpointV1, String> {
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("checkpoint commit must be 40 ASCII hex characters".to_owned());
    }
    let temporary =
        tempfile::tempdir().map_err(|_| "create checkpoint workspace failed".to_owned())?;
    let checkout = temporary.path().join("checkpoint");
    command_output(
        std::process::Command::new("git")
            .args(["clone", "--quiet", "--no-checkout", CANONICAL_REPOSITORY])
            .arg(&checkout),
        "clone canonical checkpoint",
    )?;
    command_output(
        std::process::Command::new("git")
            .args(["cat-file", "-e", &format!("{commit}^{{commit}}")])
            .current_dir(&checkout),
        "resolve canonical checkpoint",
    )?;
    let reachable = command_output(
        std::process::Command::new("git")
            .args([
                "for-each-ref",
                "--format=%(refname)",
                &format!("--contains={commit}"),
                "refs/remotes/origin",
                "refs/tags",
            ])
            .current_dir(&checkout),
        "check canonical checkpoint reachability",
    )?;
    if reachable.trim().is_empty() {
        return Err("checkpoint commit is not reachable from the canonical repository".to_owned());
    }
    command_output(
        std::process::Command::new("git")
            .args(["checkout", "--quiet", "--detach", commit])
            .current_dir(&checkout),
        "checkout canonical checkpoint",
    )?;
    if !command_output(
        std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&checkout),
        "inspect canonical checkpoint",
    )?
    .trim()
    .is_empty()
    {
        return Err("canonical checkpoint checkout is not clean".to_owned());
    }
    let build_toolchain = read_verifiable_build_config(&checkout)?;
    let solana_verify = crate::demo::resolve_on_path("solana-verify")
        .map_err(|_| "resolve solana-verify failed".to_owned())?;
    let observed_version = command_output(
        std::process::Command::new(&solana_verify)
            .arg("--version")
            .current_dir(&checkout),
        "read solana-verify identity",
    )?;
    if observed_version.trim() != build_toolchain.solana_verify {
        return Err(format!(
            "solana-verify identity differs from checkpoint config: expected {:?}, observed {:?}",
            build_toolchain.solana_verify,
            observed_version.trim()
        ));
    }
    command_output(
        std::process::Command::new(&solana_verify)
            .arg("build")
            .arg(&checkout)
            .arg("--workspace-path")
            .arg(&checkout)
            .args(["--library-name", "kageb_program", "--base-image"])
            .arg(&build_toolchain.build_image)
            .current_dir(&checkout),
        "build canonical checkpoint",
    )?;
    let artifact = std::fs::read(checkout.join("target/deploy/kageb_program.so"))
        .map_err(|_| "read canonical checkpoint artifact failed".to_owned())?;
    if !artifact.starts_with(b"\x7fELF") {
        return Err("canonical checkpoint artifact is not ELF".to_owned());
    }
    Ok(CanonicalCheckpointV1 {
        artifact,
        build_toolchain,
    })
}

pub(crate) fn read_verified_checkpoint(
    root: &Path,
    path: &Path,
) -> Result<CanonicalCheckpointV1, String> {
    const MAX_CHECKPOINT_BYTES: u64 = 2 * 1024 * 1024;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = options
        .open(path)
        .map_err(|_| "read verified checkpoint failed".to_owned())?;
    let metadata = file
        .metadata()
        .map_err(|_| "read verified checkpoint metadata failed".to_owned())?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CHECKPOINT_BYTES {
        return Err("regular verified checkpoint within size limit required".to_owned());
    }
    let mut artifact = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut artifact)
        .map_err(|_| "read verified checkpoint failed".to_owned())?;
    if !artifact.starts_with(b"\x7fELF") {
        return Err("verified checkpoint artifact is not ELF".to_owned());
    }
    Ok(CanonicalCheckpointV1 {
        artifact,
        build_toolchain: read_verifiable_build_config(root)?,
    })
}

fn read_verifiable_build_config(root: &Path) -> Result<EvidenceBuildToolchainV1, String> {
    let encoded = std::fs::read(root.join("verifiable-build.json"))
        .map_err(|_| "read verifiable build config failed".to_owned())?;
    let config: VerifiableBuildConfigV1 = serde_json::from_slice(&encoded)
        .map_err(|_| "parse verifiable build config failed".to_owned())?;
    if config.schema_version != 1
        || config.solana_verify != "solana-verify 0.5.1"
        || !config
            .build_image
            .starts_with("solanafoundation/solana-verifiable-build@sha256:")
        || config.build_image.len() != "solanafoundation/solana-verifiable-build@sha256:".len() + 64
        || !config
            .build_image
            .rsplit_once(':')
            .map(|(_, digest)| digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .unwrap_or(false)
    {
        return Err("invalid verifiable build config".to_owned());
    }
    Ok(EvidenceBuildToolchainV1 {
        solana_verify: config.solana_verify,
        build_image: config.build_image,
    })
}

fn command_output(command: &mut std::process::Command, label: &str) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|_| format!("{label} failed to launch"))?;
    if !output.status.success() {
        return Err(format!("{label} failed"));
    }
    String::from_utf8(output.stdout).map_err(|_| format!("{label} returned non-UTF-8 output"))
}

pub fn verify_evidence_file(path: &Path, rpc_url: &str) -> Result<String, String> {
    let json = read_evidence_input(path)?;
    let bundle = DevnetEvidenceBundleV1::from_json(&json)
        .map_err(|error| format!("parse evidence: {error:?}"))?;
    bundle
        .verify_content_hash()
        .map_err(|error| format!("verify evidence content address: {error:?}"))?;
    let checkpoint = build_canonical_checkpoint(&bundle.content.public_commit)?;
    if let Some(mismatch) =
        build_toolchain_mismatch(&bundle.content.build_toolchain, &checkpoint.build_toolchain)
    {
        return Err(mismatch);
    }
    let checkpoint_sha256 = hex_digest(Sha256::digest(&checkpoint.artifact));
    if checkpoint.artifact.len() != bundle.content.checkpoint_artifact_len
        || checkpoint_sha256 != bundle.content.checkpoint_artifact_sha256
    {
        return Err(format!(
            "canonical checkpoint artifact differs from evidence: expected len {} sha256 {}, observed len {} sha256 {}",
            bundle.content.checkpoint_artifact_len,
            bundle.content.checkpoint_artifact_sha256,
            checkpoint.artifact.len(),
            checkpoint_sha256
        ));
    }
    verify_devnet_evidence_at_rpc(&bundle, &checkpoint.artifact, rpc_url)
        .map_err(|error| format!("verify finalized devnet evidence: {error:?}"))?;
    Ok(format!(
        "VERIFIED: evidence {} settlement {}\n",
        bundle.evidence_sha256, bundle.content.transactions.settlement.signature
    ))
}

fn build_toolchain_mismatch(
    expected: &EvidenceBuildToolchainV1,
    observed: &EvidenceBuildToolchainV1,
) -> Option<String> {
    [
        (
            "solana_verify",
            &expected.solana_verify,
            &observed.solana_verify,
        ),
        ("build_image", &expected.build_image, &observed.build_image),
    ]
    .into_iter()
    .find(|(_, expected, observed)| expected != observed)
    .map(|(field, expected, observed)| {
        format!(
            "canonical checkpoint {field} differs from evidence: expected {expected:?}, observed {observed:?}"
        )
    })
}

fn read_evidence_input(path: &Path) -> Result<String, String> {
    const MAX_EVIDENCE_BYTES: usize = 65_536;

    let mut bytes = Vec::with_capacity(MAX_EVIDENCE_BYTES.min(8 * 1024));
    if path == Path::new("-") {
        std::io::stdin()
            .lock()
            .take((MAX_EVIDENCE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "read evidence stdin failed".to_owned())?;
    } else {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options
            .open(path)
            .map_err(|_| "regular evidence file required".to_owned())?;
        if !file
            .metadata()
            .map_err(|_| "read evidence metadata failed".to_owned())?
            .file_type()
            .is_file()
        {
            return Err("regular evidence file required".to_owned());
        }
        file.take((MAX_EVIDENCE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "read evidence failed".to_owned())?;
    }
    if bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(format!("evidence exceeds {MAX_EVIDENCE_BYTES} bytes"));
    }
    String::from_utf8(bytes).map_err(|_| "evidence is not UTF-8".to_owned())
}

fn fetch_finalized_account(
    rpc: &RpcClient,
    address: Pubkey,
) -> Result<PublicAccountSnapshotV1, DevnetEvidenceError> {
    let account = rpc
        .get_account_with_commitment(
            &address,
            solana_commitment_config::CommitmentConfig::finalized(),
        )
        .map_err(|_| DevnetEvidenceError::RpcUnavailable)?
        .value
        .ok_or(DevnetEvidenceError::RpcUnavailable)?;
    Ok(PublicAccountSnapshotV1 {
        owner: account.owner,
        executable: account.executable,
        data: account.data,
    })
}

fn observer_accounts(
    evidence: &DevnetEvidenceContentV1,
) -> Result<KagebObserverAccounts, DevnetEvidenceError> {
    Ok(KagebObserverAccounts {
        fee_payer: parse_pubkey(&evidence.accounts.fee_payer)?,
        payer: parse_pubkey(&evidence.accounts.operator)?,
        pool: parse_pubkey(&evidence.accounts.pool)?,
        epoch: parse_pubkey(&evidence.accounts.epoch)?,
        vault_authority: parse_pubkey(&evidence.accounts.vault_authority)?,
        pool_base_vault: parse_pubkey(&evidence.accounts.pool_base_vault)?,
        pool_quote_vault: parse_pubkey(&evidence.accounts.pool_quote_vault)?,
        venue_authority: parse_pubkey(&evidence.accounts.venue_authority)?,
        venue_base_account: parse_pubkey(&evidence.accounts.venue_base_account)?,
        venue_quote_account: parse_pubkey(&evidence.accounts.venue_quote_account)?,
        base_mint: parse_pubkey(&evidence.accounts.base_mint)?,
        quote_mint: parse_pubkey(&evidence.accounts.quote_mint)?,
        base_lot_atoms: evidence.configuration.base_lot_atoms,
        quote_atoms_per_lot: evidence.configuration.quote_atoms_per_lot,
    })
}

fn decode_funding_transaction(
    confirmed: &EncodedConfirmedTransactionWithStatusMeta,
    funding_index: usize,
    funding: &FundingTransactionEvidenceV1,
    evidence: &DevnetEvidenceContentV1,
    global_sources: &mut BTreeSet<Pubkey>,
) -> Result<Vec<DecodedInstructionEvidenceV1>, DevnetEvidenceError> {
    let meta = confirmed
        .transaction
        .meta
        .as_ref()
        .ok_or(DevnetEvidenceError::InvalidTransaction)?;
    if meta.err.is_some() || meta.status.is_err() {
        return Err(DevnetEvidenceError::FailedTransaction);
    }
    if !matches!(
        &meta.inner_instructions,
        OptionSerializer::None | OptionSerializer::Skip
    ) && !matches!(&meta.inner_instructions, OptionSerializer::Some(inner) if inner.is_empty())
    {
        return Err(DevnetEvidenceError::InvalidTransaction);
    }
    let transaction = confirmed
        .transaction
        .transaction
        .decode()
        .ok_or(DevnetEvidenceError::InvalidTransaction)?;
    let keys = transaction.message.static_account_keys();
    let instructions = transaction.message.instructions();
    let pre = token_balance_list(&meta.pre_token_balances)?;
    let post = token_balance_list(&meta.post_token_balances)?;
    let authority = parse_pubkey(&funding.authority)?;
    if keys.first() != Some(&parse_pubkey(&evidence.accounts.fee_payer)?)
        || instructions.len() != 2
        || !keys
            .iter()
            .take(usize::from(
                transaction.message.header().num_required_signatures,
            ))
            .any(|key| *key == authority)
    {
        return Err(DevnetEvidenceError::InvalidTransaction);
    }
    let expected = [
        (
            parse_pubkey(&evidence.accounts.base_mint)?,
            parse_pubkey(&evidence.accounts.pool_base_vault)?,
            evidence.configuration.base_lot_atoms,
            parse_pubkey(&funding.base_source)?,
            "pool-funding-base",
        ),
        (
            parse_pubkey(&evidence.accounts.quote_mint)?,
            parse_pubkey(&evidence.accounts.pool_quote_vault)?,
            evidence.configuration.quote_atoms_per_lot,
            parse_pubkey(&funding.quote_source)?,
            "pool-funding-quote",
        ),
    ];
    let mut decoded = Vec::with_capacity(2);
    for (position, (instruction, (mint, destination, amount, source, kind))) in
        instructions.iter().zip(expected).enumerate()
    {
        if keys.get(instruction.program_id_index as usize) != Some(&kageb_program::TOKEN_PROGRAM_ID)
            || instruction.accounts.len() != 4
        {
            return Err(DevnetEvidenceError::InvalidTransaction);
        }
        let accounts: Vec<_> = instruction
            .accounts
            .iter()
            .map(|index| {
                keys.get(*index as usize)
                    .copied()
                    .ok_or(DevnetEvidenceError::InvalidTransaction)
            })
            .collect::<Result<_, _>>()?;
        let token = spl_token_interface::instruction::TokenInstruction::unpack(&instruction.data)
            .map_err(|_| DevnetEvidenceError::InvalidTransaction)?;
        if accounts[1] != mint
            || accounts[2] != destination
            || accounts[3] != authority
            || accounts[0] != source
            || accounts[0] == destination
            || !global_sources.insert(accounts[0])
            || !matches!(
                token,
                spl_token_interface::instruction::TokenInstruction::TransferChecked {
                    amount: actual,
                    decimals: 0,
                } if actual == amount
            )
        {
            return Err(DevnetEvidenceError::InvalidTransaction);
        }
        let source_pre = token_balance_at(
            pre,
            keys,
            &source.to_string(),
            &mint.to_string(),
            &authority.to_string(),
        )?;
        let source_post = token_balance_at(
            post,
            keys,
            &source.to_string(),
            &mint.to_string(),
            &authority.to_string(),
        )?;
        let destination_owner = parse_pubkey(&evidence.accounts.vault_authority)?;
        let destination_pre = token_balance_at(
            pre,
            keys,
            &destination.to_string(),
            &mint.to_string(),
            &destination_owner.to_string(),
        )?;
        let destination_post = token_balance_at(
            post,
            keys,
            &destination.to_string(),
            &mint.to_string(),
            &destination_owner.to_string(),
        )?;
        if source_pre.checked_sub(amount) != Some(source_post)
            || destination_pre.checked_add(amount) != Some(destination_post)
        {
            return Err(DevnetEvidenceError::InvalidTransaction);
        }
        decoded.push(DecodedInstructionEvidenceV1 {
            transaction: format!("funding-{funding_index}"),
            position: u16::try_from(position)
                .map_err(|_| DevnetEvidenceError::InvalidTransaction)?,
            program: kageb_program::TOKEN_PROGRAM_ID.to_string(),
            kind: kind.to_owned(),
            digest: None,
        });
    }
    Ok(decoded)
}

fn decode_kageb_transaction(
    confirmed: &EncodedConfirmedTransactionWithStatusMeta,
    transaction_name: &str,
    evidence: &DevnetEvidenceContentV1,
) -> Result<Vec<DecodedInstructionEvidenceV1>, DevnetEvidenceError> {
    let transaction = confirmed
        .transaction
        .transaction
        .decode()
        .ok_or(DevnetEvidenceError::InvalidTransaction)?;
    let keys = transaction.message.static_account_keys();
    let instructions = transaction.message.instructions();
    let mut decoded = Vec::new();
    let mut actual_program_digest = None;
    let mut actual_signers = BTreeSet::new();
    for (position, instruction) in instructions.iter().enumerate() {
        let program = keys
            .get(instruction.program_id_index as usize)
            .copied()
            .ok_or(DevnetEvidenceError::InvalidTransaction)?;
        let (kind, digest) = if program == solana_program::ed25519_program::ID {
            let parsed = verify_ed25519_instruction(&Instruction {
                program_id: program,
                accounts: Vec::new(),
                data: instruction.data.clone(),
            })?;
            if !actual_signers.insert(parsed.signer) {
                return Err(DevnetEvidenceError::WrongKeyper);
            }
            (
                if transaction_name == "lock" {
                    "keyper-lock-approval"
                } else {
                    "keyper-settlement-approval"
                },
                parsed.digest,
            )
        } else if program == kageb_program::ID {
            let (kind, digest) =
                match kageb_program::instruction::KagebInstruction::decode(&instruction.data)
                    .map_err(|_| DevnetEvidenceError::InvalidTransaction)?
                {
                    kageb_program::instruction::KagebInstruction::Lock(payload)
                        if transaction_name == "lock" =>
                    {
                        ("epoch-lock", payload.digest())
                    }
                    kageb_program::instruction::KagebInstruction::Settle(payload)
                        if transaction_name == "settlement" =>
                    {
                        let full = SettlementPayloadV1 {
                            epoch_account: parse_pubkey(&evidence.accounts.epoch)?,
                            lock_digest: parse_digest(&evidence.commitments.lock_digest)?,
                            result_commitment: payload.result_commitment,
                            residual_side: payload.residual_side,
                            residual_lots: payload.residual_lots,
                            base_lot_atoms: evidence.configuration.base_lot_atoms,
                            quote_atoms_per_lot: evidence.configuration.quote_atoms_per_lot,
                            base_mint: parse_pubkey(&evidence.accounts.base_mint)?,
                            quote_mint: parse_pubkey(&evidence.accounts.quote_mint)?,
                            pool_base_vault: parse_pubkey(&evidence.accounts.pool_base_vault)?,
                            pool_quote_vault: parse_pubkey(&evidence.accounts.pool_quote_vault)?,
                            venue_base_account: parse_pubkey(
                                &evidence.accounts.venue_base_account,
                            )?,
                            venue_quote_account: parse_pubkey(
                                &evidence.accounts.venue_quote_account,
                            )?,
                            venue_authority: parse_pubkey(&evidence.accounts.venue_authority)?,
                            settlement_nonce: payload.settlement_nonce,
                        };
                        ("aggregate-settlement", full.digest())
                    }
                    _ => return Err(DevnetEvidenceError::InvalidTransaction),
                };
            actual_program_digest = Some(digest);
            (kind, digest)
        } else {
            return Err(DevnetEvidenceError::InvalidTransaction);
        };
        decoded.push(DecodedInstructionEvidenceV1 {
            transaction: transaction_name.to_owned(),
            position: u16::try_from(position)
                .map_err(|_| DevnetEvidenceError::InvalidTransaction)?,
            program: program.to_string(),
            kind: kind.to_owned(),
            digest: Some(hex_digest(digest)),
        });
    }
    let actual_program_digest =
        actual_program_digest.ok_or(DevnetEvidenceError::InvalidTransaction)?;
    if decoded.iter().any(|instruction| {
        instruction.digest.as_deref() != Some(hex_digest(actual_program_digest).as_str())
    }) {
        return Err(DevnetEvidenceError::InvalidTransaction);
    }
    let expected_keypers: BTreeSet<_> = evidence
        .configuration
        .keypers
        .iter()
        .map(|key| parse_pubkey(key))
        .collect::<Result<_, _>>()?;
    if !actual_signers.is_subset(&expected_keypers) {
        return Err(DevnetEvidenceError::WrongKeyper);
    }
    if transaction_name == "settlement" {
        let meta = confirmed
            .transaction
            .meta
            .as_ref()
            .ok_or(DevnetEvidenceError::InvalidTransaction)?;
        let inner = match &meta.inner_instructions {
            OptionSerializer::Some(inner) => inner,
            OptionSerializer::None | OptionSerializer::Skip => {
                return Err(DevnetEvidenceError::InvalidTransaction)
            }
        };
        let group = inner
            .iter()
            .find(|group| group.index == 2)
            .ok_or(DevnetEvidenceError::InvalidTransaction)?;
        for (inner_index, instruction) in group.instructions.iter().enumerate() {
            let UiInstruction::Compiled(instruction) = instruction else {
                return Err(DevnetEvidenceError::InvalidTransaction);
            };
            if keys.get(instruction.program_id_index as usize)
                != Some(&kageb_program::TOKEN_PROGRAM_ID)
                || instruction.accounts.len() != 4
            {
                return Err(DevnetEvidenceError::InvalidTransaction);
            }
            let mint = keys
                .get(instruction.accounts[1] as usize)
                .ok_or(DevnetEvidenceError::InvalidTransaction)?;
            let kind = if *mint == parse_pubkey(&evidence.accounts.base_mint)? {
                "aggregate-base-leg"
            } else if *mint == parse_pubkey(&evidence.accounts.quote_mint)? {
                "aggregate-quote-leg"
            } else {
                return Err(DevnetEvidenceError::InvalidTransaction);
            };
            decoded.push(DecodedInstructionEvidenceV1 {
                transaction: transaction_name.to_owned(),
                position: u16::try_from(instructions.len() + inner_index)
                    .map_err(|_| DevnetEvidenceError::InvalidTransaction)?,
                program: kageb_program::TOKEN_PROGRAM_ID.to_string(),
                kind: kind.to_owned(),
                digest: None,
            });
        }
    }
    Ok(decoded)
}

fn transaction_token_balances(
    settlement: &EncodedConfirmedTransactionWithStatusMeta,
    evidence: &DevnetEvidenceContentV1,
) -> Result<EvidenceTokenBalancesV1, DevnetEvidenceError> {
    let meta = settlement
        .transaction
        .meta
        .as_ref()
        .ok_or(DevnetEvidenceError::InvalidTransaction)?;
    let transaction = settlement
        .transaction
        .transaction
        .decode()
        .ok_or(DevnetEvidenceError::InvalidTransaction)?;
    let keys = transaction.message.static_account_keys();
    let pre = token_balance_list(&meta.pre_token_balances)?;
    let post = token_balance_list(&meta.post_token_balances)?;
    let amount = |list: &[UiTransactionTokenBalance], address: &str, mint: &str, owner: &str| {
        token_balance_at(list, keys, address, mint, owner)
    };
    Ok(EvidenceTokenBalancesV1 {
        pool_base_before: amount(
            pre,
            &evidence.accounts.pool_base_vault,
            &evidence.accounts.base_mint,
            &evidence.accounts.vault_authority,
        )?,
        pool_base_after: amount(
            post,
            &evidence.accounts.pool_base_vault,
            &evidence.accounts.base_mint,
            &evidence.accounts.vault_authority,
        )?,
        pool_quote_before: amount(
            pre,
            &evidence.accounts.pool_quote_vault,
            &evidence.accounts.quote_mint,
            &evidence.accounts.vault_authority,
        )?,
        pool_quote_after: amount(
            post,
            &evidence.accounts.pool_quote_vault,
            &evidence.accounts.quote_mint,
            &evidence.accounts.vault_authority,
        )?,
        venue_base_before: amount(
            pre,
            &evidence.accounts.venue_base_account,
            &evidence.accounts.base_mint,
            &evidence.accounts.venue_authority,
        )?,
        venue_base_after: amount(
            post,
            &evidence.accounts.venue_base_account,
            &evidence.accounts.base_mint,
            &evidence.accounts.venue_authority,
        )?,
        venue_quote_before: amount(
            pre,
            &evidence.accounts.venue_quote_account,
            &evidence.accounts.quote_mint,
            &evidence.accounts.venue_authority,
        )?,
        venue_quote_after: amount(
            post,
            &evidence.accounts.venue_quote_account,
            &evidence.accounts.quote_mint,
            &evidence.accounts.venue_authority,
        )?,
    })
}

fn token_balance_list(
    balances: &OptionSerializer<Vec<UiTransactionTokenBalance>>,
) -> Result<&[UiTransactionTokenBalance], DevnetEvidenceError> {
    match balances {
        OptionSerializer::Some(balances) => Ok(balances),
        OptionSerializer::None | OptionSerializer::Skip => {
            Err(DevnetEvidenceError::InvalidTransaction)
        }
    }
}

fn token_balance_at(
    balances: &[UiTransactionTokenBalance],
    keys: &[Pubkey],
    address: &str,
    mint: &str,
    owner: &str,
) -> Result<u64, DevnetEvidenceError> {
    let address = parse_pubkey(address)?;
    let balance = balances
        .iter()
        .find(|balance| keys.get(balance.account_index as usize) == Some(&address))
        .ok_or(DevnetEvidenceError::InvalidTransaction)?;
    if balance.mint != mint
        || balance.ui_token_amount.decimals != 0
        || !matches!(&balance.owner, OptionSerializer::Some(actual) if actual == owner)
        || !matches!(
            &balance.program_id,
            OptionSerializer::Some(actual) if actual == &kageb_program::TOKEN_PROGRAM_ID.to_string()
        )
    {
        return Err(DevnetEvidenceError::InvalidTransaction);
    }
    balance
        .ui_token_amount
        .amount
        .parse()
        .map_err(|_| DevnetEvidenceError::InvalidTransaction)
}

fn fetch_live_token_accounts(
    rpc: &RpcClient,
    evidence: &DevnetEvidenceContentV1,
) -> Result<[PublicAccountSnapshotV1; 4], DevnetEvidenceError> {
    let accounts = [
        &evidence.accounts.pool_base_vault,
        &evidence.accounts.pool_quote_vault,
        &evidence.accounts.venue_base_account,
        &evidence.accounts.venue_quote_account,
    ];
    accounts
        .map(|address| fetch_finalized_account(rpc, parse_pubkey(address)?))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| DevnetEvidenceError::RpcUnavailable)
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.as_ref().len() * 2);
    for byte in bytes.as_ref() {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SettlementBalanceV1 {
    pub participant_id: [u8; 32],
    pub base_atoms: u64,
    pub quote_atoms: u64,
}

impl std::fmt::Debug for SettlementBalanceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SettlementBalanceV1(..redacted)")
    }
}

#[derive(Clone)]
pub struct DecryptionEvidenceV1 {
    shares: [ReleasedShareV1; 2],
}

impl std::fmt::Debug for DecryptionEvidenceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DecryptionEvidenceV1(..redacted)")
    }
}

impl DecryptionEvidenceV1 {
    pub fn new(
        first: ReleasedShareV1,
        second: ReleasedShareV1,
    ) -> Result<Self, SettlementValidationError> {
        if first.index() == second.index() {
            return Err(SettlementValidationError::InvalidBatch);
        }
        Ok(Self {
            shares: [first, second],
        })
    }

    fn shares(&self) -> [&ReleasedShareV1; 2] {
        [&self.shares[0], &self.shares[1]]
    }
}

#[derive(Clone)]
pub struct SettlementRequestV1 {
    pub package: LockPackageV1,
    pub decryption_evidence: Vec<DecryptionEvidenceV1>,
    pub post_balances: Vec<SettlementBalanceV1>,
    pub pre_balance_root: [u8; 32],
    pub post_balance_root: [u8; 32],
    pub residual: Residual,
    pub result_root: [u8; 32],
    pub result_commitment: [u8; 32],
    pub settlement_nonce: [u8; 32],
    pub settlement_digest: [u8; 32],
}

impl std::fmt::Debug for SettlementRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SettlementRequestV1(..redacted)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementValidationError {
    InvalidLock,
    InvalidBatch,
    InvalidBalance,
    InvalidResult,
    InvalidNonce,
    WrongKeyper,
    MemberLimitExceeded,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SettlementApprovalV1 {
    keyper_key: [u8; 32],
    payload: SettlementPayloadV1,
    digest: [u8; 32],
    signature: [u8; 64],
}

impl std::fmt::Debug for SettlementApprovalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SettlementApprovalV1(..redacted)")
    }
}

impl SettlementApprovalV1 {
    #[must_use]
    pub const fn payload(&self) -> SettlementPayloadV1 {
        self.payload
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.keyper_key) else {
            return false;
        };
        self.digest == self.payload.digest()
            && key
                .verify(&self.digest, &Signature::from_bytes(&self.signature))
                .is_ok()
    }

    pub(crate) const fn keyper_key(&self) -> [u8; 32] {
        self.keyper_key
    }

    pub(crate) const fn signature(&self) -> [u8; 64] {
        self.signature
    }

    pub(crate) fn encode_wire(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(503);
        bytes.push(1);
        bytes.extend_from_slice(&self.keyper_key);
        bytes.extend_from_slice(&self.payload.encode());
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub(crate) fn decode_wire(bytes: &[u8]) -> Result<Self, SettlementValidationError> {
        if bytes.len() != 503 || bytes[0] != 1 {
            return Err(SettlementValidationError::InvalidResult);
        }
        let payload = SettlementPayloadV1::decode(&bytes[33..407])
            .ok_or(SettlementValidationError::InvalidResult)?;
        Ok(Self {
            keyper_key: bytes[1..33]
                .try_into()
                .map_err(|_| SettlementValidationError::InvalidResult)?,
            payload,
            digest: bytes[407..439]
                .try_into()
                .map_err(|_| SettlementValidationError::InvalidResult)?,
            signature: bytes[439..503]
                .try_into()
                .map_err(|_| SettlementValidationError::InvalidResult)?,
        })
    }
}

struct RecomputedSettlement {
    post_balances: Vec<SettlementBalanceV1>,
    pre_balance_root: [u8; 32],
    post_balance_root: [u8; 32],
    residual: Residual,
    result_root: [u8; 32],
    result_commitment: [u8; 32],
    payload: SettlementPayloadV1,
}

impl SettlementRequestV1 {
    pub fn build(
        package: LockPackageV1,
        decryption_evidence: Vec<DecryptionEvidenceV1>,
        settlement_nonce: [u8; 32],
        confirmed: &ConfirmedLock,
    ) -> Result<Self, SettlementValidationError> {
        let recomputed = recompute(&package, &decryption_evidence, settlement_nonce, confirmed)?;
        let settlement_digest = recomputed.payload.digest();
        Ok(Self {
            package,
            decryption_evidence,
            post_balances: recomputed.post_balances,
            pre_balance_root: recomputed.pre_balance_root,
            post_balance_root: recomputed.post_balance_root,
            residual: recomputed.residual,
            result_root: recomputed.result_root,
            result_commitment: recomputed.result_commitment,
            settlement_nonce,
            settlement_digest,
        })
    }

    pub(crate) fn encode_wire(&self) -> Result<Vec<u8>, SettlementValidationError> {
        let package = self
            .package
            .encode_wire()
            .map_err(|_| SettlementValidationError::InvalidBatch)?;
        let mut bytes = Vec::new();
        bytes.push(1);
        bytes.extend_from_slice(
            &u32::try_from(package.len())
                .map_err(|_| SettlementValidationError::InvalidBatch)?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&package);
        bytes.extend_from_slice(
            &u32::try_from(self.decryption_evidence.len())
                .map_err(|_| SettlementValidationError::InvalidBatch)?
                .to_le_bytes(),
        );
        for evidence in &self.decryption_evidence {
            for share in &evidence.shares {
                let encoded = share
                    .encode_wire()
                    .map_err(|_| SettlementValidationError::InvalidBatch)?;
                if encoded.len() > MAX_RELEASED_SHARE_WIRE_LEN {
                    return Err(SettlementValidationError::InvalidBatch);
                }
                bytes.extend_from_slice(
                    &u32::try_from(encoded.len())
                        .map_err(|_| SettlementValidationError::InvalidBatch)?
                        .to_le_bytes(),
                );
                bytes.extend_from_slice(&encoded);
            }
        }
        bytes.extend_from_slice(
            &u32::try_from(self.post_balances.len())
                .map_err(|_| SettlementValidationError::InvalidBalance)?
                .to_le_bytes(),
        );
        for balance in &self.post_balances {
            bytes.extend_from_slice(&encode_settlement_balance(balance));
        }
        bytes.extend_from_slice(&self.pre_balance_root);
        bytes.extend_from_slice(&self.post_balance_root);
        let (side, lots) = residual_wire(self.residual);
        bytes.push(side);
        bytes.extend_from_slice(&lots.to_le_bytes());
        bytes.extend_from_slice(&self.result_root);
        bytes.extend_from_slice(&self.result_commitment);
        bytes.extend_from_slice(&self.settlement_nonce);
        bytes.extend_from_slice(&self.settlement_digest);
        Ok(bytes)
    }

    pub(crate) fn decode_wire(bytes: &[u8]) -> Result<Self, SettlementValidationError> {
        if bytes.len() < 1 + 4 || bytes[0] != 1 {
            return Err(SettlementValidationError::InvalidBatch);
        }
        let mut offset = 1_usize;
        let package_len = take_u32(bytes, &mut offset)? as usize;
        let package_end = offset
            .checked_add(package_len)
            .ok_or(SettlementValidationError::InvalidBatch)?;
        let package = LockPackageV1::decode_wire(
            bytes
                .get(offset..package_end)
                .ok_or(SettlementValidationError::InvalidBatch)?,
        )
        .map_err(|_| SettlementValidationError::InvalidBatch)?;
        offset = package_end;
        let evidence_count = take_u32(bytes, &mut offset)? as usize;
        if evidence_count > MAX_BATCH_MEMBERS
            || evidence_count != package.submissions.len()
            || evidence_count != package.member_count as usize
        {
            return Err(SettlementValidationError::MemberLimitExceeded);
        }
        let mut decryption_evidence = Vec::with_capacity(evidence_count);
        for _ in 0..evidence_count {
            let mut shares = Vec::with_capacity(2);
            for _ in 0..2 {
                let share_len = take_u32(bytes, &mut offset)? as usize;
                if share_len > MAX_RELEASED_SHARE_WIRE_LEN {
                    return Err(SettlementValidationError::InvalidBatch);
                }
                let end = offset
                    .checked_add(share_len)
                    .ok_or(SettlementValidationError::InvalidBatch)?;
                shares.push(
                    ReleasedShareV1::decode_wire(
                        bytes
                            .get(offset..end)
                            .ok_or(SettlementValidationError::InvalidBatch)?,
                    )
                    .map_err(|_| SettlementValidationError::InvalidBatch)?,
                );
                offset = end;
            }
            decryption_evidence.push(DecryptionEvidenceV1::new(
                shares.remove(0),
                shares.remove(0),
            )?);
        }
        let post_count = take_u32(bytes, &mut offset)? as usize;
        if post_count > MAX_BATCH_MEMBERS || post_count != package.balances.len() {
            return Err(SettlementValidationError::MemberLimitExceeded);
        }
        let mut post_balances = Vec::with_capacity(post_count);
        for _ in 0..post_count {
            let encoded = take_array::<48>(bytes, &mut offset)?;
            post_balances.push(SettlementBalanceV1 {
                participant_id: encoded[0..32]
                    .try_into()
                    .map_err(|_| SettlementValidationError::InvalidBalance)?,
                base_atoms: u64::from_le_bytes(
                    encoded[32..40]
                        .try_into()
                        .map_err(|_| SettlementValidationError::InvalidBalance)?,
                ),
                quote_atoms: u64::from_le_bytes(
                    encoded[40..48]
                        .try_into()
                        .map_err(|_| SettlementValidationError::InvalidBalance)?,
                ),
            });
        }
        let pre_balance_root = take_array(bytes, &mut offset)?;
        let post_balance_root = take_array(bytes, &mut offset)?;
        let side = *bytes
            .get(offset)
            .ok_or(SettlementValidationError::InvalidResult)?;
        offset += 1;
        let lots = take_u32(bytes, &mut offset)?;
        let residual = match (side, lots) {
            (0, 0) => Residual::None,
            (1, 1..=u32::MAX) => Residual::Buy { lots },
            (2, 1..=u32::MAX) => Residual::Sell { lots },
            _ => return Err(SettlementValidationError::InvalidResult),
        };
        let result_root = take_array(bytes, &mut offset)?;
        let result_commitment = take_array(bytes, &mut offset)?;
        let settlement_nonce = take_array(bytes, &mut offset)?;
        let settlement_digest = take_array(bytes, &mut offset)?;
        if offset != bytes.len() {
            return Err(SettlementValidationError::InvalidBatch);
        }
        Ok(Self {
            package,
            decryption_evidence,
            post_balances,
            pre_balance_root,
            post_balance_root,
            residual,
            result_root,
            result_commitment,
            settlement_nonce,
            settlement_digest,
        })
    }
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, SettlementValidationError> {
    Ok(u32::from_le_bytes(take_array(bytes, offset)?))
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], SettlementValidationError> {
    let end = offset
        .checked_add(N)
        .ok_or(SettlementValidationError::InvalidBatch)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(SettlementValidationError::InvalidBatch)?
        .try_into()
        .map_err(|_| SettlementValidationError::InvalidBatch)?;
    *offset = end;
    Ok(value)
}

impl ReferenceKeyper {
    pub fn sign_settlement(
        &self,
        request: &SettlementRequestV1,
        confirmed: &ConfirmedLock,
        secret: &crate::KeyperSecretShare,
    ) -> Result<SettlementApprovalV1, SettlementValidationError> {
        let recomputed = recompute(
            &request.package,
            &request.decryption_evidence,
            request.settlement_nonce,
            confirmed,
        )?;
        let digest = recomputed.payload.digest();
        if request.post_balances != recomputed.post_balances
            || request.pre_balance_root != recomputed.pre_balance_root
            || request.post_balance_root != recomputed.post_balance_root
            || request.residual != recomputed.residual
            || request.result_root != recomputed.result_root
            || request.result_commitment != recomputed.result_commitment
            || request.settlement_digest != digest
        {
            return Err(SettlementValidationError::InvalidResult);
        }
        let pool = confirmed
            .pool
            .as_ref()
            .ok_or(SettlementValidationError::InvalidLock)?;
        let configured = pool
            .keypers
            .get(self.index)
            .ok_or(SettlementValidationError::WrongKeyper)?;
        let keyper_key = self.signing_key.verifying_key().to_bytes();
        if configured.to_bytes() != keyper_key
            || secret.index() != self.index
            || secret.epoch_account() != request.package.epoch_account()
            || !request.package.epoch_public_keys.matches_share(secret)
            || self.journal.digest(confirmed.epoch_account()) != Some(confirmed.lock_digest())
        {
            return Err(SettlementValidationError::WrongKeyper);
        }
        Ok(SettlementApprovalV1 {
            keyper_key,
            payload: recomputed.payload,
            digest,
            signature: self.signing_key.sign(&digest).to_bytes(),
        })
    }
}

fn recompute(
    package: &LockPackageV1,
    decryption_evidence: &[DecryptionEvidenceV1],
    settlement_nonce: [u8; 32],
    confirmed: &ConfirmedLock,
) -> Result<RecomputedSettlement, SettlementValidationError> {
    package
        .validate_locked(confirmed)
        .map_err(|_| SettlementValidationError::InvalidLock)?;
    if settlement_nonce == [0; 32] || settlement_nonce == confirmed.state.lock_nonce {
        return Err(SettlementValidationError::InvalidNonce);
    }
    if decryption_evidence.len() != package.submissions.len()
        || decryption_evidence.len() > MAX_BATCH_MEMBERS
    {
        return Err(SettlementValidationError::InvalidBatch);
    }
    let mut recovered = Vec::with_capacity(decryption_evidence.len());
    for (submission, evidence) in package.submissions.iter().zip(decryption_evidence) {
        if evidence.shares.iter().any(|share| {
            share.epoch_account() != confirmed.epoch_account()
                || share.lock_digest() != confirmed.lock_digest()
        }) {
            return Err(SettlementValidationError::InvalidBatch);
        }
        recovered.push(
            package
                .epoch_public_keys
                .recover_submission(submission, evidence.shares())
                .map_err(|_| SettlementValidationError::InvalidBatch)?,
        );
    }
    let mut submissions = BTreeMap::new();
    for submission in &package.submissions {
        let participant = submission.authorization.participant_id;
        if submissions.insert(participant, submission).is_some() {
            return Err(SettlementValidationError::InvalidBatch);
        }
    }
    let mut seen = BTreeSet::new();
    let mut orders = Vec::with_capacity(recovered.len());
    for intent in &recovered {
        let participant = intent.body().participant_id();
        let submission = submissions
            .get(&participant)
            .ok_or(SettlementValidationError::InvalidBatch)?;
        if !seen.insert(participant) {
            return Err(SettlementValidationError::InvalidBatch);
        }
        let trading_key = VerifyingKey::from_bytes(&submission.authorization.trading_key)
            .map_err(|_| SettlementValidationError::InvalidBatch)?;
        intent
            .verify(&trading_key, package.configuration.epoch_id, participant)
            .map_err(|_| SettlementValidationError::InvalidBatch)?;
        orders.push(
            FundedOrder::new(
                participant,
                intent.body().side(),
                intent.body().limit_price(),
            )
            .map_err(|_| SettlementValidationError::InvalidBatch)?,
        );
    }
    let before: BTreeMap<[u8; 32], PoolBalance> = package
        .balances
        .iter()
        .map(|balance| (balance.participant_id(), balance.pool_balance()))
        .collect();
    if before.len() != package.balances.len() {
        return Err(SettlementValidationError::InvalidBalance);
    }
    let result = crate::net_batch(
        BatchConfig::new(
            package.configuration.base_lot_atoms,
            package.configuration.quote_atoms_per_lot,
        )
        .map_err(|_| SettlementValidationError::InvalidBatch)?,
        &before,
        &orders,
    )
    .map_err(|_| SettlementValidationError::InvalidBatch)?;
    if !result.conserves(&before) {
        return Err(SettlementValidationError::InvalidBalance);
    }
    let post_balances: Vec<_> = result
        .balances()
        .iter()
        .map(|(participant_id, balance)| SettlementBalanceV1 {
            participant_id: *participant_id,
            base_atoms: balance.base_atoms,
            quote_atoms: balance.quote_atoms,
        })
        .collect();
    let post_balance_root = settlement_balance_root(&post_balances)?;
    let result_root = per_participant_result_root(&before, &post_balances)?;
    let recovered_root = recovered_intents_root(&recovered);
    let pre_balance_root = package.pre_balance_root;
    let result_commitment = result_commitment(
        confirmed,
        recovered_root,
        pre_balance_root,
        post_balance_root,
        result.residual(),
        result_root,
    );
    let pool = confirmed
        .pool
        .as_ref()
        .ok_or(SettlementValidationError::InvalidLock)?;
    let (residual_side, residual_lots) = residual_wire(result.residual());
    let payload = SettlementPayloadV1 {
        epoch_account: confirmed.epoch_account(),
        lock_digest: confirmed.lock_digest(),
        result_commitment,
        residual_side,
        residual_lots,
        base_lot_atoms: confirmed.state.base_lot_atoms,
        quote_atoms_per_lot: confirmed.state.quote_atoms_per_lot,
        base_mint: pool.base_mint,
        quote_mint: pool.quote_mint,
        pool_base_vault: pool.pool_base_vault,
        pool_quote_vault: pool.pool_quote_vault,
        venue_base_account: pool.venue_base_account,
        venue_quote_account: pool.venue_quote_account,
        venue_authority: pool.venue_authority,
        settlement_nonce,
    };
    Ok(RecomputedSettlement {
        post_balances,
        pre_balance_root,
        post_balance_root,
        residual: result.residual(),
        result_root,
        result_commitment,
        payload,
    })
}

fn settlement_balance_root(
    balances: &[SettlementBalanceV1],
) -> Result<[u8; 32], SettlementValidationError> {
    let leaves: Vec<_> = balances.iter().map(encode_settlement_balance).collect();
    let refs: Vec<_> = leaves.iter().map(<[u8; 48]>::as_slice).collect();
    content_root(crate::CommitmentDomain::BalanceSet, &refs)
        .map_err(|_| SettlementValidationError::InvalidBalance)
}

fn per_participant_result_root(
    before: &BTreeMap<[u8; 32], PoolBalance>,
    after: &[SettlementBalanceV1],
) -> Result<[u8; 32], SettlementValidationError> {
    let mut leaves = Vec::with_capacity(after.len());
    for balance in after {
        let prior = before
            .get(&balance.participant_id)
            .ok_or(SettlementValidationError::InvalidBalance)?;
        let mut leaf = [0_u8; 64];
        leaf[0..32].copy_from_slice(&balance.participant_id);
        leaf[32..40].copy_from_slice(&prior.base_atoms.to_le_bytes());
        leaf[40..48].copy_from_slice(&prior.quote_atoms.to_le_bytes());
        leaf[48..56].copy_from_slice(&balance.base_atoms.to_le_bytes());
        leaf[56..64].copy_from_slice(&balance.quote_atoms.to_le_bytes());
        leaves.push(leaf);
    }
    let refs: Vec<_> = leaves.iter().map(<[u8; 64]>::as_slice).collect();
    content_root(crate::CommitmentDomain::ResultSet, &refs)
        .map_err(|_| SettlementValidationError::InvalidResult)
}

fn encode_settlement_balance(balance: &SettlementBalanceV1) -> [u8; 48] {
    let mut bytes = [0_u8; 48];
    bytes[0..32].copy_from_slice(&balance.participant_id);
    bytes[32..40].copy_from_slice(&balance.base_atoms.to_le_bytes());
    bytes[40..48].copy_from_slice(&balance.quote_atoms.to_le_bytes());
    bytes
}

fn recovered_intents_root(recovered: &[SignedIntentV1]) -> [u8; 32] {
    let mut leaves: Vec<[u8; 32]> = recovered
        .iter()
        .map(|intent| Sha256::digest(intent.encode()).into())
        .collect();
    leaves.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(RECOVERED_INTENTS_DOMAIN);
    hasher.update((leaves.len() as u64).to_le_bytes());
    for leaf in leaves {
        hasher.update(leaf);
    }
    hasher.finalize().into()
}

fn result_commitment(
    confirmed: &ConfirmedLock,
    recovered_root: [u8; 32],
    pre_balance_root: [u8; 32],
    post_balance_root: [u8; 32],
    residual: Residual,
    result_root: [u8; 32],
) -> [u8; 32] {
    let (side, lots) = residual_wire(residual);
    let mut hasher = Sha256::new();
    hasher.update(RESULT_COMMITMENT_DOMAIN);
    hasher.update(confirmed.epoch_account().as_ref());
    hasher.update(confirmed.lock_digest());
    hasher.update(recovered_root);
    hasher.update(pre_balance_root);
    hasher.update(post_balance_root);
    hasher.update([side]);
    hasher.update(lots.to_le_bytes());
    hasher.update(result_root);
    hasher.finalize().into()
}

const fn residual_wire(residual: Residual) -> (u8, u32) {
    match residual {
        Residual::None => (0, 0),
        Residual::Buy { lots } => (1, lots),
        Residual::Sell { lots } => (2, lots),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use kageb_program::wire::EpochConfigurationV1;
    use solana_keypair::Keypair;
    use solana_program::pubkey::Pubkey;
    use solana_signer::Signer as _;
    use solana_transaction::Transaction;

    use super::*;
    use crate::{EpochDealer, SignedBalanceSnapshotV1};

    #[test]
    fn settlement_wire_rejects_coordinator_counts_before_allocating() {
        let epoch = Pubkey::new_unique();
        let epoch_id = [1; 32];
        let operator = SigningKey::from_bytes(&[2; 32]);
        let package = LockPackageV1::new(
            epoch,
            EpochConfigurationV1 {
                pool: Pubkey::new_unique(),
                epoch_id,
                base_mint: Pubkey::new_unique(),
                quote_mint: Pubkey::new_unique(),
                base_lot_atoms: 1,
                quote_atoms_per_lot: 100,
                minimum_count: 4,
                lock_threshold: 2,
                settlement_threshold: 2,
                keypers: [
                    Pubkey::new_unique(),
                    Pubkey::new_unique(),
                    Pubkey::new_unique(),
                ],
                lock_deadline: 900,
                abort_deadline: 1_000,
            },
            EpochDealer::random().unwrap().public_keys().clone(),
            Vec::new(),
            Vec::new(),
            SignedBalanceSnapshotV1::sign(epoch_id, &[], &operator).unwrap(),
            [3; 32],
        )
        .unwrap();
        let encoded_package = package.encode_wire().unwrap();
        let mut bytes = vec![1];
        bytes.extend_from_slice(&(encoded_package.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&encoded_package);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            SettlementRequestV1::decode_wire(&bytes),
            Err(SettlementValidationError::MemberLimitExceeded)
        ));
    }

    #[test]
    fn public_verifier_checks_ed25519_instruction_signature_bytes() {
        let key = SigningKey::from_bytes(&[41; 32]);
        let digest = [42; 32];
        let signature = key.sign(&digest);
        let instruction = solana_ed25519_program::new_ed25519_instruction_with_signature(
            &digest,
            &signature.to_bytes(),
            &key.verifying_key().to_bytes(),
        );
        verify_ed25519_instruction(&instruction).unwrap();

        let mut tampered = instruction;
        tampered.data[48] ^= 1;
        assert_eq!(
            verify_ed25519_instruction(&tampered),
            Err(DevnetEvidenceError::InvalidTransaction)
        );
    }

    #[test]
    fn public_verifier_checks_queried_transaction_identity_and_signatures() {
        let payer = Keypair::new();
        let transaction = Transaction::new_signed_with_payer(
            &[],
            Some(&payer.pubkey()),
            &[&payer],
            Default::default(),
        );
        let expected = transaction.signatures[0];
        let mut versioned = solana_transaction::versioned::VersionedTransaction::from(transaction);
        verify_queried_transaction(&versioned, &expected).unwrap();

        assert_eq!(
            verify_queried_transaction(&versioned, &solana_signature::Signature::from([9_u8; 64]),),
            Err(DevnetEvidenceError::InvalidTransaction)
        );
        versioned.signatures[0] = solana_signature::Signature::from([8_u8; 64]);
        assert_eq!(
            verify_queried_transaction(&versioned, &expected),
            Err(DevnetEvidenceError::InvalidTransaction)
        );
    }

    #[test]
    fn rpc_response_lengths_are_exact() {
        assert!(validate_rpc_response_len(6, 6).is_ok());
        assert_eq!(
            validate_rpc_response_len(5, 6),
            Err(DevnetEvidenceError::RpcUnavailable)
        );
        assert_eq!(
            validate_rpc_response_len(7, 6),
            Err(DevnetEvidenceError::RpcUnavailable)
        );
    }

    #[test]
    fn build_toolchain_mismatch_names_the_first_changed_identity() {
        let expected = EvidenceBuildToolchainV1 {
            solana_verify: "solana-verify 0.5.1".to_owned(),
            build_image: "solanafoundation/solana-verifiable-build@sha256:test".to_owned(),
        };
        let mut observed = expected.clone();
        observed.build_image = "solanafoundation/solana-verifiable-build@sha256:changed".to_owned();

        assert_eq!(
            build_toolchain_mismatch(&expected, &observed),
            Some(
                "canonical checkpoint build_image differs from evidence: expected \"solanafoundation/solana-verifiable-build@sha256:test\", observed \"solanafoundation/solana-verifiable-build@sha256:changed\""
                    .to_owned()
            )
        );
        assert_eq!(build_toolchain_mismatch(&expected, &expected), None);
    }
}
