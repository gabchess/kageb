use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    net::{TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use base64::Engine as _;
use bincode::Options as _;
use ed25519_dalek::SigningKey;
use kageb_program::{
    epoch_address,
    instruction::{
        abort_instruction, create_epoch_instruction, initialize_pool_instruction, lock_instruction,
        settle_instruction, CreateEpochArgs, InitializePoolAccounts, InitializePoolArgs,
        SettleAccounts,
    },
    pool_address,
    state::{EpochStateV1, EpochTerminalState, PoolStateV1},
    vault_authority_address, ID, TOKEN_PROGRAM_ID,
};
use sha2::{Digest, Sha256};
use solana_commitment_config::CommitmentConfig;
use solana_ed25519_program::new_ed25519_instruction_with_signature;
use solana_keypair::{read_keypair_file, Keypair};
use solana_loader_v3_interface::{
    instruction::UpgradeableLoaderInstruction, state::UpgradeableLoaderState,
};
use solana_program::{
    clock::Clock,
    instruction::{AccountMeta, Instruction},
    program_pack::Pack,
    pubkey::Pubkey,
};
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::{
    EncodedConfirmedTransactionWithStatusMeta, UiTransactionEncoding,
};
use tempfile::TempDir;
use threshold_crypto::serde_impl::SerdeSecret;

use crate::evidence::{build_canonical_checkpoint, CanonicalCheckpointV1};
use crate::{
    admit_batch, content_root, extract_upgradeable_program, net_batch, run_keyper_release_share,
    run_keyper_sign_lock, run_keyper_sign_settlement, AdmissionPolicyV1, BalanceRecordV1,
    BatchConfig, CommitmentDomain, CryptoError, DecodedInstructionEvidenceV1, DecryptionEvidenceV1,
    DevnetEvidenceBundleV1, DevnetEvidenceContentV1, DirectMarketAccounts, DirectOrder,
    EncryptedSubmissionV1, EpochDealer, EvidenceAccountsV1, EvidenceCommitmentsV1,
    EvidenceConfigurationV1, EvidenceDeploymentV1, EvidenceTokenBalancesV1, EvidenceTransactionV1,
    EvidenceTransactionsV1, FundedOrder, FundingTransactionEvidenceV1, IntentBodyV1,
    KagebObserverAccounts, KeyperProcessError, LedgerError, LockPackageV1, PoolBalance,
    ProgramClient, PublicAccountSnapshotV1, PublicTrace, ReservationJournal, ReservationRecord,
    SettlementRequestV1, Side, SignedBalanceSnapshotV1, SignedIntentV1, SuspensionError,
    SuspensionRegistry, DEVNET_GENESIS_HASH, UPGRADEABLE_LOADER_ID,
};

const NON_CLAIM: &str = "It does not prove unique humans, production anonymity, private funding or withdrawal, a trustless exchange, protection from the KageB operator, or safe use with real funds.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DevnetDeploymentAction {
    Noop,
    Initial,
    Upgrade,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeployedCheckpointDiscovery {
    upgrade_authority: Option<Pubkey>,
    artifact_matches: bool,
}

#[derive(Clone, Copy, Debug)]
struct DevnetPeakRents {
    setup: u64,
    program: u64,
    programdata: u64,
    buffer: u64,
    fees: u64,
}

fn select_deployment_action(
    deployed: Option<&DeployedCheckpointDiscovery>,
    payer: Pubkey,
    initial_program_key: Option<Pubkey>,
) -> Result<DevnetDeploymentAction, String> {
    let Some(deployed) = deployed else {
        if initial_program_key != Some(ID) {
            return Err("initial deployment requires the fixed external program key".to_owned());
        }
        return Ok(DevnetDeploymentAction::Initial);
    };
    if deployed.artifact_matches {
        return Ok(DevnetDeploymentAction::Noop);
    }
    if deployed.upgrade_authority != Some(payer) {
        return Err("deployed checkpoint differs and payer is not upgrade authority".to_owned());
    }
    Ok(DevnetDeploymentAction::Upgrade)
}

fn required_peak_balance(
    action: DevnetDeploymentAction,
    rents: DevnetPeakRents,
) -> Result<u64, String> {
    let mut required = rents
        .setup
        .checked_add(rents.fees)
        .ok_or("devnet peak balance overflow")?;
    if action != DevnetDeploymentAction::Noop {
        required = required
            .checked_add(rents.program)
            .and_then(|value| value.checked_add(rents.programdata))
            .and_then(|value| value.checked_add(rents.buffer))
            .ok_or("devnet peak balance overflow")?;
    }
    Ok(required)
}

fn checked_devnet_deadlines(now: i64, current_slot: u64) -> Result<(i64, i64, u64), String> {
    Ok((
        now.checked_add(300).ok_or("lock deadline overflow")?,
        now.checked_add(900).ok_or("abort deadline overflow")?,
        current_slot
            .checked_add(2_000)
            .ok_or("authorization slot overflow")?,
    ))
}

fn publish_bytes_noclobber(out: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = out
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|_| "create evidence directory failed".to_owned())?;
    let absolute_parent = if parent.is_absolute() {
        parent.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| "locate evidence directory failed".to_owned())?
            .join(parent)
    };
    for ancestor in absolute_parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|_| "inspect evidence directory ancestry failed".to_owned())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("evidence directory ancestry must contain real directories".to_owned());
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(
                "evidence directory ancestry must not be group or world writable".to_owned(),
            );
        }
    }
    let mut pending = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| "create pending evidence failed".to_owned())?;
    pending
        .write_all(bytes)
        .and_then(|()| pending.as_file().sync_all())
        .map_err(|_| "write pending evidence failed".to_owned())?;
    let persisted = pending
        .persist_noclobber(out)
        .map_err(|_| "evidence output already exists".to_owned())?;
    persisted
        .sync_all()
        .map_err(|_| "sync evidence failed".to_owned())?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "sync evidence directory failed".to_owned())
}

fn scan_public_evidence_bytes(bytes: &[u8], secret_encodings: &[Vec<u8>]) -> Result<(), String> {
    const FORBIDDEN: [&[u8]; 7] = [
        b"plaintext",
        b"signed_intent",
        b"ciphertext",
        b"decryption",
        b"reservation",
        b".kageb-private",
        b"keyper-attestation-key",
    ];
    let contains = |needle: &[u8]| {
        !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
    };
    if FORBIDDEN.into_iter().any(contains) || secret_encodings.iter().any(|secret| contains(secret))
    {
        return Err("public evidence contains private material".to_owned());
    }
    Ok(())
}

fn private_material_encodings(material: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut encodings = Vec::with_capacity(material.len() * 7);
    for secret in material.iter().filter(|secret| !secret.is_empty()) {
        let hex = hex_bytes(secret);
        encodings.push(secret.clone());
        encodings.push(hex.as_bytes().to_vec());
        encodings.push(hex.to_ascii_uppercase().into_bytes());
        encodings.push(bs58::encode(secret).into_string().into_bytes());
        encodings.push(
            base64::engine::general_purpose::STANDARD
                .encode(secret)
                .into_bytes(),
        );
        encodings.push(
            base64::engine::general_purpose::STANDARD_NO_PAD
                .encode(secret)
                .into_bytes(),
        );
        if let Ok(json) = serde_json::to_vec(secret) {
            encodings.push(json);
        }
    }
    encodings
}

fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0_u8; N];
    getrandom::getrandom(&mut bytes).map_err(|error| format!("OS randomness failed: {error}"))?;
    Ok(bytes)
}

fn random_signing_key() -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&random_bytes()?))
}

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

pub fn local_proof() -> Result<String, String> {
    let executable =
        std::env::current_exe().map_err(|_| "locate KageB executable failed".to_owned())?;
    let cargo = resolve_cargo()?;
    let validator_executable = resolve_on_path("solana-test-validator")?;
    let (artifact, token_artifact) = fresh_sbf_artifacts(&cargo)?;
    let validator = LocalValidator::start(&validator_executable, &artifact, &token_artifact)?;
    let rpc =
        RpcClient::new_with_commitment(validator.rpc_url.clone(), CommitmentConfig::confirmed());
    wait_for_validator(&rpc, &validator)?;
    let token_program = rpc
        .get_account(&TOKEN_PROGRAM_ID)
        .map_err(|error| format!("classic token fixture missing from genesis: {error}"))?;
    if !token_program.executable {
        return Err("classic token fixture is not executable".to_owned());
    }

    let mut output = String::new();
    output.push_str("WARNING: synthetic assets only; this prototype is not safe for real funds.\n");
    let payer = read_keypair_file(validator._ledger.path().join("faucet-keypair.json"))
        .map_err(|error| format!("read synthetic genesis payer: {error}"))?;

    let operator_seed = random_bytes()?;
    let operator = Keypair::new_from_array(operator_seed);
    let operator_attestation = SigningKey::from_bytes(&operator_seed);
    let venue_authority = Keypair::new();
    let attesters = [
        random_signing_key()?,
        random_signing_key()?,
        random_signing_key()?,
    ];
    let participant_wallets = [
        Keypair::new(),
        Keypair::new(),
        Keypair::new(),
        Keypair::new(),
    ];
    let base_mint = create_mint(&rpc, &payer).map_err(|error| {
        format!(
            "{error}\nvalidator diagnostics:\n{}",
            validator.diagnostics()
        )
    })?;
    let quote_mint = create_mint(&rpc, &payer)?;
    let (pool, _) = pool_address(
        &operator.pubkey(),
        &base_mint.pubkey(),
        &quote_mint.pubkey(),
    );
    let (vault_authority, _) = vault_authority_address(&pool);
    let pool_base_vault =
        create_token_account(&rpc, &payer, &base_mint.pubkey(), &vault_authority)?;
    let pool_quote_vault =
        create_token_account(&rpc, &payer, &quote_mint.pubkey(), &vault_authority)?;
    let venue_base_account =
        create_token_account(&rpc, &payer, &base_mint.pubkey(), &venue_authority.pubkey())?;
    let venue_quote_account = create_token_account(
        &rpc,
        &payer,
        &quote_mint.pubkey(),
        &venue_authority.pubkey(),
    )?;
    let direct_venue_base_account =
        create_token_account(&rpc, &payer, &base_mint.pubkey(), &payer.pubkey())?;
    let direct_venue_quote_account =
        create_token_account(&rpc, &payer, &quote_mint.pubkey(), &payer.pubkey())?;
    mint_to(&rpc, &payer, &base_mint.pubkey(), &venue_base_account, 10)?;

    let direct_sides = [Side::Buy, Side::Sell, Side::Buy, Side::Buy];
    let mut direct_signatures = Vec::new();
    for (wallet, direct_side) in participant_wallets.iter().zip(direct_sides) {
        let base = create_token_account(&rpc, &payer, &base_mint.pubkey(), &wallet.pubkey())?;
        let quote = create_token_account(&rpc, &payer, &quote_mint.pubkey(), &wallet.pubkey())?;
        mint_to(
            &rpc,
            &payer,
            &base_mint.pubkey(),
            &base,
            if direct_side == Side::Sell { 2 } else { 1 },
        )?;
        mint_to(
            &rpc,
            &payer,
            &quote_mint.pubkey(),
            &quote,
            if direct_side == Side::Buy { 200 } else { 100 },
        )?;
        direct_signatures.push(match direct_side {
            Side::Buy => transfer_tokens_with_signature(
                &rpc,
                &payer,
                wallet,
                &quote,
                &quote_mint.pubkey(),
                &direct_venue_quote_account,
                100,
            )?,
            Side::Sell => transfer_tokens_with_signature(
                &rpc,
                &payer,
                wallet,
                &base,
                &base_mint.pubkey(),
                &direct_venue_base_account,
                1,
            )?,
        });
        transfer_tokens(
            &rpc,
            &payer,
            wallet,
            &base,
            &base_mint.pubkey(),
            &pool_base_vault,
            1,
        )?;
        transfer_tokens(
            &rpc,
            &payer,
            wallet,
            &quote,
            &quote_mint.pubkey(),
            &pool_quote_vault,
            100,
        )?;
    }

    let dealer = EpochDealer::random().map_err(|error| format!("dealer: {error:?}"))?;
    send(
        &rpc,
        &payer,
        &[initialize_pool_instruction(
            InitializePoolAccounts {
                payer: payer.pubkey(),
                operator: operator.pubkey(),
                pool,
                vault_authority,
                base_mint: base_mint.pubkey(),
                quote_mint: quote_mint.pubkey(),
                pool_base_vault,
                pool_quote_vault,
                venue_authority: venue_authority.pubkey(),
                venue_base_account,
                venue_quote_account,
            },
            InitializePoolArgs {
                lock_threshold: 2,
                settlement_threshold: 2,
                base_lot_atoms: 1,
                keypers: attesters
                    .each_ref()
                    .map(|key| Pubkey::new_from_array(key.verifying_key().to_bytes())),
            },
        )],
        &[&operator],
    )?;
    let clock_account = rpc
        .get_account(&solana_program::sysvar::clock::ID)
        .map_err(|error| error.to_string())?;
    let clock: Clock =
        bincode::deserialize(&clock_account.data).map_err(|error| error.to_string())?;
    let epoch_id = random_bytes()?;
    let (epoch, _) = epoch_address(&pool, &epoch_id);
    let lock_deadline = clock.unix_timestamp + 300;
    let abort_deadline = clock.unix_timestamp + 600;
    send(
        &rpc,
        &payer,
        &[create_epoch_instruction(
            payer.pubkey(),
            operator.pubkey(),
            pool,
            epoch,
            CreateEpochArgs {
                epoch_id,
                minimum_count: 4,
                quote_atoms_per_lot: 100,
                lock_deadline,
                abort_deadline,
            },
        )],
        &[&operator],
    )?;

    let private = tempfile::tempdir().map_err(|error| error.to_string())?;
    let mut reservations = ReservationJournal::open(private.path().join("reservations.bin"))
        .map_err(|error| format!("reservation journal: {error:?}"))?;
    let suspensions = SuspensionRegistry::open(private.path().join("suspensions.bin"))
        .map_err(|error| format!("suspension registry: {error:?}"))?;
    let mut submissions = Vec::new();
    let mut signed_intents = Vec::new();
    let mut participant_ids = Vec::new();
    let current_slot = rpc.get_slot().map_err(|error| error.to_string())?;
    for side in direct_sides {
        let trading = random_signing_key()?;
        let participant_id = random_bytes()?;
        let reserved = reservations
            .reserve(
                ReservationRecord::new(random_bytes()?, participant_id, 1, 100)
                    .map_err(|error| format!("reservation: {error:?}"))?,
                PoolBalance::new(1, 100),
            )
            .map_err(|error| format!("reservation: {error:?}"))?;
        let authorization = suspensions
            .issue_authorization(
                reserved,
                epoch_id,
                trading.verifying_key(),
                &operator_attestation,
                current_slot + 1_000,
            )
            .map_err(|error| format!("authorization: {error:?}"))?;
        let body = IntentBodyV1::new(side, 1, 100, epoch_id, participant_id, random_bytes()?)
            .map_err(|error| error.to_string())?;
        let signed = SignedIntentV1::sign(body, &trading);
        let encrypted = dealer
            .public_keys()
            .encrypt(&signed)
            .map_err(|error| format!("encrypt: {error:?}"))?;
        submissions.push(
            EncryptedSubmissionV1::sign(authorization, encrypted, random_bytes()?, &trading)
                .map_err(|error| format!("submission: {error:?}"))?,
        );
        signed_intents.push(signed);
        participant_ids.push(participant_id);
    }
    let balances: Vec<_> = participant_ids
        .iter()
        .map(|participant_id| BalanceRecordV1::new(*participant_id, 1, 100, 1, 100))
        .collect::<Result<_, _>>()
        .map_err(|error| format!("balance: {error:?}"))?;
    let snapshot = SignedBalanceSnapshotV1::sign(epoch_id, &balances, &operator_attestation)
        .map_err(|error| format!("snapshot: {error:?}"))?;
    let package = LockPackageV1::new(
        epoch,
        kageb_program::wire::EpochConfigurationV1 {
            pool,
            epoch_id,
            base_mint: base_mint.pubkey(),
            quote_mint: quote_mint.pubkey(),
            base_lot_atoms: 1,
            quote_atoms_per_lot: 100,
            minimum_count: 4,
            lock_threshold: 2,
            settlement_threshold: 2,
            keypers: attesters
                .each_ref()
                .map(|key| Pubkey::new_from_array(key.verifying_key().to_bytes())),
            lock_deadline,
            abort_deadline,
        },
        dealer.public_keys().clone(),
        submissions,
        balances,
        snapshot,
        random_bytes()?,
    )
    .map_err(|error| format!("lock package: {error:?}"))?;

    let keyper_dirs = create_keyper_directories(&validator.rpc_url, &attesters)?;
    let keyper_shares = [
        dealer.share(epoch, 0),
        dealer.share(epoch, 1),
        dealer.share(epoch, 2),
    ];
    let admission = AdmissionPolicyV1::new(
        epoch_id,
        operator_attestation.verifying_key(),
        4,
        1,
        100,
        current_slot,
    )
    .map_err(|error| format!("admission policy: {error:?}"))?;
    let mut structurally_invalid = package.submissions[3].clone();
    let (authorization, ciphertext, receipt, mut signature) =
        structurally_invalid.into_wire_parts();
    signature[0] ^= 1;
    structurally_invalid =
        EncryptedSubmissionV1::from_wire_parts(authorization, ciphertext, receipt, signature);
    let duplicate_and_invalid = vec![
        package.submissions[0].clone(),
        package.submissions[1].clone(),
        package.submissions[2].clone(),
        package.submissions[0].clone(),
        structurally_invalid,
    ];
    if admit_batch(&duplicate_and_invalid, &admission)
        != Err(CryptoError::InsufficientCrowd {
            valid: 3,
            minimum: 4,
        })
    {
        return Err("duplicate or invalid submission raised the admitted crowd count".to_owned());
    }
    let partial_balances = package.balances[..3].to_vec();
    let partial_snapshot =
        SignedBalanceSnapshotV1::sign(epoch_id, &partial_balances, &operator_attestation)
            .map_err(|error| format!("partial snapshot: {error:?}"))?;
    let partial_package = LockPackageV1::new(
        epoch,
        package.configuration,
        dealer.public_keys().clone(),
        package.submissions[..3].to_vec(),
        partial_balances,
        partial_snapshot,
        random_bytes()?,
    )
    .map_err(|error| format!("partial package: {error:?}"))?;
    if run_keyper_sign_lock(
        &executable,
        keyper_dirs[0].path(),
        &keyper_shares[0],
        package.configuration.keypers[0],
        &partial_package,
    ) != Err(KeyperProcessError::ChildFailed)
        || !matches!(
            run_keyper_release_share(
                &executable,
                keyper_dirs[0].path(),
                &keyper_shares[0],
                &partial_package,
                0,
            ),
            Err(KeyperProcessError::ChildFailed)
        )
    {
        return Err("three-member lock/release path did not refuse the crowd".to_owned());
    }
    output.push_str("WAIT: crowd 3/4\n");
    let mut lock_approvals = Vec::new();
    for (index, directory) in keyper_dirs.iter().enumerate() {
        lock_approvals.push(
            run_keyper_sign_lock(
                &executable,
                directory.path(),
                &keyper_shares[index],
                package.configuration.keypers[index],
                &package,
            )
            .map_err(|error| format!("sign lock {index}: {error:?}"))?,
        );
    }
    let lock_digest = package.lock_payload().digest();
    let lock_signature = send_with_signature(
        &rpc,
        &payer,
        &[
            lock_verifier(&lock_approvals[0], &lock_digest),
            lock_verifier(&lock_approvals[1], &lock_digest),
            lock_instruction(operator.pubkey(), pool, epoch, package.lock_payload()),
        ],
        &[&operator],
    )?;
    output.push_str("LOCKED: crowd 4/4\n");

    let mut recovered = Vec::new();
    let mut evidence = Vec::new();
    for member_index in 0..4 {
        let mut releases = Vec::new();
        for (index, directory) in keyper_dirs.iter().enumerate() {
            releases.push(
                run_keyper_release_share(
                    &executable,
                    directory.path(),
                    &keyper_shares[index],
                    &package,
                    member_index,
                )
                .map_err(|error| format!("release share {index}/{member_index}: {error:?}"))?,
            );
        }
        if member_index == 0 {
            if dealer
                .public_keys()
                .recover_submission(&package.submissions[member_index], [&releases[0]])
                .is_ok()
            {
                return Err("one share unexpectedly decrypted an intent".to_owned());
            }
            output.push_str("REFUSED: one share\n");
        }
        recovered.push(
            dealer
                .public_keys()
                .recover_submission(
                    &package.submissions[member_index],
                    [&releases[0], &releases[1]],
                )
                .map_err(|error| format!("recover {member_index}: {error:?}"))?,
        );
        evidence.push(
            DecryptionEvidenceV1::new(releases.remove(0), releases.remove(0))
                .map_err(|error| format!("evidence {member_index}: {error:?}"))?,
        );
    }
    if recovered != signed_intents {
        return Err("recovered batch differs from submitted intents".to_owned());
    }

    let confirmed = ProgramClient::new(&validator.rpc_url)
        .fetch_confirmed_lock(epoch)
        .map_err(|error| format!("confirmed lock: {error:?}"))?;
    let settlement =
        SettlementRequestV1::build(package.clone(), evidence, random_bytes()?, &confirmed)
            .map_err(|error| format!("settlement request: {error:?}"))?;
    let mut settlement_approvals = Vec::new();
    for (index, directory) in keyper_dirs.iter().enumerate() {
        settlement_approvals.push(
            run_keyper_sign_settlement(
                &executable,
                directory.path(),
                &keyper_shares[index],
                package.configuration.keypers[index],
                &settlement,
            )
            .map_err(|error| format!("sign settlement {index}: {error:?}"))?,
        );
    }
    let payload = settlement_approvals[0].payload();
    let digest = payload.digest();
    let settlement_signature = send_with_signature(
        &rpc,
        &payer,
        &[
            settlement_verifier(&settlement_approvals[0], &digest),
            settlement_verifier(&settlement_approvals[1], &digest),
            settle_instruction(
                SettleAccounts {
                    payer: operator.pubkey(),
                    pool,
                    epoch,
                    vault_authority,
                    pool_base_vault,
                    pool_quote_vault,
                    venue_authority: venue_authority.pubkey(),
                    venue_base_account,
                    venue_quote_account,
                    base_mint: base_mint.pubkey(),
                    quote_mint: quote_mint.pubkey(),
                },
                payload,
            ),
        ],
        &[&operator, &venue_authority],
    )?;

    let state_account = rpc.get_account(&epoch).map_err(|error| error.to_string())?;
    let state = EpochStateV1::decode(&state_account.data).map_err(|error| error.to_string())?;
    let pool_state_account = rpc.get_account(&pool).map_err(|error| error.to_string())?;
    let pool_state =
        PoolStateV1::decode(&pool_state_account.data).map_err(|error| error.to_string())?;
    if state.base_lot_atoms != pool_state.base_lot_atoms {
        return Err("epoch base lot differs from its pool configuration".to_owned());
    }
    let balances = [
        token_amount(&rpc, &pool_base_vault)?,
        token_amount(&rpc, &pool_quote_vault)?,
        token_amount(&rpc, &venue_base_account)?,
        token_amount(&rpc, &venue_quote_account)?,
    ];
    if state.terminal_state != EpochTerminalState::Settled || balances != [6, 200, 8, 200] {
        return Err(format!(
            "unexpected settlement state {:?} balances {balances:?}",
            state.terminal_state
        ));
    }
    output.push_str("SETTLED: one aggregate\n");
    balanced_zero_residual_settlement(
        &rpc,
        &payer,
        &executable,
        pool,
        vault_authority,
        base_mint.pubkey(),
        quote_mint.pubkey(),
        &operator,
        &operator_attestation,
        &venue_authority,
        &attesters,
        [
            pool_base_vault,
            pool_quote_vault,
            venue_base_account,
            venue_quote_account,
        ],
    )?;
    output.push_str("BALANCED: zero residual; no venue leg\n");
    invalid_reveal_aborts_and_suspends(
        &rpc,
        &payer,
        &executable,
        pool,
        base_mint.pubkey(),
        quote_mint.pubkey(),
        &operator,
        &operator_attestation,
        &attesters,
        [
            pool_base_vault,
            pool_quote_vault,
            venue_base_account,
            venue_quote_account,
        ],
    )?;
    output.push_str("ABORTED: invalid reveal; trading key suspended\n");
    let direct_confirmed = direct_signatures
        .iter()
        .map(|signature| fetch_confirmed_transaction(&rpc, signature))
        .collect::<Result<Vec<_>, _>>()?;
    let lock_confirmed = fetch_confirmed_transaction(&rpc, &lock_signature)?;
    let settlement_confirmed = fetch_confirmed_transaction(&rpc, &settlement_signature)?;
    let direct_trace = PublicTrace::from_confirmed_direct(
        &direct_confirmed,
        DirectMarketAccounts {
            fee_payer: payer.pubkey(),
            base_mint: base_mint.pubkey(),
            quote_mint: quote_mint.pubkey(),
            venue_base_account: direct_venue_base_account,
            venue_quote_account: direct_venue_quote_account,
            base_lot_atoms: 1,
            quote_atoms_per_lot: 100,
        },
    )
    .map_err(|error| format!("decode direct observer trace: {error:?}"))?;
    let kageb_trace = PublicTrace::from_confirmed_kageb(
        &lock_confirmed,
        &settlement_confirmed,
        KagebObserverAccounts {
            fee_payer: payer.pubkey(),
            payer: operator.pubkey(),
            pool,
            epoch,
            vault_authority,
            pool_base_vault,
            pool_quote_vault,
            venue_authority: venue_authority.pubkey(),
            venue_base_account,
            venue_quote_account,
            base_mint: base_mint.pubkey(),
            quote_mint: quote_mint.pubkey(),
            base_lot_atoms: pool_state.base_lot_atoms,
            quote_atoms_per_lot: state.quote_atoms_per_lot,
        },
    )
    .map_err(|error| format!("decode KageB observer trace: {error:?}"))?;
    if direct_trace.individual_order_count() != 4
        || direct_trace.aggregate_count() != 0
        || kageb_trace.individual_order_count() != 0
        || kageb_trace.aggregate_count() != 1
        || !kageb_trace.visible_participant_wallets().is_empty()
    {
        return Err(
            "decoded observer comparison did not match 4 direct orders and 1 aggregate".to_owned(),
        );
    }
    output.push_str(&format!(
        "OBSERVER: direct {} orders; KageB {} aggregate\n",
        direct_trace.individual_order_count(),
        kageb_trace.aggregate_count()
    ));
    output.push_str(NON_CLAIM);
    output.push('\n');
    Ok(output)
}

pub fn devnet_proof(
    payer_path: &Path,
    program: &str,
    out: &Path,
    rpc_url: &str,
) -> Result<String, String> {
    let program = program
        .parse::<Pubkey>()
        .map_err(|_| "invalid program ID".to_owned())?;
    if program != ID {
        return Err(format!("fixed program ID required: {ID}"));
    }
    if out.exists() {
        return Err("refusing to overwrite existing evidence".to_owned());
    }
    let (public_commit, checkpoint) = clean_public_checkpoint_artifact()?;
    let artifact = checkpoint.artifact;
    let build_toolchain = checkpoint.build_toolchain;
    let checkpoint_artifact_sha256 = hex_sha256(&artifact);
    let rpc = RpcClient::new_with_commitment(rpc_url.to_owned(), CommitmentConfig::confirmed());
    if rpc
        .get_genesis_hash()
        .map_err(|error| format!("read RPC genesis hash: {error}"))?
        .to_string()
        != DEVNET_GENESIS_HASH
    {
        return Err("RPC endpoint is not Solana devnet".to_owned());
    }
    let programdata_address =
        Pubkey::find_program_address(&[ID.as_ref()], &UPGRADEABLE_LOADER_ID).0;
    let deployed_before = fetch_deployed_checkpoint_discovery(&rpc, &artifact)?;
    let payer = read_keypair_file(payer_path).map_err(|_| "read devnet payer failed".to_owned())?;
    let initial_program_key = if deployed_before.is_none() {
        Some(resolve_external_program_keypair()?)
    } else {
        None
    };
    let deployment_action = select_deployment_action(
        deployed_before.as_ref(),
        payer.pubkey(),
        initial_program_key.as_ref().map(Signer::pubkey),
    )?;
    require_devnet_peak_balance(&rpc, &payer, deployment_action, artifact.len())?;
    let executable =
        std::env::current_exe().map_err(|_| "locate KageB executable failed".to_owned())?;
    let private_root = private_runtime_root()?;
    let run_directory =
        tempfile::tempdir_in(&private_root).map_err(|_| "create private run failed".to_owned())?;
    if deployment_action != DevnetDeploymentAction::Noop {
        deploy_checkpoint(
            rpc_url,
            &payer,
            initial_program_key.as_ref(),
            deployment_action,
            run_directory.path(),
            &artifact,
        )?;
    }
    let deployed = fetch_deployed_checkpoint(&rpc, artifact.len())?
        .ok_or("fixed program deployment is missing after deploy")?;
    if deployed.executable != artifact {
        return Err("deployed executable does not match the public checkpoint".to_owned());
    }
    if deployment_action != DevnetDeploymentAction::Noop
        && deployed.upgrade_authority != Some(payer.pubkey())
    {
        return Err("payer is not recorded as provisional upgrade authority".to_owned());
    }

    let operator_seed = random_bytes()?;
    let operator = Keypair::new_from_array(operator_seed);
    let operator_attestation = SigningKey::from_bytes(&operator_seed);
    let venue_authority = Keypair::new();
    let attesters = [
        random_signing_key()?,
        random_signing_key()?,
        random_signing_key()?,
    ];
    let participant_wallets = [
        Keypair::new(),
        Keypair::new(),
        Keypair::new(),
        Keypair::new(),
    ];
    let mut private_material = vec![
        payer.to_bytes().to_vec(),
        operator_seed.to_vec(),
        venue_authority.to_bytes().to_vec(),
        payer_path.as_os_str().as_encoded_bytes().to_vec(),
        private_root.as_os_str().as_encoded_bytes().to_vec(),
        run_directory.path().as_os_str().as_encoded_bytes().to_vec(),
        executable.as_os_str().as_encoded_bytes().to_vec(),
    ];
    if let Some(keypair) = &initial_program_key {
        private_material.push(keypair.to_bytes().to_vec());
    }
    private_material.extend(attesters.iter().map(|key| key.to_bytes().to_vec()));
    private_material.extend(
        participant_wallets
            .iter()
            .map(|wallet| wallet.to_bytes().to_vec()),
    );
    let base_mint = create_mint(&rpc, &payer)?;
    let quote_mint = create_mint(&rpc, &payer)?;
    let (pool, _) = pool_address(
        &operator.pubkey(),
        &base_mint.pubkey(),
        &quote_mint.pubkey(),
    );
    let (vault_authority, _) = vault_authority_address(&pool);
    let pool_base_vault =
        create_token_account(&rpc, &payer, &base_mint.pubkey(), &vault_authority)?;
    let pool_quote_vault =
        create_token_account(&rpc, &payer, &quote_mint.pubkey(), &vault_authority)?;
    let venue_base_account =
        create_token_account(&rpc, &payer, &base_mint.pubkey(), &venue_authority.pubkey())?;
    let venue_quote_account = create_token_account(
        &rpc,
        &payer,
        &quote_mint.pubkey(),
        &venue_authority.pubkey(),
    )?;
    mint_to(&rpc, &payer, &base_mint.pubkey(), &venue_base_account, 10)?;
    let mut funding_signatures = Vec::with_capacity(4);
    let mut funding_sources = Vec::with_capacity(4);
    for wallet in &participant_wallets {
        let base = create_token_account(&rpc, &payer, &base_mint.pubkey(), &wallet.pubkey())?;
        let quote = create_token_account(&rpc, &payer, &quote_mint.pubkey(), &wallet.pubkey())?;
        mint_to(&rpc, &payer, &base_mint.pubkey(), &base, 1)?;
        mint_to(&rpc, &payer, &quote_mint.pubkey(), &quote, 100)?;
        funding_sources.push((base, quote));
        funding_signatures.push(fund_pool_accounts(
            &rpc,
            &payer,
            wallet,
            base,
            quote,
            base_mint.pubkey(),
            quote_mint.pubkey(),
            pool_base_vault,
            pool_quote_vault,
        )?);
    }
    let revoke_base_mint = spl_token_interface::instruction::set_authority(
        &TOKEN_PROGRAM_ID,
        &base_mint.pubkey(),
        None,
        spl_token_interface::instruction::AuthorityType::MintTokens,
        &payer.pubkey(),
        &[],
    )
    .map_err(|error| error.to_string())?;
    let revoke_quote_mint = spl_token_interface::instruction::set_authority(
        &TOKEN_PROGRAM_ID,
        &quote_mint.pubkey(),
        None,
        spl_token_interface::instruction::AuthorityType::MintTokens,
        &payer.pubkey(),
        &[],
    )
    .map_err(|error| error.to_string())?;
    send(&rpc, &payer, &[revoke_base_mint, revoke_quote_mint], &[])?;

    let dealer = EpochDealer::random().map_err(|error| format!("dealer: {error:?}"))?;
    send(
        &rpc,
        &payer,
        &[initialize_pool_instruction(
            InitializePoolAccounts {
                payer: payer.pubkey(),
                operator: operator.pubkey(),
                pool,
                vault_authority,
                base_mint: base_mint.pubkey(),
                quote_mint: quote_mint.pubkey(),
                pool_base_vault,
                pool_quote_vault,
                venue_authority: venue_authority.pubkey(),
                venue_base_account,
                venue_quote_account,
            },
            InitializePoolArgs {
                lock_threshold: 2,
                settlement_threshold: 2,
                base_lot_atoms: 1,
                keypers: attesters
                    .each_ref()
                    .map(|key| Pubkey::new_from_array(key.verifying_key().to_bytes())),
            },
        )],
        &[&operator],
    )?;
    let clock_account = rpc
        .get_account(&solana_program::sysvar::clock::ID)
        .map_err(|error| error.to_string())?;
    let clock: Clock =
        bincode::deserialize(&clock_account.data).map_err(|error| error.to_string())?;
    let epoch_id = random_bytes()?;
    let (epoch, _) = epoch_address(&pool, &epoch_id);
    let current_slot = rpc.get_slot().map_err(|error| error.to_string())?;
    let (lock_deadline, abort_deadline, authorization_expiry_slot) =
        checked_devnet_deadlines(clock.unix_timestamp, current_slot)?;
    send(
        &rpc,
        &payer,
        &[create_epoch_instruction(
            payer.pubkey(),
            operator.pubkey(),
            pool,
            epoch,
            CreateEpochArgs {
                epoch_id,
                minimum_count: 4,
                quote_atoms_per_lot: 100,
                lock_deadline,
                abort_deadline,
            },
        )],
        &[&operator],
    )?;

    let mut reservations = ReservationJournal::open(run_directory.path().join("reservations.bin"))
        .map_err(|error| format!("reservation journal: {error:?}"))?;
    let suspensions = SuspensionRegistry::open(run_directory.path().join("suspensions.bin"))
        .map_err(|error| format!("suspension registry: {error:?}"))?;
    let sides = [Side::Buy, Side::Sell, Side::Buy, Side::Buy];
    let mut submissions = Vec::with_capacity(4);
    let mut participant_ids = Vec::with_capacity(4);
    for side in sides {
        let trading = random_signing_key()?;
        let participant_id = random_bytes()?;
        let reservation_id = random_bytes()?;
        let intent_nonce = random_bytes()?;
        let receipt = random_bytes()?;
        private_material.extend([
            trading.to_bytes().to_vec(),
            participant_id.to_vec(),
            reservation_id.to_vec(),
            intent_nonce.to_vec(),
            receipt.to_vec(),
        ]);
        let reserved = reservations
            .reserve(
                ReservationRecord::new(reservation_id, participant_id, 1, 100)
                    .map_err(|error| format!("reservation: {error:?}"))?,
                PoolBalance::new(1, 100),
            )
            .map_err(|error| format!("reservation: {error:?}"))?;
        let authorization = suspensions
            .issue_authorization(
                reserved,
                epoch_id,
                trading.verifying_key(),
                &operator_attestation,
                authorization_expiry_slot,
            )
            .map_err(|error| format!("authorization: {error:?}"))?;
        let body = IntentBodyV1::new(side, 1, 100, epoch_id, participant_id, intent_nonce)
            .map_err(|error| error.to_string())?;
        let signed = SignedIntentV1::sign(body, &trading);
        let encrypted = dealer
            .public_keys()
            .encrypt(&signed)
            .map_err(|error| format!("encrypt: {error:?}"))?;
        submissions.push(
            EncryptedSubmissionV1::sign(authorization, encrypted, receipt, &trading)
                .map_err(|error| format!("submission: {error:?}"))?,
        );
        participant_ids.push(participant_id);
    }
    let balances: Vec<_> = participant_ids
        .iter()
        .map(|participant_id| BalanceRecordV1::new(*participant_id, 1, 100, 1, 100))
        .collect::<Result<_, _>>()
        .map_err(|error| format!("balance: {error:?}"))?;
    let snapshot = SignedBalanceSnapshotV1::sign(epoch_id, &balances, &operator_attestation)
        .map_err(|error| format!("snapshot: {error:?}"))?;
    let package_nonce = random_bytes()?;
    private_material.push(package_nonce.to_vec());
    let package = LockPackageV1::new(
        epoch,
        kageb_program::wire::EpochConfigurationV1 {
            pool,
            epoch_id,
            base_mint: base_mint.pubkey(),
            quote_mint: quote_mint.pubkey(),
            base_lot_atoms: 1,
            quote_atoms_per_lot: 100,
            minimum_count: 4,
            lock_threshold: 2,
            settlement_threshold: 2,
            keypers: attesters
                .each_ref()
                .map(|key| Pubkey::new_from_array(key.verifying_key().to_bytes())),
            lock_deadline,
            abort_deadline,
        },
        dealer.public_keys().clone(),
        submissions,
        balances,
        snapshot,
        package_nonce,
    )
    .map_err(|error| format!("lock package: {error:?}"))?;
    let keyper_dirs = create_devnet_keyper_directories(&private_root, rpc_url, &attesters)?;
    let keyper_shares = [
        dealer.share(epoch, 0),
        dealer.share(epoch, 1),
        dealer.share(epoch, 2),
    ];
    private_material.extend(
        keyper_dirs
            .iter()
            .map(|directory| directory.path().as_os_str().as_encoded_bytes().to_vec()),
    );
    for share in &keyper_shares {
        private_material.push(
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .reject_trailing_bytes()
                .serialize(&SerdeSecret(share.secret()))
                .map_err(|_| "encode private keyper share failed".to_owned())?,
        );
    }
    let lock_approvals = [0_usize, 1]
        .into_iter()
        .map(|index| {
            run_keyper_sign_lock(
                &executable,
                keyper_dirs[index].path(),
                &keyper_shares[index],
                package.configuration.keypers[index],
                &package,
            )
            .map_err(|error| format!("sign lock {index}: {error:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let lock_digest = package.lock_payload().digest();
    let lock_signature = send_with_signature(
        &rpc,
        &payer,
        &[
            lock_verifier(&lock_approvals[0], &lock_digest),
            lock_verifier(&lock_approvals[1], &lock_digest),
            lock_instruction(operator.pubkey(), pool, epoch, package.lock_payload()),
        ],
        &[&operator],
    )?;
    let mut decryption_evidence = Vec::with_capacity(4);
    for member_index in 0..4 {
        let first = run_keyper_release_share(
            &executable,
            keyper_dirs[0].path(),
            &keyper_shares[0],
            &package,
            member_index,
        )
        .map_err(|error| format!("release share 0/{member_index}: {error:?}"))?;
        let second = run_keyper_release_share(
            &executable,
            keyper_dirs[1].path(),
            &keyper_shares[1],
            &package,
            member_index,
        )
        .map_err(|error| format!("release share 1/{member_index}: {error:?}"))?;
        decryption_evidence.push(
            DecryptionEvidenceV1::new(first, second)
                .map_err(|error| format!("decryption evidence {member_index}: {error:?}"))?,
        );
    }
    let confirmed = ProgramClient::new(rpc_url)
        .fetch_confirmed_lock(epoch)
        .map_err(|error| format!("confirmed lock: {error:?}"))?;
    let settlement_nonce = random_bytes()?;
    private_material.push(settlement_nonce.to_vec());
    let settlement = SettlementRequestV1::build(
        package.clone(),
        decryption_evidence,
        settlement_nonce,
        &confirmed,
    )
    .map_err(|error| format!("settlement request: {error:?}"))?;
    let transcript_hash = hex_sha256(
        &settlement
            .encode_wire()
            .map_err(|error| format!("settlement transcript: {error:?}"))?,
    );
    let settlement_approvals = [0_usize, 1]
        .into_iter()
        .map(|index| {
            run_keyper_sign_settlement(
                &executable,
                keyper_dirs[index].path(),
                &keyper_shares[index],
                package.configuration.keypers[index],
                &settlement,
            )
            .map_err(|error| format!("sign settlement {index}: {error:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let payload = settlement_approvals[0].payload();
    let settlement_digest = payload.digest();
    let token_balances_before = [
        token_amount(&rpc, &pool_base_vault)?,
        token_amount(&rpc, &pool_quote_vault)?,
        token_amount(&rpc, &venue_base_account)?,
        token_amount(&rpc, &venue_quote_account)?,
    ];
    let settlement_signature = send_with_signature(
        &rpc,
        &payer,
        &[
            settlement_verifier(&settlement_approvals[0], &settlement_digest),
            settlement_verifier(&settlement_approvals[1], &settlement_digest),
            settle_instruction(
                SettleAccounts {
                    payer: operator.pubkey(),
                    pool,
                    epoch,
                    vault_authority,
                    pool_base_vault,
                    pool_quote_vault,
                    venue_authority: venue_authority.pubkey(),
                    venue_base_account,
                    venue_quote_account,
                    base_mint: base_mint.pubkey(),
                    quote_mint: quote_mint.pubkey(),
                },
                payload,
            ),
        ],
        &[&operator, &venue_authority],
    )?;
    let token_balances_after = [
        token_amount(&rpc, &pool_base_vault)?,
        token_amount(&rpc, &pool_quote_vault)?,
        token_amount(&rpc, &venue_base_account)?,
        token_amount(&rpc, &venue_quote_account)?,
    ];
    if token_balances_before != [4, 400, 10, 0] || token_balances_after != [6, 200, 8, 200] {
        return Err(format!(
            "unexpected aggregate token balances {token_balances_before:?} -> {token_balances_after:?}"
        ));
    }
    let epoch_state = EpochStateV1::decode(
        &rpc.get_account(&epoch)
            .map_err(|error| error.to_string())?
            .data,
    )
    .map_err(|error| error.to_string())?;
    if epoch_state.terminal_state != EpochTerminalState::Settled
        || epoch_state.member_count != 4
        || epoch_state.result_commitment != settlement.result_commitment
    {
        return Err("devnet epoch did not reach the expected settled state".to_owned());
    }

    let mut finalized_transactions = Vec::with_capacity(6);
    for signature in funding_signatures
        .iter()
        .chain([&lock_signature, &settlement_signature])
    {
        finalized_transactions.push(wait_for_finalized_transaction(rpc_url, signature)?);
    }
    let mut funding_evidence = Vec::with_capacity(4);
    for index in 0..4 {
        let wallet = participant_wallets
            .get(index)
            .ok_or("four participant wallets required")?;
        let signature = funding_signatures
            .get(index)
            .ok_or("four funding signatures required")?;
        let (base_source, quote_source) = funding_sources
            .get(index)
            .ok_or("four funding source pairs required")?;
        let transaction = finalized_transactions
            .get(index)
            .ok_or("four finalized funding transactions required")?;
        funding_evidence.push(FundingTransactionEvidenceV1 {
            authority: wallet.pubkey().to_string(),
            base_source: base_source.to_string(),
            quote_source: quote_source.to_string(),
            transaction: EvidenceTransactionV1 {
                signature: signature.to_string(),
                slot: transaction.slot,
            },
        });
    }
    let funding_evidence: [FundingTransactionEvidenceV1; 4] = funding_evidence
        .try_into()
        .map_err(|_| "four funding records required".to_owned())?;
    let configuration_hash = package.configuration.digest();
    let mut content = DevnetEvidenceContentV1 {
        cluster: "devnet".to_owned(),
        public_commit,
        build_toolchain,
        checkpoint_artifact_len: artifact.len(),
        checkpoint_artifact_sha256,
        deployment: EvidenceDeploymentV1 {
            program: ID.to_string(),
            loader: UPGRADEABLE_LOADER_ID.to_string(),
            programdata: programdata_address.to_string(),
            deployment_slot: deployed.deployment_slot,
            upgrade_authority: deployed.upgrade_authority.map(|key| key.to_string()),
            deployed_executable_sha256: deployed.executable_sha256,
        },
        transactions: EvidenceTransactionsV1 {
            funding: funding_evidence,
            lock: EvidenceTransactionV1 {
                signature: lock_signature.to_string(),
                slot: finalized_transactions[4].slot,
            },
            settlement: EvidenceTransactionV1 {
                signature: settlement_signature.to_string(),
                slot: finalized_transactions[5].slot,
            },
        },
        accounts: EvidenceAccountsV1 {
            fee_payer: payer.pubkey().to_string(),
            operator: operator.pubkey().to_string(),
            pool: pool.to_string(),
            epoch: epoch.to_string(),
            vault_authority: vault_authority.to_string(),
            base_mint: base_mint.pubkey().to_string(),
            quote_mint: quote_mint.pubkey().to_string(),
            pool_base_vault: pool_base_vault.to_string(),
            pool_quote_vault: pool_quote_vault.to_string(),
            venue_authority: venue_authority.pubkey().to_string(),
            venue_base_account: venue_base_account.to_string(),
            venue_quote_account: venue_quote_account.to_string(),
            token_program: TOKEN_PROGRAM_ID.to_string(),
        },
        configuration: EvidenceConfigurationV1 {
            epoch_id: hex_bytes(epoch_id),
            minimum_count: 4,
            member_count: 4,
            lock_threshold: 2,
            settlement_threshold: 2,
            keypers: package.configuration.keypers.map(|key| key.to_string()),
            base_lot_atoms: 1,
            quote_atoms_per_lot: 100,
        },
        commitments: EvidenceCommitmentsV1 {
            configuration_hash: hex_bytes(configuration_hash),
            pre_balance_root: hex_bytes(settlement.pre_balance_root),
            member_set: hex_bytes(package.member_root),
            lock_digest: hex_bytes(lock_digest),
            result: hex_bytes(settlement.result_commitment),
            settlement_digest: hex_bytes(settlement_digest),
            local_transcript_sha256: transcript_hash,
        },
        token_balances: EvidenceTokenBalancesV1 {
            pool_base_before: token_balances_before[0],
            pool_base_after: token_balances_after[0],
            pool_quote_before: token_balances_before[1],
            pool_quote_after: token_balances_after[1],
            venue_base_before: token_balances_before[2],
            venue_base_after: token_balances_after[2],
            venue_quote_before: token_balances_before[3],
            venue_quote_after: token_balances_after[3],
        },
        decoded_allowlist: Vec::new(),
        explorer_links: funding_signatures
            .iter()
            .chain([&lock_signature, &settlement_signature])
            .map(|signature| format!("https://explorer.solana.com/tx/{signature}?cluster=devnet"))
            .collect(),
    };
    content.decoded_allowlist = canonical_devnet_allowlist(&content);
    let bundle = DevnetEvidenceBundleV1::seal(content)
        .map_err(|error| format!("seal devnet evidence: {error:?}"))?;
    crate::verify_devnet_evidence_at_rpc(&bundle, &artifact, rpc_url)
        .map_err(|error| format!("verify devnet evidence before write: {error:?}"))?;
    persist_verified_evidence(out, rpc_url, &bundle, &private_material)?;
    Ok(format!(
        "LOCKED: crowd 4/4\nSETTLED: one aggregate BUY 2 lots\nVERIFIED: evidence {} settlement {}\n{NON_CLAIM}\n",
        bundle.evidence_sha256, settlement_signature
    ))
}

fn clean_public_checkpoint_artifact() -> Result<(String, CanonicalCheckpointV1), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|_| "resolve repository root failed".to_owned())?;
    let status = command_stdout(
        Command::new("git")
            .arg("status")
            .arg("--porcelain")
            .current_dir(&root),
    )?;
    if !status.trim().is_empty() {
        return Err("public checkpoint requires a clean repository".to_owned());
    }
    let commit = command_stdout(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&root),
    )?
    .trim()
    .to_owned();
    let checkpoint = build_canonical_checkpoint(&commit)?;
    Ok((commit, checkpoint))
}

fn command_stdout(command: &mut Command) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|_| "repository command failed to launch".to_owned())?;
    if !output.status.success() {
        return Err("repository command failed".to_owned());
    }
    String::from_utf8(output.stdout).map_err(|_| "repository command returned non-UTF-8".to_owned())
}

fn discover_deployed_checkpoint(
    program: &PublicAccountSnapshotV1,
    expected_programdata: Pubkey,
    programdata: &PublicAccountSnapshotV1,
    artifact: &[u8],
) -> Result<DeployedCheckpointDiscovery, String> {
    if program.owner != UPGRADEABLE_LOADER_ID || !program.executable {
        return Err("fixed program is not an upgradeable loader program".to_owned());
    }
    let program_state: UpgradeableLoaderState = bincode::deserialize(&program.data)
        .map_err(|_| "fixed program loader metadata is malformed".to_owned())?;
    let UpgradeableLoaderState::Program {
        programdata_address,
    } = program_state
    else {
        return Err("fixed program loader metadata is malformed".to_owned());
    };
    if programdata_address != expected_programdata {
        return Err("fixed program points to unexpected ProgramData".to_owned());
    }
    if programdata.owner != UPGRADEABLE_LOADER_ID || programdata.executable {
        return Err("fixed ProgramData account is invalid".to_owned());
    }
    let metadata_len = UpgradeableLoaderState::size_of_programdata_metadata();
    let metadata = programdata
        .data
        .get(..metadata_len)
        .ok_or("fixed ProgramData metadata is malformed")?;
    let programdata_state: UpgradeableLoaderState = bincode::deserialize(metadata)
        .map_err(|_| "fixed ProgramData metadata is malformed".to_owned())?;
    let UpgradeableLoaderState::ProgramData {
        upgrade_authority_address,
        ..
    } = programdata_state
    else {
        return Err("fixed ProgramData metadata is malformed".to_owned());
    };
    let executable_region = &programdata.data[metadata_len..];
    if !executable_region.starts_with(b"\x7fELF") {
        return Err("fixed ProgramData executable is not ELF".to_owned());
    }
    let artifact_matches = executable_region.starts_with(artifact)
        && executable_region[artifact.len()..]
            .iter()
            .all(|byte| *byte == 0);
    Ok(DeployedCheckpointDiscovery {
        upgrade_authority: upgrade_authority_address,
        artifact_matches,
    })
}

fn fetch_deployed_checkpoint(
    rpc: &RpcClient,
    artifact_len: usize,
) -> Result<Option<crate::ExtractedUpgradeableProgramV1>, String> {
    let Some((program, programdata)) = fetch_deployment_accounts(rpc)? else {
        return Ok(None);
    };
    let programdata_address =
        Pubkey::find_program_address(&[ID.as_ref()], &UPGRADEABLE_LOADER_ID).0;
    extract_upgradeable_program(&program, programdata_address, &programdata, artifact_len)
        .map(Some)
        .map_err(|error| format!("extract fixed deployment failed: {error:?}"))
}

fn fetch_deployed_checkpoint_discovery(
    rpc: &RpcClient,
    artifact: &[u8],
) -> Result<Option<DeployedCheckpointDiscovery>, String> {
    let Some((program, programdata)) = fetch_deployment_accounts(rpc)? else {
        return Ok(None);
    };
    let programdata_address =
        Pubkey::find_program_address(&[ID.as_ref()], &UPGRADEABLE_LOADER_ID).0;
    discover_deployed_checkpoint(&program, programdata_address, &programdata, artifact).map(Some)
}

fn fetch_deployment_accounts(
    rpc: &RpcClient,
) -> Result<Option<(PublicAccountSnapshotV1, PublicAccountSnapshotV1)>, String> {
    let programdata_address =
        Pubkey::find_program_address(&[ID.as_ref()], &UPGRADEABLE_LOADER_ID).0;
    let program = rpc
        .get_account_with_commitment(&ID, CommitmentConfig::finalized())
        .map_err(|_| "read fixed program account failed".to_owned())?
        .value;
    let programdata = rpc
        .get_account_with_commitment(&programdata_address, CommitmentConfig::finalized())
        .map_err(|_| "read fixed ProgramData account failed".to_owned())?
        .value;
    let (program, programdata) = match (program, programdata) {
        (None, None) => return Ok(None),
        (Some(program), Some(programdata)) => (program, programdata),
        _ => return Err("fixed deployment accounts are incomplete".to_owned()),
    };
    Ok(Some((
        PublicAccountSnapshotV1 {
            owner: program.owner,
            executable: program.executable,
            data: program.data,
        },
        PublicAccountSnapshotV1 {
            owner: programdata.owner,
            executable: programdata.executable,
            data: programdata.data,
        },
    )))
}

fn resolve_external_program_keypair() -> Result<Keypair, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|_| "resolve repository root failed".to_owned())?;
    let configured = std::env::var_os("KAGEB_PROGRAM_KEYPAIR").map(PathBuf::from);
    let path = configured
        .clone()
        .unwrap_or_else(|| root.join("target/deploy/kageb_program-keypair.json"));
    if configured.is_none()
        && !fs::symlink_metadata(&path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
    {
        return Err(
            "initial deployment needs KAGEB_PROGRAM_KEYPAIR or the ignored target symlink"
                .to_owned(),
        );
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| "resolve external program key failed".to_owned())?;
    if canonical.starts_with(&root) {
        return Err("program key must live outside the public repository".to_owned());
    }
    let keypair =
        read_keypair_file(&canonical).map_err(|_| "read external program key failed".to_owned())?;
    if keypair.pubkey() != ID {
        return Err("external program key does not match the fixed program ID".to_owned());
    }
    Ok(keypair)
}

fn devnet_peak_rents(rpc: &RpcClient, artifact_len: usize) -> Result<DevnetPeakRents, String> {
    let mint_rent = rpc
        .get_minimum_balance_for_rent_exemption(spl_token_interface::state::Mint::LEN)
        .map_err(|_| "read mint rent failed".to_owned())?;
    let token_rent = rpc
        .get_minimum_balance_for_rent_exemption(spl_token_interface::state::Account::LEN)
        .map_err(|_| "read token rent failed".to_owned())?;
    let state_rent = rpc
        .get_minimum_balance_for_rent_exemption(kageb_program::state::STATE_LEN)
        .map_err(|_| "read state rent failed".to_owned())?;
    let setup = mint_rent
        .checked_mul(2)
        .and_then(|value| value.checked_add(token_rent.checked_mul(12)?))
        .and_then(|value| value.checked_add(state_rent.checked_mul(2)?))
        .ok_or("devnet setup balance overflow")?;
    let program = rpc
        .get_minimum_balance_for_rent_exemption(UpgradeableLoaderState::size_of_program())
        .map_err(|_| "read program rent failed".to_owned())?;
    let programdata = rpc
        .get_minimum_balance_for_rent_exemption(UpgradeableLoaderState::size_of_programdata(
            artifact_len,
        ))
        .map_err(|_| "read ProgramData rent failed".to_owned())?;
    let buffer = rpc
        .get_minimum_balance_for_rent_exemption(UpgradeableLoaderState::size_of_buffer(
            artifact_len,
        ))
        .map_err(|_| "read deploy buffer rent failed".to_owned())?;
    Ok(DevnetPeakRents {
        setup,
        program,
        programdata,
        buffer,
        fees: 20_000_000,
    })
}

fn require_devnet_peak_balance(
    rpc: &RpcClient,
    payer: &Keypair,
    action: DevnetDeploymentAction,
    artifact_len: usize,
) -> Result<(), String> {
    let required = required_peak_balance(action, devnet_peak_rents(rpc, artifact_len)?)?;
    let available = rpc
        .get_balance(&payer.pubkey())
        .map_err(|_| "read devnet payer balance failed".to_owned())?;
    if available < required {
        return Err(format!(
            "devnet payer needs {required} lamports at peak; available {available}"
        ));
    }
    Ok(())
}

fn write_private_keypair(path: &Path, keypair: &Keypair) -> Result<(), String> {
    let encoded = serde_json::to_vec(&keypair.to_bytes().to_vec())
        .map_err(|_| "encode private key failed".to_owned())?;
    write_private_file(path, &encoded)
}

fn deploy_checkpoint(
    rpc_url: &str,
    payer: &Keypair,
    initial_program_key: Option<&Keypair>,
    action: DevnetDeploymentAction,
    private_directory: &Path,
    artifact: &[u8],
) -> Result<(), String> {
    let solana = resolve_on_path("solana")?;
    deploy_checkpoint_with_runner_and_refunder(
        &solana,
        rpc_url,
        payer,
        initial_program_key,
        action,
        private_directory,
        artifact,
        |command| {
            command
                .output()
                .map(|output| {
                    if !output.status.success() {
                        eprintln!(
                            "Solana program deploy failed: {}",
                            classify_deploy_failure(&output.stdout, &output.stderr)
                        );
                    }
                    output.status.success()
                })
                .map_err(|_| ())
        },
        |buffer| close_deploy_buffer(rpc_url, payer, buffer),
    )
}

fn classify_deploy_failure(stdout: &[u8], stderr: &[u8]) -> &'static str {
    let stdout = String::from_utf8_lossy(stdout).to_ascii_lowercase();
    let stderr = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    let contains = |needle: &str| stdout.contains(needle) || stderr.contains(needle);
    if contains("insufficient funds") {
        "insufficient payer funds"
    } else if contains("max retries")
        || contains("timed out")
        || contains("blockhash not found")
        || contains("node is behind")
        || contains("429")
    {
        "devnet transport retries exhausted"
    } else if contains("elf error")
        || contains("verification failed")
        || contains("program failed to complete")
    {
        "program rejected by the cluster"
    } else {
        "unclassified CLI failure"
    }
}

fn close_deploy_buffer_instruction(
    buffer: Pubkey,
    recipient: Pubkey,
    authority: Pubkey,
) -> Instruction {
    Instruction::new_with_bincode(
        UPGRADEABLE_LOADER_ID,
        &UpgradeableLoaderInstruction::Close,
        vec![
            AccountMeta::new(buffer, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(authority, true),
        ],
    )
}

fn close_deploy_buffer(rpc_url: &str, payer: &Keypair, buffer: Pubkey) -> Result<(), ()> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_owned(), CommitmentConfig::finalized());
    let blockhash = rpc.get_latest_blockhash().map_err(|_| ())?;
    let instruction = close_deploy_buffer_instruction(buffer, payer.pubkey(), payer.pubkey());
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );
    rpc.send_and_confirm_transaction(&transaction)
        .map(|_| ())
        .map_err(|_| ())
}

#[allow(clippy::too_many_arguments)]
fn deploy_checkpoint_with_runner_and_refunder<F, R>(
    solana: &Path,
    rpc_url: &str,
    payer: &Keypair,
    initial_program_key: Option<&Keypair>,
    action: DevnetDeploymentAction,
    private_directory: &Path,
    artifact: &[u8],
    mut runner: F,
    mut refunder: R,
) -> Result<(), String>
where
    F: FnMut(&mut Command) -> Result<bool, ()>,
    R: FnMut(Pubkey) -> Result<(), ()>,
{
    let artifact_path = private_directory.join("checkpoint.so");
    write_private_file(&artifact_path, artifact)?;
    let signer_directory = tempfile::Builder::new()
        .prefix("deploy-signers-")
        .tempdir_in(private_directory)
        .map_err(|_| "create private deploy signer directory failed".to_owned())?;
    #[cfg(unix)]
    fs::set_permissions(signer_directory.path(), fs::Permissions::from_mode(0o700))
        .map_err(|_| "secure private deploy signer directory failed".to_owned())?;
    let payer_path = signer_directory.path().join("payer.json");
    let buffer_path = signer_directory.path().join("buffer.json");
    let buffer = Keypair::new();
    let buffer_pubkey = buffer.pubkey();
    write_private_keypair(&payer_path, payer)?;
    write_private_keypair(&buffer_path, &buffer)?;
    let program_id = if action == DevnetDeploymentAction::Initial {
        let keypair = initial_program_key.ok_or("initial program key is missing")?;
        let program_path = signer_directory.path().join("program.json");
        write_private_keypair(&program_path, keypair)?;
        program_path.into_os_string()
    } else {
        ID.to_string().into()
    };
    let deploy_status = {
        let mut command = Command::new(solana);
        command
            .args(["program", "deploy"])
            .arg(&artifact_path)
            .args([
                "--url",
                rpc_url,
                "--commitment",
                "finalized",
                "--use-tpu-client",
            ])
            .arg("--fee-payer")
            .arg(&payer_path)
            .arg("--keypair")
            .arg(&payer_path)
            .arg("--upgrade-authority")
            .arg(&payer_path)
            .arg("--program-id")
            .arg(program_id)
            .arg("--buffer")
            .arg(&buffer_path)
            .arg("--max-len")
            .arg(artifact.len().to_string())
            .args(["--max-sign-attempts", "20"])
            .args(["--output", "json"]);
        runner(&mut command)
    };
    let buffer_cleanup_failed = deploy_status != Ok(true) && refunder(buffer_pubkey).is_err();
    let signer_cleanup_failed = signer_directory.close().is_err();
    finish_deploy_attempt(
        deploy_status,
        buffer_cleanup_failed,
        signer_cleanup_failed,
        buffer_pubkey,
    )
}

fn finish_deploy_attempt(
    deploy_status: Result<bool, ()>,
    buffer_cleanup_failed: bool,
    signer_cleanup_failed: bool,
    buffer_pubkey: Pubkey,
) -> Result<(), String> {
    if signer_cleanup_failed {
        if buffer_cleanup_failed {
            return Err(format!(
                "Solana program deploy failed; buffer cleanup failed: {buffer_pubkey}; private signer cleanup also failed"
            ));
        }
        return Err("remove private deploy signer files failed".to_owned());
    }
    if buffer_cleanup_failed {
        return Err(format!(
            "Solana program deploy failed; buffer cleanup failed: {buffer_pubkey}"
        ));
    }
    match deploy_status {
        Ok(true) => Ok(()),
        Ok(false) => Err("Solana program deploy failed".to_owned()),
        Err(()) => Err("launch Solana program deploy failed".to_owned()),
    }
}

fn private_runtime_root() -> Result<PathBuf, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.kageb-private");
    fs::create_dir_all(&root).map_err(|_| "create private runtime failed".to_owned())?;
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .map_err(|_| "secure private runtime failed".to_owned())?;
    root.canonicalize()
        .map_err(|_| "resolve private runtime failed".to_owned())
}

#[allow(clippy::too_many_arguments)]
fn fund_pool_accounts(
    rpc: &RpcClient,
    payer: &Keypair,
    authority: &Keypair,
    base_source: Pubkey,
    quote_source: Pubkey,
    base_mint: Pubkey,
    quote_mint: Pubkey,
    pool_base_vault: Pubkey,
    pool_quote_vault: Pubkey,
) -> Result<Signature, String> {
    let base = spl_token_interface::instruction::transfer_checked(
        &TOKEN_PROGRAM_ID,
        &base_source,
        &base_mint,
        &pool_base_vault,
        &authority.pubkey(),
        &[],
        1,
        0,
    )
    .map_err(|error| error.to_string())?;
    let quote = spl_token_interface::instruction::transfer_checked(
        &TOKEN_PROGRAM_ID,
        &quote_source,
        &quote_mint,
        &pool_quote_vault,
        &authority.pubkey(),
        &[],
        100,
        0,
    )
    .map_err(|error| error.to_string())?;
    send_with_signature(rpc, payer, &[base, quote], &[authority])
}

fn create_devnet_keyper_directories(
    private_root: &Path,
    rpc_url: &str,
    attesters: &[SigningKey; 3],
) -> Result<[TempDir; 3], String> {
    let directories = [
        tempfile::tempdir_in(private_root)
            .map_err(|_| "create private keyper runtime failed".to_owned())?,
        tempfile::tempdir_in(private_root)
            .map_err(|_| "create private keyper runtime failed".to_owned())?,
        tempfile::tempdir_in(private_root)
            .map_err(|_| "create private keyper runtime failed".to_owned())?,
    ];
    for index in 0..3 {
        #[cfg(unix)]
        fs::set_permissions(directories[index].path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| "secure private keyper runtime failed".to_owned())?;
        write_private_file(
            &directories[index].path().join("keyper-rpc-url"),
            rpc_url.as_bytes(),
        )?;
        write_private_file(
            &directories[index].path().join("keyper-attestation-key"),
            &attesters[index].to_bytes(),
        )?;
    }
    Ok(directories)
}

fn wait_for_finalized_transaction(
    rpc_url: &str,
    signature: &Signature,
) -> Result<EncodedConfirmedTransactionWithStatusMeta, String> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_owned(), CommitmentConfig::finalized());
    for _ in 0..240 {
        let status = rpc
            .get_signature_statuses_with_history(&[*signature])
            .map_err(|error| error.to_string())?
            .value
            .into_iter()
            .next()
            .flatten();
        if let Some(status) = status {
            if status.err.is_some() {
                return Err(format!("transaction {signature} failed"));
            }
            if status.satisfies_commitment(CommitmentConfig::finalized()) {
                return rpc
                    .get_transaction(signature, UiTransactionEncoding::Base64)
                    .map_err(|error| error.to_string());
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
    Err(format!("transaction {signature} did not finalize"))
}

fn canonical_devnet_allowlist(
    content: &DevnetEvidenceContentV1,
) -> Vec<DecodedInstructionEvidenceV1> {
    let mut allowlist = Vec::new();
    for index in 0..4 {
        for (position, kind) in ["pool-funding-base", "pool-funding-quote"]
            .into_iter()
            .enumerate()
        {
            allowlist.push(DecodedInstructionEvidenceV1 {
                transaction: format!("funding-{index}"),
                position: position as u16,
                program: TOKEN_PROGRAM_ID.to_string(),
                kind: kind.to_owned(),
                digest: None,
            });
        }
    }
    for position in 0..2 {
        allowlist.push(DecodedInstructionEvidenceV1 {
            transaction: "lock".to_owned(),
            position,
            program: solana_program::ed25519_program::ID.to_string(),
            kind: "keyper-lock-approval".to_owned(),
            digest: Some(content.commitments.lock_digest.clone()),
        });
    }
    allowlist.push(DecodedInstructionEvidenceV1 {
        transaction: "lock".to_owned(),
        position: 2,
        program: ID.to_string(),
        kind: "epoch-lock".to_owned(),
        digest: Some(content.commitments.lock_digest.clone()),
    });
    for position in 0..2 {
        allowlist.push(DecodedInstructionEvidenceV1 {
            transaction: "settlement".to_owned(),
            position,
            program: solana_program::ed25519_program::ID.to_string(),
            kind: "keyper-settlement-approval".to_owned(),
            digest: Some(content.commitments.settlement_digest.clone()),
        });
    }
    allowlist.push(DecodedInstructionEvidenceV1 {
        transaction: "settlement".to_owned(),
        position: 2,
        program: ID.to_string(),
        kind: "aggregate-settlement".to_owned(),
        digest: Some(content.commitments.settlement_digest.clone()),
    });
    allowlist.push(DecodedInstructionEvidenceV1 {
        transaction: "settlement".to_owned(),
        position: 3,
        program: TOKEN_PROGRAM_ID.to_string(),
        kind: "aggregate-quote-leg".to_owned(),
        digest: None,
    });
    allowlist.push(DecodedInstructionEvidenceV1 {
        transaction: "settlement".to_owned(),
        position: 4,
        program: TOKEN_PROGRAM_ID.to_string(),
        kind: "aggregate-base-leg".to_owned(),
        digest: None,
    });
    allowlist
}

fn persist_verified_evidence(
    out: &Path,
    rpc_url: &str,
    bundle: &DevnetEvidenceBundleV1,
    private_material: &[Vec<u8>],
) -> Result<(), String> {
    let mut bytes = bundle
        .to_json_pretty()
        .map_err(|_| "encode evidence failed".to_owned())?
        .into_bytes();
    bytes.push(b'\n');
    scan_public_evidence_bytes(&bytes, &private_material_encodings(private_material))?;

    let executable =
        std::env::current_exe().map_err(|_| "locate fresh evidence verifier failed".to_owned())?;
    let mut child = Command::new(executable)
        .args(["verify", "evidence", "-"])
        .args(["--rpc", rpc_url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "launch fresh evidence verifier failed".to_owned())?;
    child
        .stdin
        .take()
        .ok_or("fresh evidence verifier stdin missing")?
        .write_all(&bytes)
        .map_err(|_| "write fresh evidence verifier input failed".to_owned())?;
    let output = child
        .wait_with_output()
        .map_err(|_| "wait for fresh evidence verifier failed".to_owned())?;
    let expected = format!(
        "VERIFIED: evidence {} settlement {}\n",
        bundle.evidence_sha256, bundle.content.transactions.settlement.signature
    );
    if !output.status.success() || output.stdout != expected.as_bytes() {
        return Err("fresh evidence verifier failed".to_owned());
    }
    publish_bytes_noclobber(out, &bytes)
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex_bytes(Sha256::digest(bytes))
}

fn hex_bytes(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.as_ref().len() * 2);
    for byte in bytes.as_ref() {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

#[allow(clippy::too_many_arguments)]
fn balanced_zero_residual_settlement(
    rpc: &RpcClient,
    payer: &Keypair,
    executable: &Path,
    pool: Pubkey,
    vault_authority: Pubkey,
    base_mint: Pubkey,
    quote_mint: Pubkey,
    operator: &Keypair,
    operator_attestation: &SigningKey,
    venue_authority: &Keypair,
    attesters: &[SigningKey; 3],
    backed_accounts: [Pubkey; 4],
) -> Result<(), String> {
    let clock_account = rpc
        .get_account(&solana_program::sysvar::clock::ID)
        .map_err(|error| error.to_string())?;
    let clock: Clock =
        bincode::deserialize(&clock_account.data).map_err(|error| error.to_string())?;
    let epoch_id = random_bytes()?;
    let (epoch, _) = epoch_address(&pool, &epoch_id);
    let lock_deadline = clock.unix_timestamp + 300;
    let abort_deadline = clock.unix_timestamp + 600;
    send(
        rpc,
        payer,
        &[create_epoch_instruction(
            payer.pubkey(),
            operator.pubkey(),
            pool,
            epoch,
            CreateEpochArgs {
                epoch_id,
                minimum_count: 4,
                quote_atoms_per_lot: 100,
                lock_deadline,
                abort_deadline,
            },
        )],
        &[operator],
    )?;

    let private = tempfile::tempdir().map_err(|error| error.to_string())?;
    let mut reservations = ReservationJournal::open(private.path().join("reservations.bin"))
        .map_err(|error| format!("balanced reservation journal: {error:?}"))?;
    let suspensions = SuspensionRegistry::open(private.path().join("suspensions.bin"))
        .map_err(|error| format!("balanced suspension registry: {error:?}"))?;
    let dealer = EpochDealer::random().map_err(|error| format!("balanced dealer: {error:?}"))?;
    let current_slot = rpc.get_slot().map_err(|error| error.to_string())?;
    let sides = [Side::Buy, Side::Sell, Side::Buy, Side::Sell];
    let mut submissions = Vec::new();
    let mut balances = Vec::new();
    for side in sides {
        let trading = random_signing_key()?;
        let participant_id = random_bytes()?;
        let reserved = reservations
            .reserve(
                ReservationRecord::new(random_bytes()?, participant_id, 1, 100)
                    .map_err(|error| format!("balanced reservation: {error:?}"))?,
                PoolBalance::new(1, 100),
            )
            .map_err(|error| format!("balanced reservation: {error:?}"))?;
        let authorization = suspensions
            .issue_authorization(
                reserved,
                epoch_id,
                trading.verifying_key(),
                operator_attestation,
                current_slot + 1_000,
            )
            .map_err(|error| format!("balanced authorization: {error:?}"))?;
        let signed = SignedIntentV1::sign(
            IntentBodyV1::new(side, 1, 100, epoch_id, participant_id, random_bytes()?)
                .map_err(|error| format!("balanced intent: {error}"))?,
            &trading,
        );
        let encrypted = dealer
            .public_keys()
            .encrypt(&signed)
            .map_err(|error| format!("balanced encrypt: {error:?}"))?;
        submissions.push(
            EncryptedSubmissionV1::sign(authorization, encrypted, random_bytes()?, &trading)
                .map_err(|error| format!("balanced submission: {error:?}"))?,
        );
        balances.push(
            BalanceRecordV1::new(participant_id, 1, 100, 1, 100)
                .map_err(|error| format!("balanced balance: {error:?}"))?,
        );
    }
    let snapshot = SignedBalanceSnapshotV1::sign(epoch_id, &balances, operator_attestation)
        .map_err(|error| format!("balanced snapshot: {error:?}"))?;
    let package = LockPackageV1::new(
        epoch,
        kageb_program::wire::EpochConfigurationV1 {
            pool,
            epoch_id,
            base_mint,
            quote_mint,
            base_lot_atoms: 1,
            quote_atoms_per_lot: 100,
            minimum_count: 4,
            lock_threshold: 2,
            settlement_threshold: 2,
            keypers: attesters
                .each_ref()
                .map(|key| Pubkey::new_from_array(key.verifying_key().to_bytes())),
            lock_deadline,
            abort_deadline,
        },
        dealer.public_keys().clone(),
        submissions,
        balances,
        snapshot,
        random_bytes()?,
    )
    .map_err(|error| format!("balanced package: {error:?}"))?;
    let keyper_dirs = create_keyper_directories(&rpc.url(), attesters)?;
    let keyper_shares = [
        dealer.share(epoch, 0),
        dealer.share(epoch, 1),
        dealer.share(epoch, 2),
    ];
    let mut lock_approvals = Vec::new();
    for index in 0..3 {
        lock_approvals.push(
            run_keyper_sign_lock(
                executable,
                keyper_dirs[index].path(),
                &keyper_shares[index],
                package.configuration.keypers[index],
                &package,
            )
            .map_err(|error| format!("balanced sign lock {index}: {error:?}"))?,
        );
    }
    let lock_digest = package.lock_payload().digest();
    send(
        rpc,
        payer,
        &[
            lock_verifier(&lock_approvals[0], &lock_digest),
            lock_verifier(&lock_approvals[1], &lock_digest),
            lock_instruction(operator.pubkey(), pool, epoch, package.lock_payload()),
        ],
        &[operator],
    )?;
    let confirmed = ProgramClient::new(rpc.url())
        .fetch_confirmed_lock(epoch)
        .map_err(|error| format!("balanced confirmed lock: {error:?}"))?;
    let evidence = (0..4)
        .map(|member_index| {
            let first = run_keyper_release_share(
                executable,
                keyper_dirs[0].path(),
                &keyper_shares[0],
                &package,
                member_index,
            )
            .map_err(|error| format!("balanced release 0/{member_index}: {error:?}"))?;
            let second = run_keyper_release_share(
                executable,
                keyper_dirs[1].path(),
                &keyper_shares[1],
                &package,
                member_index,
            )
            .map_err(|error| format!("balanced release 1/{member_index}: {error:?}"))?;
            DecryptionEvidenceV1::new(first, second)
                .map_err(|error| format!("balanced evidence {member_index}: {error:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let settlement =
        SettlementRequestV1::build(package.clone(), evidence, random_bytes()?, &confirmed)
            .map_err(|error| format!("balanced settlement: {error:?}"))?;
    let mut approvals = Vec::new();
    for index in 0..2 {
        approvals.push(
            run_keyper_sign_settlement(
                executable,
                keyper_dirs[index].path(),
                &keyper_shares[index],
                package.configuration.keypers[index],
                &settlement,
            )
            .map_err(|error| format!("balanced sign settlement {index}: {error:?}"))?,
        );
    }
    let payload = approvals[0].payload();
    if payload.residual_side != 0 || payload.residual_lots != 0 {
        return Err("balanced batch produced a venue leg".to_owned());
    }
    let before = backed_accounts
        .map(|account| token_amount(rpc, &account))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let digest = payload.digest();
    send(
        rpc,
        payer,
        &[
            settlement_verifier(&approvals[0], &digest),
            settlement_verifier(&approvals[1], &digest),
            settle_instruction(
                SettleAccounts {
                    payer: operator.pubkey(),
                    pool,
                    epoch,
                    vault_authority,
                    pool_base_vault: backed_accounts[0],
                    pool_quote_vault: backed_accounts[1],
                    venue_authority: venue_authority.pubkey(),
                    venue_base_account: backed_accounts[2],
                    venue_quote_account: backed_accounts[3],
                    base_mint,
                    quote_mint,
                },
                payload,
            ),
        ],
        &[operator, venue_authority],
    )?;
    let after = backed_accounts
        .map(|account| token_amount(rpc, &account))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let state = EpochStateV1::decode(
        &rpc.get_account(&epoch)
            .map_err(|error| error.to_string())?
            .data,
    )
    .map_err(|error| error.to_string())?;
    if before != after
        || state.terminal_state != EpochTerminalState::Settled
        || state.residual_side != 0
        || state.residual_lots != 0
    {
        return Err("balanced real settlement changed venue balances".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn invalid_reveal_aborts_and_suspends(
    rpc: &RpcClient,
    payer: &Keypair,
    executable: &Path,
    pool: Pubkey,
    base_mint: Pubkey,
    quote_mint: Pubkey,
    operator: &Keypair,
    operator_attestation: &SigningKey,
    attesters: &[SigningKey; 3],
    backed_accounts: [Pubkey; 4],
) -> Result<(), String> {
    let clock_account = rpc
        .get_account(&solana_program::sysvar::clock::ID)
        .map_err(|error| error.to_string())?;
    let clock: Clock =
        bincode::deserialize(&clock_account.data).map_err(|error| error.to_string())?;
    let epoch_id = random_bytes()?;
    let (epoch, _) = epoch_address(&pool, &epoch_id);
    let lock_deadline = clock.unix_timestamp + 30;
    let abort_deadline = clock.unix_timestamp + 32;
    send(
        rpc,
        payer,
        &[create_epoch_instruction(
            payer.pubkey(),
            operator.pubkey(),
            pool,
            epoch,
            CreateEpochArgs {
                epoch_id,
                minimum_count: 4,
                quote_atoms_per_lot: 100,
                lock_deadline,
                abort_deadline,
            },
        )],
        &[operator],
    )?;

    let dealer = EpochDealer::random().map_err(|error| format!("invalid dealer: {error:?}"))?;
    let private = tempfile::tempdir().map_err(|error| error.to_string())?;
    let mut reservations = ReservationJournal::open(private.path().join("reservations.bin"))
        .map_err(|error| format!("invalid reservation journal: {error:?}"))?;
    let mut suspensions = SuspensionRegistry::open(private.path().join("suspensions.bin"))
        .map_err(|error| format!("invalid suspension registry: {error:?}"))?;
    let mut submissions = Vec::new();
    let mut balance_records = Vec::new();
    let current_slot = rpc.get_slot().map_err(|error| error.to_string())?;
    let mut malformed_trading = None;
    let mut malformed_participant = None;
    for index in 0..4 {
        let trading = random_signing_key()?;
        let participant_id = random_bytes()?;
        if index == 3 {
            malformed_trading = Some(trading.clone());
            malformed_participant = Some(participant_id);
        }
        let reserved = reservations
            .reserve(
                ReservationRecord::new(random_bytes()?, participant_id, 1, 100)
                    .map_err(|error| format!("invalid reservation: {error:?}"))?,
                PoolBalance::new(1, 100),
            )
            .map_err(|error| format!("invalid reservation: {error:?}"))?;
        let authorization = suspensions
            .issue_authorization(
                reserved,
                epoch_id,
                trading.verifying_key(),
                operator_attestation,
                current_slot + 1_000,
            )
            .map_err(|error| format!("invalid authorization: {error:?}"))?;
        let body = IntentBodyV1::new(Side::Buy, 1, 100, epoch_id, participant_id, random_bytes()?)
            .map_err(|error| error.to_string())?;
        let signed = SignedIntentV1::sign(body, &trading);
        let encrypted = if index == 3 {
            let mut encoded = signed.encode();
            encoded[2..6].copy_from_slice(&2_u32.to_le_bytes());
            dealer
                .public_keys()
                .encrypt_encoded_intent(&encoded)
                .map_err(|error| format!("encrypt invalid intent: {error:?}"))?
        } else {
            dealer
                .public_keys()
                .encrypt(&signed)
                .map_err(|error| format!("encrypt invalid batch: {error:?}"))?
        };
        submissions.push(
            EncryptedSubmissionV1::sign(authorization, encrypted, random_bytes()?, &trading)
                .map_err(|error| format!("invalid submission: {error:?}"))?,
        );
        balance_records.push(
            BalanceRecordV1::new(participant_id, 1, 100, 1, 100)
                .map_err(|error| format!("invalid balance: {error:?}"))?,
        );
    }
    let snapshot = SignedBalanceSnapshotV1::sign(epoch_id, &balance_records, operator_attestation)
        .map_err(|error| format!("invalid snapshot: {error:?}"))?;
    let package = LockPackageV1::new(
        epoch,
        kageb_program::wire::EpochConfigurationV1 {
            pool,
            epoch_id,
            base_mint,
            quote_mint,
            base_lot_atoms: 1,
            quote_atoms_per_lot: 100,
            minimum_count: 4,
            lock_threshold: 2,
            settlement_threshold: 2,
            keypers: attesters
                .each_ref()
                .map(|key| Pubkey::new_from_array(key.verifying_key().to_bytes())),
            lock_deadline,
            abort_deadline,
        },
        dealer.public_keys().clone(),
        submissions,
        balance_records,
        snapshot,
        random_bytes()?,
    )
    .map_err(|error| format!("invalid lock package: {error:?}"))?;

    let keyper_dirs = create_keyper_directories(&rpc.url(), attesters)?;
    let keyper_shares = [
        dealer.share(epoch, 0),
        dealer.share(epoch, 1),
        dealer.share(epoch, 2),
    ];
    let mut approvals = Vec::new();
    for (index, directory) in keyper_dirs.iter().enumerate() {
        approvals.push(
            run_keyper_sign_lock(
                executable,
                directory.path(),
                &keyper_shares[index],
                package.configuration.keypers[index],
                &package,
            )
            .map_err(|error| format!("sign invalid lock {index}: {error:?}"))?,
        );
    }
    let digest = package.lock_payload().digest();
    send(
        rpc,
        payer,
        &[
            lock_verifier(&approvals[0], &digest),
            lock_verifier(&approvals[1], &digest),
            lock_instruction(operator.pubkey(), pool, epoch, package.lock_payload()),
        ],
        &[operator],
    )?;

    let malformed_index = package
        .submissions
        .iter()
        .position(|submission| Some(submission.participant_id()) == malformed_participant)
        .ok_or("malformed member missing from frozen set")?;
    let shares = [0, 1]
        .map(|index| {
            run_keyper_release_share(
                executable,
                keyper_dirs[index].path(),
                &keyper_shares[index],
                &package,
                malformed_index,
            )
            .map_err(|error| format!("release invalid share {index}: {error:?}"))
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    if dealer
        .public_keys()
        .recover_submission(
            &package.submissions[malformed_index],
            [&shares[0], &shares[1]],
        )
        .is_ok()
    {
        return Err("semantically invalid intent unexpectedly decoded".to_owned());
    }
    let before = backed_accounts
        .map(|account| token_amount(rpc, &account))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    loop {
        let account = rpc
            .get_account(&solana_program::sysvar::clock::ID)
            .map_err(|error| error.to_string())?;
        let current: Clock =
            bincode::deserialize(&account.data).map_err(|error| error.to_string())?;
        if current.unix_timestamp > abort_deadline {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    send(
        rpc,
        payer,
        &[abort_instruction(operator.pubkey(), pool, epoch)],
        &[operator],
    )?;
    let state = EpochStateV1::decode(
        &rpc.get_account(&epoch)
            .map_err(|error| error.to_string())?
            .data,
    )
    .map_err(|error| error.to_string())?;
    let after = backed_accounts
        .map(|account| token_amount(rpc, &account))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    if state.terminal_state != EpochTerminalState::Aborted || before != after {
        return Err("invalid reveal abort changed backed token balances".to_owned());
    }
    let malformed_trading = malformed_trading.ok_or("malformed trading key missing")?;
    let malformed_trading_key = malformed_trading.verifying_key().to_bytes();
    suspensions
        .suspend(malformed_trading_key)
        .map_err(|error| format!("persist suspension: {error:?}"))?;
    drop(suspensions);
    let reopened = SuspensionRegistry::open(private.path().join("suspensions.bin"))
        .map_err(|error| format!("reopen suspension registry: {error:?}"))?;
    if !reopened.is_suspended(malformed_trading_key) {
        return Err("invalid revealer trading key was not durably suspended".to_owned());
    }
    let later = reservations
        .reserve(
            ReservationRecord::new(random_bytes()?, random_bytes()?, 1, 100)
                .map_err(|error| format!("later reservation: {error:?}"))?,
            PoolBalance::new(1, 100),
        )
        .map_err(|error| format!("later reservation: {error:?}"))?;
    if reopened.issue_authorization(
        later,
        random_bytes()?,
        malformed_trading.verifying_key(),
        operator_attestation,
        current_slot + 2_000,
    ) != Err(SuspensionError::Suspended)
    {
        return Err("suspended trading key received a later authorization".to_owned());
    }
    Ok(())
}

fn fresh_sbf_artifacts(cargo: &Path) -> Result<(PathBuf, PathBuf), String> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let program = fresh_sbf_artifact(cargo, manifest, "kageb-program", "kageb_program.so")?;
    let token = fresh_sbf_artifact(
        cargo,
        manifest,
        "kageb-token-fixture",
        "kageb_token_fixture.so",
    )?;
    Ok((program, token))
}

fn fresh_sbf_artifact(
    cargo: &Path,
    host_manifest: &Path,
    package: &str,
    artifact_name: &str,
) -> Result<PathBuf, String> {
    let package_manifest = host_manifest.join(format!("../{package}"));
    let artifact = host_manifest.join(format!("../../target/deploy/{artifact_name}"));
    let mut inputs = vec![
        package_manifest.join("Cargo.toml"),
        host_manifest.join("../../Cargo.toml"),
        host_manifest.join("../../Cargo.lock"),
        host_manifest.join("../../rust-toolchain.toml"),
    ];
    recursive_files(&package_manifest.join("src"), &mut inputs)?;
    let stale = match fs::metadata(&artifact).and_then(|metadata| metadata.modified()) {
        Ok(artifact_time) => inputs.iter().try_fold(false, |stale, input| {
            fs::metadata(input)
                .and_then(|metadata| metadata.modified())
                .map(|modified| stale || modified > artifact_time)
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
    .map_err(|error| error.to_string())?;
    if stale {
        let manifest_path = package_manifest.join("Cargo.toml");
        let output = Command::new(cargo)
            .args(["build-sbf", "--manifest-path"])
            .arg(&manifest_path)
            .output()
            .map_err(|error| format!("launch cargo build-sbf for {package}: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "cargo build-sbf failed for {package}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        if !artifact.is_file() {
            return Err(format!(
                "cargo build-sbf did not create {}",
                artifact.display()
            ));
        }
    }
    Ok(artifact)
}

fn recursive_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_dir() {
            recursive_files(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

pub(crate) fn resolve_on_path(executable: &str) -> Result<PathBuf, String> {
    executable_on_path(executable)
        .ok_or_else(|| format!("{executable} was not found as an executable on PATH"))
}

pub(crate) fn resolve_cargo() -> Result<PathBuf, String> {
    if let Some(cargo) = std::env::var_os("CARGO") {
        return verified_executable(PathBuf::from(cargo), "CARGO");
    }
    if let Some(cargo) = executable_on_path("cargo") {
        return Ok(cargo);
    }
    if let Some(cargo_home) = std::env::var_os("CARGO_HOME") {
        let cargo = PathBuf::from(cargo_home)
            .join("bin")
            .join(executable_file_name("cargo"));
        if cargo.exists() {
            return verified_executable(cargo, "CARGO_HOME/bin/cargo");
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let cargo = PathBuf::from(home)
            .join(".cargo/bin")
            .join(executable_file_name("cargo"));
        if cargo.exists() {
            return verified_executable(cargo, "HOME/.cargo/bin/cargo");
        }
    }
    Err("cargo was not found. Set CARGO to an executable path, add cargo to PATH, or install it at CARGO_HOME/bin/cargo or HOME/.cargo/bin/cargo".to_owned())
}

fn executable_on_path(executable: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let name = executable_file_name(executable);
    std::env::split_paths(&path)
        .map(|directory| directory.join(&name))
        .find(|candidate| is_executable(candidate))
}

fn executable_file_name(executable: &str) -> String {
    format!("{executable}{}", std::env::consts::EXE_SUFFIX)
}

fn verified_executable(candidate: PathBuf, source: &str) -> Result<PathBuf, String> {
    if is_executable(&candidate) {
        Ok(candidate)
    } else {
        Err(format!(
            "{source} points to {}, which is not executable",
            candidate.display()
        ))
    }
}

#[cfg(unix)]
fn is_executable(candidate: &Path) -> bool {
    fs::metadata(candidate)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(candidate: &Path) -> bool {
    candidate.is_file()
}

struct LocalValidator {
    child: Child,
    rpc_url: String,
    _ledger: TempDir,
}

impl LocalValidator {
    fn start(
        validator_executable: &Path,
        artifact: &Path,
        token_artifact: &Path,
    ) -> Result<Self, String> {
        let (gossip_port, dynamic_port_end) = available_port_range()?;
        let dynamic_port_range = format!("{gossip_port}-{dynamic_port_end}");
        let port = loop {
            let candidate = available_port()?;
            if candidate < gossip_port || candidate > dynamic_port_end {
                break candidate;
            }
        };
        let faucet_port = loop {
            let candidate = available_port()?;
            if candidate != port
                && Some(candidate) != port.checked_add(1)
                && (candidate < gossip_port || candidate > dynamic_port_end)
            {
                break candidate;
            }
        };
        let ledger = tempfile::tempdir().map_err(|error| error.to_string())?;
        let log = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(ledger.path().join("validator.log"))
            .map_err(|error| error.to_string())?;
        let stdout = log.try_clone().map_err(|error| error.to_string())?;
        let child = Command::new(validator_executable)
            .args([
                "--reset",
                "--quiet",
                "--ledger",
                ledger.path().to_str().ok_or("non-UTF-8 ledger path")?,
                "--rpc-port",
                &port.to_string(),
                "--gossip-port",
                &gossip_port.to_string(),
                "--dynamic-port-range",
                &dynamic_port_range,
                "--faucet-port",
                &faucet_port.to_string(),
                "--bpf-program",
                &ID.to_string(),
                artifact.to_str().ok_or("non-UTF-8 SBF path")?,
                "--bpf-program",
                &TOKEN_PROGRAM_ID.to_string(),
                token_artifact.to_str().ok_or("non-UTF-8 token SBF path")?,
            ])
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(log))
            .spawn()
            .map_err(|error| format!("launch validator: {error}"))?;
        Ok(Self {
            child,
            rpc_url: format!("http://127.0.0.1:{port}"),
            _ledger: ledger,
        })
    }

    fn diagnostics(&self) -> String {
        fs::read_to_string(self._ledger.path().join("validator.log"))
            .unwrap_or_else(|error| format!("unavailable validator log: {error}"))
            .lines()
            .filter(|line| {
                let line = line.to_ascii_lowercase();
                line.contains("program")
                    || line.contains("cache")
                    || line.contains("error")
                    || line.contains("fail")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn available_port() -> Result<u16, String> {
    TcpListener::bind("127.0.0.1:0")
        .map_err(|error| error.to_string())?
        .local_addr()
        .map_err(|error| error.to_string())
        .map(|address| address.port())
}

fn available_port_range() -> Result<(u16, u16), String> {
    const RANGE_LEN: u16 = 32;
    for _ in 0..200 {
        let start = available_port()?;
        let Some(end) = start.checked_add(RANGE_LEN - 1) else {
            continue;
        };
        let mut tcp = Vec::with_capacity(usize::from(RANGE_LEN));
        let mut udp = Vec::with_capacity(usize::from(RANGE_LEN));
        let mut available = true;
        for port in start..=end {
            match (
                TcpListener::bind(("127.0.0.1", port)),
                UdpSocket::bind(("127.0.0.1", port)),
            ) {
                (Ok(tcp_socket), Ok(udp_socket)) => {
                    tcp.push(tcp_socket);
                    udp.push(udp_socket);
                }
                _ => {
                    available = false;
                    break;
                }
            }
        }
        if available {
            return Ok((start, end));
        }
    }
    Err("could not reserve an isolated validator port range".to_owned())
}

impl Drop for LocalValidator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_for_validator(rpc: &RpcClient, validator: &LocalValidator) -> Result<(), String> {
    for _ in 0..600 {
        if rpc.get_health().is_ok()
            && rpc
                .get_slot_with_commitment(CommitmentConfig::confirmed())
                .is_ok_and(|slot| slot > 0)
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    let log = fs::read_to_string(validator._ledger.path().join("validator.log"))
        .unwrap_or_else(|error| format!("unavailable validator log: {error}"));
    Err(format!("local validator did not become healthy:\n{log}"))
}

fn send(
    rpc: &RpcClient,
    payer: &Keypair,
    instructions: &[Instruction],
    extra_signers: &[&Keypair],
) -> Result<(), String> {
    send_with_signature(rpc, payer, instructions, extra_signers).map(|_| ())
}

fn send_with_signature(
    rpc: &RpcClient,
    payer: &Keypair,
    instructions: &[Instruction],
    extra_signers: &[&Keypair],
) -> Result<Signature, String> {
    let blockhash = rpc
        .get_latest_blockhash()
        .map_err(|error| error.to_string())?;
    let mut signers = vec![payer];
    signers.extend_from_slice(extra_signers);
    let transaction = Transaction::new_signed_with_payer(
        instructions,
        Some(&payer.pubkey()),
        &signers,
        blockhash,
    );
    rpc.send_and_confirm_transaction(&transaction)
        .map_err(|error| error.to_string())
}

fn fetch_confirmed_transaction(
    rpc: &RpcClient,
    signature: &Signature,
) -> Result<EncodedConfirmedTransactionWithStatusMeta, String> {
    for _ in 0..100 {
        match rpc.get_transaction(signature, UiTransactionEncoding::Base64) {
            Ok(transaction) => return Ok(transaction),
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    }
    Err(format!(
        "confirmed transaction {signature} was not available"
    ))
}

fn create_mint(rpc: &RpcClient, payer: &Keypair) -> Result<Keypair, String> {
    let mint = Keypair::new();
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(spl_token_interface::state::Mint::LEN)
        .map_err(|error| error.to_string())?;
    send(
        rpc,
        payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &mint.pubkey(),
                rent,
                spl_token_interface::state::Mint::LEN as u64,
                &TOKEN_PROGRAM_ID,
            ),
            spl_token_interface::instruction::initialize_mint2(
                &TOKEN_PROGRAM_ID,
                &mint.pubkey(),
                &payer.pubkey(),
                None,
                0,
            )
            .map_err(|error| error.to_string())?,
        ],
        &[&mint],
    )?;
    Ok(mint)
}

fn create_token_account(
    rpc: &RpcClient,
    payer: &Keypair,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Result<Pubkey, String> {
    let account = Keypair::new();
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(spl_token_interface::state::Account::LEN)
        .map_err(|error| error.to_string())?;
    send(
        rpc,
        payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &account.pubkey(),
                rent,
                spl_token_interface::state::Account::LEN as u64,
                &TOKEN_PROGRAM_ID,
            ),
            spl_token_interface::instruction::initialize_account3(
                &TOKEN_PROGRAM_ID,
                &account.pubkey(),
                mint,
                owner,
            )
            .map_err(|error| error.to_string())?,
        ],
        &[&account],
    )?;
    Ok(account.pubkey())
}

fn mint_to(
    rpc: &RpcClient,
    payer: &Keypair,
    mint: &Pubkey,
    destination: &Pubkey,
    amount: u64,
) -> Result<(), String> {
    let instruction = spl_token_interface::instruction::mint_to_checked(
        &TOKEN_PROGRAM_ID,
        mint,
        destination,
        &payer.pubkey(),
        &[],
        amount,
        0,
    )
    .map_err(|error| error.to_string())?;
    send(rpc, payer, &[instruction], &[])
}

fn transfer_tokens(
    rpc: &RpcClient,
    payer: &Keypair,
    authority: &Keypair,
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    amount: u64,
) -> Result<(), String> {
    transfer_tokens_with_signature(rpc, payer, authority, source, mint, destination, amount)
        .map(|_| ())
}

fn transfer_tokens_with_signature(
    rpc: &RpcClient,
    payer: &Keypair,
    authority: &Keypair,
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    amount: u64,
) -> Result<Signature, String> {
    let instruction = spl_token_interface::instruction::transfer_checked(
        &TOKEN_PROGRAM_ID,
        source,
        mint,
        destination,
        &authority.pubkey(),
        &[],
        amount,
        0,
    )
    .map_err(|error| error.to_string())?;
    send_with_signature(rpc, payer, &[instruction], &[authority])
}

fn create_keyper_directories(
    rpc_url: &str,
    attesters: &[SigningKey; 3],
) -> Result<[TempDir; 3], String> {
    let directories = [
        tempfile::tempdir().map_err(|error| error.to_string())?,
        tempfile::tempdir().map_err(|error| error.to_string())?,
        tempfile::tempdir().map_err(|error| error.to_string())?,
    ];
    for index in 0..3 {
        #[cfg(unix)]
        fs::set_permissions(directories[index].path(), fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        write_private_file(
            &directories[index].path().join("keyper-rpc-url"),
            rpc_url.as_bytes(),
        )?;
        write_private_file(
            &directories[index].path().join("keyper-attestation-key"),
            &attesters[index].to_bytes(),
        )?;
    }
    Ok(directories)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|_| "create private file failed".to_owned())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "write private file failed".to_owned())
}

fn lock_verifier(approval: &crate::LockApprovalV1, digest: &[u8; 32]) -> Instruction {
    new_ed25519_instruction_with_signature(digest, &approval.signature(), &approval.keyper_key())
}

fn settlement_verifier(approval: &crate::SettlementApprovalV1, digest: &[u8; 32]) -> Instruction {
    new_ed25519_instruction_with_signature(digest, &approval.signature(), &approval.keyper_key())
}

fn token_amount(rpc: &RpcClient, address: &Pubkey) -> Result<u64, String> {
    let account = rpc
        .get_account(address)
        .map_err(|error| error.to_string())?;
    let bytes: [u8; 8] = account
        .data
        .get(64..72)
        .ok_or("short token account")?
        .try_into()
        .map_err(|_| "invalid token amount")?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod devnet_tests {
    use super::*;

    fn command_args(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    fn argument_after(command: &Command, flag: &str) -> String {
        let arguments = command_args(command);
        let position = arguments
            .iter()
            .position(|argument| argument == flag)
            .unwrap();
        arguments[position + 1].clone()
    }

    fn trusted_publication_directory() -> TempDir {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        tempfile::tempdir_in(repository).unwrap()
    }

    fn program_account(programdata: Pubkey) -> PublicAccountSnapshotV1 {
        let mut data = 2_u32.to_le_bytes().to_vec();
        data.extend_from_slice(programdata.as_ref());
        PublicAccountSnapshotV1 {
            owner: UPGRADEABLE_LOADER_ID,
            executable: true,
            data,
        }
    }

    fn programdata_account(
        slot: u64,
        authority: Option<Pubkey>,
        executable: &[u8],
        padding: &[u8],
    ) -> PublicAccountSnapshotV1 {
        let mut data = 3_u32.to_le_bytes().to_vec();
        data.extend_from_slice(&slot.to_le_bytes());
        match authority {
            Some(authority) => {
                data.push(1);
                data.extend_from_slice(authority.as_ref());
            }
            None => data.push(0),
        }
        data.resize(UpgradeableLoaderState::size_of_programdata_metadata(), 0);
        data.extend_from_slice(executable);
        data.extend_from_slice(padding);
        PublicAccountSnapshotV1 {
            owner: UPGRADEABLE_LOADER_ID,
            executable: false,
            data,
        }
    }

    fn deployed(artifact_matches: bool, authority: Option<Pubkey>) -> DeployedCheckpointDiscovery {
        DeployedCheckpointDiscovery {
            upgrade_authority: authority,
            artifact_matches,
        }
    }

    #[test]
    fn deployment_action_is_noop_initial_or_authorized_upgrade() {
        let payer = Pubkey::new_unique();
        assert_eq!(
            select_deployment_action(None, payer, Some(ID)).unwrap(),
            DevnetDeploymentAction::Initial
        );
        assert_eq!(
            select_deployment_action(Some(&deployed(true, None)), payer, None).unwrap(),
            DevnetDeploymentAction::Noop
        );
        assert_eq!(
            select_deployment_action(Some(&deployed(false, Some(payer))), payer, None).unwrap(),
            DevnetDeploymentAction::Upgrade
        );
        assert!(select_deployment_action(
            Some(&deployed(false, Some(Pubkey::new_unique()))),
            payer,
            None,
        )
        .is_err());
        assert!(select_deployment_action(None, payer, Some(Pubkey::new_unique())).is_err());
    }

    #[test]
    fn deployment_discovery_accepts_a_shorter_valid_elf_as_an_authorized_mismatch() {
        let programdata = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let artifact = b"\x7fELFnew-checkpoint-is-longer";
        let program = program_account(programdata);
        let account = programdata_account(10, Some(payer), b"\x7fELFold", &[0; 32]);

        let discovered =
            discover_deployed_checkpoint(&program, programdata, &account, artifact).unwrap();

        assert_eq!(discovered.upgrade_authority, Some(payer));
        assert!(!discovered.artifact_matches);
        assert_eq!(
            select_deployment_action(Some(&discovered), payer, None).unwrap(),
            DevnetDeploymentAction::Upgrade
        );
    }

    #[test]
    fn deployment_discovery_accepts_a_longer_valid_elf_as_an_authorized_mismatch() {
        let programdata = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let artifact = b"\x7fELFnew";
        let program = program_account(programdata);
        let account = programdata_account(
            10,
            Some(payer),
            b"\x7fELFold-checkpoint-is-longer",
            &[0; 32],
        );

        let discovered =
            discover_deployed_checkpoint(&program, programdata, &account, artifact).unwrap();

        assert_eq!(discovered.upgrade_authority, Some(payer));
        assert!(!discovered.artifact_matches);
        assert_eq!(
            select_deployment_action(Some(&discovered), payer, None).unwrap(),
            DevnetDeploymentAction::Upgrade
        );
    }

    #[test]
    fn peak_balance_and_deadline_math_fail_closed_on_overflow() {
        let rents = DevnetPeakRents {
            setup: 10,
            program: 20,
            programdata: 30,
            buffer: 40,
            fees: 50,
        };
        assert_eq!(
            required_peak_balance(DevnetDeploymentAction::Noop, rents),
            Ok(60)
        );
        assert_eq!(
            required_peak_balance(DevnetDeploymentAction::Initial, rents),
            Ok(150)
        );
        assert!(required_peak_balance(
            DevnetDeploymentAction::Initial,
            DevnetPeakRents {
                setup: u64::MAX,
                ..rents
            },
        )
        .is_err());
        assert!(checked_devnet_deadlines(i64::MAX, u64::MAX).is_err());
    }

    #[test]
    fn deploy_buffer_refund_targets_only_the_named_buffer() {
        let buffer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let instruction = close_deploy_buffer_instruction(buffer, recipient, authority);

        assert_eq!(instruction.program_id, UPGRADEABLE_LOADER_ID);
        assert_eq!(
            instruction.accounts,
            vec![
                AccountMeta::new(buffer, false),
                AccountMeta::new(recipient, false),
                AccountMeta::new_readonly(authority, true),
            ]
        );
        assert_eq!(
            bincode::deserialize::<UpgradeableLoaderInstruction>(&instruction.data).unwrap(),
            UpgradeableLoaderInstruction::Close
        );
    }

    #[test]
    fn deploy_failure_output_is_reduced_to_a_safe_class() {
        assert_eq!(
            classify_deploy_failure(b"", b"RPC max retries exceeded at /private/key.json"),
            "devnet transport retries exhausted"
        );
        assert_eq!(
            classify_deploy_failure(b"Insufficient funds", b""),
            "insufficient payer funds"
        );
        assert_eq!(
            classify_deploy_failure(b"unknown /private/key.json", b""),
            "unclassified CLI failure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn deploy_uses_an_exact_max_len_named_buffer_and_ephemeral_private_signers() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let payer = Keypair::new();
        let program = Keypair::new();
        let artifact = b"\x7fELFcheckpoint";
        let mut signer_paths = Vec::new();

        deploy_checkpoint_with_runner_and_refunder(
            Path::new("/fake/solana"),
            "https://api.devnet.solana.com",
            &payer,
            Some(&program),
            DevnetDeploymentAction::Initial,
            directory.path(),
            artifact,
            |command: &mut Command| {
                assert_eq!(command.get_program(), "/fake/solana");
                assert_eq!(
                    argument_after(command, "--max-len"),
                    artifact.len().to_string()
                );
                assert_eq!(argument_after(command, "--max-sign-attempts"), "20");
                let arguments = command_args(command);
                assert!(arguments
                    .iter()
                    .any(|argument| argument == "--use-tpu-client"));
                assert!(!arguments.iter().any(|argument| argument == "--use-rpc"));
                for flag in ["--fee-payer", "--program-id", "--buffer"] {
                    let path = PathBuf::from(argument_after(command, flag));
                    assert!(path.exists());
                    assert_eq!(
                        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                        0o600
                    );
                    assert_eq!(
                        fs::metadata(path.parent().unwrap())
                            .unwrap()
                            .permissions()
                            .mode()
                            & 0o777,
                        0o700
                    );
                    signer_paths.push(path);
                }
                Ok(true)
            },
            |_| panic!("successful deploy must not refund its buffer"),
        )
        .unwrap();

        assert_eq!(signer_paths.len(), 3);
        assert!(signer_paths.iter().all(|path| !path.exists()));
    }

    #[cfg(unix)]
    #[test]
    fn failed_deploy_attempts_named_buffer_refund_before_removing_signers() {
        let directory = tempfile::tempdir().unwrap();
        let payer = Keypair::new();
        let artifact = b"\x7fELFcheckpoint";
        let buffer = std::cell::Cell::new(None);
        let signer_paths = std::cell::RefCell::new(Vec::new());
        let deploy_invocations = std::cell::Cell::new(0);
        let refund_invocations = std::cell::Cell::new(0);

        let result = deploy_checkpoint_with_runner_and_refunder(
            Path::new("/fake/solana"),
            "https://api.devnet.solana.com",
            &payer,
            None,
            DevnetDeploymentAction::Upgrade,
            directory.path(),
            artifact,
            |command: &mut Command| {
                deploy_invocations.set(deploy_invocations.get() + 1);
                let payer_path = PathBuf::from(argument_after(command, "--fee-payer"));
                let buffer_path = PathBuf::from(argument_after(command, "--buffer"));
                buffer.set(Some(read_keypair_file(&buffer_path).unwrap().pubkey()));
                signer_paths.borrow_mut().extend([payer_path, buffer_path]);
                Ok(false)
            },
            |actual_buffer| {
                refund_invocations.set(refund_invocations.get() + 1);
                assert_eq!(Some(actual_buffer), buffer.get());
                for path in signer_paths.borrow().iter() {
                    assert!(path.exists());
                }
                Ok(())
            },
        );

        assert_eq!(result, Err("Solana program deploy failed".to_owned()));
        assert_eq!(deploy_invocations.get(), 1);
        assert_eq!(refund_invocations.get(), 1);
        assert!(signer_paths.borrow().iter().all(|path| !path.exists()));
    }

    #[cfg(unix)]
    #[test]
    fn deploy_runner_error_refunds_the_buffer_before_removing_signers() {
        let directory = tempfile::tempdir().unwrap();
        let payer = Keypair::new();
        let artifact = b"\x7fELFcheckpoint";
        let buffer = std::cell::Cell::new(None);
        let signer_paths = std::cell::RefCell::new(Vec::new());
        let deploy_invocations = std::cell::Cell::new(0);
        let refund_invocations = std::cell::Cell::new(0);

        let result = deploy_checkpoint_with_runner_and_refunder(
            Path::new("/fake/solana"),
            "https://api.devnet.solana.com",
            &payer,
            None,
            DevnetDeploymentAction::Upgrade,
            directory.path(),
            artifact,
            |command: &mut Command| {
                deploy_invocations.set(deploy_invocations.get() + 1);
                let payer_path = PathBuf::from(argument_after(command, "--fee-payer"));
                let buffer_path = PathBuf::from(argument_after(command, "--buffer"));
                buffer.set(Some(read_keypair_file(&buffer_path).unwrap().pubkey()));
                signer_paths.borrow_mut().extend([payer_path, buffer_path]);
                Err(())
            },
            |actual_buffer| {
                refund_invocations.set(refund_invocations.get() + 1);
                assert_eq!(Some(actual_buffer), buffer.get());
                for path in signer_paths.borrow().iter() {
                    assert!(path.exists());
                }
                Ok(())
            },
        );

        assert_eq!(
            result,
            Err("launch Solana program deploy failed".to_owned())
        );
        assert_eq!(deploy_invocations.get(), 1);
        assert_eq!(refund_invocations.get(), 1);
        assert!(signer_paths.borrow().iter().all(|path| !path.exists()));
    }

    #[cfg(unix)]
    #[test]
    fn deploy_runner_and_refund_errors_report_only_the_public_buffer_address() {
        let directory = tempfile::tempdir().unwrap();
        let payer = Keypair::new();
        let artifact = b"\x7fELFcheckpoint";
        let buffer = std::cell::Cell::new(None);
        let signer_paths = std::cell::RefCell::new(Vec::new());
        let deploy_invocations = std::cell::Cell::new(0);
        let refund_invocations = std::cell::Cell::new(0);

        let error = deploy_checkpoint_with_runner_and_refunder(
            Path::new("/fake/solana"),
            "https://api.devnet.solana.com",
            &payer,
            None,
            DevnetDeploymentAction::Upgrade,
            directory.path(),
            artifact,
            |command: &mut Command| {
                deploy_invocations.set(deploy_invocations.get() + 1);
                let payer_path = PathBuf::from(argument_after(command, "--fee-payer"));
                let buffer_path = PathBuf::from(argument_after(command, "--buffer"));
                buffer.set(Some(read_keypair_file(&buffer_path).unwrap().pubkey()));
                signer_paths.borrow_mut().extend([payer_path, buffer_path]);
                Err(())
            },
            |actual_buffer| {
                refund_invocations.set(refund_invocations.get() + 1);
                assert_eq!(Some(actual_buffer), buffer.get());
                Err(())
            },
        )
        .unwrap_err();

        assert_eq!(
            error,
            format!(
                "Solana program deploy failed; buffer cleanup failed: {}",
                buffer.get().unwrap()
            )
        );
        assert_eq!(deploy_invocations.get(), 1);
        assert_eq!(refund_invocations.get(), 1);
        assert!(signer_paths.borrow().iter().all(|path| !path.exists()));
    }

    #[test]
    fn deploy_reports_buffer_and_private_signer_cleanup_failures_together() {
        let buffer = Pubkey::new_unique();

        assert_eq!(
            finish_deploy_attempt(Err(()), true, true, buffer),
            Err(format!(
                "Solana program deploy failed; buffer cleanup failed: {buffer}; private signer cleanup also failed"
            ))
        );
    }

    #[cfg(unix)]
    #[test]
    fn failed_buffer_refund_reports_only_the_recoverable_public_buffer_address() {
        let directory = tempfile::tempdir().unwrap();
        let payer = Keypair::new();
        let artifact = b"\x7fELFcheckpoint";
        let buffer = std::cell::Cell::new(None);
        let deploy_invocations = std::cell::Cell::new(0);
        let refund_invocations = std::cell::Cell::new(0);

        let error = deploy_checkpoint_with_runner_and_refunder(
            Path::new("/fake/solana"),
            "https://api.devnet.solana.com",
            &payer,
            None,
            DevnetDeploymentAction::Upgrade,
            directory.path(),
            artifact,
            |command: &mut Command| {
                deploy_invocations.set(deploy_invocations.get() + 1);
                let buffer_path = PathBuf::from(argument_after(command, "--buffer"));
                buffer.set(Some(read_keypair_file(&buffer_path).unwrap().pubkey()));
                Ok(false)
            },
            |actual_buffer| {
                refund_invocations.set(refund_invocations.get() + 1);
                assert_eq!(Some(actual_buffer), buffer.get());
                Err(())
            },
        )
        .unwrap_err();

        assert_eq!(
            error,
            format!(
                "Solana program deploy failed; buffer cleanup failed: {}",
                buffer.get().unwrap()
            )
        );
        assert_eq!(deploy_invocations.get(), 1);
        assert_eq!(refund_invocations.get(), 1);
    }

    #[test]
    fn evidence_publication_never_clobbers_an_existing_path() {
        let directory = trusted_publication_directory();
        let output = directory.path().join("proof.json");
        fs::write(&output, b"winner").unwrap();

        assert!(publish_bytes_noclobber(&output, b"loser").is_err());
        assert_eq!(fs::read(&output).unwrap(), b"winner");
    }

    #[cfg(unix)]
    #[test]
    fn evidence_publication_rejects_a_symlinked_output_ancestor() {
        use std::os::unix::fs::symlink;

        let directory = trusted_publication_directory();
        let real_parent = directory.path().join("real");
        let linked_parent = directory.path().join("linked");
        fs::create_dir(&real_parent).unwrap();
        fs::create_dir(real_parent.join("safe-child")).unwrap();
        symlink(&real_parent, &linked_parent).unwrap();
        let output = linked_parent.join("safe-child/proof.json");

        assert!(publish_bytes_noclobber(&output, b"proof").is_err());
        assert!(!real_parent.join("safe-child/proof.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn evidence_publication_rejects_a_group_or_world_writable_ancestor() {
        let directory = trusted_publication_directory();
        let shared = directory.path().join("shared");
        let safe_child = shared.join("safe-child");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        fs::create_dir(&safe_child).unwrap();
        fs::set_permissions(&safe_child, fs::Permissions::from_mode(0o700)).unwrap();
        let output = safe_child.join("proof.json");

        assert!(publish_bytes_noclobber(&output, b"proof").is_err());
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn evidence_publication_accepts_the_normal_repository_ancestry() {
        let directory = trusted_publication_directory();
        let output = directory.path().join("proof.json");

        publish_bytes_noclobber(&output, b"proof").unwrap();

        assert_eq!(fs::read(output).unwrap(), b"proof");
    }

    #[test]
    fn concurrent_evidence_publication_has_exactly_one_winner() {
        use std::sync::{Arc, Barrier};

        let directory = trusted_publication_directory();
        let output = directory.path().join("proof.json");
        let barrier = Arc::new(Barrier::new(2));
        let attempts: Vec<_> = [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .map(|bytes| {
                let output = output.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    publish_bytes_noclobber(&output, bytes)
                })
            })
            .collect();
        let results: Vec<_> = attempts
            .into_iter()
            .map(|attempt| attempt.join().unwrap())
            .collect();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(matches!(
            fs::read(&output).unwrap().as_slice(),
            b"first" | b"second"
        ));
    }

    #[test]
    fn public_evidence_scan_rejects_secret_encodings_and_private_terms() {
        assert!(scan_public_evidence_bytes(b"{\"ok\":true}", &[b"secret".to_vec()]).is_ok());
        assert!(
            scan_public_evidence_bytes(b"{\"value\":\"secret\"}", &[b"secret".to_vec()]).is_err()
        );
        assert!(scan_public_evidence_bytes(b"{\"plaintext_orders\":[]}", &[]).is_err());
        assert!(scan_public_evidence_bytes(b"{\"path\":\".kageb-private/run\"}", &[]).is_err());

        let secret = vec![0x41; 32];
        let encodings = private_material_encodings(&[secret]);
        for encoded in encodings {
            let mut json = b"{\"value\":\"".to_vec();
            json.extend_from_slice(&encoded);
            json.extend_from_slice(b"\"}");
            assert!(scan_public_evidence_bytes(&json, &[encoded]).is_err());
        }
    }
}
