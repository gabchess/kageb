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
use solana_program::{clock::Clock, instruction::Instruction, program_pack::Pack, pubkey::Pubkey};
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::{
    EncodedConfirmedTransactionWithStatusMeta, UiTransactionEncoding,
};
use tempfile::TempDir;

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
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
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
        return Err(format!("refusing to overwrite evidence {}", out.display()));
    }
    let (public_commit, artifact) = clean_public_checkpoint_artifact()?;
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
    let program_account = rpc
        .get_account(&ID)
        .map_err(|_| format!("fixed program {ID} is not deployed on devnet"))?;
    let programdata_account = rpc
        .get_account(&programdata_address)
        .map_err(|error| format!("read ProgramData {programdata_address}: {error}"))?;
    let deployed = extract_upgradeable_program(
        &PublicAccountSnapshotV1 {
            owner: program_account.owner,
            executable: program_account.executable,
            data: program_account.data,
        },
        programdata_address,
        &PublicAccountSnapshotV1 {
            owner: programdata_account.owner,
            executable: programdata_account.executable,
            data: programdata_account.data,
        },
        artifact.len(),
    )
    .map_err(|error| format!("extract deployed checkpoint: {error:?}"))?;
    if deployed.executable != artifact {
        return Err("deployed executable does not match the public checkpoint".to_owned());
    }
    let payer = read_keypair_file(payer_path).map_err(|_| "read devnet payer failed".to_owned())?;
    require_devnet_setup_balance(&rpc, &payer)?;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let private_root = private_runtime_root()?;

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
    for wallet in &participant_wallets {
        let base = create_token_account(&rpc, &payer, &base_mint.pubkey(), &wallet.pubkey())?;
        let quote = create_token_account(&rpc, &payer, &quote_mint.pubkey(), &wallet.pubkey())?;
        mint_to(&rpc, &payer, &base_mint.pubkey(), &base, 1)?;
        mint_to(&rpc, &payer, &quote_mint.pubkey(), &quote, 100)?;
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
    let lock_deadline = clock.unix_timestamp + 300;
    let abort_deadline = clock.unix_timestamp + 900;
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

    let run_directory = tempfile::tempdir_in(&private_root).map_err(|error| error.to_string())?;
    let mut reservations = ReservationJournal::open(run_directory.path().join("reservations.bin"))
        .map_err(|error| format!("reservation journal: {error:?}"))?;
    let suspensions = SuspensionRegistry::open(run_directory.path().join("suspensions.bin"))
        .map_err(|error| format!("suspension registry: {error:?}"))?;
    let sides = [Side::Buy, Side::Sell, Side::Buy, Side::Buy];
    let current_slot = rpc.get_slot().map_err(|error| error.to_string())?;
    let mut submissions = Vec::with_capacity(4);
    let mut participant_ids = Vec::with_capacity(4);
    for side in sides {
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
                current_slot + 2_000,
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
    let keyper_dirs = create_devnet_keyper_directories(&private_root, rpc_url, &attesters)?;
    let keyper_shares = [
        dealer.share(epoch, 0),
        dealer.share(epoch, 1),
        dealer.share(epoch, 2),
    ];
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
    let settlement = SettlementRequestV1::build(
        package.clone(),
        decryption_evidence,
        random_bytes()?,
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
    let funding_evidence: [FundingTransactionEvidenceV1; 4] = participant_wallets
        .iter()
        .zip(funding_signatures.iter())
        .zip(&finalized_transactions[..4])
        .map(
            |((wallet, signature), transaction)| FundingTransactionEvidenceV1 {
                authority: wallet.pubkey().to_string(),
                transaction: EvidenceTransactionV1 {
                    signature: signature.to_string(),
                    slot: transaction.slot,
                },
            },
        )
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "four funding records required".to_owned())?;
    let configuration_hash = package.configuration.digest();
    let mut content = DevnetEvidenceContentV1 {
        cluster: "devnet".to_owned(),
        public_commit,
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
    let verifier_artifact = run_directory.path().join("checkpoint.so");
    write_private_file(&verifier_artifact, &artifact)?;
    persist_verified_evidence(out, rpc_url, &bundle, &verifier_artifact)?;
    Ok(format!(
        "LOCKED: crowd 4/4\nSETTLED: one aggregate BUY 2 lots\nVERIFIED: finalized {}\nEVIDENCE: {}\n{NON_CLAIM}\n",
        settlement_signature,
        out.display()
    ))
}

fn clean_public_checkpoint_artifact() -> Result<(String, Vec<u8>), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| format!("resolve repository root: {error}"))?;
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
    let branch = command_stdout(
        Command::new("git")
            .args(["branch", "--show-current"])
            .current_dir(&root),
    )?
    .trim()
    .to_owned();
    if branch.is_empty() {
        return Err("public checkpoint cannot use a detached HEAD".to_owned());
    }
    let remote = command_stdout(
        Command::new("git")
            .args(["ls-remote", "--heads", "origin", &branch])
            .current_dir(&root),
    )?;
    if remote.split_whitespace().next() != Some(commit.as_str()) {
        return Err(format!(
            "push checkpoint commit {commit} to origin/{branch} before devnet"
        ));
    }
    let clean = tempfile::tempdir().map_err(|error| error.to_string())?;
    let checkout = clean.path().join("checkpoint");
    command_stdout(
        Command::new("git")
            .args(["clone", "--quiet", "--no-hardlinks"])
            .arg(&root)
            .arg(&checkout),
    )?;
    command_stdout(
        Command::new("git")
            .args(["checkout", "--quiet", "--detach", &commit])
            .current_dir(&checkout),
    )?;
    let cargo = resolve_cargo()?;
    let build = Command::new(cargo)
        .args(["build-sbf", "--manifest-path"])
        .arg(checkout.join("crates/kageb-program/Cargo.toml"))
        .current_dir(&checkout)
        .output()
        .map_err(|error| format!("launch clean cargo build-sbf: {error}"))?;
    if !build.status.success() {
        return Err(format!(
            "clean checkpoint cargo build-sbf failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        ));
    }
    let artifact = fs::read(checkout.join("target/deploy/kageb_program.so"))
        .map_err(|error| format!("read clean checkpoint artifact: {error}"))?;
    if !artifact.starts_with(b"\x7fELF") {
        return Err("clean checkpoint artifact is not ELF".to_owned());
    }
    Ok((commit, artifact))
}

fn command_stdout(command: &mut Command) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|error| format!("launch command: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

fn require_devnet_setup_balance(rpc: &RpcClient, payer: &Keypair) -> Result<(), String> {
    let mint_rent = rpc
        .get_minimum_balance_for_rent_exemption(spl_token_interface::state::Mint::LEN)
        .map_err(|error| error.to_string())?;
    let token_rent = rpc
        .get_minimum_balance_for_rent_exemption(spl_token_interface::state::Account::LEN)
        .map_err(|error| error.to_string())?;
    let state_rent = rpc
        .get_minimum_balance_for_rent_exemption(kageb_program::state::STATE_LEN)
        .map_err(|error| error.to_string())?;
    let required = mint_rent
        .checked_mul(2)
        .and_then(|value| value.checked_add(token_rent.checked_mul(12)?))
        .and_then(|value| value.checked_add(state_rent.checked_mul(2)?))
        .and_then(|value| value.checked_add(10_000_000))
        .ok_or("devnet setup balance overflow")?;
    let available = rpc
        .get_balance(&payer.pubkey())
        .map_err(|error| error.to_string())?;
    if available < required {
        return Err(format!(
            "devnet payer needs at least {required} lamports after deployment; available {available}"
        ));
    }
    Ok(())
}

fn private_runtime_root() -> Result<PathBuf, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.kageb-private");
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    root.canonicalize().map_err(|error| error.to_string())
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
        tempfile::tempdir_in(private_root).map_err(|error| error.to_string())?,
        tempfile::tempdir_in(private_root).map_err(|error| error.to_string())?,
        tempfile::tempdir_in(private_root).map_err(|error| error.to_string())?,
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
    checkpoint_artifact: &Path,
) -> Result<(), String> {
    let parent = out.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let pending = out.with_extension("json.pending");
    let json = bundle
        .to_json_pretty()
        .map_err(|error| format!("encode evidence: {error:?}"))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(&pending)
        .map_err(|error| format!("create pending evidence: {error}"))?;
    file.write_all(json.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write pending evidence: {error}"))?;
    drop(file);
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let verify = Command::new(executable)
        .args(["verify", "evidence"])
        .arg(&pending)
        .args(["--rpc", rpc_url])
        .env("KAGEB_CHECKPOINT_ARTIFACT", checkpoint_artifact)
        .output()
        .map_err(|error| format!("launch fresh evidence verifier: {error}"))?;
    if !verify.status.success() {
        let _ = fs::remove_file(&pending);
        return Err(format!(
            "fresh evidence verifier failed: {}",
            String::from_utf8_lossy(&verify.stderr).trim()
        ));
    }
    fs::rename(&pending, out).map_err(|error| format!("publish verified evidence: {error}"))
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

fn resolve_on_path(executable: &str) -> Result<PathBuf, String> {
    executable_on_path(executable)
        .ok_or_else(|| format!("{executable} was not found as an executable on PATH"))
}

fn resolve_cargo() -> Result<PathBuf, String> {
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
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())
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
