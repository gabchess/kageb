use kageb::{
    extract_upgradeable_program, verify_devnet_evidence, DecodedInstructionEvidenceV1,
    DevnetEvidenceBundleV1, DevnetEvidenceContentV1, DevnetEvidenceError, DevnetPublicSnapshotV1,
    EvidenceAccountsV1, EvidenceBuildToolchainV1, EvidenceCommitmentsV1, EvidenceConfigurationV1,
    EvidenceDeploymentV1, EvidenceTokenBalancesV1, EvidenceTransactionV1, EvidenceTransactionsV1,
    FinalizedTransactionSnapshotV1, FundingTransactionEvidenceV1, PublicAccountSnapshotV1,
    UPGRADEABLE_LOADER_ID,
};
use kageb_program::state::{EpochStateV1, EpochTerminalState, PoolStateV1};
use solana_program::{program_option::COption, program_pack::Pack, pubkey::Pubkey};
use std::str::FromStr;

fn key(value: u8) -> String {
    Pubkey::new_from_array([value; 32]).to_string()
}

fn digest(value: u8) -> String {
    format!("{value:02x}").repeat(32)
}

fn signature(value: u8) -> String {
    bs58::encode([value; 64]).into_string()
}

fn transaction(value: u8, slot: u64) -> EvidenceTransactionV1 {
    EvidenceTransactionV1 {
        signature: signature(value),
        slot,
    }
}

fn content() -> DevnetEvidenceContentV1 {
    let funding = std::array::from_fn(|index| FundingTransactionEvidenceV1 {
        authority: key(index as u8 + 20),
        base_source: key(index as u8 + 50),
        quote_source: key(index as u8 + 60),
        transaction: transaction(index as u8 + 30, 90 + index as u64),
    });
    DevnetEvidenceContentV1 {
        cluster: "devnet".to_owned(),
        public_commit: "1".repeat(40),
        build_toolchain: EvidenceBuildToolchainV1 {
            host_rustc: "rustc 1.95.0".to_owned(),
            cargo_build_sbf: "cargo-build-sbf 4.0.0".to_owned(),
            platform_tools: "platform-tools v1.53".to_owned(),
            sbf_rustc: "rustc 1.89.0".to_owned(),
            solana_cli: "solana-cli 4.0.1".to_owned(),
        },
        checkpoint_artifact_len: 187_872,
        checkpoint_artifact_sha256: digest(1),
        deployment: EvidenceDeploymentV1 {
            program: kageb_program::ID.to_string(),
            loader: UPGRADEABLE_LOADER_ID.to_string(),
            programdata: key(2),
            deployment_slot: 80,
            upgrade_authority: Some(key(3)),
            deployed_executable_sha256: digest(1),
        },
        transactions: EvidenceTransactionsV1 {
            funding,
            lock: transaction(40, 100),
            settlement: transaction(41, 101),
        },
        accounts: EvidenceAccountsV1 {
            fee_payer: key(18),
            operator: key(4),
            pool: key(5),
            epoch: key(6),
            vault_authority: key(7),
            base_mint: key(8),
            quote_mint: key(9),
            pool_base_vault: key(10),
            pool_quote_vault: key(11),
            venue_authority: key(12),
            venue_base_account: key(13),
            venue_quote_account: key(14),
            token_program: kageb_program::TOKEN_PROGRAM_ID.to_string(),
        },
        configuration: EvidenceConfigurationV1 {
            epoch_id: digest(2),
            minimum_count: 4,
            member_count: 4,
            lock_threshold: 2,
            settlement_threshold: 2,
            keypers: [key(15), key(16), key(17)],
            base_lot_atoms: 1,
            quote_atoms_per_lot: 100,
        },
        commitments: EvidenceCommitmentsV1 {
            configuration_hash: digest(9),
            pre_balance_root: digest(3),
            member_set: digest(4),
            lock_digest: digest(5),
            result: digest(6),
            settlement_digest: digest(7),
            local_transcript_sha256: digest(8),
        },
        token_balances: EvidenceTokenBalancesV1 {
            pool_base_before: 4,
            pool_base_after: 5,
            pool_quote_before: 400,
            pool_quote_after: 300,
            venue_base_before: 10,
            venue_base_after: 9,
            venue_quote_before: 0,
            venue_quote_after: 100,
        },
        decoded_allowlist: vec![
            DecodedInstructionEvidenceV1 {
                transaction: "lock".to_owned(),
                position: 0,
                program: solana_sdk::ed25519_program::ID.to_string(),
                kind: "keyper-lock-approval".to_owned(),
                digest: Some(digest(5)),
            },
            DecodedInstructionEvidenceV1 {
                transaction: "settlement".to_owned(),
                position: 2,
                program: kageb_program::ID.to_string(),
                kind: "aggregate-settlement".to_owned(),
                digest: Some(digest(7)),
            },
        ],
        explorer_links: [30_u8, 31, 32, 33, 40, 41]
            .map(|value| {
                format!(
                    "https://explorer.solana.com/tx/{}?cluster=devnet",
                    signature(value)
                )
            })
            .to_vec(),
    }
}

#[test]
fn evidence_schema_is_public_only_strict_and_content_addressed() {
    let bundle = DevnetEvidenceBundleV1::seal(content()).unwrap();
    assert_ne!(
        bundle.evidence_sha256, bundle.content.commitments.result,
        "the post-confirmation bundle hash is not the onchain result commitment"
    );
    bundle.verify_content_hash().unwrap();

    let json = bundle.to_json_pretty().unwrap();
    assert!(!json.contains("rpc_url"));
    let parsed = DevnetEvidenceBundleV1::from_json(&json).unwrap();
    assert_eq!(parsed, bundle);

    let mut unknown: serde_json::Value = serde_json::from_str(&json).unwrap();
    unknown["content"]["plaintext_orders"] = serde_json::json!(["buy"]);
    assert_eq!(
        DevnetEvidenceBundleV1::from_json(&serde_json::to_string(&unknown).unwrap()),
        Err(DevnetEvidenceError::InvalidSchema)
    );

    let mut changed: serde_json::Value = serde_json::from_str(&json).unwrap();
    changed["content"]["transactions"]["settlement"]["slot"] = serde_json::json!(102);
    assert_eq!(
        DevnetEvidenceBundleV1::from_json(&serde_json::to_string(&changed).unwrap())
            .unwrap()
            .verify_content_hash(),
        Err(DevnetEvidenceError::ContentHashMismatch)
    );
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
    data.resize(45, 0);
    data.extend_from_slice(executable);
    data.extend_from_slice(padding);
    PublicAccountSnapshotV1 {
        owner: UPGRADEABLE_LOADER_ID,
        executable: false,
        data,
    }
}

fn mint_account(
    mint_authority: Option<Pubkey>,
    freeze_authority: Option<Pubkey>,
) -> PublicAccountSnapshotV1 {
    let mint = spl_token_interface::state::Mint {
        mint_authority: mint_authority.into(),
        supply: 810,
        decimals: 0,
        is_initialized: true,
        freeze_authority: freeze_authority.into(),
    };
    let mut data = vec![0; spl_token_interface::state::Mint::LEN];
    spl_token_interface::state::Mint::pack(mint, &mut data).unwrap();
    PublicAccountSnapshotV1 {
        owner: kageb_program::TOKEN_PROGRAM_ID,
        executable: false,
        data,
    }
}

fn token_account(mint: Pubkey, owner: Pubkey, amount: u64) -> PublicAccountSnapshotV1 {
    let token = spl_token_interface::state::Account {
        mint,
        owner,
        amount,
        delegate: COption::None,
        state: spl_token_interface::state::AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    };
    let mut data = vec![0; spl_token_interface::state::Account::LEN];
    spl_token_interface::state::Account::pack(token, &mut data).unwrap();
    PublicAccountSnapshotV1 {
        owner: kageb_program::TOKEN_PROGRAM_ID,
        executable: false,
        data,
    }
}

#[test]
fn extractor_accepts_only_the_official_programdata_executable_slice() {
    let programdata = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let executable = b"\x7fELFcanonical-checkpoint";
    let program = program_account(programdata);
    let account = programdata_account(77, Some(authority), executable, &[0; 32]);

    let extracted =
        extract_upgradeable_program(&program, programdata, &account, executable.len()).unwrap();
    assert_eq!(extracted.deployment_slot, 77);
    assert_eq!(extracted.upgrade_authority, Some(authority));
    assert_eq!(extracted.executable, executable);
    assert_eq!(extracted.executable_sha256, digest_bytes(executable));

    let mut wrong_loader = program.clone();
    wrong_loader.owner = Pubkey::new_unique();
    assert_eq!(
        extract_upgradeable_program(&wrong_loader, programdata, &account, executable.len()),
        Err(DevnetEvidenceError::WrongLoader)
    );

    let mut malformed_program = program.clone();
    malformed_program.data[0] = 3;
    assert_eq!(
        extract_upgradeable_program(&malformed_program, programdata, &account, executable.len()),
        Err(DevnetEvidenceError::MalformedLoaderMetadata)
    );

    let mut wrong_programdata = programdata_account(77, Some(authority), executable, &[0; 32]);
    wrong_programdata.owner = Pubkey::new_unique();
    assert_eq!(
        extract_upgradeable_program(&program, programdata, &wrong_programdata, executable.len()),
        Err(DevnetEvidenceError::WrongProgramDataOwner)
    );

    let wrong_address = Pubkey::new_unique();
    assert_eq!(
        extract_upgradeable_program(&program, wrong_address, &account, executable.len()),
        Err(DevnetEvidenceError::WrongProgramDataAddress)
    );
}

#[test]
fn extractor_rejects_truncation_changed_elf_and_nonzero_tail() {
    let programdata = Pubkey::new_unique();
    let executable = b"\x7fELFcanonical-checkpoint";
    let program = program_account(programdata);

    let truncated = programdata_account(77, None, &executable[..4], &[]);
    assert_eq!(
        extract_upgradeable_program(&program, programdata, &truncated, executable.len()),
        Err(DevnetEvidenceError::TruncatedExecutable)
    );

    let changed_prefix = programdata_account(77, None, b"NOPEcanonical-checkpoint", &[]);
    assert_eq!(
        extract_upgradeable_program(&program, programdata, &changed_prefix, executable.len()),
        Err(DevnetEvidenceError::InvalidElf)
    );

    let nonzero_tail = programdata_account(77, None, executable, &[0, 1]);
    assert_eq!(
        extract_upgradeable_program(&program, programdata, &nonzero_tail, executable.len()),
        Err(DevnetEvidenceError::NonZeroProgramDataTail)
    );
}

fn digest_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn pubkey(value: &str) -> Pubkey {
    Pubkey::from_str(value).unwrap()
}

fn canonical_allowlist(content: &DevnetEvidenceContentV1) -> Vec<DecodedInstructionEvidenceV1> {
    let mut allowlist = Vec::new();
    for index in 0..4 {
        allowlist.push(DecodedInstructionEvidenceV1 {
            transaction: format!("funding-{index}"),
            position: 0,
            program: kageb_program::TOKEN_PROGRAM_ID.to_string(),
            kind: "pool-funding-base".to_owned(),
            digest: None,
        });
        allowlist.push(DecodedInstructionEvidenceV1 {
            transaction: format!("funding-{index}"),
            position: 1,
            program: kageb_program::TOKEN_PROGRAM_ID.to_string(),
            kind: "pool-funding-quote".to_owned(),
            digest: None,
        });
    }
    for position in 0..2 {
        allowlist.push(DecodedInstructionEvidenceV1 {
            transaction: "lock".to_owned(),
            position,
            program: solana_sdk::ed25519_program::ID.to_string(),
            kind: "keyper-lock-approval".to_owned(),
            digest: Some(content.commitments.lock_digest.clone()),
        });
    }
    allowlist.push(DecodedInstructionEvidenceV1 {
        transaction: "lock".to_owned(),
        position: 2,
        program: kageb_program::ID.to_string(),
        kind: "epoch-lock".to_owned(),
        digest: Some(content.commitments.lock_digest.clone()),
    });
    for position in 0..2 {
        allowlist.push(DecodedInstructionEvidenceV1 {
            transaction: "settlement".to_owned(),
            position,
            program: solana_sdk::ed25519_program::ID.to_string(),
            kind: "keyper-settlement-approval".to_owned(),
            digest: Some(content.commitments.settlement_digest.clone()),
        });
    }
    allowlist.push(DecodedInstructionEvidenceV1 {
        transaction: "settlement".to_owned(),
        position: 2,
        program: kageb_program::ID.to_string(),
        kind: "aggregate-settlement".to_owned(),
        digest: Some(content.commitments.settlement_digest.clone()),
    });
    allowlist.push(DecodedInstructionEvidenceV1 {
        transaction: "settlement".to_owned(),
        position: 3,
        program: kageb_program::TOKEN_PROGRAM_ID.to_string(),
        kind: "aggregate-quote-leg".to_owned(),
        digest: None,
    });
    allowlist.push(DecodedInstructionEvidenceV1 {
        transaction: "settlement".to_owned(),
        position: 4,
        program: kageb_program::TOKEN_PROGRAM_ID.to_string(),
        kind: "aggregate-base-leg".to_owned(),
        digest: None,
    });
    allowlist
}

fn verifier_fixture() -> (DevnetEvidenceBundleV1, DevnetPublicSnapshotV1, Vec<u8>) {
    let artifact = b"\x7fELFcanonical-checkpoint".to_vec();
    let mut content = content();
    let operator = pubkey(&content.accounts.operator);
    let base_mint = pubkey(&content.accounts.base_mint);
    let quote_mint = pubkey(&content.accounts.quote_mint);
    let (pool, pool_bump) = kageb_program::pool_address(&operator, &base_mint, &quote_mint);
    let (vault_authority, vault_bump) = kageb_program::vault_authority_address(&pool);
    let epoch_id = [2; 32];
    let (epoch, epoch_bump) = kageb_program::epoch_address(&pool, &epoch_id);
    content.accounts.pool = pool.to_string();
    content.accounts.vault_authority = vault_authority.to_string();
    content.accounts.epoch = epoch.to_string();
    content.checkpoint_artifact_len = artifact.len();
    content.checkpoint_artifact_sha256 = digest_bytes(&artifact);
    content.deployment.deployed_executable_sha256 = digest_bytes(&artifact);
    content.configuration.epoch_id = digest(2);
    content.decoded_allowlist = canonical_allowlist(&content);

    let keypers = content
        .configuration
        .keypers
        .each_ref()
        .map(|key| pubkey(key));
    let pool_state = PoolStateV1 {
        pool_bump,
        vault_bump,
        lock_threshold: 2,
        settlement_threshold: 2,
        operator,
        base_mint,
        quote_mint,
        pool_base_vault: pubkey(&content.accounts.pool_base_vault),
        pool_quote_vault: pubkey(&content.accounts.pool_quote_vault),
        venue_authority: pubkey(&content.accounts.venue_authority),
        venue_base_account: pubkey(&content.accounts.venue_base_account),
        venue_quote_account: pubkey(&content.accounts.venue_quote_account),
        keypers,
        base_lot_atoms: 1,
    };
    let epoch_state = EpochStateV1 {
        epoch_bump,
        terminal_state: EpochTerminalState::Settled,
        residual_side: 1,
        pool,
        epoch_id,
        configuration_hash: [9; 32],
        pre_balance_root: [3; 32],
        member_root: [4; 32],
        lock_digest: [5; 32],
        result_commitment: [6; 32],
        settlement_digest: [7; 32],
        lock_nonce: [10; 32],
        settlement_nonce: [11; 32],
        member_count: 4,
        minimum_count: 4,
        residual_lots: 1,
        base_lot_atoms: 1,
        quote_atoms_per_lot: 100,
        lock_deadline: 1_000,
        abort_deadline: 2_000,
    };
    let transaction_snapshots = content
        .transactions
        .funding
        .iter()
        .map(|funding| funding.transaction.clone())
        .chain([
            content.transactions.lock.clone(),
            content.transactions.settlement.clone(),
        ])
        .map(|transaction| FinalizedTransactionSnapshotV1 {
            signature: transaction.signature,
            slot: transaction.slot,
            status_slot: transaction.slot,
            finalized: true,
            succeeded: true,
        })
        .collect();
    let programdata =
        Pubkey::find_program_address(&[kageb_program::ID.as_ref()], &UPGRADEABLE_LOADER_ID).0;
    content.deployment.programdata = programdata.to_string();
    let snapshot = DevnetPublicSnapshotV1 {
        program: program_account(programdata),
        programdata_address: programdata,
        programdata: programdata_account(
            content.deployment.deployment_slot,
            content.deployment.upgrade_authority.as_deref().map(pubkey),
            &artifact,
            &[0; 32],
        ),
        pool: PublicAccountSnapshotV1 {
            owner: kageb_program::ID,
            executable: false,
            data: pool_state.encode().to_vec(),
        },
        epoch: PublicAccountSnapshotV1 {
            owner: kageb_program::ID,
            executable: false,
            data: epoch_state.encode().to_vec(),
        },
        base_mint: mint_account(None, None),
        quote_mint: mint_account(None, None),
        current_token_accounts: [
            token_account(
                base_mint,
                vault_authority,
                content.token_balances.pool_base_after,
            ),
            token_account(
                quote_mint,
                vault_authority,
                content.token_balances.pool_quote_after,
            ),
            token_account(
                base_mint,
                pubkey(&content.accounts.venue_authority),
                content.token_balances.venue_base_after,
            ),
            token_account(
                quote_mint,
                pubkey(&content.accounts.venue_authority),
                content.token_balances.venue_quote_after,
            ),
        ],
        transactions: transaction_snapshots,
        token_balances: content.token_balances.clone(),
        decoded_allowlist: content.decoded_allowlist.clone(),
    };
    (
        DevnetEvidenceBundleV1::seal(content).unwrap(),
        snapshot,
        artifact,
    )
}

#[test]
fn injected_verifier_accepts_one_finalized_public_trace() {
    let (bundle, snapshot, artifact) = verifier_fixture();
    verify_devnet_evidence(&bundle, &snapshot, &artifact).unwrap();
}

#[test]
fn injected_verifier_fails_closed_at_each_public_trust_boundary() {
    let (bundle, snapshot, artifact) = verifier_fixture();

    let mut content = bundle.content.clone();
    content.cluster = "mainnet-beta".to_owned();
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();
    assert_eq!(
        verify_devnet_evidence(&changed, &snapshot, &artifact),
        Err(DevnetEvidenceError::WrongCluster)
    );

    let mut content = bundle.content.clone();
    content.deployment.program = Pubkey::new_unique().to_string();
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();
    assert_eq!(
        verify_devnet_evidence(&changed, &snapshot, &artifact),
        Err(DevnetEvidenceError::WrongProgram)
    );

    let mut content = bundle.content.clone();
    content.deployment.deployment_slot += 1;
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();
    assert_eq!(
        verify_devnet_evidence(&changed, &snapshot, &artifact),
        Err(DevnetEvidenceError::DeploymentMismatch)
    );

    let mut content = bundle.content.clone();
    content.deployment.programdata = Pubkey::new_unique().to_string();
    let mut changed_snapshot = snapshot.clone();
    changed_snapshot.programdata_address = pubkey(&content.deployment.programdata);
    changed_snapshot.program = program_account(changed_snapshot.programdata_address);
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();
    assert_eq!(
        verify_devnet_evidence(&changed, &changed_snapshot, &artifact),
        Err(DevnetEvidenceError::WrongProgramDataAddress)
    );

    let mut content = bundle.content.clone();
    content.deployment.deployment_slot = content.transactions.settlement.slot + 1;
    let mut changed_snapshot = snapshot.clone();
    changed_snapshot.programdata = programdata_account(
        content.deployment.deployment_slot,
        content.deployment.upgrade_authority.as_deref().map(pubkey),
        &artifact,
        &[0; 32],
    );
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();
    assert_eq!(
        verify_devnet_evidence(&changed, &changed_snapshot, &artifact),
        Err(DevnetEvidenceError::InvalidChronology)
    );

    let mut changed = snapshot.clone();
    changed.transactions.pop();
    assert_eq!(
        verify_devnet_evidence(&bundle, &changed, &artifact),
        Err(DevnetEvidenceError::MissingTransaction)
    );

    let mut changed = snapshot.clone();
    changed.transactions[0].finalized = false;
    assert_eq!(
        verify_devnet_evidence(&bundle, &changed, &artifact),
        Err(DevnetEvidenceError::UnfinalizedTransaction)
    );

    let mut changed = snapshot.clone();
    changed.transactions[0].succeeded = false;
    assert_eq!(
        verify_devnet_evidence(&bundle, &changed, &artifact),
        Err(DevnetEvidenceError::FailedTransaction)
    );

    let mut changed = snapshot.clone();
    changed.transactions[0].slot += 1;
    assert_eq!(
        verify_devnet_evidence(&bundle, &changed, &artifact),
        Err(DevnetEvidenceError::TransactionSlotMismatch)
    );

    let mut changed = snapshot.clone();
    changed.transactions[0].status_slot += 1;
    assert_eq!(
        verify_devnet_evidence(&bundle, &changed, &artifact),
        Err(DevnetEvidenceError::TransactionSlotMismatch)
    );

    let mut content = bundle.content.clone();
    content.transactions.funding[0].transaction.slot = content.transactions.lock.slot;
    let mut changed_snapshot = snapshot.clone();
    changed_snapshot.transactions[0].slot = content.transactions.lock.slot;
    changed_snapshot.transactions[0].status_slot = content.transactions.lock.slot;
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();
    assert_eq!(
        verify_devnet_evidence(&changed, &changed_snapshot, &artifact),
        Err(DevnetEvidenceError::InvalidChronology)
    );

    let mut content = bundle.content.clone();
    content.transactions.funding[1].authority = content.transactions.funding[0].authority.clone();
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();
    assert_eq!(
        verify_devnet_evidence(&changed, &snapshot, &artifact),
        Err(DevnetEvidenceError::RepeatedFundingAuthority)
    );

    let mut content = bundle.content.clone();
    content.transactions.funding[1].base_source =
        content.transactions.funding[0].base_source.clone();
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();
    assert_eq!(
        verify_devnet_evidence(&changed, &snapshot, &artifact),
        Err(DevnetEvidenceError::RepeatedFundingSource)
    );

    let mut content = bundle.content.clone();
    content.configuration.member_count = 3;
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();
    assert_eq!(
        verify_devnet_evidence(&changed, &snapshot, &artifact),
        Err(DevnetEvidenceError::WrongMemberCount)
    );

    let mut changed = snapshot.clone();
    changed.pool.owner = Pubkey::new_unique();
    assert_eq!(
        verify_devnet_evidence(&bundle, &changed, &artifact),
        Err(DevnetEvidenceError::WrongAccountOwner)
    );

    let mut content = bundle.content.clone();
    content.configuration.keypers[0] = key(99);
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();
    assert_eq!(
        verify_devnet_evidence(&changed, &snapshot, &artifact),
        Err(DevnetEvidenceError::WrongKeyper)
    );

    let mut content = bundle.content.clone();
    content.token_balances.pool_base_after += 1;
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();
    assert_eq!(
        verify_devnet_evidence(&changed, &snapshot, &artifact),
        Err(DevnetEvidenceError::WrongTokenDelta)
    );

    let mut changed = snapshot.clone();
    changed
        .decoded_allowlist
        .push(DecodedInstructionEvidenceV1 {
            transaction: "settlement".to_owned(),
            position: 5,
            program: kageb_program::ID.to_string(),
            kind: "aggregate-settlement".to_owned(),
            digest: Some(bundle.content.commitments.settlement_digest.clone()),
        });
    assert_eq!(
        verify_devnet_evidence(&bundle, &changed, &artifact),
        Err(DevnetEvidenceError::SecondSettlement)
    );

    let mut content = bundle.content.clone();
    content.commitments.result = digest(88);
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();
    assert_eq!(
        verify_devnet_evidence(&changed, &snapshot, &artifact),
        Err(DevnetEvidenceError::ChangedCommitment)
    );

    let mut content = bundle.content.clone();
    content.explorer_links[5] = "https://explorer.solana.com/tx/wrong?cluster=devnet".to_owned();
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();
    assert_eq!(
        verify_devnet_evidence(&changed, &snapshot, &artifact),
        Err(DevnetEvidenceError::InvalidPublicField)
    );

    let mut changed = snapshot.clone();
    changed.base_mint = mint_account(Some(Pubkey::new_unique()), None);
    assert_eq!(
        verify_devnet_evidence(&bundle, &changed, &artifact),
        Err(DevnetEvidenceError::InvalidTokenAccount)
    );

    let mut changed = snapshot.clone();
    changed.quote_mint = mint_account(None, Some(Pubkey::new_unique()));
    assert_eq!(
        verify_devnet_evidence(&bundle, &changed, &artifact),
        Err(DevnetEvidenceError::InvalidTokenAccount)
    );

    let mut changed = snapshot.clone();
    let base_mint = pubkey(&bundle.content.accounts.base_mint);
    let vault_authority = pubkey(&bundle.content.accounts.vault_authority);
    changed.current_token_accounts[0] = token_account(base_mint, vault_authority, 999);
    verify_devnet_evidence(&bundle, &changed, &artifact).unwrap();
}

#[test]
fn verifier_rejects_overflowing_public_token_totals_without_panicking() {
    let (bundle, mut snapshot, artifact) = verifier_fixture();
    let mut content = bundle.content;
    content.token_balances.pool_base_before = u64::MAX;
    content.token_balances.venue_base_before = 1;
    snapshot.token_balances = content.token_balances.clone();
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();

    assert_eq!(
        verify_devnet_evidence(&changed, &snapshot, &artifact),
        Err(DevnetEvidenceError::WrongTokenDelta)
    );
}

#[test]
fn verifier_rejects_unicode_hex_without_panicking() {
    let (bundle, snapshot, artifact) = verifier_fixture();
    let mut content = bundle.content;
    content.commitments.result = "é".repeat(32);
    let changed = DevnetEvidenceBundleV1::seal(content).unwrap();

    let result =
        std::panic::catch_unwind(|| verify_devnet_evidence(&changed, &snapshot, &artifact));
    assert!(matches!(
        result,
        Ok(Err(DevnetEvidenceError::InvalidPublicField))
    ));
}
