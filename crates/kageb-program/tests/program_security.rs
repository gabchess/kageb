#![allow(deprecated)]

use kageb_program::{
    epoch_address,
    error::KagebError,
    instruction::{
        abort_instruction, create_epoch_instruction, expire_instruction,
        initialize_pool_instruction, lock_instruction, CreateEpochArgs, InitializePoolAccounts,
        InitializePoolArgs,
    },
    pool_address,
    state::{EpochStateV1, EpochTerminalState, PoolStateV1},
    vault_authority_address,
    wire::{EpochConfigurationV1, LockPayloadV1},
    ID, TOKEN_PROGRAM_ID,
};
use solana_account::{Account, AccountSharedData};
use solana_ed25519_program::new_ed25519_instruction_with_signature;
use solana_keypair::Keypair;
use solana_program::{
    clock::Clock,
    instruction::{Instruction, InstructionError},
    pubkey::Pubkey,
};
use solana_program_test::{BanksClientError, ProgramTest, ProgramTestContext};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use std::str::FromStr;

#[test]
fn sbf_freshness_inputs_cover_workspace_build_settings_and_every_program_source() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let inputs = sbf_freshness_inputs(manifest_dir);
    for required in [
        manifest_dir.join("Cargo.toml"),
        manifest_dir.join("src/lib.rs"),
        manifest_dir.join("../../Cargo.toml"),
        manifest_dir.join("../../Cargo.lock"),
        manifest_dir.join("../../rust-toolchain.toml"),
    ] {
        assert!(inputs.contains(&required), "missing {}", required.display());
    }
    for entry in std::fs::read_dir(manifest_dir.join("src")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            assert!(
                inputs.contains(&entry.path()),
                "missing {}",
                entry.path().display()
            );
        }
    }
}

struct Fixture {
    context: ProgramTestContext,
    operator: Keypair,
    keypers: [Keypair; 3],
    base_mint: Pubkey,
    quote_mint: Pubkey,
    pool_base_vault: Pubkey,
    pool_quote_vault: Pubkey,
    venue_authority: Keypair,
    venue_base_account: Pubkey,
    venue_quote_account: Pubkey,
    pool: Pubkey,
    vault_authority: Pubkey,
    outsider: Keypair,
}

#[derive(Clone, Copy)]
enum InitAccountShape {
    Valid,
    BaseMintOwnedBy(Pubkey),
    BaseVaultUsesMint(Pubkey),
    BaseVaultUsesAuthority(Pubkey),
}

impl Fixture {
    async fn start() -> Self {
        Self::start_with(InitAccountShape::Valid).await
    }

    async fn start_with(shape: InitAccountShape) -> Self {
        let operator = Keypair::new();
        let keypers = [Keypair::new(), Keypair::new(), Keypair::new()];
        let base_mint = Pubkey::new_unique();
        let quote_mint = Pubkey::new_unique();
        let pool_base_vault = Pubkey::new_unique();
        let pool_quote_vault = Pubkey::new_unique();
        let venue_authority = Keypair::new();
        let venue_base_account = Pubkey::new_unique();
        let venue_quote_account = Pubkey::new_unique();
        let outsider = Keypair::new();
        let (pool, _) = pool_address(&operator.pubkey(), &base_mint, &quote_mint);
        let (vault_authority, _) = vault_authority_address(&pool);

        let mut program_test = ProgramTest::default();
        program_test.add_account(ID, sbf_program_account());
        program_test.add_account(operator.pubkey(), system_account());
        program_test.add_account(venue_authority.pubkey(), system_account());
        program_test.add_account(outsider.pubkey(), system_account());
        program_test.add_account(vault_authority, system_account());
        program_test.add_account(TOKEN_PROGRAM_ID, token_program_account());
        let base_mint_account = match shape {
            InitAccountShape::BaseMintOwnedBy(owner) => mint_account_owned_by(owner),
            _ => mint_account(),
        };
        program_test.add_account(base_mint, base_mint_account);
        program_test.add_account(quote_mint, mint_account());
        let base_vault = match shape {
            InitAccountShape::BaseVaultUsesMint(mint) => token_account(mint, vault_authority),
            InitAccountShape::BaseVaultUsesAuthority(authority) => {
                token_account(base_mint, authority)
            }
            _ => token_account(base_mint, vault_authority),
        };
        program_test.add_account(pool_base_vault, base_vault);
        program_test.add_account(pool_quote_vault, token_account(quote_mint, vault_authority));
        program_test.add_account(
            venue_base_account,
            token_account(base_mint, venue_authority.pubkey()),
        );
        program_test.add_account(
            venue_quote_account,
            token_account(quote_mint, venue_authority.pubkey()),
        );

        Self {
            context: program_test.start_with_context().await,
            operator,
            keypers,
            base_mint,
            quote_mint,
            pool_base_vault,
            pool_quote_vault,
            venue_authority,
            venue_base_account,
            venue_quote_account,
            pool,
            vault_authority,
            outsider,
        }
    }

    fn initialize_instruction(&self, args: InitializePoolArgs) -> Instruction {
        initialize_pool_instruction(
            InitializePoolAccounts {
                payer: self.context.payer.pubkey(),
                operator: self.operator.pubkey(),
                pool: self.pool,
                vault_authority: self.vault_authority,
                base_mint: self.base_mint,
                quote_mint: self.quote_mint,
                pool_base_vault: self.pool_base_vault,
                pool_quote_vault: self.pool_quote_vault,
                venue_authority: self.venue_authority.pubkey(),
                venue_base_account: self.venue_base_account,
                venue_quote_account: self.venue_quote_account,
            },
            args,
        )
    }

    fn valid_initialize_args(&self) -> InitializePoolArgs {
        InitializePoolArgs {
            lock_threshold: 2,
            settlement_threshold: 2,
            base_lot_atoms: 1,
            keypers: self.keypers.each_ref().map(Signer::pubkey),
        }
    }

    async fn initialize(&mut self) {
        let instruction = self.initialize_instruction(self.valid_initialize_args());
        process(&mut self.context, &[instruction], &[&self.operator])
            .await
            .unwrap();
    }

    async fn create_epoch(&mut self, epoch_id: [u8; 32], lock: i64, abort: i64) -> Pubkey {
        let (epoch, _) = epoch_address(&self.pool, &epoch_id);
        let instruction = self.create_epoch_instruction(CreateEpochArgs {
            epoch_id,
            minimum_count: 4,
            quote_atoms_per_lot: 100,
            lock_deadline: lock,
            abort_deadline: abort,
        });
        process(&mut self.context, &[instruction], &[&self.operator])
            .await
            .unwrap();
        epoch
    }

    fn create_epoch_instruction(&self, args: CreateEpochArgs) -> Instruction {
        let (epoch, _) = epoch_address(&self.pool, &args.epoch_id);
        create_epoch_instruction(
            self.context.payer.pubkey(),
            self.operator.pubkey(),
            self.pool,
            epoch,
            args,
        )
    }

    fn config(&self, epoch_id: [u8; 32], lock: i64, abort: i64) -> EpochConfigurationV1 {
        EpochConfigurationV1 {
            pool: self.pool,
            epoch_id,
            base_mint: self.base_mint,
            quote_mint: self.quote_mint,
            base_lot_atoms: 1,
            quote_atoms_per_lot: 100,
            minimum_count: 4,
            lock_threshold: 2,
            settlement_threshold: 2,
            keypers: self.keypers.each_ref().map(Signer::pubkey),
            lock_deadline: lock,
            abort_deadline: abort,
        }
    }
}

#[tokio::test]
async fn initialize_accepts_a_pre_funded_pool_pda() {
    let mut fixture = Fixture::start().await;
    prefund(&mut fixture.context, fixture.pool, 1_000_000).await;

    fixture.initialize().await;

    let account = fixture
        .context
        .banks_client
        .get_account(fixture.pool)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.owner, ID);
    assert_eq!(account.data.len(), 384);
    assert!(account.lamports >= 1_000_000);
    PoolStateV1::decode(&account.data).unwrap();
}

#[tokio::test]
async fn create_epoch_accepts_a_pre_funded_epoch_pda() {
    let mut fixture = Fixture::start().await;
    fixture.initialize().await;
    let now = fixture
        .context
        .banks_client
        .get_sysvar::<Clock>()
        .await
        .unwrap()
        .unix_timestamp;
    let epoch_id = [30; 32];
    let (epoch, _) = epoch_address(&fixture.pool, &epoch_id);
    prefund(&mut fixture.context, epoch, 1_000_000).await;

    fixture.create_epoch(epoch_id, now + 100, now + 200).await;

    let account = fixture
        .context
        .banks_client
        .get_account(epoch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.owner, ID);
    assert_eq!(account.data.len(), 384);
    assert!(account.lamports >= 1_000_000);
    assert_eq!(
        EpochStateV1::decode(&account.data).unwrap().terminal_state,
        EpochTerminalState::Open
    );
}

#[tokio::test]
async fn initialize_rejects_bad_configuration_duplicate_accounts_and_reinitialization() {
    let mut fixture = Fixture::start().await;

    for (lock_threshold, settlement_threshold, base_lot_atoms) in [(1, 2, 1), (2, 3, 1), (2, 2, 0)]
    {
        let mut args = fixture.valid_initialize_args();
        args.lock_threshold = lock_threshold;
        args.settlement_threshold = settlement_threshold;
        args.base_lot_atoms = base_lot_atoms;
        let instruction = fixture.initialize_instruction(args);
        assert!(
            process(&mut fixture.context, &[instruction], &[&fixture.operator],)
                .await
                .is_err()
        );
    }

    let mut duplicate = fixture.initialize_instruction(fixture.valid_initialize_args());
    duplicate.accounts[10].pubkey = duplicate.accounts[9].pubkey;
    assert!(
        process(&mut fixture.context, &[duplicate], &[&fixture.operator],)
            .await
            .is_err()
    );

    fixture.initialize().await;
    let reinitialize = fixture.initialize_instruction(fixture.valid_initialize_args());
    assert!(
        process(&mut fixture.context, &[reinitialize], &[&fixture.operator],)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn initialize_rejects_token_2022_like_mints_and_mismatched_vaults() {
    let token_2022_like = Pubkey::from_str("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap();
    let mut wrong_owner =
        Fixture::start_with(InitAccountShape::BaseMintOwnedBy(token_2022_like)).await;
    let instruction = wrong_owner.initialize_instruction(wrong_owner.valid_initialize_args());
    assert!(process(
        &mut wrong_owner.context,
        &[instruction],
        &[&wrong_owner.operator],
    )
    .await
    .is_err());

    let mut wrong_mint =
        Fixture::start_with(InitAccountShape::BaseVaultUsesMint(Pubkey::new_unique())).await;
    let instruction = wrong_mint.initialize_instruction(wrong_mint.valid_initialize_args());
    assert!(process(
        &mut wrong_mint.context,
        &[instruction],
        &[&wrong_mint.operator],
    )
    .await
    .is_err());

    let mut wrong_authority = Fixture::start_with(InitAccountShape::BaseVaultUsesAuthority(
        Pubkey::new_unique(),
    ))
    .await;
    let instruction =
        wrong_authority.initialize_instruction(wrong_authority.valid_initialize_args());
    assert!(process(
        &mut wrong_authority.context,
        &[instruction],
        &[&wrong_authority.operator],
    )
    .await
    .is_err());
}

#[tokio::test]
async fn create_epoch_rejects_bad_policy_time_authority_pda_and_duplicate_accounts() {
    let mut fixture = Fixture::start().await;
    fixture.initialize().await;
    let now = fixture
        .context
        .banks_client
        .get_sysvar::<Clock>()
        .await
        .unwrap()
        .unix_timestamp;
    let valid = CreateEpochArgs {
        epoch_id: [31; 32],
        minimum_count: 4,
        quote_atoms_per_lot: 100,
        lock_deadline: now + 100,
        abort_deadline: now + 200,
    };

    let invalid_args = [
        CreateEpochArgs {
            minimum_count: 3,
            ..valid
        },
        CreateEpochArgs {
            quote_atoms_per_lot: 0,
            ..valid
        },
        CreateEpochArgs {
            lock_deadline: now,
            ..valid
        },
        CreateEpochArgs {
            lock_deadline: now - 1,
            ..valid
        },
        CreateEpochArgs {
            abort_deadline: valid.lock_deadline,
            ..valid
        },
        CreateEpochArgs {
            abort_deadline: valid.lock_deadline - 1,
            ..valid
        },
    ];
    for args in invalid_args {
        let instruction = fixture.create_epoch_instruction(args);
        assert!(
            process(&mut fixture.context, &[instruction], &[&fixture.operator],)
                .await
                .is_err()
        );
    }

    let mut missing_operator_signature = fixture.create_epoch_instruction(valid);
    missing_operator_signature.accounts[1].is_signer = false;
    assert!(
        process(&mut fixture.context, &[missing_operator_signature], &[],)
            .await
            .is_err()
    );

    let mut wrong_operator = fixture.create_epoch_instruction(valid);
    wrong_operator.accounts[1].pubkey = fixture.outsider.pubkey();
    assert!(process(
        &mut fixture.context,
        &[wrong_operator],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    let mut wrong_pda = fixture.create_epoch_instruction(valid);
    wrong_pda.accounts[3].pubkey = Pubkey::new_unique();
    assert!(
        process(&mut fixture.context, &[wrong_pda], &[&fixture.operator],)
            .await
            .is_err()
    );

    let mut duplicate = fixture.create_epoch_instruction(valid);
    duplicate.accounts[3].pubkey = duplicate.accounts[2].pubkey;
    assert!(
        process(&mut fixture.context, &[duplicate], &[&fixture.operator],)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn instructions_reject_representable_signer_and_writable_privilege_escalation() {
    let mut fixture = Fixture::start().await;

    let mut unexpected_signer = fixture.initialize_instruction(fixture.valid_initialize_args());
    unexpected_signer.accounts[8].is_signer = true;
    assert!(process(
        &mut fixture.context,
        &[unexpected_signer],
        &[&fixture.operator, &fixture.venue_authority],
    )
    .await
    .is_err());

    let mut writable_mint = fixture.initialize_instruction(fixture.valid_initialize_args());
    writable_mint.accounts[4].is_writable = true;
    assert!(
        process(&mut fixture.context, &[writable_mint], &[&fixture.operator],)
            .await
            .is_err()
    );
    fixture.initialize().await;

    let now = fixture
        .context
        .banks_client
        .get_sysvar::<Clock>()
        .await
        .unwrap()
        .unix_timestamp;
    let epoch_id = [32; 32];
    let lock_deadline = now + 100;
    let abort_deadline = now + 200;
    let args = CreateEpochArgs {
        epoch_id,
        minimum_count: 4,
        quote_atoms_per_lot: 100,
        lock_deadline,
        abort_deadline,
    };
    let mut writable_pool = fixture.create_epoch_instruction(args);
    writable_pool.accounts[2].is_writable = true;
    assert!(
        process(&mut fixture.context, &[writable_pool], &[&fixture.operator],)
            .await
            .is_err()
    );
    let epoch = fixture
        .create_epoch(epoch_id, lock_deadline, abort_deadline)
        .await;

    let payload = LockPayloadV1 {
        epoch_account: epoch,
        configuration_hash: fixture
            .config(epoch_id, lock_deadline, abort_deadline)
            .digest(),
        pre_balance_root: [35; 32],
        member_root: [33; 32],
        member_count: 4,
        lock_deadline,
        lock_nonce: [34; 32],
    };
    let digest = payload.digest();
    let caller = fixture.outsider.pubkey();
    for account_index in [0, 1] {
        let mut instruction = lock_instruction(caller, fixture.pool, epoch, payload);
        instruction.accounts[account_index].is_writable = true;
        assert!(process(
            &mut fixture.context,
            &[
                verifier(&fixture.keypers[0], &digest),
                verifier(&fixture.keypers[1], &digest),
                instruction,
            ],
            &[&fixture.outsider],
        )
        .await
        .is_err());
    }

    let mut clock = fixture
        .context
        .banks_client
        .get_sysvar::<Clock>()
        .await
        .unwrap();
    clock.unix_timestamp = lock_deadline + 1;
    fixture.context.set_sysvar(&clock);
    for account_index in [0, 1] {
        let mut instruction = expire_instruction(caller, fixture.pool, epoch);
        instruction.accounts[account_index].is_writable = true;
        assert!(
            process(&mut fixture.context, &[instruction], &[&fixture.outsider],)
                .await
                .is_err()
        );
    }
    assert_eq!(
        read_epoch(&mut fixture.context, epoch).await.terminal_state,
        EpochTerminalState::Open
    );
}

#[tokio::test]
async fn lock_rejects_payload_drift_bad_quorum_and_non_strict_verifiers() {
    let mut fixture = Fixture::start().await;
    fixture.initialize().await;
    let now = fixture
        .context
        .banks_client
        .get_sysvar::<Clock>()
        .await
        .unwrap()
        .unix_timestamp;
    let epoch_id = [7; 32];
    let lock_deadline = now + 100;
    let abort_deadline = now + 200;
    let epoch = fixture
        .create_epoch(epoch_id, lock_deadline, abort_deadline)
        .await;

    let pool_account = fixture
        .context
        .banks_client
        .get_account(fixture.pool)
        .await
        .unwrap()
        .unwrap();
    let pool = PoolStateV1::decode(&pool_account.data).unwrap();
    assert_eq!(pool.keypers, fixture.keypers.each_ref().map(Signer::pubkey));

    let payload = LockPayloadV1 {
        epoch_account: epoch,
        configuration_hash: fixture
            .config(epoch_id, lock_deadline, abort_deadline)
            .digest(),
        pre_balance_root: [6; 32],
        member_root: [8; 32],
        member_count: 4,
        lock_deadline,
        lock_nonce: [9; 32],
    };
    let digest = payload.digest();
    let payer = fixture.outsider.pubkey();

    let under_minimum = LockPayloadV1 {
        member_count: 3,
        ..payload
    };
    let under_minimum_digest = under_minimum.digest();
    let error = process(
        &mut fixture.context,
        &[
            verifier(&fixture.keypers[0], &under_minimum_digest),
            verifier(&fixture.keypers[1], &under_minimum_digest),
            lock_instruction(payer, fixture.pool, epoch, under_minimum),
        ],
        &[&fixture.outsider],
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.unwrap(),
        TransactionError::InstructionError(
            2,
            InstructionError::Custom(KagebError::CrowdBelowMinimum as u32),
        )
    );

    for changed in [
        LockPayloadV1 {
            member_count: 5,
            ..payload
        },
        LockPayloadV1 {
            pre_balance_root: [10; 32],
            ..payload
        },
        LockPayloadV1 {
            member_root: [10; 32],
            ..payload
        },
        LockPayloadV1 {
            configuration_hash: [11; 32],
            ..payload
        },
        LockPayloadV1 {
            lock_deadline: lock_deadline + 1,
            ..payload
        },
        LockPayloadV1 {
            lock_nonce: [12; 32],
            ..payload
        },
    ] {
        assert!(process(
            &mut fixture.context,
            &[
                verifier(&fixture.keypers[0], &digest),
                verifier(&fixture.keypers[1], &digest),
                lock_instruction(payer, fixture.pool, epoch, changed),
            ],
            &[&fixture.outsider],
        )
        .await
        .is_err());
    }

    assert!(process(
        &mut fixture.context,
        &[
            verifier(&fixture.keypers[0], &digest),
            lock_instruction(payer, fixture.pool, epoch, payload),
        ],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    assert!(process(
        &mut fixture.context,
        &[
            verifier(&fixture.keypers[0], &digest),
            verifier(&fixture.keypers[0], &digest),
            lock_instruction(payer, fixture.pool, epoch, payload),
        ],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    assert!(process(
        &mut fixture.context,
        &[
            verifier(&fixture.keypers[0], &digest),
            verifier(&fixture.outsider, &digest),
            lock_instruction(payer, fixture.pool, epoch, payload),
        ],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    let wrong_digest = [13; 32];
    assert!(process(
        &mut fixture.context,
        &[
            verifier(&fixture.keypers[0], &wrong_digest),
            verifier(&fixture.keypers[1], &wrong_digest),
            lock_instruction(payer, fixture.pool, epoch, payload),
        ],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    let mut malformed = verifier(&fixture.keypers[0], &digest);
    malformed.data[1] = 1;
    assert!(process(
        &mut fixture.context,
        &[
            malformed,
            verifier(&fixture.keypers[1], &digest),
            lock_instruction(payer, fixture.pool, epoch, payload),
        ],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    let source = verifier(&fixture.keypers[1], &digest);
    let cross_instruction = cross_instruction_verifier(&source, 1);
    assert!(process(
        &mut fixture.context,
        &[
            cross_instruction,
            source,
            lock_instruction(payer, fixture.pool, epoch, payload),
        ],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    assert!(process(
        &mut fixture.context,
        &[
            verifier(&fixture.keypers[0], &digest),
            lock_instruction(payer, fixture.pool, epoch, payload),
            verifier(&fixture.keypers[1], &digest),
        ],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    process(
        &mut fixture.context,
        &[
            verifier(&fixture.keypers[0], &digest),
            verifier(&fixture.keypers[1], &digest),
            lock_instruction(payer, fixture.pool, epoch, payload),
        ],
        &[&fixture.outsider],
    )
    .await
    .unwrap();

    let epoch_account = fixture
        .context
        .banks_client
        .get_account(epoch)
        .await
        .unwrap()
        .unwrap();
    let state = EpochStateV1::decode(&epoch_account.data).unwrap();
    assert_eq!(state.terminal_state, EpochTerminalState::Locked);
    assert_eq!(state.member_count, 4);
    assert_eq!(state.pre_balance_root, [6; 32]);
    assert_eq!(state.member_root, [8; 32]);
    assert_eq!(state.lock_digest, digest);

    assert!(process(
        &mut fixture.context,
        &[
            verifier(&fixture.keypers[0], &digest),
            verifier(&fixture.keypers[1], &digest),
            lock_instruction(payer, fixture.pool, epoch, payload),
        ],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    let conflict = LockPayloadV1 {
        member_root: [14; 32],
        ..payload
    };
    let conflict_digest = conflict.digest();
    assert!(process(
        &mut fixture.context,
        &[
            verifier(&fixture.keypers[0], &conflict_digest),
            verifier(&fixture.keypers[1], &conflict_digest),
            lock_instruction(payer, fixture.pool, epoch, conflict),
        ],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    let mut clock = fixture
        .context
        .banks_client
        .get_sysvar::<Clock>()
        .await
        .unwrap();
    clock.unix_timestamp = abort_deadline;
    fixture.context.set_sysvar(&clock);
    assert!(process(
        &mut fixture.context,
        &[abort_instruction(payer, fixture.pool, epoch)],
        &[&fixture.outsider],
    )
    .await
    .is_err());
    clock.unix_timestamp = abort_deadline + 1;
    fixture.context.set_sysvar(&clock);
    process(
        &mut fixture.context,
        &[abort_instruction(payer, fixture.pool, epoch)],
        &[&fixture.outsider],
    )
    .await
    .unwrap();
    assert_eq!(
        read_epoch(&mut fixture.context, epoch).await.terminal_state,
        EpochTerminalState::Aborted
    );
}

#[tokio::test]
async fn lock_rejects_a_valid_quorum_at_the_lock_deadline() {
    let mut fixture = Fixture::start().await;
    fixture.initialize().await;
    let mut clock = fixture
        .context
        .banks_client
        .get_sysvar::<Clock>()
        .await
        .unwrap();
    let epoch_id = [15; 32];
    let lock_deadline = clock.unix_timestamp + 10;
    let abort_deadline = clock.unix_timestamp + 20;
    let epoch = fixture
        .create_epoch(epoch_id, lock_deadline, abort_deadline)
        .await;
    let payload = LockPayloadV1 {
        epoch_account: epoch,
        configuration_hash: fixture
            .config(epoch_id, lock_deadline, abort_deadline)
            .digest(),
        pre_balance_root: [18; 32],
        member_root: [16; 32],
        member_count: 4,
        lock_deadline,
        lock_nonce: [17; 32],
    };
    let digest = payload.digest();
    let payer = fixture.outsider.pubkey();
    clock.unix_timestamp = lock_deadline;
    fixture.context.set_sysvar(&clock);

    assert!(process(
        &mut fixture.context,
        &[
            verifier(&fixture.keypers[0], &digest),
            verifier(&fixture.keypers[1], &digest),
            lock_instruction(payer, fixture.pool, epoch, payload),
        ],
        &[&fixture.outsider],
    )
    .await
    .is_err());
    assert_eq!(
        read_epoch(&mut fixture.context, epoch).await.terminal_state,
        EpochTerminalState::Open
    );
}

#[tokio::test]
async fn lock_and_terminal_paths_reject_a_tampered_program_owned_pool_bump() {
    let mut fixture = Fixture::start().await;
    fixture.initialize().await;
    let mut clock = fixture
        .context
        .banks_client
        .get_sysvar::<Clock>()
        .await
        .unwrap();
    let epoch_id = [40; 32];
    let lock_deadline = clock.unix_timestamp + 10;
    let abort_deadline = clock.unix_timestamp + 20;
    let epoch = fixture
        .create_epoch(epoch_id, lock_deadline, abort_deadline)
        .await;
    let payload = LockPayloadV1 {
        epoch_account: epoch,
        configuration_hash: fixture
            .config(epoch_id, lock_deadline, abort_deadline)
            .digest(),
        pre_balance_root: [43; 32],
        member_root: [41; 32],
        member_count: 4,
        lock_deadline,
        lock_nonce: [42; 32],
    };
    let digest = payload.digest();
    let caller = fixture.outsider.pubkey();

    let mut account = fixture
        .context
        .banks_client
        .get_account(fixture.pool)
        .await
        .unwrap()
        .unwrap();
    let mut state = PoolStateV1::decode(&account.data).unwrap();
    state.pool_bump = state.pool_bump.wrapping_add(1);
    account.data = state.encode().to_vec();
    fixture
        .context
        .set_account(&fixture.pool, &AccountSharedData::from(account));

    assert!(process(
        &mut fixture.context,
        &[
            verifier(&fixture.keypers[0], &digest),
            verifier(&fixture.keypers[1], &digest),
            lock_instruction(caller, fixture.pool, epoch, payload),
        ],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    clock.unix_timestamp = lock_deadline + 1;
    fixture.context.set_sysvar(&clock);
    assert!(process(
        &mut fixture.context,
        &[expire_instruction(caller, fixture.pool, epoch)],
        &[&fixture.outsider],
    )
    .await
    .is_err());
    assert_eq!(
        read_epoch(&mut fixture.context, epoch).await.terminal_state,
        EpochTerminalState::Open
    );
}

#[tokio::test]
async fn lock_and_terminal_paths_reject_a_configuration_hash_unbound_from_epoch_state() {
    let mut fixture = Fixture::start().await;
    fixture.initialize().await;
    let mut clock = fixture
        .context
        .banks_client
        .get_sysvar::<Clock>()
        .await
        .unwrap();
    let epoch_id = [43; 32];
    let lock_deadline = clock.unix_timestamp + 10;
    let abort_deadline = clock.unix_timestamp + 20;
    let epoch = fixture
        .create_epoch(epoch_id, lock_deadline, abort_deadline)
        .await;

    let mut account = fixture
        .context
        .banks_client
        .get_account(epoch)
        .await
        .unwrap()
        .unwrap();
    let mut state = EpochStateV1::decode(&account.data).unwrap();
    state.configuration_hash = [44; 32];
    account.data = state.encode().to_vec();
    fixture
        .context
        .set_account(&epoch, &AccountSharedData::from(account));

    let payload = LockPayloadV1 {
        epoch_account: epoch,
        configuration_hash: state.configuration_hash,
        pre_balance_root: [47; 32],
        member_root: [45; 32],
        member_count: 4,
        lock_deadline,
        lock_nonce: [46; 32],
    };
    let digest = payload.digest();
    let caller = fixture.outsider.pubkey();
    assert!(process(
        &mut fixture.context,
        &[
            verifier(&fixture.keypers[0], &digest),
            verifier(&fixture.keypers[1], &digest),
            lock_instruction(caller, fixture.pool, epoch, payload),
        ],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    clock.unix_timestamp = lock_deadline + 1;
    fixture.context.set_sysvar(&clock);
    assert!(process(
        &mut fixture.context,
        &[expire_instruction(caller, fixture.pool, epoch)],
        &[&fixture.outsider],
    )
    .await
    .is_err());
    assert_eq!(
        read_epoch(&mut fixture.context, epoch)
            .await
            .configuration_hash,
        [44; 32]
    );
}

#[tokio::test]
async fn expire_and_abort_are_clock_gated_terminal_transitions() {
    let mut fixture = Fixture::start().await;
    fixture.initialize().await;
    let mut clock = fixture
        .context
        .banks_client
        .get_sysvar::<Clock>()
        .await
        .unwrap();
    let epoch_id = [11; 32];
    let lock_deadline = clock.unix_timestamp + 10;
    let abort_deadline = clock.unix_timestamp + 20;
    let epoch = fixture
        .create_epoch(epoch_id, lock_deadline, abort_deadline)
        .await;
    let payer = fixture.outsider.pubkey();

    assert!(process(
        &mut fixture.context,
        &[expire_instruction(payer, fixture.pool, epoch,)],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    clock.unix_timestamp = lock_deadline;
    fixture.context.set_sysvar(&clock);
    assert!(process(
        &mut fixture.context,
        &[expire_instruction(payer, fixture.pool, epoch)],
        &[&fixture.outsider],
    )
    .await
    .is_err());

    clock.unix_timestamp = lock_deadline + 1;
    fixture.context.set_sysvar(&clock);
    process(
        &mut fixture.context,
        &[expire_instruction(payer, fixture.pool, epoch)],
        &[&fixture.outsider],
    )
    .await
    .unwrap();
    assert_eq!(
        read_epoch(&mut fixture.context, epoch).await.terminal_state,
        EpochTerminalState::Expired
    );
    assert!(process(
        &mut fixture.context,
        &[abort_instruction(payer, fixture.pool, epoch,)],
        &[&fixture.outsider],
    )
    .await
    .is_err());
}

async fn prefund(context: &mut ProgramTestContext, address: Pubkey, lamports: u64) {
    let payer = context.payer.pubkey();
    let instruction = solana_system_interface::instruction::transfer(&payer, &address, lamports);
    process(context, &[instruction], &[]).await.unwrap();
}

async fn process(
    context: &mut ProgramTestContext,
    instructions: &[Instruction],
    extra_signers: &[&Keypair],
) -> Result<(), BanksClientError> {
    let blockhash = context.get_new_latest_blockhash().await.unwrap();
    let mut signers = vec![&context.payer];
    signers.extend_from_slice(extra_signers);
    let transaction = Transaction::new_signed_with_payer(
        instructions,
        Some(&context.payer.pubkey()),
        &signers,
        blockhash,
    );
    context.banks_client.process_transaction(transaction).await
}

async fn read_epoch(context: &mut ProgramTestContext, epoch: Pubkey) -> EpochStateV1 {
    let account = context
        .banks_client
        .get_account(epoch)
        .await
        .unwrap()
        .unwrap();
    EpochStateV1::decode(&account.data).unwrap()
}

fn verifier(keyper: &Keypair, digest: &[u8; 32]) -> Instruction {
    let signature = keyper.sign_message(digest);
    let pubkey = keyper.pubkey().to_bytes();
    new_ed25519_instruction_with_signature(digest, signature.as_ref().try_into().unwrap(), &pubkey)
}

fn cross_instruction_verifier(source: &Instruction, source_index: u16) -> Instruction {
    let mut instruction = source.clone();
    for offset in [4, 8, 14] {
        instruction.data[offset..offset + 2].copy_from_slice(&source_index.to_le_bytes());
    }
    instruction
}

fn system_account() -> Account {
    Account {
        lamports: 1_000_000,
        owner: solana_system_interface::program::ID,
        ..Account::default()
    }
}

fn sbf_program_account() -> Account {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join("../../target/deploy/kageb_program.so");
    let artifact_modified = std::fs::metadata(&path)
        .and_then(|metadata| metadata.modified())
        .unwrap_or_else(|error| {
            panic!(
                "inspect SBF artifact at {} ({error}); run cargo build-sbf before cargo test",
                path.display()
            )
        });
    for input in sbf_freshness_inputs(manifest_dir) {
        let input_modified = std::fs::metadata(&input)
            .and_then(|metadata| metadata.modified())
            .unwrap_or_else(|error| panic!("inspect SBF input {} ({error})", input.display()));
        assert!(
            artifact_modified >= input_modified,
            "SBF artifact {} is older than {}; run cargo build-sbf before cargo test",
            path.display(),
            input.display()
        );
    }
    let data = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "read SBF artifact at {} ({error}); run cargo build-sbf before cargo test",
            path.display()
        )
    });
    Account {
        lamports: solana_program::rent::Rent::default()
            .minimum_balance(data.len())
            .max(1),
        data,
        owner: solana_sdk_ids::bpf_loader::ID,
        executable: true,
        rent_epoch: 0,
    }
}

fn sbf_freshness_inputs(manifest_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut inputs = vec![
        manifest_dir.join("Cargo.toml"),
        manifest_dir.join("../../Cargo.toml"),
        manifest_dir.join("../../Cargo.lock"),
        manifest_dir.join("../../rust-toolchain.toml"),
    ];
    collect_files(&manifest_dir.join("src"), &mut inputs);
    inputs.sort();
    inputs.dedup();
    inputs
}

fn collect_files(directory: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
    let entries = std::fs::read_dir(directory).unwrap_or_else(|error| {
        panic!(
            "read SBF source directory {} ({error})",
            directory.display()
        )
    });
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!("read SBF source entry in {} ({error})", directory.display())
        });
        let kind = entry.file_type().unwrap_or_else(|error| {
            panic!("inspect SBF source {} ({error})", entry.path().display())
        });
        if kind.is_dir() {
            collect_files(&entry.path(), files);
        } else if kind.is_file() {
            files.push(entry.path());
        }
    }
}

fn token_program_account() -> Account {
    Account {
        lamports: 1_000_000,
        owner: solana_program::bpf_loader::ID,
        executable: true,
        ..Account::default()
    }
}

fn mint_account() -> Account {
    mint_account_owned_by(TOKEN_PROGRAM_ID)
}

fn mint_account_owned_by(owner: Pubkey) -> Account {
    let mut data = vec![0_u8; 82];
    data[45] = 1;
    Account {
        lamports: 1_000_000,
        data,
        owner,
        ..Account::default()
    }
}

fn token_account(mint: Pubkey, authority: Pubkey) -> Account {
    let mut data = vec![0_u8; 165];
    data[0..32].copy_from_slice(mint.as_ref());
    data[32..64].copy_from_slice(authority.as_ref());
    data[108] = 1;
    Account {
        lamports: 1_000_000,
        data,
        owner: TOKEN_PROGRAM_ID,
        ..Account::default()
    }
}
