use crate::{
    ed25519::count_preceding_keypers,
    epoch_address,
    error::KagebError,
    instruction::{CreateEpochArgs, InitializePoolArgs, KagebInstruction},
    pool_address,
    state::{EpochStateV1, EpochTerminalState, PoolStateV1, STATE_LEN},
    vault_authority_address,
    wire::{EpochConfigurationV1, SettlementPayloadV1},
    ID, TOKEN_PROGRAM_ID,
};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
};
use solana_sysvar::{Sysvar, SysvarSerialize};

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if *program_id != ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    match KagebInstruction::decode(data)? {
        KagebInstruction::InitializePool(args) => initialize_pool(program_id, accounts, args),
        KagebInstruction::CreateEpoch(args) => create_epoch(program_id, accounts, args),
        KagebInstruction::Lock(payload) => lock(program_id, accounts, payload),
        KagebInstruction::Settle(payload) => settle_compact(program_id, accounts, payload),
        KagebInstruction::Expire => expire_or_abort(program_id, accounts, false),
        KagebInstruction::Abort => expire_or_abort(program_id, accounts, true),
    }
}

fn settle_compact(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    compact: crate::instruction::CompactSettlementPayload,
) -> ProgramResult {
    if accounts.len() != 14 {
        return Err(KagebError::InvalidAccounts.into());
    }
    let pool_state = PoolStateV1::decode(&accounts[1].try_borrow_data()?)?;
    let epoch_state = EpochStateV1::decode(&accounts[2].try_borrow_data()?)?;
    settle(
        program_id,
        accounts,
        SettlementPayloadV1 {
            epoch_account: *accounts[2].key,
            lock_digest: epoch_state.lock_digest,
            result_commitment: compact.result_commitment,
            residual_side: compact.residual_side,
            residual_lots: compact.residual_lots,
            base_lot_atoms: epoch_state.base_lot_atoms,
            quote_atoms_per_lot: epoch_state.quote_atoms_per_lot,
            base_mint: pool_state.base_mint,
            quote_mint: pool_state.quote_mint,
            pool_base_vault: pool_state.pool_base_vault,
            pool_quote_vault: pool_state.pool_quote_vault,
            venue_base_account: pool_state.venue_base_account,
            venue_quote_account: pool_state.venue_quote_account,
            venue_authority: pool_state.venue_authority,
            settlement_nonce: compact.settlement_nonce,
        },
    )
}

fn initialize_pool(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: InitializePoolArgs,
) -> ProgramResult {
    if accounts.len() != 13 {
        return Err(KagebError::InvalidAccounts.into());
    }
    let payer = &accounts[0];
    let operator = &accounts[1];
    let pool = &accounts[2];
    let vault_authority = &accounts[3];
    let base_mint = &accounts[4];
    let quote_mint = &accounts[5];
    let pool_base_vault = &accounts[6];
    let pool_quote_vault = &accounts[7];
    let venue_authority = &accounts[8];
    let venue_base_account = &accounts[9];
    let venue_quote_account = &accounts[10];
    let system_program = &accounts[11];
    let token_program = &accounts[12];

    require_account_flags(payer, true, true, false)?;
    require_account_flags(operator, true, false, false)?;
    require_account_flags(pool, false, true, false)?;
    for account in [
        vault_authority,
        base_mint,
        quote_mint,
        pool_base_vault,
        pool_quote_vault,
        venue_authority,
        venue_base_account,
        venue_quote_account,
    ] {
        require_account_flags(account, false, false, false)?;
    }
    require_account_flags(system_program, false, false, true)?;
    require_account_flags(token_program, false, false, true)?;
    require_distinct(accounts)?;
    if *system_program.key != solana_system_interface::program::ID
        || !system_program.executable
        || *token_program.key != TOKEN_PROGRAM_ID
        || !token_program.executable
    {
        return Err(KagebError::InvalidAccounts.into());
    }
    if args.lock_threshold != 2
        || args.settlement_threshold != 2
        || args.base_lot_atoms == 0
        || args.keypers.iter().any(|key| *key == Pubkey::default())
        || !three_distinct(&args.keypers)
        || base_mint.key == quote_mint.key
    {
        return Err(KagebError::InvalidConfiguration.into());
    }

    let (expected_pool, pool_bump) = pool_address(operator.key, base_mint.key, quote_mint.key);
    let (expected_vault_authority, vault_bump) = vault_authority_address(pool.key);
    if *pool.key != expected_pool || *vault_authority.key != expected_vault_authority {
        return Err(KagebError::InvalidPda.into());
    }
    validate_mint(base_mint)?;
    validate_mint(quote_mint)?;
    validate_token_account(pool_base_vault, base_mint.key, vault_authority.key)?;
    validate_token_account(pool_quote_vault, quote_mint.key, vault_authority.key)?;
    validate_token_account(venue_base_account, base_mint.key, venue_authority.key)?;
    validate_token_account(venue_quote_account, quote_mint.key, venue_authority.key)?;

    let pool_bump_seed = [pool_bump];
    initialize_pda_account(
        payer,
        pool,
        system_program,
        program_id,
        &[&[
            b"pool",
            operator.key.as_ref(),
            base_mint.key.as_ref(),
            quote_mint.key.as_ref(),
            &pool_bump_seed,
        ]],
    )?;

    let state = PoolStateV1 {
        pool_bump,
        vault_bump,
        lock_threshold: args.lock_threshold,
        settlement_threshold: args.settlement_threshold,
        operator: *operator.key,
        base_mint: *base_mint.key,
        quote_mint: *quote_mint.key,
        pool_base_vault: *pool_base_vault.key,
        pool_quote_vault: *pool_quote_vault.key,
        venue_authority: *venue_authority.key,
        venue_base_account: *venue_base_account.key,
        venue_quote_account: *venue_quote_account.key,
        keypers: args.keypers,
        base_lot_atoms: args.base_lot_atoms,
    };
    pool.try_borrow_mut_data()?.copy_from_slice(&state.encode());
    Ok(())
}

fn create_epoch(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: CreateEpochArgs,
) -> ProgramResult {
    if accounts.len() != 6 {
        return Err(KagebError::InvalidAccounts.into());
    }
    let payer = &accounts[0];
    let operator = &accounts[1];
    let pool = &accounts[2];
    let epoch = &accounts[3];
    let system_program = &accounts[4];
    let clock_account = &accounts[5];
    require_account_flags(payer, true, true, false)?;
    require_account_flags(operator, true, false, false)?;
    require_account_flags(pool, false, false, false)?;
    require_account_flags(epoch, false, true, false)?;
    require_account_flags(system_program, false, false, true)?;
    require_account_flags(clock_account, false, false, false)?;
    require_distinct(accounts)?;
    require_program_account(pool, program_id)?;
    if *system_program.key != solana_system_interface::program::ID
        || !system_program.executable
        || *clock_account.key != solana_sdk_ids::sysvar::clock::ID
    {
        return Err(KagebError::InvalidAccounts.into());
    }
    let pool_state = PoolStateV1::decode(&pool.try_borrow_data()?)?;
    validate_pool_state(pool, &pool_state)?;
    if pool_state.operator != *operator.key {
        return Err(KagebError::InvalidConfiguration.into());
    }
    let clock = solana_program::clock::Clock::from_account_info(clock_account)?;
    if args.minimum_count < 4
        || args.quote_atoms_per_lot == 0
        || args.lock_deadline <= clock.unix_timestamp
        || args.abort_deadline <= args.lock_deadline
    {
        return Err(KagebError::InvalidConfiguration.into());
    }
    let (expected_epoch, epoch_bump) = epoch_address(pool.key, &args.epoch_id);
    if *epoch.key != expected_epoch {
        return Err(KagebError::InvalidPda.into());
    }

    let epoch_bump_seed = [epoch_bump];
    initialize_pda_account(
        payer,
        epoch,
        system_program,
        program_id,
        &[&[
            b"epoch",
            pool.key.as_ref(),
            &args.epoch_id,
            &epoch_bump_seed,
        ]],
    )?;

    let configuration_hash = EpochConfigurationV1 {
        pool: *pool.key,
        epoch_id: args.epoch_id,
        base_mint: pool_state.base_mint,
        quote_mint: pool_state.quote_mint,
        base_lot_atoms: pool_state.base_lot_atoms,
        quote_atoms_per_lot: args.quote_atoms_per_lot,
        minimum_count: args.minimum_count,
        lock_threshold: pool_state.lock_threshold,
        settlement_threshold: pool_state.settlement_threshold,
        keypers: pool_state.keypers,
        lock_deadline: args.lock_deadline,
        abort_deadline: args.abort_deadline,
    }
    .digest();
    let state = EpochStateV1 {
        epoch_bump,
        terminal_state: EpochTerminalState::Open,
        residual_side: 0,
        pool: *pool.key,
        epoch_id: args.epoch_id,
        configuration_hash,
        pre_balance_root: [0; 32],
        member_root: [0; 32],
        lock_digest: [0; 32],
        result_commitment: [0; 32],
        settlement_digest: [0; 32],
        lock_nonce: [0; 32],
        settlement_nonce: [0; 32],
        member_count: 0,
        minimum_count: args.minimum_count,
        residual_lots: 0,
        base_lot_atoms: pool_state.base_lot_atoms,
        quote_atoms_per_lot: args.quote_atoms_per_lot,
        lock_deadline: args.lock_deadline,
        abort_deadline: args.abort_deadline,
    };
    epoch
        .try_borrow_mut_data()?
        .copy_from_slice(&state.encode());
    Ok(())
}

fn lock(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: crate::wire::LockPayloadV1,
) -> ProgramResult {
    if accounts.len() != 5 {
        return Err(KagebError::InvalidAccounts.into());
    }
    let payer = &accounts[0];
    let pool = &accounts[1];
    let epoch = &accounts[2];
    let instructions_account = &accounts[3];
    let clock_account = &accounts[4];
    require_account_flags(payer, true, false, false)?;
    require_account_flags(pool, false, false, false)?;
    require_account_flags(epoch, false, true, false)?;
    require_account_flags(instructions_account, false, false, false)?;
    require_account_flags(clock_account, false, false, false)?;
    require_distinct(accounts)?;
    require_program_account(pool, program_id)?;
    require_program_account(epoch, program_id)?;
    if *instructions_account.key != solana_sdk_ids::sysvar::instructions::ID
        || *clock_account.key != solana_sdk_ids::sysvar::clock::ID
    {
        return Err(KagebError::InvalidAccounts.into());
    }

    let pool_state = PoolStateV1::decode(&pool.try_borrow_data()?)?;
    validate_pool_state(pool, &pool_state)?;
    let mut epoch_state = EpochStateV1::decode(&epoch.try_borrow_data()?)?;
    validate_epoch_state(epoch, &epoch_state, pool, &pool_state)?;
    if epoch_state.terminal_state != EpochTerminalState::Open {
        return Err(KagebError::InvalidState.into());
    }
    let clock = solana_program::clock::Clock::from_account_info(clock_account)?;
    if clock.unix_timestamp >= epoch_state.lock_deadline {
        return Err(KagebError::DeadlinePassed.into());
    }
    if payload.epoch_account != *epoch.key
        || payload.configuration_hash != epoch_state.configuration_hash
        || payload.lock_deadline != epoch_state.lock_deadline
        || payload.lock_nonce == [0; 32]
        || payload.pre_balance_root == [0; 32]
        || payload.member_root == [0; 32]
    {
        return Err(KagebError::InvalidLock.into());
    }
    if payload.member_count < epoch_state.minimum_count {
        return Err(KagebError::CrowdBelowMinimum.into());
    }
    let digest = payload.digest();
    if count_preceding_keypers(instructions_account, &pool_state.keypers, &digest)?
        < pool_state.lock_threshold
    {
        return Err(KagebError::InsufficientQuorum.into());
    }

    epoch_state.terminal_state = EpochTerminalState::Locked;
    epoch_state.pre_balance_root = payload.pre_balance_root;
    epoch_state.member_root = payload.member_root;
    epoch_state.member_count = payload.member_count;
    epoch_state.lock_digest = digest;
    epoch_state.lock_nonce = payload.lock_nonce;
    epoch
        .try_borrow_mut_data()?
        .copy_from_slice(&epoch_state.encode());
    Ok(())
}

fn settle(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: SettlementPayloadV1,
) -> ProgramResult {
    if accounts.len() != 14 {
        return Err(KagebError::InvalidAccounts.into());
    }
    let payer = &accounts[0];
    let pool = &accounts[1];
    let epoch = &accounts[2];
    let vault_authority = &accounts[3];
    let pool_base_vault = &accounts[4];
    let pool_quote_vault = &accounts[5];
    let venue_authority = &accounts[6];
    let venue_base_account = &accounts[7];
    let venue_quote_account = &accounts[8];
    let base_mint = &accounts[9];
    let quote_mint = &accounts[10];
    let token_program = &accounts[11];
    let instructions_account = &accounts[12];
    let clock_account = &accounts[13];

    require_account_flags(payer, true, false, false)?;
    require_account_flags(pool, false, false, false)?;
    require_account_flags(epoch, false, true, false)?;
    require_account_flags(vault_authority, false, false, false)?;
    for account in [
        pool_base_vault,
        pool_quote_vault,
        venue_base_account,
        venue_quote_account,
    ] {
        require_account_flags(account, false, true, false)?;
    }
    require_account_flags(venue_authority, true, false, false)?;
    require_account_flags(base_mint, false, false, false)?;
    require_account_flags(quote_mint, false, false, false)?;
    require_account_flags(token_program, false, false, true)?;
    require_account_flags(instructions_account, false, false, false)?;
    require_account_flags(clock_account, false, false, false)?;
    require_distinct(accounts)?;
    require_program_account(pool, program_id)?;
    require_program_account(epoch, program_id)?;
    if *token_program.key != TOKEN_PROGRAM_ID
        || !token_program.executable
        || *instructions_account.key != solana_sdk_ids::sysvar::instructions::ID
        || *clock_account.key != solana_sdk_ids::sysvar::clock::ID
    {
        return Err(KagebError::InvalidAccounts.into());
    }
    let _clock = solana_program::clock::Clock::from_account_info(clock_account)?;

    let pool_state = PoolStateV1::decode(&pool.try_borrow_data()?)?;
    validate_pool_state(pool, &pool_state)?;
    let mut epoch_state = EpochStateV1::decode(&epoch.try_borrow_data()?)?;
    validate_epoch_state(epoch, &epoch_state, pool, &pool_state)?;
    if epoch_state.terminal_state != EpochTerminalState::Locked {
        return Err(KagebError::InvalidState.into());
    }
    let (expected_vault_authority, canonical_vault_bump) = vault_authority_address(pool.key);
    if expected_vault_authority != *vault_authority.key
        || canonical_vault_bump != pool_state.vault_bump
    {
        return Err(KagebError::InvalidPda.into());
    }
    if *base_mint.key != pool_state.base_mint
        || *quote_mint.key != pool_state.quote_mint
        || *pool_base_vault.key != pool_state.pool_base_vault
        || *pool_quote_vault.key != pool_state.pool_quote_vault
        || *venue_authority.key != pool_state.venue_authority
        || *venue_base_account.key != pool_state.venue_base_account
        || *venue_quote_account.key != pool_state.venue_quote_account
    {
        return Err(KagebError::InvalidAccounts.into());
    }
    validate_mint(base_mint)?;
    validate_mint(quote_mint)?;
    validate_token_account(pool_base_vault, base_mint.key, vault_authority.key)?;
    validate_token_account(pool_quote_vault, quote_mint.key, vault_authority.key)?;
    validate_token_account(venue_base_account, base_mint.key, venue_authority.key)?;
    validate_token_account(venue_quote_account, quote_mint.key, venue_authority.key)?;

    if payload.epoch_account != *epoch.key
        || payload.lock_digest != epoch_state.lock_digest
        || payload.result_commitment == [0; 32]
        || payload.base_lot_atoms != epoch_state.base_lot_atoms
        || payload.quote_atoms_per_lot != epoch_state.quote_atoms_per_lot
        || payload.base_mint != pool_state.base_mint
        || payload.quote_mint != pool_state.quote_mint
        || payload.pool_base_vault != pool_state.pool_base_vault
        || payload.pool_quote_vault != pool_state.pool_quote_vault
        || payload.venue_authority != pool_state.venue_authority
        || payload.venue_base_account != pool_state.venue_base_account
        || payload.venue_quote_account != pool_state.venue_quote_account
        || payload.settlement_nonce == [0; 32]
        || payload.settlement_nonce == epoch_state.lock_nonce
        || !valid_residual(payload.residual_side, payload.residual_lots)
    {
        return Err(KagebError::InvalidSettlement.into());
    }
    let digest = payload.digest();
    if count_preceding_keypers(instructions_account, &pool_state.keypers, &digest)?
        < pool_state.settlement_threshold
    {
        return Err(KagebError::InsufficientQuorum.into());
    }

    let lots = u64::from(payload.residual_lots);
    let base_amount = payload
        .base_lot_atoms
        .checked_mul(lots)
        .ok_or(KagebError::ArithmeticOverflow)?;
    let quote_amount = payload
        .quote_atoms_per_lot
        .checked_mul(lots)
        .ok_or(KagebError::ArithmeticOverflow)?;
    let vault_bump = [pool_state.vault_bump];
    let vault_seeds: &[&[u8]] = &[b"vault", pool.key.as_ref(), &vault_bump];

    match payload.residual_side {
        0 => {}
        1 => {
            transfer_checked(
                pool_quote_vault,
                quote_mint,
                venue_quote_account,
                vault_authority,
                token_program,
                quote_amount,
                Some(vault_seeds),
            )?;
            transfer_checked(
                venue_base_account,
                base_mint,
                pool_base_vault,
                venue_authority,
                token_program,
                base_amount,
                None,
            )?;
        }
        2 => {
            transfer_checked(
                pool_base_vault,
                base_mint,
                venue_base_account,
                vault_authority,
                token_program,
                base_amount,
                Some(vault_seeds),
            )?;
            transfer_checked(
                venue_quote_account,
                quote_mint,
                pool_quote_vault,
                venue_authority,
                token_program,
                quote_amount,
                None,
            )?;
        }
        _ => return Err(KagebError::InvalidSettlement.into()),
    }

    epoch_state.terminal_state = EpochTerminalState::Settled;
    epoch_state.residual_side = payload.residual_side;
    epoch_state.residual_lots = payload.residual_lots;
    epoch_state.result_commitment = payload.result_commitment;
    epoch_state.settlement_digest = digest;
    epoch_state.settlement_nonce = payload.settlement_nonce;
    epoch
        .try_borrow_mut_data()?
        .copy_from_slice(&epoch_state.encode());
    Ok(())
}

fn valid_residual(side: u8, lots: u32) -> bool {
    matches!((side, lots), (0, 0) | (1 | 2, 1..=u32::MAX))
}

#[allow(clippy::too_many_arguments)]
fn transfer_checked<'a>(
    source: &AccountInfo<'a>,
    mint: &AccountInfo<'a>,
    destination: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    amount: u64,
    signer_seeds: Option<&[&[u8]]>,
) -> ProgramResult {
    let instruction = spl_token_interface::instruction::transfer_checked(
        token_program.key,
        source.key,
        mint.key,
        destination.key,
        authority.key,
        &[],
        amount,
        0,
    )?;
    let account_infos = [
        source.clone(),
        mint.clone(),
        destination.clone(),
        authority.clone(),
        token_program.clone(),
    ];
    match signer_seeds {
        Some(seeds) => invoke_signed(&instruction, &account_infos, &[seeds]),
        None => invoke(&instruction, &account_infos),
    }
}

fn expire_or_abort(program_id: &Pubkey, accounts: &[AccountInfo], abort: bool) -> ProgramResult {
    if accounts.len() != 4 {
        return Err(KagebError::InvalidAccounts.into());
    }
    let caller = &accounts[0];
    let pool = &accounts[1];
    let epoch = &accounts[2];
    let clock_account = &accounts[3];
    require_account_flags(caller, true, false, false)?;
    require_account_flags(pool, false, false, false)?;
    require_account_flags(epoch, false, true, false)?;
    require_account_flags(clock_account, false, false, false)?;
    require_distinct(accounts)?;
    require_program_account(pool, program_id)?;
    require_program_account(epoch, program_id)?;
    if *clock_account.key != solana_sdk_ids::sysvar::clock::ID {
        return Err(KagebError::InvalidAccounts.into());
    }
    let pool_state = PoolStateV1::decode(&pool.try_borrow_data()?)?;
    validate_pool_state(pool, &pool_state)?;
    let mut state = EpochStateV1::decode(&epoch.try_borrow_data()?)?;
    validate_epoch_state(epoch, &state, pool, &pool_state)?;
    let clock = solana_program::clock::Clock::from_account_info(clock_account)?;
    let (required_state, deadline, terminal_state) = if abort {
        (
            EpochTerminalState::Locked,
            state.abort_deadline,
            EpochTerminalState::Aborted,
        )
    } else {
        (
            EpochTerminalState::Open,
            state.lock_deadline,
            EpochTerminalState::Expired,
        )
    };
    if state.terminal_state != required_state {
        return Err(KagebError::InvalidState.into());
    }
    if clock.unix_timestamp <= deadline {
        return Err(KagebError::DeadlineNotReached.into());
    }
    state.terminal_state = terminal_state;
    epoch
        .try_borrow_mut_data()?
        .copy_from_slice(&state.encode());
    Ok(())
}

fn require_account_flags(
    account: &AccountInfo,
    is_signer: bool,
    is_writable: bool,
    is_executable: bool,
) -> ProgramResult {
    if account.is_signer != is_signer {
        return if is_signer {
            Err(KagebError::MissingSignature.into())
        } else {
            Err(KagebError::InvalidAccounts.into())
        };
    }
    if account.is_writable != is_writable || account.executable != is_executable {
        return Err(KagebError::InvalidAccounts.into());
    }
    Ok(())
}

fn require_program_account(account: &AccountInfo, program_id: &Pubkey) -> ProgramResult {
    if account.owner != program_id || account.data_len() != STATE_LEN || account.executable {
        return Err(KagebError::InvalidOwner.into());
    }
    Ok(())
}

fn initialize_pda_account<'a>(
    payer: &AccountInfo<'a>,
    pda: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    program_id: &Pubkey,
    signer_seeds: &[&[&[u8]]],
) -> ProgramResult {
    if pda.owner != &solana_system_interface::program::ID || pda.data_len() != 0 || pda.executable {
        return Err(KagebError::InvalidState.into());
    }

    let space = u64::try_from(STATE_LEN).map_err(|_| KagebError::ArithmeticOverflow)?;
    let required_lamports = Rent::get()?.minimum_balance(STATE_LEN);
    let existing_lamports = pda.lamports();
    if existing_lamports < required_lamports {
        let deficit = required_lamports
            .checked_sub(existing_lamports)
            .ok_or(KagebError::ArithmeticOverflow)?;
        let transfer = solana_system_interface::instruction::transfer(payer.key, pda.key, deficit);
        invoke(
            &transfer,
            &[payer.clone(), pda.clone(), system_program.clone()],
        )?;
    }

    let allocate = solana_system_interface::instruction::allocate(pda.key, space);
    invoke_signed(
        &allocate,
        &[pda.clone(), system_program.clone()],
        signer_seeds,
    )?;
    let assign = solana_system_interface::instruction::assign(pda.key, program_id);
    invoke_signed(
        &assign,
        &[pda.clone(), system_program.clone()],
        signer_seeds,
    )?;

    if pda.owner != program_id || pda.data_len() != STATE_LEN {
        return Err(KagebError::InvalidState.into());
    }
    Ok(())
}

fn validate_pool_state(account: &AccountInfo, state: &PoolStateV1) -> ProgramResult {
    let (expected_pool, canonical_pool_bump) =
        pool_address(&state.operator, &state.base_mint, &state.quote_mint);
    let (_, canonical_vault_bump) = vault_authority_address(account.key);
    if expected_pool != *account.key
        || state.pool_bump != canonical_pool_bump
        || state.vault_bump != canonical_vault_bump
    {
        return Err(KagebError::InvalidPda.into());
    }
    if state.lock_threshold != 2
        || state.settlement_threshold != 2
        || state.base_lot_atoms == 0
        || state.base_mint == state.quote_mint
        || state.keypers.iter().any(|key| *key == Pubkey::default())
        || !three_distinct(&state.keypers)
    {
        return Err(KagebError::InvalidState.into());
    }
    Ok(())
}

fn validate_epoch_state(
    account: &AccountInfo,
    state: &EpochStateV1,
    pool: &AccountInfo,
    pool_state: &PoolStateV1,
) -> ProgramResult {
    if state.pool != *pool.key {
        return Err(KagebError::InvalidState.into());
    }
    let (expected_epoch, canonical_bump) = epoch_address(pool.key, &state.epoch_id);
    if expected_epoch != *account.key || state.epoch_bump != canonical_bump {
        return Err(KagebError::InvalidPda.into());
    }
    if state.minimum_count < 4
        || state.base_lot_atoms != pool_state.base_lot_atoms
        || state.quote_atoms_per_lot == 0
        || state.abort_deadline <= state.lock_deadline
    {
        return Err(KagebError::InvalidState.into());
    }
    let expected_configuration = EpochConfigurationV1 {
        pool: *pool.key,
        epoch_id: state.epoch_id,
        base_mint: pool_state.base_mint,
        quote_mint: pool_state.quote_mint,
        base_lot_atoms: pool_state.base_lot_atoms,
        quote_atoms_per_lot: state.quote_atoms_per_lot,
        minimum_count: state.minimum_count,
        lock_threshold: pool_state.lock_threshold,
        settlement_threshold: pool_state.settlement_threshold,
        keypers: pool_state.keypers,
        lock_deadline: state.lock_deadline,
        abort_deadline: state.abort_deadline,
    }
    .digest();
    if state.configuration_hash != expected_configuration {
        return Err(KagebError::InvalidState.into());
    }
    Ok(())
}

fn require_distinct(accounts: &[AccountInfo]) -> ProgramResult {
    for (index, account) in accounts.iter().enumerate() {
        if accounts[..index]
            .iter()
            .any(|previous| previous.key == account.key)
        {
            return Err(KagebError::InvalidAccounts.into());
        }
    }
    Ok(())
}

fn three_distinct(keys: &[Pubkey; 3]) -> bool {
    keys[0] != keys[1] && keys[0] != keys[2] && keys[1] != keys[2]
}

fn validate_mint(account: &AccountInfo) -> ProgramResult {
    let data = account.try_borrow_data()?;
    if *account.owner != TOKEN_PROGRAM_ID
        || account.executable
        || data.len() != 82
        || data[44] != 0
        || data[45] != 1
    {
        return Err(KagebError::InvalidTokenAccount.into());
    }
    Ok(())
}

fn validate_token_account(
    account: &AccountInfo,
    expected_mint: &Pubkey,
    expected_authority: &Pubkey,
) -> ProgramResult {
    let data = account.try_borrow_data()?;
    if *account.owner != TOKEN_PROGRAM_ID
        || account.executable
        || data.len() != 165
        || data[0..32] != expected_mint.to_bytes()
        || data[32..64] != expected_authority.to_bytes()
        || data[108] != 1
    {
        return Err(KagebError::InvalidTokenAccount.into());
    }
    Ok(())
}
