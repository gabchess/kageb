use kageb_program::{instruction::KagebInstruction, ID, TOKEN_PROGRAM_ID};
use solana_program::{pubkey::Pubkey, sysvar};
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta, UiInstruction,
};

use crate::{Residual, Side};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KagebObserverAccounts {
    pub fee_payer: Pubkey,
    pub payer: Pubkey,
    pub pool: Pubkey,
    pub epoch: Pubkey,
    pub vault_authority: Pubkey,
    pub pool_base_vault: Pubkey,
    pub pool_quote_vault: Pubkey,
    pub venue_authority: Pubkey,
    pub venue_base_account: Pubkey,
    pub venue_quote_account: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub base_lot_atoms: u64,
    pub quote_atoms_per_lot: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectMarketAccounts {
    pub fee_payer: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub venue_base_account: Pubkey,
    pub venue_quote_account: Pubkey,
    pub base_lot_atoms: u64,
    pub quote_atoms_per_lot: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverError {
    FailedTransaction,
    InvalidEncoding,
    UnexpectedInstruction,
    UnexpectedAccount,
    UnexpectedTokenEffect,
    InvalidResidual,
}

/// A one-lot order sent directly from a public wallet, for observer comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectOrder {
    wallet: [u8; 32],
    side: Side,
}

impl DirectOrder {
    #[must_use]
    pub const fn one_lot(wallet: [u8; 32], side: Side) -> Self {
        Self { wallet, side }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PublicAction {
    Individual {
        wallet: [u8; 32],
        side: Side,
        lots: u32,
    },
    Aggregate {
        pool: [u8; 32],
        venue: [u8; 32],
        residual: Residual,
        member_root: [u8; 32],
        result_commitment: [u8; 32],
        keyper_approvals: u8,
    },
}

/// The fields a public chain observer can decode from a reference trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicTrace {
    actions: Vec<PublicAction>,
}

impl PublicTrace {
    #[must_use]
    pub fn direct(orders: &[DirectOrder]) -> Self {
        Self {
            actions: orders
                .iter()
                .map(|order| PublicAction::Individual {
                    wallet: order.wallet,
                    side: order.side,
                    lots: 1,
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn pooled(
        pool: [u8; 32],
        venue: [u8; 32],
        residual: Residual,
        member_root: [u8; 32],
        result_root: [u8; 32],
    ) -> Self {
        Self {
            actions: vec![PublicAction::Aggregate {
                pool,
                venue,
                residual,
                member_root,
                result_commitment: result_root,
                keyper_approvals: 0,
            }],
        }
    }

    pub fn from_confirmed_kageb(
        lock: &EncodedConfirmedTransactionWithStatusMeta,
        settlement: &EncodedConfirmedTransactionWithStatusMeta,
        accounts: KagebObserverAccounts,
    ) -> Result<Self, ObserverError> {
        let lock = decode_confirmed(lock)?;
        let settlement = decode_confirmed(settlement)?;
        require_fee_payer(&lock.keys, accounts.fee_payer)?;
        require_fee_payer(&settlement.keys, accounts.fee_payer)?;
        let (lock_instruction, lock_approvals) = exact_kageb_instruction(&lock, 2)?;
        let (settlement_instruction, settlement_approvals) =
            exact_kageb_instruction(&settlement, 3)?;
        if lock_approvals != 2 || settlement_approvals != 2 {
            return Err(ObserverError::UnexpectedInstruction);
        }
        require_exact_keys(
            &lock.keys,
            &[
                accounts.fee_payer,
                accounts.payer,
                accounts.pool,
                accounts.epoch,
                sysvar::instructions::ID,
                sysvar::clock::ID,
                solana_program::ed25519_program::ID,
                ID,
            ],
        )?;
        require_accounts(
            &lock.keys,
            &lock_instruction.accounts,
            &[
                accounts.payer,
                accounts.pool,
                accounts.epoch,
                sysvar::instructions::ID,
                sysvar::clock::ID,
            ],
        )?;
        let lock_payload = match KagebInstruction::decode(&lock_instruction.data)
            .map_err(|_| ObserverError::UnexpectedInstruction)?
        {
            KagebInstruction::Lock(payload)
                if payload.epoch_account == accounts.epoch && payload.member_count >= 4 =>
            {
                payload
            }
            _ => return Err(ObserverError::UnexpectedInstruction),
        };
        require_exact_keys(
            &settlement.keys,
            &[
                accounts.fee_payer,
                accounts.payer,
                accounts.pool,
                accounts.epoch,
                accounts.vault_authority,
                accounts.pool_base_vault,
                accounts.pool_quote_vault,
                accounts.venue_authority,
                accounts.venue_base_account,
                accounts.venue_quote_account,
                accounts.base_mint,
                accounts.quote_mint,
                TOKEN_PROGRAM_ID,
                sysvar::instructions::ID,
                sysvar::clock::ID,
                solana_program::ed25519_program::ID,
                ID,
            ],
        )?;
        require_accounts(
            &settlement.keys,
            &settlement_instruction.accounts,
            &[
                accounts.payer,
                accounts.pool,
                accounts.epoch,
                accounts.vault_authority,
                accounts.pool_base_vault,
                accounts.pool_quote_vault,
                accounts.venue_authority,
                accounts.venue_base_account,
                accounts.venue_quote_account,
                accounts.base_mint,
                accounts.quote_mint,
                TOKEN_PROGRAM_ID,
                sysvar::instructions::ID,
                sysvar::clock::ID,
            ],
        )?;
        let compact = match KagebInstruction::decode(&settlement_instruction.data)
            .map_err(|_| ObserverError::UnexpectedInstruction)?
        {
            KagebInstruction::Settle(payload) => payload,
            _ => return Err(ObserverError::UnexpectedInstruction),
        };
        let residual = match (compact.residual_side, compact.residual_lots) {
            (0, 0) => Residual::None,
            (1, 1..=u32::MAX) => Residual::Buy {
                lots: compact.residual_lots,
            },
            (2, 1..=u32::MAX) => Residual::Sell {
                lots: compact.residual_lots,
            },
            _ => return Err(ObserverError::InvalidResidual),
        };
        validate_settlement_token_effects(
            settlement.inner.as_slice(),
            &settlement.keys,
            2,
            accounts,
            residual,
        )?;
        Ok(Self {
            actions: vec![PublicAction::Aggregate {
                pool: accounts.pool.to_bytes(),
                venue: accounts.venue_authority.to_bytes(),
                residual,
                member_root: lock_payload.member_root,
                result_commitment: compact.result_commitment,
                keyper_approvals: settlement_approvals,
            }],
        })
    }

    pub fn from_confirmed_direct(
        transactions: &[EncodedConfirmedTransactionWithStatusMeta],
        market: DirectMarketAccounts,
    ) -> Result<Self, ObserverError> {
        let mut actions = Vec::with_capacity(transactions.len());
        for transaction in transactions {
            let transaction = decode_confirmed(transaction)?;
            require_fee_payer(&transaction.keys, market.fee_payer)?;
            if !transaction.inner.is_empty() || transaction.instructions.len() != 1 {
                return Err(ObserverError::UnexpectedInstruction);
            }
            let instruction = &transaction.instructions[0];
            if transaction.keys.get(instruction.program_id_index as usize)
                != Some(&TOKEN_PROGRAM_ID)
                || instruction.accounts.len() != 4
            {
                return Err(ObserverError::UnexpectedInstruction);
            }
            let source = account_at(&transaction.keys, instruction.accounts[0])?;
            let mint = account_at(&transaction.keys, instruction.accounts[1])?;
            let destination = account_at(&transaction.keys, instruction.accounts[2])?;
            let wallet = account_at(&transaction.keys, instruction.accounts[3])?;
            if source == destination || wallet == destination {
                return Err(ObserverError::UnexpectedAccount);
            }
            require_exact_keys(
                &transaction.keys,
                &[
                    market.fee_payer,
                    source,
                    mint,
                    destination,
                    wallet,
                    TOKEN_PROGRAM_ID,
                ],
            )?;
            let token =
                spl_token_interface::instruction::TokenInstruction::unpack(&instruction.data)
                    .map_err(|_| ObserverError::UnexpectedTokenEffect)?;
            let (side, amount) = match (mint, destination) {
                (mint, destination)
                    if mint == market.base_mint && destination == market.venue_base_account =>
                {
                    (Side::Sell, market.base_lot_atoms)
                }
                (mint, destination)
                    if mint == market.quote_mint && destination == market.venue_quote_account =>
                {
                    (Side::Buy, market.quote_atoms_per_lot)
                }
                _ => return Err(ObserverError::UnexpectedAccount),
            };
            match token {
                spl_token_interface::instruction::TokenInstruction::TransferChecked {
                    amount: actual,
                    decimals: 0,
                } if actual == amount => {}
                _ => return Err(ObserverError::UnexpectedTokenEffect),
            }
            actions.push(PublicAction::Individual {
                wallet: wallet.to_bytes(),
                side,
                lots: 1,
            });
        }
        Ok(Self { actions })
    }

    #[must_use]
    pub fn visible_participant_wallets(&self) -> Vec<[u8; 32]> {
        self.actions
            .iter()
            .filter_map(|action| match action {
                PublicAction::Individual { wallet, .. } => Some(*wallet),
                PublicAction::Aggregate { .. } => None,
            })
            .collect()
    }

    #[must_use]
    pub fn individual_order_count(&self) -> usize {
        self.actions
            .iter()
            .filter(|action| matches!(action, PublicAction::Individual { .. }))
            .count()
    }

    #[must_use]
    pub fn aggregate_count(&self) -> usize {
        self.actions
            .iter()
            .filter(|action| matches!(action, PublicAction::Aggregate { .. }))
            .count()
    }

    #[must_use]
    pub fn render(&self) -> String {
        self.actions
            .iter()
            .map(|action| match action {
                PublicAction::Individual { wallet, side, lots } => format!(
                    "wallet {}: {} {lots} lots",
                    short_key(wallet),
                    side_name(*side)
                ),
                PublicAction::Aggregate {
                    pool,
                    venue,
                    residual,
                    member_root,
                    result_commitment,
                    keyper_approvals,
                } => format!(
                    "pool aggregate: {} | pool {} | venue {} | member root {} | result commitment {} | keyper approvals {keyper_approvals}",
                    residual_name(*residual),
                    short_key(pool),
                    short_key(venue),
                    short_key(member_root),
                    short_key(result_commitment)
                ),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

struct DecodedConfirmed {
    keys: Vec<Pubkey>,
    instructions: Vec<solana_message::compiled_instruction::CompiledInstruction>,
    inner: Vec<solana_transaction_status_client_types::UiInnerInstructions>,
}

fn decode_confirmed(
    confirmed: &EncodedConfirmedTransactionWithStatusMeta,
) -> Result<DecodedConfirmed, ObserverError> {
    let meta = confirmed
        .transaction
        .meta
        .as_ref()
        .ok_or(ObserverError::FailedTransaction)?;
    if meta.err.is_some() || meta.status.is_err() {
        return Err(ObserverError::FailedTransaction);
    }
    let transaction = confirmed
        .transaction
        .transaction
        .decode()
        .ok_or(ObserverError::InvalidEncoding)?;
    let inner = match &meta.inner_instructions {
        OptionSerializer::Some(inner) => inner.clone(),
        OptionSerializer::None | OptionSerializer::Skip => Vec::new(),
    };
    Ok(DecodedConfirmed {
        keys: transaction.message.static_account_keys().to_vec(),
        instructions: transaction.message.instructions().to_vec(),
        inner,
    })
}

fn exact_kageb_instruction(
    transaction: &DecodedConfirmed,
    discriminator: u8,
) -> Result<
    (
        &solana_message::compiled_instruction::CompiledInstruction,
        u8,
    ),
    ObserverError,
> {
    let mut found = None;
    let mut approvals = 0_u8;
    for (index, instruction) in transaction.instructions.iter().enumerate() {
        let program = transaction
            .keys
            .get(instruction.program_id_index as usize)
            .ok_or(ObserverError::UnexpectedInstruction)?;
        if *program == solana_program::ed25519_program::ID {
            if found.is_some() || !instruction.accounts.is_empty() {
                return Err(ObserverError::UnexpectedInstruction);
            }
            let verifier = solana_program::instruction::Instruction {
                program_id: *program,
                accounts: Vec::new(),
                data: instruction.data.clone(),
            };
            kageb_program::ed25519::parse_strict_ed25519(&verifier)
                .map_err(|_| ObserverError::UnexpectedInstruction)?;
            approvals = approvals
                .checked_add(1)
                .ok_or(ObserverError::UnexpectedInstruction)?;
        } else if *program == ID {
            if found.is_some()
                || instruction.data.first() != Some(&discriminator)
                || index != approvals as usize
            {
                return Err(ObserverError::UnexpectedInstruction);
            }
            found = Some(instruction);
        } else {
            return Err(ObserverError::UnexpectedInstruction);
        }
    }
    Ok((
        found.ok_or(ObserverError::UnexpectedInstruction)?,
        approvals,
    ))
}

fn require_accounts(
    keys: &[Pubkey],
    indexes: &[u8],
    expected: &[Pubkey],
) -> Result<(), ObserverError> {
    if indexes.len() != expected.len()
        || indexes
            .iter()
            .zip(expected)
            .any(|(index, expected)| keys.get(*index as usize) != Some(expected))
    {
        return Err(ObserverError::UnexpectedAccount);
    }
    Ok(())
}

fn require_exact_keys(keys: &[Pubkey], expected: &[Pubkey]) -> Result<(), ObserverError> {
    let unique_expected = expected
        .iter()
        .enumerate()
        .filter(|(index, key)| !expected[..*index].contains(key))
        .count();
    if keys.len() != unique_expected
        || keys.iter().any(|key| !expected.contains(key))
        || expected.iter().any(|key| !keys.contains(key))
    {
        return Err(ObserverError::UnexpectedAccount);
    }
    Ok(())
}

fn require_fee_payer(keys: &[Pubkey], expected: Pubkey) -> Result<(), ObserverError> {
    if keys.first() != Some(&expected) {
        return Err(ObserverError::UnexpectedAccount);
    }
    Ok(())
}

fn account_at(keys: &[Pubkey], index: u8) -> Result<Pubkey, ObserverError> {
    keys.get(index as usize)
        .copied()
        .ok_or(ObserverError::UnexpectedAccount)
}

fn validate_settlement_token_effects(
    inner: &[solana_transaction_status_client_types::UiInnerInstructions],
    keys: &[Pubkey],
    settlement_index: u8,
    accounts: KagebObserverAccounts,
    residual: Residual,
) -> Result<(), ObserverError> {
    let lots = match residual {
        Residual::None => 0,
        Residual::Buy { lots } | Residual::Sell { lots } => u64::from(lots),
    };
    let base_amount = accounts
        .base_lot_atoms
        .checked_mul(lots)
        .ok_or(ObserverError::UnexpectedTokenEffect)?;
    let quote_amount = accounts
        .quote_atoms_per_lot
        .checked_mul(lots)
        .ok_or(ObserverError::UnexpectedTokenEffect)?;
    let expected: Vec<([Pubkey; 4], u64)> = match residual {
        Residual::None => Vec::new(),
        Residual::Buy { .. } => vec![
            (
                [
                    accounts.pool_quote_vault,
                    accounts.quote_mint,
                    accounts.venue_quote_account,
                    accounts.vault_authority,
                ],
                quote_amount,
            ),
            (
                [
                    accounts.venue_base_account,
                    accounts.base_mint,
                    accounts.pool_base_vault,
                    accounts.venue_authority,
                ],
                base_amount,
            ),
        ],
        Residual::Sell { .. } => vec![
            (
                [
                    accounts.pool_base_vault,
                    accounts.base_mint,
                    accounts.venue_base_account,
                    accounts.vault_authority,
                ],
                base_amount,
            ),
            (
                [
                    accounts.venue_quote_account,
                    accounts.quote_mint,
                    accounts.pool_quote_vault,
                    accounts.venue_authority,
                ],
                quote_amount,
            ),
        ],
    };
    let instructions = match inner {
        [] if expected.is_empty() => return Ok(()),
        [group] if group.index == settlement_index => &group.instructions,
        _ => return Err(ObserverError::UnexpectedTokenEffect),
    };
    if instructions.len() != expected.len() {
        return Err(ObserverError::UnexpectedTokenEffect);
    }
    for (instruction, (expected_accounts, expected_amount)) in instructions.iter().zip(expected) {
        let UiInstruction::Compiled(instruction) = instruction else {
            return Err(ObserverError::UnexpectedTokenEffect);
        };
        if keys.get(instruction.program_id_index as usize) != Some(&TOKEN_PROGRAM_ID) {
            return Err(ObserverError::UnexpectedTokenEffect);
        }
        require_accounts(keys, &instruction.accounts, &expected_accounts)?;
        let data = bs58::decode(&instruction.data)
            .into_vec()
            .map_err(|_| ObserverError::UnexpectedTokenEffect)?;
        match spl_token_interface::instruction::TokenInstruction::unpack(&data)
            .map_err(|_| ObserverError::UnexpectedTokenEffect)?
        {
            spl_token_interface::instruction::TokenInstruction::TransferChecked {
                amount,
                decimals: 0,
            } if amount == expected_amount => {}
            _ => return Err(ObserverError::UnexpectedTokenEffect),
        }
    }
    Ok(())
}

fn residual_name(residual: Residual) -> String {
    match residual {
        Residual::None => "NO VENUE LEG".to_owned(),
        Residual::Buy { lots } => format!("BUY {lots} lots"),
        Residual::Sell { lots } => format!("SELL {lots} lots"),
    }
}

const fn side_name(side: Side) -> &'static str {
    match side {
        Side::Buy => "BUY",
        Side::Sell => "SELL",
    }
}

fn short_key(key: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", key[0], key[1], key[2], key[3])
}
