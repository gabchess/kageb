use crate::{
    error::KagebError,
    wire::{LockPayloadV1, SettlementPayloadV1},
    ID, TOKEN_PROGRAM_ID,
};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitializePoolArgs {
    pub lock_threshold: u8,
    pub settlement_threshold: u8,
    pub base_lot_atoms: u64,
    pub keypers: [Pubkey; 3],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateEpochArgs {
    pub epoch_id: [u8; 32],
    pub minimum_count: u32,
    pub quote_atoms_per_lot: u64,
    pub lock_deadline: i64,
    pub abort_deadline: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KagebInstruction {
    InitializePool(InitializePoolArgs),
    CreateEpoch(CreateEpochArgs),
    Lock(LockPayloadV1),
    Settle(CompactSettlementPayload),
    Expire,
    Abort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactSettlementPayload {
    pub result_commitment: [u8; 32],
    pub residual_side: u8,
    pub residual_lots: u32,
    pub settlement_nonce: [u8; 32],
}

impl From<SettlementPayloadV1> for CompactSettlementPayload {
    fn from(payload: SettlementPayloadV1) -> Self {
        Self {
            result_commitment: payload.result_commitment,
            residual_side: payload.residual_side,
            residual_lots: payload.residual_lots,
            settlement_nonce: payload.settlement_nonce,
        }
    }
}

impl KagebInstruction {
    pub fn encode(self) -> Vec<u8> {
        match self {
            Self::InitializePool(args) => {
                let mut out = vec![0_u8; 107];
                out[0] = 0;
                out[1] = args.lock_threshold;
                out[2] = args.settlement_threshold;
                out[3..11].copy_from_slice(&args.base_lot_atoms.to_le_bytes());
                let mut offset = 11;
                for keyper in args.keypers {
                    out[offset..offset + 32].copy_from_slice(keyper.as_ref());
                    offset += 32;
                }
                out
            }
            Self::CreateEpoch(args) => {
                let mut out = vec![0_u8; 61];
                out[0] = 1;
                out[1..33].copy_from_slice(&args.epoch_id);
                out[33..37].copy_from_slice(&args.minimum_count.to_le_bytes());
                out[37..45].copy_from_slice(&args.quote_atoms_per_lot.to_le_bytes());
                out[45..53].copy_from_slice(&args.lock_deadline.to_le_bytes());
                out[53..61].copy_from_slice(&args.abort_deadline.to_le_bytes());
                out
            }
            Self::Lock(payload) => {
                let mut out = Vec::with_capacity(1 + LockPayloadV1::ENCODED_LEN);
                out.push(2);
                out.extend_from_slice(&payload.encode());
                out
            }
            Self::Settle(payload) => encode_settlement(payload),
            Self::Expire => vec![4],
            Self::Abort => vec![5],
        }
    }

    pub fn decode(data: &[u8]) -> Result<Self, ProgramError> {
        let invalid = || ProgramError::from(KagebError::InvalidInstruction);
        match data.first().copied() {
            Some(0) if data.len() == 107 => {
                let mut offset = 11;
                let mut keypers = [Pubkey::default(); 3];
                for keyper in &mut keypers {
                    *keyper = Pubkey::new_from_array(
                        data[offset..offset + 32]
                            .try_into()
                            .map_err(|_| invalid())?,
                    );
                    offset += 32;
                }
                Ok(Self::InitializePool(InitializePoolArgs {
                    lock_threshold: data[1],
                    settlement_threshold: data[2],
                    base_lot_atoms: u64::from_le_bytes(
                        data[3..11].try_into().map_err(|_| invalid())?,
                    ),
                    keypers,
                }))
            }
            Some(1) if data.len() == 61 => Ok(Self::CreateEpoch(CreateEpochArgs {
                epoch_id: data[1..33].try_into().map_err(|_| invalid())?,
                minimum_count: u32::from_le_bytes(data[33..37].try_into().map_err(|_| invalid())?),
                quote_atoms_per_lot: u64::from_le_bytes(
                    data[37..45].try_into().map_err(|_| invalid())?,
                ),
                lock_deadline: i64::from_le_bytes(data[45..53].try_into().map_err(|_| invalid())?),
                abort_deadline: i64::from_le_bytes(data[53..61].try_into().map_err(|_| invalid())?),
            })),
            Some(2) if data.len() == 1 + LockPayloadV1::ENCODED_LEN => {
                LockPayloadV1::decode(&data[1..])
                    .map(Self::Lock)
                    .ok_or_else(invalid)
            }
            Some(3) if data.len() == 70 => Ok(Self::Settle(CompactSettlementPayload {
                result_commitment: data[1..33].try_into().map_err(|_| invalid())?,
                residual_side: data[33],
                residual_lots: u32::from_le_bytes(data[34..38].try_into().map_err(|_| invalid())?),
                settlement_nonce: data[38..70].try_into().map_err(|_| invalid())?,
            })),
            Some(4) if data.len() == 1 => Ok(Self::Expire),
            Some(5) if data.len() == 1 => Ok(Self::Abort),
            _ => Err(invalid()),
        }
    }
}

fn encode_settlement(payload: CompactSettlementPayload) -> Vec<u8> {
    let mut out = vec![0_u8; 70];
    out[0] = 3;
    out[1..33].copy_from_slice(&payload.result_commitment);
    out[33] = payload.residual_side;
    out[34..38].copy_from_slice(&payload.residual_lots.to_le_bytes());
    out[38..70].copy_from_slice(&payload.settlement_nonce);
    out
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitializePoolAccounts {
    pub payer: Pubkey,
    pub operator: Pubkey,
    pub pool: Pubkey,
    pub vault_authority: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub pool_base_vault: Pubkey,
    pub pool_quote_vault: Pubkey,
    pub venue_authority: Pubkey,
    pub venue_base_account: Pubkey,
    pub venue_quote_account: Pubkey,
}

pub fn initialize_pool_instruction(
    accounts: InitializePoolAccounts,
    args: InitializePoolArgs,
) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new(accounts.payer, true),
            AccountMeta::new_readonly(accounts.operator, true),
            AccountMeta::new(accounts.pool, false),
            AccountMeta::new_readonly(accounts.vault_authority, false),
            AccountMeta::new_readonly(accounts.base_mint, false),
            AccountMeta::new_readonly(accounts.quote_mint, false),
            AccountMeta::new_readonly(accounts.pool_base_vault, false),
            AccountMeta::new_readonly(accounts.pool_quote_vault, false),
            AccountMeta::new_readonly(accounts.venue_authority, false),
            AccountMeta::new_readonly(accounts.venue_base_account, false),
            AccountMeta::new_readonly(accounts.venue_quote_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
        ],
        data: KagebInstruction::InitializePool(args).encode(),
    }
}

pub fn create_epoch_instruction(
    payer: Pubkey,
    operator: Pubkey,
    pool: Pubkey,
    epoch: Pubkey,
    args: CreateEpochArgs,
) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(operator, true),
            AccountMeta::new_readonly(pool, false),
            AccountMeta::new(epoch, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(solana_sdk_ids::sysvar::clock::ID, false),
        ],
        data: KagebInstruction::CreateEpoch(args).encode(),
    }
}

pub fn lock_instruction(
    payer: Pubkey,
    pool: Pubkey,
    epoch: Pubkey,
    payload: LockPayloadV1,
) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new_readonly(pool, false),
            AccountMeta::new(epoch, false),
            AccountMeta::new_readonly(solana_sdk_ids::sysvar::instructions::ID, false),
            AccountMeta::new_readonly(solana_sdk_ids::sysvar::clock::ID, false),
        ],
        data: KagebInstruction::Lock(payload).encode(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettleAccounts {
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
}

pub fn settle_instruction(accounts: SettleAccounts, payload: SettlementPayloadV1) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(accounts.payer, true),
            AccountMeta::new_readonly(accounts.pool, false),
            AccountMeta::new(accounts.epoch, false),
            AccountMeta::new_readonly(accounts.vault_authority, false),
            AccountMeta::new(accounts.pool_base_vault, false),
            AccountMeta::new(accounts.pool_quote_vault, false),
            AccountMeta::new_readonly(accounts.venue_authority, true),
            AccountMeta::new(accounts.venue_base_account, false),
            AccountMeta::new(accounts.venue_quote_account, false),
            AccountMeta::new_readonly(accounts.base_mint, false),
            AccountMeta::new_readonly(accounts.quote_mint, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
            AccountMeta::new_readonly(solana_sdk_ids::sysvar::instructions::ID, false),
            AccountMeta::new_readonly(solana_sdk_ids::sysvar::clock::ID, false),
        ],
        data: KagebInstruction::Settle(payload.into()).encode(),
    }
}

pub fn expire_instruction(caller: Pubkey, pool: Pubkey, epoch: Pubkey) -> Instruction {
    terminal_instruction(caller, pool, epoch, KagebInstruction::Expire)
}

pub fn abort_instruction(caller: Pubkey, pool: Pubkey, epoch: Pubkey) -> Instruction {
    terminal_instruction(caller, pool, epoch, KagebInstruction::Abort)
}

fn terminal_instruction(
    caller: Pubkey,
    pool: Pubkey,
    epoch: Pubkey,
    instruction: KagebInstruction,
) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(caller, true),
            AccountMeta::new_readonly(pool, false),
            AccountMeta::new(epoch, false),
            AccountMeta::new_readonly(solana_sdk_ids::sysvar::clock::ID, false),
        ],
        data: instruction.encode(),
    }
}
