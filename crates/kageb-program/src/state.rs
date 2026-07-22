use solana_program::{program_error::ProgramError, pubkey::Pubkey};

pub const STATE_LEN: usize = 384;
const POOL_DISCRIMINATOR: &[u8; 8] = b"KAGEPOOL";
const EPOCH_DISCRIMINATOR: &[u8; 8] = b"KAGEEPCH";
const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EpochTerminalState {
    Open = 1,
    Locked = 2,
    Settled = 3,
    Expired = 4,
    Aborted = 5,
}

impl TryFrom<u8> for EpochTerminalState {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Open),
            2 => Ok(Self::Locked),
            3 => Ok(Self::Settled),
            4 => Ok(Self::Expired),
            5 => Ok(Self::Aborted),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolStateV1 {
    pub pool_bump: u8,
    pub vault_bump: u8,
    pub lock_threshold: u8,
    pub settlement_threshold: u8,
    pub operator: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub pool_base_vault: Pubkey,
    pub pool_quote_vault: Pubkey,
    pub venue_authority: Pubkey,
    pub venue_base_account: Pubkey,
    pub venue_quote_account: Pubkey,
    pub keypers: [Pubkey; 3],
    pub base_lot_atoms: u64,
}

impl PoolStateV1 {
    pub fn encode(&self) -> [u8; STATE_LEN] {
        let mut out = [0_u8; STATE_LEN];
        out[0..8].copy_from_slice(POOL_DISCRIMINATOR);
        out[8] = VERSION;
        out[9] = self.pool_bump;
        out[10] = self.vault_bump;
        out[11] = self.lock_threshold;
        out[12] = self.settlement_threshold;
        let mut offset = 16;
        for key in [
            self.operator,
            self.base_mint,
            self.quote_mint,
            self.pool_base_vault,
            self.pool_quote_vault,
            self.venue_authority,
            self.venue_base_account,
            self.venue_quote_account,
            self.keypers[0],
            self.keypers[1],
            self.keypers[2],
        ] {
            put_pubkey(&mut out, &mut offset, &key);
        }
        put_u64(&mut out, &mut offset, self.base_lot_atoms);
        debug_assert_eq!(offset, 376);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, ProgramError> {
        require_header_and_reserved(data, POOL_DISCRIMINATOR, 376)?;
        let mut offset = 16;
        let state = Self {
            pool_bump: data[9],
            vault_bump: data[10],
            lock_threshold: data[11],
            settlement_threshold: data[12],
            operator: take_pubkey(data, &mut offset)?,
            base_mint: take_pubkey(data, &mut offset)?,
            quote_mint: take_pubkey(data, &mut offset)?,
            pool_base_vault: take_pubkey(data, &mut offset)?,
            pool_quote_vault: take_pubkey(data, &mut offset)?,
            venue_authority: take_pubkey(data, &mut offset)?,
            venue_base_account: take_pubkey(data, &mut offset)?,
            venue_quote_account: take_pubkey(data, &mut offset)?,
            keypers: [
                take_pubkey(data, &mut offset)?,
                take_pubkey(data, &mut offset)?,
                take_pubkey(data, &mut offset)?,
            ],
            base_lot_atoms: take_u64(data, &mut offset)?,
        };
        if data[13..16] != [0; 3] || offset != 376 {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(state)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochStateV1 {
    pub epoch_bump: u8,
    pub terminal_state: EpochTerminalState,
    pub residual_side: u8,
    pub pool: Pubkey,
    pub epoch_id: [u8; 32],
    pub configuration_hash: [u8; 32],
    pub pre_balance_root: [u8; 32],
    pub member_root: [u8; 32],
    pub lock_digest: [u8; 32],
    pub result_commitment: [u8; 32],
    pub settlement_digest: [u8; 32],
    pub lock_nonce: [u8; 32],
    pub settlement_nonce: [u8; 32],
    pub member_count: u32,
    pub minimum_count: u32,
    pub residual_lots: u32,
    pub base_lot_atoms: u64,
    pub quote_atoms_per_lot: u64,
    pub lock_deadline: i64,
    pub abort_deadline: i64,
}

impl EpochStateV1 {
    pub fn encode(&self) -> [u8; STATE_LEN] {
        let mut out = [0_u8; STATE_LEN];
        out[0..8].copy_from_slice(EPOCH_DISCRIMINATOR);
        out[8] = VERSION;
        out[9] = self.epoch_bump;
        out[10] = self.terminal_state as u8;
        out[11] = self.residual_side;
        let mut offset = 16;
        put_pubkey(&mut out, &mut offset, &self.pool);
        for value in [
            self.epoch_id,
            self.configuration_hash,
            self.pre_balance_root,
            self.member_root,
            self.lock_digest,
            self.result_commitment,
            self.settlement_digest,
            self.lock_nonce,
            self.settlement_nonce,
        ] {
            put_bytes32(&mut out, &mut offset, &value);
        }
        put_u32(&mut out, &mut offset, self.member_count);
        put_u32(&mut out, &mut offset, self.minimum_count);
        put_u32(&mut out, &mut offset, self.residual_lots);
        put_u64(&mut out, &mut offset, self.base_lot_atoms);
        put_u64(&mut out, &mut offset, self.quote_atoms_per_lot);
        put_i64(&mut out, &mut offset, self.lock_deadline);
        put_i64(&mut out, &mut offset, self.abort_deadline);
        debug_assert_eq!(offset, 380);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, ProgramError> {
        require_header_and_reserved(data, EPOCH_DISCRIMINATOR, 380)?;
        if data[12..16] != [0; 4] {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut offset = 16;
        let state = Self {
            epoch_bump: data[9],
            terminal_state: data[10].try_into()?,
            residual_side: data[11],
            pool: take_pubkey(data, &mut offset)?,
            epoch_id: take_bytes32(data, &mut offset)?,
            configuration_hash: take_bytes32(data, &mut offset)?,
            pre_balance_root: take_bytes32(data, &mut offset)?,
            member_root: take_bytes32(data, &mut offset)?,
            lock_digest: take_bytes32(data, &mut offset)?,
            result_commitment: take_bytes32(data, &mut offset)?,
            settlement_digest: take_bytes32(data, &mut offset)?,
            lock_nonce: take_bytes32(data, &mut offset)?,
            settlement_nonce: take_bytes32(data, &mut offset)?,
            member_count: take_u32(data, &mut offset)?,
            minimum_count: take_u32(data, &mut offset)?,
            residual_lots: take_u32(data, &mut offset)?,
            base_lot_atoms: take_u64(data, &mut offset)?,
            quote_atoms_per_lot: take_u64(data, &mut offset)?,
            lock_deadline: take_i64(data, &mut offset)?,
            abort_deadline: take_i64(data, &mut offset)?,
        };
        if offset != 380 {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(state)
    }
}

fn require_header_and_reserved(
    data: &[u8],
    discriminator: &[u8; 8],
    reserved_start: usize,
) -> Result<(), ProgramError> {
    if data.len() != STATE_LEN
        || &data[0..8] != discriminator
        || data[8] != VERSION
        || data[reserved_start..].iter().any(|byte| *byte != 0)
    {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

fn put_pubkey(out: &mut [u8], offset: &mut usize, key: &Pubkey) {
    out[*offset..*offset + 32].copy_from_slice(key.as_ref());
    *offset += 32;
}

fn put_bytes32(out: &mut [u8], offset: &mut usize, value: &[u8; 32]) {
    out[*offset..*offset + 32].copy_from_slice(value);
    *offset += 32;
}

fn put_u32(out: &mut [u8], offset: &mut usize, value: u32) {
    out[*offset..*offset + 4].copy_from_slice(&value.to_le_bytes());
    *offset += 4;
}

fn put_u64(out: &mut [u8], offset: &mut usize, value: u64) {
    out[*offset..*offset + 8].copy_from_slice(&value.to_le_bytes());
    *offset += 8;
}

fn put_i64(out: &mut [u8], offset: &mut usize, value: i64) {
    put_u64(out, offset, value as u64);
}

fn take_bytes<const N: usize>(data: &[u8], offset: &mut usize) -> Result<[u8; N], ProgramError> {
    let bytes: [u8; N] = data
        .get(*offset..*offset + N)
        .ok_or(ProgramError::InvalidAccountData)?
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    *offset += N;
    Ok(bytes)
}

fn take_pubkey(data: &[u8], offset: &mut usize) -> Result<Pubkey, ProgramError> {
    Ok(Pubkey::new_from_array(take_bytes(data, offset)?))
}

fn take_bytes32(data: &[u8], offset: &mut usize) -> Result<[u8; 32], ProgramError> {
    take_bytes(data, offset)
}

fn take_u32(data: &[u8], offset: &mut usize) -> Result<u32, ProgramError> {
    Ok(u32::from_le_bytes(take_bytes(data, offset)?))
}

fn take_u64(data: &[u8], offset: &mut usize) -> Result<u64, ProgramError> {
    Ok(u64::from_le_bytes(take_bytes(data, offset)?))
}

fn take_i64(data: &[u8], offset: &mut usize) -> Result<i64, ProgramError> {
    Ok(i64::from_le_bytes(take_bytes(data, offset)?))
}
