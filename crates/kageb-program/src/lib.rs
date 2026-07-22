#![allow(unexpected_cfgs)]

pub mod ed25519;
pub mod error;
pub mod instruction;
pub mod processor;
pub mod state;
pub mod wire;

use solana_program::pubkey::Pubkey;

pub const ID: Pubkey = solana_program::pubkey!("HbMyCP5GxicksRpSVrchRTJTznP3zTrzCMb7FmZNRa77");
pub const TOKEN_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

pub fn pool_address(operator: &Pubkey, base_mint: &Pubkey, quote_mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"pool",
            operator.as_ref(),
            base_mint.as_ref(),
            quote_mint.as_ref(),
        ],
        &ID,
    )
}

pub fn vault_authority_address(pool: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault", pool.as_ref()], &ID)
}

pub fn epoch_address(pool: &Pubkey, epoch_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"epoch", pool.as_ref(), epoch_id], &ID)
}

#[cfg(not(feature = "no-entrypoint"))]
mod program_entrypoint {
    solana_program::entrypoint!(process_instruction);

    fn process_instruction<'a>(
        program_id: &'a solana_program::pubkey::Pubkey,
        accounts: &'a [solana_program::account_info::AccountInfo<'a>],
        instruction_data: &'a [u8],
    ) -> solana_program::entrypoint::ProgramResult {
        crate::processor::process_instruction(program_id, accounts, instruction_data)
    }
}
