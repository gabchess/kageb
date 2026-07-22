//! Deterministic classic SPL Token program fixture for local validation only.

use solana_account_info::AccountInfo;
use solana_program_error::ProgramResult;
use solana_pubkey::Pubkey;

solana_program_entrypoint::entrypoint!(process_instruction);

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    spl_token::processor::Processor::process(program_id, accounts, instruction_data)
}
