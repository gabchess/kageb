use crate::error::KagebError;
use solana_instructions_sysvar::{load_current_index_checked, load_instruction_at_checked};
use solana_program::{
    account_info::AccountInfo, instruction::Instruction, program_error::ProgramError,
    pubkey::Pubkey,
};

const VERIFIER_DATA_LEN: usize = 144;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictEd25519 {
    pub signer: Pubkey,
    pub digest: [u8; 32],
}

pub fn parse_strict_ed25519(instruction: &Instruction) -> Result<StrictEd25519, ProgramError> {
    let data = &instruction.data;
    if instruction.program_id != solana_program::ed25519_program::ID
        || !instruction.accounts.is_empty()
        || data.len() != VERIFIER_DATA_LEN
        || data[0] != 1
        || data[1] != 0
        || read_u16(data, 2)? != 48
        || read_u16(data, 4)? != u16::MAX
        || read_u16(data, 6)? != 16
        || read_u16(data, 8)? != u16::MAX
        || read_u16(data, 10)? != 112
        || read_u16(data, 12)? != 32
        || read_u16(data, 14)? != u16::MAX
    {
        return Err(KagebError::InvalidLock.into());
    }
    Ok(StrictEd25519 {
        signer: Pubkey::new_from_array(
            data[16..48]
                .try_into()
                .map_err(|_| ProgramError::from(KagebError::InvalidLock))?,
        ),
        digest: data[112..144]
            .try_into()
            .map_err(|_| ProgramError::from(KagebError::InvalidLock))?,
    })
}

pub fn count_matching_keypers<'a>(
    instructions: impl IntoIterator<Item = &'a Instruction>,
    keypers: &[Pubkey; 3],
    digest: &[u8; 32],
) -> u8 {
    let mut matched = [false; 3];
    for instruction in instructions {
        let Ok(parsed) = parse_strict_ed25519(instruction) else {
            continue;
        };
        if &parsed.digest != digest {
            continue;
        }
        if let Some(index) = keypers.iter().position(|keyper| *keyper == parsed.signer) {
            matched[index] = true;
        }
    }
    matched.into_iter().filter(|value| *value).count() as u8
}

pub fn count_preceding_keypers(
    instructions_account: &AccountInfo,
    keypers: &[Pubkey; 3],
    digest: &[u8; 32],
) -> Result<u8, ProgramError> {
    let current_index = load_current_index_checked(instructions_account)?;
    let mut matched = [false; 3];
    for index in 0..current_index {
        let instruction = load_instruction_at_checked(index as usize, instructions_account)?;
        let Ok(parsed) = parse_strict_ed25519(&instruction) else {
            continue;
        };
        if &parsed.digest != digest {
            continue;
        }
        if let Some(keyper_index) = keypers.iter().position(|keyper| *keyper == parsed.signer) {
            matched[keyper_index] = true;
        }
    }
    Ok(matched.into_iter().filter(|value| *value).count() as u8)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, ProgramError> {
    Ok(u16::from_le_bytes(
        data.get(offset..offset + 2)
            .ok_or(KagebError::InvalidLock)?
            .try_into()
            .map_err(|_| KagebError::InvalidLock)?,
    ))
}
