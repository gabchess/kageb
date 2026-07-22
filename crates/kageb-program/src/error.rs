use solana_program::program_error::ProgramError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum KagebError {
    InvalidInstruction = 1,
    InvalidAccounts = 2,
    MissingSignature = 3,
    InvalidOwner = 4,
    InvalidPda = 5,
    InvalidState = 6,
    InvalidConfiguration = 7,
    InvalidTokenAccount = 8,
    DeadlinePassed = 9,
    DeadlineNotReached = 10,
    CrowdBelowMinimum = 11,
    InvalidLock = 12,
    InsufficientQuorum = 13,
    ArithmeticOverflow = 14,
    InvalidSettlement = 15,
}

impl From<KagebError> for ProgramError {
    fn from(value: KagebError) -> Self {
        Self::Custom(value as u32)
    }
}
