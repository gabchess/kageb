use std::collections::{BTreeMap, BTreeSet};

use crate::Side;

pub type ParticipantId = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchConfig {
    base_lot_atoms: u64,
    quote_atoms_per_lot: u64,
}

impl BatchConfig {
    pub fn new(base_lot_atoms: u64, quote_atoms_per_lot: u64) -> Result<Self, LedgerError> {
        if base_lot_atoms == 0 || quote_atoms_per_lot == 0 {
            return Err(LedgerError::InvalidConfig);
        }
        Ok(Self {
            base_lot_atoms,
            quote_atoms_per_lot,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolBalance {
    pub base_atoms: u64,
    pub quote_atoms: u64,
}

impl PoolBalance {
    #[must_use]
    pub const fn new(base_atoms: u64, quote_atoms: u64) -> Self {
        Self {
            base_atoms,
            quote_atoms,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FundedOrder {
    participant_id: ParticipantId,
    side: Side,
    limit_price: u64,
}

impl FundedOrder {
    pub const fn new(
        participant_id: ParticipantId,
        side: Side,
        limit_price: u64,
    ) -> Result<Self, LedgerError> {
        if limit_price == 0 {
            return Err(LedgerError::InvalidLimit);
        }
        Ok(Self {
            participant_id,
            side,
            limit_price,
        })
    }

    #[must_use]
    pub const fn participant_id(&self) -> ParticipantId {
        self.participant_id
    }

    #[must_use]
    pub const fn side(&self) -> Side {
        self.side
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Residual {
    None,
    Buy { lots: u32 },
    Sell { lots: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultDelta {
    pub base_atoms: i128,
    pub quote_atoms: i128,
}

impl VaultDelta {
    pub const ZERO: Self = Self {
        base_atoms: 0,
        quote_atoms: 0,
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchResult {
    balances: BTreeMap<ParticipantId, PoolBalance>,
    residual: Residual,
    vault_delta: VaultDelta,
}

impl BatchResult {
    #[must_use]
    pub const fn residual(&self) -> Residual {
        self.residual
    }

    #[must_use]
    pub const fn vault_delta(&self) -> VaultDelta {
        self.vault_delta
    }

    #[must_use]
    pub fn balance(&self, participant_id: ParticipantId) -> Option<PoolBalance> {
        self.balances.get(&participant_id).copied()
    }

    #[must_use]
    pub fn conserves(&self, before: &BTreeMap<ParticipantId, PoolBalance>) -> bool {
        let Some((before_base, before_quote)) = totals(before) else {
            return false;
        };
        let Some((after_base, after_quote)) = totals(&self.balances) else {
            return false;
        };

        before_base.checked_add(self.vault_delta.base_atoms) == Some(after_base)
            && before_quote.checked_add(self.vault_delta.quote_atoms) == Some(after_quote)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    InvalidConfig,
    InvalidLimit,
    EmptyBatch,
    UnknownParticipant(ParticipantId),
    DuplicateParticipant(ParticipantId),
    InsufficientReservation(ParticipantId),
    LimitViolated(ParticipantId),
    ArithmeticOverflow,
    ConservationFailed,
}

pub fn net_batch(
    config: BatchConfig,
    before: &BTreeMap<ParticipantId, PoolBalance>,
    orders: &[FundedOrder],
) -> Result<BatchResult, LedgerError> {
    if orders.is_empty() {
        return Err(LedgerError::EmptyBatch);
    }

    let mut seen = BTreeSet::new();
    for order in orders {
        if !seen.insert(order.participant_id) {
            return Err(LedgerError::DuplicateParticipant(order.participant_id));
        }
    }

    let mut balances = before.clone();
    let mut buys = 0_u32;
    let mut sells = 0_u32;

    for order in orders {
        let balance = balances
            .get_mut(&order.participant_id)
            .ok_or(LedgerError::UnknownParticipant(order.participant_id))?;

        if balance.base_atoms < config.base_lot_atoms
            || balance.quote_atoms < config.quote_atoms_per_lot
        {
            return Err(LedgerError::InsufficientReservation(order.participant_id));
        }

        match order.side {
            Side::Buy => {
                if config.quote_atoms_per_lot > order.limit_price {
                    return Err(LedgerError::LimitViolated(order.participant_id));
                }
                balance.base_atoms = balance
                    .base_atoms
                    .checked_add(config.base_lot_atoms)
                    .ok_or(LedgerError::ArithmeticOverflow)?;
                balance.quote_atoms = balance
                    .quote_atoms
                    .checked_sub(config.quote_atoms_per_lot)
                    .ok_or(LedgerError::ArithmeticOverflow)?;
                buys = buys.checked_add(1).ok_or(LedgerError::ArithmeticOverflow)?;
            }
            Side::Sell => {
                if config.quote_atoms_per_lot < order.limit_price {
                    return Err(LedgerError::LimitViolated(order.participant_id));
                }
                balance.base_atoms = balance
                    .base_atoms
                    .checked_sub(config.base_lot_atoms)
                    .ok_or(LedgerError::ArithmeticOverflow)?;
                balance.quote_atoms = balance
                    .quote_atoms
                    .checked_add(config.quote_atoms_per_lot)
                    .ok_or(LedgerError::ArithmeticOverflow)?;
                sells = sells
                    .checked_add(1)
                    .ok_or(LedgerError::ArithmeticOverflow)?;
            }
        }
    }

    let (residual, signed_lots) = match buys.cmp(&sells) {
        std::cmp::Ordering::Greater => {
            let lots = buys - sells;
            (Residual::Buy { lots }, i128::from(lots))
        }
        std::cmp::Ordering::Less => {
            let lots = sells - buys;
            (Residual::Sell { lots }, -i128::from(lots))
        }
        std::cmp::Ordering::Equal => (Residual::None, 0),
    };

    let base_atoms = signed_lots
        .checked_mul(i128::from(config.base_lot_atoms))
        .ok_or(LedgerError::ArithmeticOverflow)?;
    let quote_atoms = signed_lots
        .checked_mul(i128::from(config.quote_atoms_per_lot))
        .and_then(i128::checked_neg)
        .ok_or(LedgerError::ArithmeticOverflow)?;

    let result = BatchResult {
        balances,
        residual,
        vault_delta: VaultDelta {
            base_atoms,
            quote_atoms,
        },
    };
    if !result.conserves(before) {
        return Err(LedgerError::ConservationFailed);
    }
    Ok(result)
}

fn totals(balances: &BTreeMap<ParticipantId, PoolBalance>) -> Option<(i128, i128)> {
    balances
        .values()
        .try_fold((0_i128, 0_i128), |totals, balance| {
            Some((
                totals.0.checked_add(i128::from(balance.base_atoms))?,
                totals.1.checked_add(i128::from(balance.quote_atoms))?,
            ))
        })
}
