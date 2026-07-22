use crate::{Residual, Side};

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
        result_root: [u8; 32],
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
                result_root,
            }],
        }
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
                    result_root,
                } => format!(
                    "pool aggregate: {} | pool {} | venue {} | member root {} | result root {}",
                    residual_name(*residual),
                    short_key(pool),
                    short_key(venue),
                    short_key(member_root),
                    short_key(result_root)
                ),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
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
