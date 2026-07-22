use core::fmt;

const INTENT_VERSION: u8 = 1;
const INTENT_LEN: usize = 128;
const PADDING_START: usize = 94;

/// The only two order directions accepted by the v1 reference market.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Side {
    Buy = 0,
    Sell = 1,
}

impl TryFrom<u8> for Side {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Buy),
            1 => Ok(Self::Sell),
            _ => Err(ProtocolError::InvalidSide(value)),
        }
    }
}

/// A strict decoding or economic validation failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidIntentLength(usize),
    InvalidVersion(u8),
    InvalidSide(u8),
    InvalidLots(u32),
    InvalidLimitPrice,
    NonZeroPadding,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIntentLength(length) => {
                write!(formatter, "intent must be {INTENT_LEN} bytes, got {length}")
            }
            Self::InvalidVersion(version) => {
                write!(formatter, "unsupported intent version {version}")
            }
            Self::InvalidSide(side) => write!(formatter, "invalid intent side {side}"),
            Self::InvalidLots(lots) => {
                write!(formatter, "v1 intent must contain one lot, got {lots}")
            }
            Self::InvalidLimitPrice => formatter.write_str("limit price must be non-zero"),
            Self::NonZeroPadding => formatter.write_str("intent padding must be zero"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// The fixed-width order body encrypted by a KageB client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntentBodyV1 {
    side: Side,
    lots: u32,
    limit_price: u64,
    epoch_id: [u8; 32],
    participant_id: [u8; 32],
    client_nonce: [u8; 16],
}

impl IntentBodyV1 {
    pub fn new(
        side: Side,
        lots: u32,
        limit_price: u64,
        epoch_id: [u8; 32],
        participant_id: [u8; 32],
        client_nonce: [u8; 16],
    ) -> Result<Self, ProtocolError> {
        if lots != 1 {
            return Err(ProtocolError::InvalidLots(lots));
        }
        if limit_price == 0 {
            return Err(ProtocolError::InvalidLimitPrice);
        }

        Ok(Self {
            side,
            lots,
            limit_price,
            epoch_id,
            participant_id,
            client_nonce,
        })
    }

    #[must_use]
    pub fn side(&self) -> Side {
        self.side
    }

    #[must_use]
    pub fn limit_price(&self) -> u64 {
        self.limit_price
    }

    #[must_use]
    pub fn participant_id(&self) -> [u8; 32] {
        self.participant_id
    }

    #[must_use]
    pub fn epoch_id(&self) -> [u8; 32] {
        self.epoch_id
    }

    #[must_use]
    pub fn encode(&self) -> [u8; INTENT_LEN] {
        let mut bytes = [0_u8; INTENT_LEN];
        bytes[0] = INTENT_VERSION;
        bytes[1] = self.side as u8;
        bytes[2..6].copy_from_slice(&self.lots.to_le_bytes());
        bytes[6..14].copy_from_slice(&self.limit_price.to_le_bytes());
        bytes[14..46].copy_from_slice(&self.epoch_id);
        bytes[46..78].copy_from_slice(&self.participant_id);
        bytes[78..94].copy_from_slice(&self.client_nonce);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != INTENT_LEN {
            return Err(ProtocolError::InvalidIntentLength(bytes.len()));
        }
        if bytes[0] != INTENT_VERSION {
            return Err(ProtocolError::InvalidVersion(bytes[0]));
        }
        if bytes[PADDING_START..].iter().any(|byte| *byte != 0) {
            return Err(ProtocolError::NonZeroPadding);
        }

        let side = Side::try_from(bytes[1])?;
        let lots = u32::from_le_bytes(bytes[2..6].try_into().expect("fixed slice"));
        let limit_price = u64::from_le_bytes(bytes[6..14].try_into().expect("fixed slice"));
        let epoch_id = bytes[14..46].try_into().expect("fixed slice");
        let participant_id = bytes[46..78].try_into().expect("fixed slice");
        let client_nonce = bytes[78..94].try_into().expect("fixed slice");

        Self::new(
            side,
            lots,
            limit_price,
            epoch_id,
            participant_id,
            client_nonce,
        )
    }
}
