use sha2::{Digest, Sha256};
use solana_program::pubkey::Pubkey;

const CONFIG_DOMAIN: &[u8] = b"KAGEB_CONFIG_V1\0";
const LOCK_DOMAIN: &[u8] = b"KAGEB_LOCK_V1\0";
const SETTLEMENT_DOMAIN: &[u8] = b"KAGEB_SETTLEMENT_V1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochConfigurationV1 {
    pub pool: Pubkey,
    pub epoch_id: [u8; 32],
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub base_lot_atoms: u64,
    pub quote_atoms_per_lot: u64,
    pub minimum_count: u32,
    pub lock_threshold: u8,
    pub settlement_threshold: u8,
    pub keypers: [Pubkey; 3],
    pub lock_deadline: i64,
    pub abort_deadline: i64,
}

impl EpochConfigurationV1 {
    pub const ENCODED_LEN: usize = 263;

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0] = 1;
        out[1..33].copy_from_slice(self.pool.as_ref());
        out[33..65].copy_from_slice(&self.epoch_id);
        out[65..97].copy_from_slice(self.base_mint.as_ref());
        out[97..129].copy_from_slice(self.quote_mint.as_ref());
        out[129..137].copy_from_slice(&self.base_lot_atoms.to_le_bytes());
        out[137..145].copy_from_slice(&self.quote_atoms_per_lot.to_le_bytes());
        out[145..149].copy_from_slice(&self.minimum_count.to_le_bytes());
        out[149] = self.lock_threshold;
        out[150] = self.settlement_threshold;
        let mut offset = 151;
        for keyper in self.keypers {
            out[offset..offset + 32].copy_from_slice(keyper.as_ref());
            offset += 32;
        }
        out[247..255].copy_from_slice(&self.lock_deadline.to_le_bytes());
        out[255..263].copy_from_slice(&self.abort_deadline.to_le_bytes());
        out
    }

    pub fn digest(&self) -> [u8; 32] {
        domain_hash(CONFIG_DOMAIN, &self.encode())
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::ENCODED_LEN || bytes[0] != 1 {
            return None;
        }
        let mut offset = 151;
        let mut keypers = [Pubkey::default(); 3];
        for keyper in &mut keypers {
            *keyper = Pubkey::new_from_array(bytes[offset..offset + 32].try_into().ok()?);
            offset += 32;
        }
        Some(Self {
            pool: Pubkey::new_from_array(bytes[1..33].try_into().ok()?),
            epoch_id: bytes[33..65].try_into().ok()?,
            base_mint: Pubkey::new_from_array(bytes[65..97].try_into().ok()?),
            quote_mint: Pubkey::new_from_array(bytes[97..129].try_into().ok()?),
            base_lot_atoms: u64::from_le_bytes(bytes[129..137].try_into().ok()?),
            quote_atoms_per_lot: u64::from_le_bytes(bytes[137..145].try_into().ok()?),
            minimum_count: u32::from_le_bytes(bytes[145..149].try_into().ok()?),
            lock_threshold: bytes[149],
            settlement_threshold: bytes[150],
            keypers,
            lock_deadline: i64::from_le_bytes(bytes[247..255].try_into().ok()?),
            abort_deadline: i64::from_le_bytes(bytes[255..263].try_into().ok()?),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockPayloadV1 {
    pub epoch_account: Pubkey,
    pub configuration_hash: [u8; 32],
    pub pre_balance_root: [u8; 32],
    pub member_root: [u8; 32],
    pub member_count: u32,
    pub lock_deadline: i64,
    pub lock_nonce: [u8; 32],
}

impl LockPayloadV1 {
    pub const ENCODED_LEN: usize = 173;

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0] = 1;
        out[1..33].copy_from_slice(self.epoch_account.as_ref());
        out[33..65].copy_from_slice(&self.configuration_hash);
        out[65..97].copy_from_slice(&self.pre_balance_root);
        out[97..129].copy_from_slice(&self.member_root);
        out[129..133].copy_from_slice(&self.member_count.to_le_bytes());
        out[133..141].copy_from_slice(&self.lock_deadline.to_le_bytes());
        out[141..173].copy_from_slice(&self.lock_nonce);
        out
    }

    pub fn digest(&self) -> [u8; 32] {
        domain_hash(LOCK_DOMAIN, &self.encode())
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::ENCODED_LEN || bytes[0] != 1 {
            return None;
        }
        Some(Self {
            epoch_account: Pubkey::new_from_array(bytes[1..33].try_into().ok()?),
            configuration_hash: bytes[33..65].try_into().ok()?,
            pre_balance_root: bytes[65..97].try_into().ok()?,
            member_root: bytes[97..129].try_into().ok()?,
            member_count: u32::from_le_bytes(bytes[129..133].try_into().ok()?),
            lock_deadline: i64::from_le_bytes(bytes[133..141].try_into().ok()?),
            lock_nonce: bytes[141..173].try_into().ok()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettlementPayloadV1 {
    pub epoch_account: Pubkey,
    pub lock_digest: [u8; 32],
    pub result_commitment: [u8; 32],
    pub residual_side: u8,
    pub residual_lots: u32,
    pub base_lot_atoms: u64,
    pub quote_atoms_per_lot: u64,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub pool_base_vault: Pubkey,
    pub pool_quote_vault: Pubkey,
    pub venue_base_account: Pubkey,
    pub venue_quote_account: Pubkey,
    pub venue_authority: Pubkey,
    pub settlement_nonce: [u8; 32],
}

impl SettlementPayloadV1 {
    pub const ENCODED_LEN: usize = 374;

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0_u8; Self::ENCODED_LEN];
        out[0] = 1;
        out[1..33].copy_from_slice(self.epoch_account.as_ref());
        out[33..65].copy_from_slice(&self.lock_digest);
        out[65..97].copy_from_slice(&self.result_commitment);
        out[97] = self.residual_side;
        out[98..102].copy_from_slice(&self.residual_lots.to_le_bytes());
        out[102..110].copy_from_slice(&self.base_lot_atoms.to_le_bytes());
        out[110..118].copy_from_slice(&self.quote_atoms_per_lot.to_le_bytes());
        let mut offset = 118;
        for key in [
            self.base_mint,
            self.quote_mint,
            self.pool_base_vault,
            self.pool_quote_vault,
            self.venue_base_account,
            self.venue_quote_account,
            self.venue_authority,
        ] {
            out[offset..offset + 32].copy_from_slice(key.as_ref());
            offset += 32;
        }
        out[offset..offset + 32].copy_from_slice(&self.settlement_nonce);
        out
    }

    pub fn digest(&self) -> [u8; 32] {
        domain_hash(SETTLEMENT_DOMAIN, &self.encode())
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::ENCODED_LEN || bytes[0] != 1 {
            return None;
        }
        Some(Self {
            epoch_account: Pubkey::new_from_array(bytes[1..33].try_into().ok()?),
            lock_digest: bytes[33..65].try_into().ok()?,
            result_commitment: bytes[65..97].try_into().ok()?,
            residual_side: bytes[97],
            residual_lots: u32::from_le_bytes(bytes[98..102].try_into().ok()?),
            base_lot_atoms: u64::from_le_bytes(bytes[102..110].try_into().ok()?),
            quote_atoms_per_lot: u64::from_le_bytes(bytes[110..118].try_into().ok()?),
            base_mint: Pubkey::new_from_array(bytes[118..150].try_into().ok()?),
            quote_mint: Pubkey::new_from_array(bytes[150..182].try_into().ok()?),
            pool_base_vault: Pubkey::new_from_array(bytes[182..214].try_into().ok()?),
            pool_quote_vault: Pubkey::new_from_array(bytes[214..246].try_into().ok()?),
            venue_base_account: Pubkey::new_from_array(bytes[246..278].try_into().ok()?),
            venue_quote_account: Pubkey::new_from_array(bytes[278..310].try_into().ok()?),
            venue_authority: Pubkey::new_from_array(bytes[310..342].try_into().ok()?),
            settlement_nonce: bytes[342..374].try_into().ok()?,
        })
    }
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
