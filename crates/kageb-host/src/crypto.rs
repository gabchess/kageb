use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use bincode::Options;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::{Digest, Sha256};
use threshold_crypto::DecryptionShare;
use threshold_crypto::{Ciphertext, PublicKeySet, SecretKeySet, SecretKeyShare};
use zeroize::Zeroize;

use solana_program::pubkey::Pubkey;

use crate::{IntentBodyV1, ProtocolError, UnsignedFundedAuthorizationV1};

const FUNDED_AUTH_DOMAIN: &[u8] = b"KAGEB_FUNDED_AUTH_V1\0";
const INTENT_DOMAIN: &[u8] = b"KAGEB_INTENT_V1\0";
const SUBMISSION_DOMAIN: &[u8] = b"KAGEB_SUBMISSION_V1\0";
const EPOCH_KEY_SET_DOMAIN: &[u8] = b"KAGEB_EPOCH_KEY_SET_V1\0";
const AUTHORIZATION_VERSION: u8 = 1;
const SIGNED_INTENT_LEN: usize = 192;
pub const FUNDED_AUTHORIZATION_V1_LEN: usize = 249;
pub const ENCRYPTED_INTENT_V1_LEN: usize = 344;
pub const ENCRYPTED_SUBMISSION_V1_LEN: usize =
    FUNDED_AUTHORIZATION_V1_LEN + ENCRYPTED_INTENT_V1_LEN + 32 + 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    EntropyUnavailable,
    InvalidAuthorization,
    InvalidInnerSignature,
    InvalidOuterSignature,
    InvalidSignedIntent,
    InvalidCiphertext,
    InvalidReceipt,
    WrongEpoch,
    WrongParticipant,
    InsufficientCrowd { valid: usize, minimum: usize },
    InsufficientShares,
    DuplicateShare,
    InvalidShare,
    InvalidMinimum,
    WrongTradingKey,
}

impl From<ProtocolError> for CryptoError {
    fn from(_: ProtocolError) -> Self {
        Self::InvalidSignedIntent
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionPolicyV1 {
    pub(crate) epoch_id: [u8; 32],
    pub(crate) operator_key: [u8; 32],
    pub(crate) minimum: usize,
    pub(crate) base_atoms: u64,
    pub(crate) quote_atoms: u64,
    pub(crate) current_slot: u64,
}

impl AdmissionPolicyV1 {
    pub fn new(
        epoch_id: [u8; 32],
        operator_key: VerifyingKey,
        minimum: usize,
        base_atoms: u64,
        quote_atoms: u64,
        current_slot: u64,
    ) -> Result<Self, CryptoError> {
        if minimum == 0 {
            return Err(CryptoError::InvalidMinimum);
        }
        if base_atoms == 0 || quote_atoms == 0 {
            return Err(CryptoError::InvalidAuthorization);
        }
        Ok(Self {
            epoch_id,
            operator_key: operator_key.to_bytes(),
            minimum,
            base_atoms,
            quote_atoms,
            current_slot,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FundedAuthorizationV1 {
    pub(crate) version: u8,
    pub(crate) operator_key: [u8; 32],
    pub(crate) epoch_id: [u8; 32],
    pub(crate) participant_id: [u8; 32],
    pub(crate) trading_key: [u8; 32],
    pub(crate) nonce: [u8; 32],
    pub(crate) base_atoms: u64,
    pub(crate) quote_atoms: u64,
    pub(crate) expiry_slot: u64,
    pub(crate) operator_signature: [u8; 64],
}

impl fmt::Debug for FundedAuthorizationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FundedAuthorizationV1(..redacted)")
    }
}

impl FundedAuthorizationV1 {
    #[must_use]
    pub(crate) fn sign(
        reserved: UnsignedFundedAuthorizationV1,
        epoch_id: [u8; 32],
        trading_key: VerifyingKey,
        operator: &SigningKey,
        expiry_slot: u64,
    ) -> Self {
        let (nonce, participant_id, base_atoms, quote_atoms) = reserved.into_parts();
        let trading_key = trading_key.to_bytes();
        let operator_key = operator.verifying_key().to_bytes();
        let unsigned = authorization_bytes(
            AUTHORIZATION_VERSION,
            operator_key,
            epoch_id,
            participant_id,
            trading_key,
            nonce,
            base_atoms,
            quote_atoms,
            expiry_slot,
        );
        Self {
            version: AUTHORIZATION_VERSION,
            operator_key,
            epoch_id,
            participant_id,
            trading_key,
            nonce,
            base_atoms,
            quote_atoms,
            expiry_slot,
            operator_signature: operator.sign(&authorization_message(&unsigned)).to_bytes(),
        }
    }

    #[must_use]
    pub const fn epoch_id(&self) -> [u8; 32] {
        self.epoch_id
    }

    #[must_use]
    pub const fn participant_id(&self) -> [u8; 32] {
        self.participant_id
    }

    fn trading_key(&self) -> Result<VerifyingKey, CryptoError> {
        VerifyingKey::from_bytes(&self.trading_key).map_err(|_| CryptoError::InvalidAuthorization)
    }

    fn verify(&self, policy: &AdmissionPolicyV1) -> Result<(), CryptoError> {
        if self.version != AUTHORIZATION_VERSION
            || self.operator_key != policy.operator_key
            || self.base_atoms != policy.base_atoms
            || self.quote_atoms != policy.quote_atoms
            || self.expiry_slot < policy.current_slot
        {
            return Err(CryptoError::InvalidAuthorization);
        }
        if self.epoch_id != policy.epoch_id {
            return Err(CryptoError::WrongEpoch);
        }
        let unsigned = authorization_bytes(
            self.version,
            self.operator_key,
            self.epoch_id,
            self.participant_id,
            self.trading_key,
            self.nonce,
            self.base_atoms,
            self.quote_atoms,
            self.expiry_slot,
        );
        let signature = Signature::from_bytes(&self.operator_signature);
        let operator = VerifyingKey::from_bytes(&self.operator_key)
            .map_err(|_| CryptoError::InvalidAuthorization)?;
        operator
            .verify(&authorization_message(&unsigned), &signature)
            .map_err(|_| CryptoError::InvalidAuthorization)
    }

    fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(FUNDED_AUTH_DOMAIN);
        hasher.update(self.encode());
        hasher.finalize().into()
    }

    #[must_use]
    pub fn encode(&self) -> [u8; FUNDED_AUTHORIZATION_V1_LEN] {
        let unsigned = authorization_bytes(
            self.version,
            self.operator_key,
            self.epoch_id,
            self.participant_id,
            self.trading_key,
            self.nonce,
            self.base_atoms,
            self.quote_atoms,
            self.expiry_slot,
        );
        let mut encoded = [0_u8; FUNDED_AUTHORIZATION_V1_LEN];
        encoded[..185].copy_from_slice(&unsigned);
        encoded[185..].copy_from_slice(&self.operator_signature);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, CryptoError> {
        if encoded.len() != FUNDED_AUTHORIZATION_V1_LEN || encoded[0] != AUTHORIZATION_VERSION {
            return Err(CryptoError::InvalidAuthorization);
        }
        let authorization = Self {
            version: encoded[0],
            operator_key: encoded[1..33]
                .try_into()
                .map_err(|_| CryptoError::InvalidAuthorization)?,
            epoch_id: encoded[33..65]
                .try_into()
                .map_err(|_| CryptoError::InvalidAuthorization)?,
            participant_id: encoded[65..97]
                .try_into()
                .map_err(|_| CryptoError::InvalidAuthorization)?,
            trading_key: encoded[97..129]
                .try_into()
                .map_err(|_| CryptoError::InvalidAuthorization)?,
            nonce: encoded[129..161]
                .try_into()
                .map_err(|_| CryptoError::InvalidAuthorization)?,
            base_atoms: u64::from_le_bytes(
                encoded[161..169]
                    .try_into()
                    .map_err(|_| CryptoError::InvalidAuthorization)?,
            ),
            quote_atoms: u64::from_le_bytes(
                encoded[169..177]
                    .try_into()
                    .map_err(|_| CryptoError::InvalidAuthorization)?,
            ),
            expiry_slot: u64::from_le_bytes(
                encoded[177..185]
                    .try_into()
                    .map_err(|_| CryptoError::InvalidAuthorization)?,
            ),
            operator_signature: encoded[185..]
                .try_into()
                .map_err(|_| CryptoError::InvalidAuthorization)?,
        };
        authorization.trading_key()?;
        VerifyingKey::from_bytes(&authorization.operator_key)
            .map_err(|_| CryptoError::InvalidAuthorization)?;
        Ok(authorization)
    }
}

#[allow(clippy::too_many_arguments)]
fn authorization_bytes(
    version: u8,
    operator_key: [u8; 32],
    epoch_id: [u8; 32],
    participant_id: [u8; 32],
    trading_key: [u8; 32],
    nonce: [u8; 32],
    base_atoms: u64,
    quote_atoms: u64,
    expiry_slot: u64,
) -> [u8; 185] {
    let mut encoded = [0_u8; 185];
    encoded[0] = version;
    encoded[1..33].copy_from_slice(&operator_key);
    encoded[33..65].copy_from_slice(&epoch_id);
    encoded[65..97].copy_from_slice(&participant_id);
    encoded[97..129].copy_from_slice(&trading_key);
    encoded[129..161].copy_from_slice(&nonce);
    encoded[161..169].copy_from_slice(&base_atoms.to_le_bytes());
    encoded[169..177].copy_from_slice(&quote_atoms.to_le_bytes());
    encoded[177..185].copy_from_slice(&expiry_slot.to_le_bytes());
    encoded
}

fn authorization_message(unsigned: &[u8; 185]) -> Vec<u8> {
    let mut message = Vec::with_capacity(FUNDED_AUTH_DOMAIN.len() + unsigned.len());
    message.extend_from_slice(FUNDED_AUTH_DOMAIN);
    message.extend_from_slice(unsigned);
    message
}

#[derive(Clone, PartialEq, Eq)]
pub struct SignedIntentV1 {
    body: IntentBodyV1,
    signature: [u8; 64],
}

impl SignedIntentV1 {
    #[must_use]
    pub fn sign(body: IntentBodyV1, trading_key: &SigningKey) -> Self {
        let message = intent_message(&body.encode());
        Self {
            body,
            signature: trading_key.sign(&message).to_bytes(),
        }
    }

    pub fn verify(
        &self,
        trading_key: &VerifyingKey,
        expected_epoch: [u8; 32],
        expected_participant: [u8; 32],
    ) -> Result<(), CryptoError> {
        if self.body.epoch_id() != expected_epoch {
            return Err(CryptoError::WrongEpoch);
        }
        if self.body.participant_id() != expected_participant {
            return Err(CryptoError::WrongParticipant);
        }
        trading_key
            .verify(
                &intent_message(&self.body.encode()),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| CryptoError::InvalidInnerSignature)
    }

    #[must_use]
    pub fn encode(&self) -> [u8; SIGNED_INTENT_LEN] {
        let mut encoded = [0_u8; SIGNED_INTENT_LEN];
        encoded[..128].copy_from_slice(&self.body.encode());
        encoded[128..].copy_from_slice(&self.signature);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, CryptoError> {
        if encoded.len() != SIGNED_INTENT_LEN {
            return Err(CryptoError::InvalidSignedIntent);
        }
        Ok(Self {
            body: IntentBodyV1::decode(&encoded[..128])?,
            signature: encoded[128..]
                .try_into()
                .map_err(|_| CryptoError::InvalidSignedIntent)?,
        })
    }

    #[must_use]
    pub const fn body(&self) -> &IntentBodyV1 {
        &self.body
    }
}

impl fmt::Debug for SignedIntentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignedIntentV1(..redacted)")
    }
}

fn intent_message(encoded_body: &[u8; 128]) -> Vec<u8> {
    let mut message = Vec::with_capacity(INTENT_DOMAIN.len() + encoded_body.len());
    message.extend_from_slice(INTENT_DOMAIN);
    message.extend_from_slice(encoded_body);
    message
}

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedIntentV1 {
    encoded: Vec<u8>,
    ciphertext: Ciphertext,
}

impl EncryptedIntentV1 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EpochPublicKeys {
    keys: PublicKeySet,
}

impl fmt::Debug for EpochPublicKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EpochPublicKeys(..public)")
    }
}

impl EpochPublicKeys {
    pub(crate) fn encode_wire(&self) -> Result<Vec<u8>, CryptoError> {
        codec()
            .serialize(&self.keys)
            .map_err(|_| CryptoError::InvalidShare)
    }

    pub(crate) fn decode_wire(encoded: &[u8]) -> Result<Self, CryptoError> {
        let keys: PublicKeySet = codec()
            .with_limit(1_024)
            .deserialize(encoded)
            .map_err(|_| CryptoError::InvalidShare)?;
        if keys.threshold() != 1 {
            return Err(CryptoError::InvalidShare);
        }
        Ok(Self { keys })
    }

    pub(crate) fn commitment_leaf(&self) -> Result<Vec<u8>, CryptoError> {
        let encoded = self.encode_wire()?;
        let mut leaf = Vec::with_capacity(EPOCH_KEY_SET_DOMAIN.len() + encoded.len());
        leaf.extend_from_slice(EPOCH_KEY_SET_DOMAIN);
        leaf.extend_from_slice(&encoded);
        Ok(leaf)
    }

    pub(crate) fn matches_share(&self, share: &KeyperSecretShare) -> bool {
        self.keys.public_key_share(share.index).to_bytes()
            == share.secret.public_key_share().to_bytes()
    }

    pub fn encrypt(&self, intent: &SignedIntentV1) -> Result<EncryptedIntentV1, CryptoError> {
        let ciphertext = self.keys.public_key().encrypt(intent.encode());
        encode_ciphertext(ciphertext)
    }

    /// Encrypts a fixed-width signed-intent wire value before semantic validation.
    ///
    /// Admission is deliberately structural: malformed plaintext is discovered only
    /// after the frozen batch reveals.
    pub fn encrypt_encoded_intent(&self, encoded: &[u8]) -> Result<EncryptedIntentV1, CryptoError> {
        if encoded.len() != SIGNED_INTENT_LEN {
            return Err(CryptoError::InvalidSignedIntent);
        }
        encode_ciphertext(self.keys.public_key().encrypt(encoded))
    }

    pub fn decode_ciphertext(&self, encoded: &[u8]) -> Result<EncryptedIntentV1, CryptoError> {
        decode_ciphertext(encoded)
    }

    pub fn recover_submission<'a>(
        &self,
        submission: &EncryptedSubmissionV1,
        shares: impl IntoIterator<Item = &'a ReleasedShareV1>,
    ) -> Result<SignedIntentV1, CryptoError> {
        let shares: Vec<_> = shares.into_iter().collect();
        let ciphertext_hash: [u8; 32] = Sha256::digest(&submission.ciphertext).into();
        let Some(first) = shares.first() else {
            return Err(CryptoError::InsufficientShares);
        };
        if shares.iter().any(|share| {
            share.epoch_account != first.epoch_account
                || share.lock_digest != first.lock_digest
                || share.ciphertext_hash != ciphertext_hash
        }) {
            return Err(CryptoError::InvalidShare);
        }
        let encrypted = decode_ciphertext(&submission.ciphertext)?;
        self.recover(&encrypted, shares)
    }

    pub fn recover<'a>(
        &self,
        encrypted: &EncryptedIntentV1,
        shares: impl IntoIterator<Item = &'a ReleasedShareV1>,
    ) -> Result<SignedIntentV1, CryptoError> {
        let shares: Vec<_> = shares.into_iter().collect();
        if shares.len() < 2 {
            return Err(CryptoError::InsufficientShares);
        }
        let mut indices = BTreeSet::new();
        for share in &shares {
            if !indices.insert(share.index) {
                return Err(CryptoError::DuplicateShare);
            }
            if !self
                .keys
                .public_key_share(share.index)
                .verify_decryption_share(&share.share, &encrypted.ciphertext)
            {
                return Err(CryptoError::InvalidShare);
            }
        }
        let plaintext = self
            .keys
            .decrypt(
                shares.iter().map(|share| (share.index, &share.share)),
                &encrypted.ciphertext,
            )
            .map_err(|_| CryptoError::InsufficientShares)?;
        SignedIntentV1::decode(&plaintext)
    }
}

#[derive(Clone)]
pub struct ReleasedShareV1 {
    epoch_account: Pubkey,
    lock_digest: [u8; 32],
    ciphertext_hash: [u8; 32],
    index: usize,
    share: DecryptionShare,
}

impl std::fmt::Debug for ReleasedShareV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReleasedShareV1(..redacted)")
    }
}

impl ReleasedShareV1 {
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    #[must_use]
    pub const fn epoch_account(&self) -> Pubkey {
        self.epoch_account
    }

    #[must_use]
    pub const fn lock_digest(&self) -> [u8; 32] {
        self.lock_digest
    }

    #[must_use]
    pub fn verify(
        &self,
        public_keys: &EpochPublicKeys,
        submission: &EncryptedSubmissionV1,
    ) -> bool {
        let ciphertext_hash: [u8; 32] = Sha256::digest(&submission.ciphertext).into();
        if self.ciphertext_hash != ciphertext_hash {
            return false;
        }
        let Ok(encrypted) = decode_ciphertext(&submission.ciphertext) else {
            return false;
        };
        public_keys
            .keys
            .public_key_share(self.index)
            .verify_decryption_share(&self.share, &encrypted.ciphertext)
    }

    pub(crate) fn from_share(
        epoch_account: Pubkey,
        lock_digest: [u8; 32],
        ciphertext_hash: [u8; 32],
        index: usize,
        share: DecryptionShare,
    ) -> Self {
        Self {
            epoch_account,
            lock_digest,
            ciphertext_hash,
            index,
            share,
        }
    }

    pub(crate) fn encode_wire(&self) -> Result<Vec<u8>, CryptoError> {
        let encoded_share = codec()
            .serialize(&self.share)
            .map_err(|_| CryptoError::InvalidShare)?;
        let share_len =
            u32::try_from(encoded_share.len()).map_err(|_| CryptoError::InvalidShare)?;
        let mut bytes = Vec::with_capacity(109 + encoded_share.len());
        bytes.push(1);
        bytes.extend_from_slice(&(self.index as u64).to_le_bytes());
        bytes.extend_from_slice(self.epoch_account.as_ref());
        bytes.extend_from_slice(&self.lock_digest);
        bytes.extend_from_slice(&self.ciphertext_hash);
        bytes.extend_from_slice(&share_len.to_le_bytes());
        bytes.extend_from_slice(&encoded_share);
        Ok(bytes)
    }

    pub(crate) fn decode_wire(bytes: &[u8]) -> Result<Self, CryptoError> {
        const PREFIX: usize = 109;
        if bytes.len() < PREFIX || bytes[0] != 1 {
            return Err(CryptoError::InvalidShare);
        }
        let share_len = u32::from_le_bytes(
            bytes[105..109]
                .try_into()
                .map_err(|_| CryptoError::InvalidShare)?,
        ) as usize;
        if PREFIX.checked_add(share_len) != Some(bytes.len()) {
            return Err(CryptoError::InvalidShare);
        }
        let share = codec()
            .deserialize(&bytes[PREFIX..])
            .map_err(|_| CryptoError::InvalidShare)?;
        Ok(Self {
            index: usize::try_from(u64::from_le_bytes(
                bytes[1..9]
                    .try_into()
                    .map_err(|_| CryptoError::InvalidShare)?,
            ))
            .map_err(|_| CryptoError::InvalidShare)?,
            epoch_account: Pubkey::new_from_array(
                bytes[9..41]
                    .try_into()
                    .map_err(|_| CryptoError::InvalidShare)?,
            ),
            lock_digest: bytes[41..73]
                .try_into()
                .map_err(|_| CryptoError::InvalidShare)?,
            ciphertext_hash: bytes[73..105]
                .try_into()
                .map_err(|_| CryptoError::InvalidShare)?,
            share,
        })
    }
}

pub struct EpochDealer {
    secrets: SecretKeySet,
    public: EpochPublicKeys,
}

impl EpochDealer {
    pub fn random() -> Result<Self, CryptoError> {
        let mut seed = [0_u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| CryptoError::EntropyUnavailable)?;
        let mut rng = ChaChaRng::from_seed(seed);
        seed.zeroize();
        let secrets =
            SecretKeySet::try_random(1, &mut rng).map_err(|_| CryptoError::EntropyUnavailable)?;
        let public = EpochPublicKeys {
            keys: secrets.public_keys(),
        };
        Ok(Self { secrets, public })
    }

    #[must_use]
    pub const fn public_keys(&self) -> &EpochPublicKeys {
        &self.public
    }

    #[must_use]
    pub fn share(&self, epoch_account: Pubkey, index: usize) -> KeyperSecretShare {
        KeyperSecretShare {
            epoch_account,
            index,
            secret: self.secrets.secret_key_share(index),
        }
    }
}

pub struct KeyperSecretShare {
    epoch_account: Pubkey,
    index: usize,
    secret: SecretKeyShare,
}

impl KeyperSecretShare {
    #[cfg(test)]
    fn decrypt(&self, encrypted: &EncryptedIntentV1) -> Result<ReleasedShareV1, CryptoError> {
        let share = self
            .secret
            .decrypt_share(&encrypted.ciphertext)
            .ok_or(CryptoError::InvalidCiphertext)?;
        Ok(ReleasedShareV1 {
            epoch_account: Pubkey::default(),
            lock_digest: [0; 32],
            ciphertext_hash: Sha256::digest(encrypted.as_bytes()).into(),
            index: self.index,
            share,
        })
    }

    pub(crate) fn release(
        &self,
        epoch_account: Pubkey,
        lock_digest: [u8; 32],
        ciphertext: &[u8],
    ) -> Result<ReleasedShareV1, CryptoError> {
        let encrypted = decode_ciphertext(ciphertext)?;
        let share = self
            .secret
            .decrypt_share(&encrypted.ciphertext)
            .ok_or(CryptoError::InvalidCiphertext)?;
        Ok(ReleasedShareV1::from_share(
            epoch_account,
            lock_digest,
            Sha256::digest(ciphertext).into(),
            self.index,
            share,
        ))
    }

    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 48] {
        self.secret.public_key_share().to_bytes()
    }

    pub(crate) const fn index(&self) -> usize {
        self.index
    }

    pub(crate) const fn epoch_account(&self) -> Pubkey {
        self.epoch_account
    }

    pub(crate) const fn secret(&self) -> &SecretKeyShare {
        &self.secret
    }

    pub(crate) const fn from_secret(
        epoch_account: Pubkey,
        index: usize,
        secret: SecretKeyShare,
    ) -> Self {
        Self {
            epoch_account,
            index,
            secret,
        }
    }
}

fn encode_ciphertext(ciphertext: Ciphertext) -> Result<EncryptedIntentV1, CryptoError> {
    if !ciphertext.verify() {
        return Err(CryptoError::InvalidCiphertext);
    }
    let encoded = codec()
        .serialize(&ciphertext)
        .map_err(|_| CryptoError::InvalidCiphertext)?;
    if encoded.len() != ENCRYPTED_INTENT_V1_LEN {
        return Err(CryptoError::InvalidCiphertext);
    }
    Ok(EncryptedIntentV1 {
        encoded,
        ciphertext,
    })
}

fn decode_ciphertext(encoded: &[u8]) -> Result<EncryptedIntentV1, CryptoError> {
    if encoded.len() != ENCRYPTED_INTENT_V1_LEN {
        return Err(CryptoError::InvalidCiphertext);
    }
    let ciphertext: Ciphertext = codec()
        .deserialize(encoded)
        .map_err(|_| CryptoError::InvalidCiphertext)?;
    if !ciphertext.verify() {
        return Err(CryptoError::InvalidCiphertext);
    }
    Ok(EncryptedIntentV1 {
        encoded: encoded.to_vec(),
        ciphertext,
    })
}

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedSubmissionV1 {
    pub(crate) authorization: FundedAuthorizationV1,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) receipt: [u8; 32],
    pub(crate) outer_signature: [u8; 64],
}

impl fmt::Debug for EncryptedSubmissionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedSubmissionV1(..redacted)")
    }
}

impl EncryptedSubmissionV1 {
    #[must_use]
    pub const fn participant_id(&self) -> [u8; 32] {
        self.authorization.participant_id()
    }

    pub fn sign(
        authorization: FundedAuthorizationV1,
        encrypted: EncryptedIntentV1,
        receipt: [u8; 32],
        trading_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        if receipt == [0; 32] {
            return Err(CryptoError::InvalidReceipt);
        }
        if trading_key.verifying_key().to_bytes() != authorization.trading_key {
            return Err(CryptoError::WrongTradingKey);
        }
        let ciphertext = encrypted.encoded;
        let message = submission_message(
            authorization.epoch_id,
            authorization.hash(),
            Sha256::digest(&ciphertext).into(),
            receipt,
        );
        Ok(Self {
            authorization,
            ciphertext,
            receipt,
            outer_signature: trading_key.sign(&message).to_bytes(),
        })
    }

    #[must_use]
    pub const fn from_wire_parts(
        authorization: FundedAuthorizationV1,
        ciphertext: Vec<u8>,
        receipt: [u8; 32],
        outer_signature: [u8; 64],
    ) -> Self {
        Self {
            authorization,
            ciphertext,
            receipt,
            outer_signature,
        }
    }

    #[must_use]
    pub fn into_wire_parts(self) -> (FundedAuthorizationV1, Vec<u8>, [u8; 32], [u8; 64]) {
        (
            self.authorization,
            self.ciphertext,
            self.receipt,
            self.outer_signature,
        )
    }

    pub fn verify_admission(&self, policy: &AdmissionPolicyV1) -> Result<(), CryptoError> {
        self.authorization.verify(policy)?;
        if self.receipt == [0; 32] {
            return Err(CryptoError::InvalidReceipt);
        }
        decode_ciphertext(&self.ciphertext)?;
        let trading_key = self.authorization.trading_key()?;
        let message = submission_message(
            self.authorization.epoch_id,
            self.authorization.hash(),
            Sha256::digest(&self.ciphertext).into(),
            self.receipt,
        );
        trading_key
            .verify(&message, &Signature::from_bytes(&self.outer_signature))
            .map_err(|_| CryptoError::InvalidOuterSignature)
    }

    pub(crate) fn commitment_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FUNDED_AUTHORIZATION_V1_LEN + 32 + 32 + 64);
        bytes.extend_from_slice(&self.authorization.encode());
        bytes.extend_from_slice(&Sha256::digest(&self.ciphertext));
        bytes.extend_from_slice(&self.receipt);
        bytes.extend_from_slice(&self.outer_signature);
        bytes
    }

    pub(crate) fn encode_wire(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ENCRYPTED_SUBMISSION_V1_LEN);
        bytes.extend_from_slice(&self.authorization.encode());
        bytes.extend_from_slice(&self.ciphertext);
        bytes.extend_from_slice(&self.receipt);
        bytes.extend_from_slice(&self.outer_signature);
        bytes
    }

    pub(crate) fn decode_wire(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ENCRYPTED_SUBMISSION_V1_LEN {
            return Err(CryptoError::InvalidCiphertext);
        }
        let authorization = FundedAuthorizationV1::decode(&bytes[..FUNDED_AUTHORIZATION_V1_LEN])?;
        let ciphertext_end = FUNDED_AUTHORIZATION_V1_LEN + ENCRYPTED_INTENT_V1_LEN;
        let receipt_end = ciphertext_end + 32;
        Ok(Self::from_wire_parts(
            authorization,
            bytes[FUNDED_AUTHORIZATION_V1_LEN..ciphertext_end].to_vec(),
            bytes[ciphertext_end..receipt_end]
                .try_into()
                .map_err(|_| CryptoError::InvalidReceipt)?,
            bytes[receipt_end..]
                .try_into()
                .map_err(|_| CryptoError::InvalidOuterSignature)?,
        ))
    }
}

fn submission_message(
    epoch_id: [u8; 32],
    authorization_hash: [u8; 32],
    ciphertext_hash: [u8; 32],
    receipt: [u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(SUBMISSION_DOMAIN.len() + 128);
    message.extend_from_slice(SUBMISSION_DOMAIN);
    message.extend_from_slice(&epoch_id);
    message.extend_from_slice(&authorization_hash);
    message.extend_from_slice(&ciphertext_hash);
    message.extend_from_slice(&receipt);
    message
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedBatch {
    members: Vec<EncryptedSubmissionV1>,
}

impl AdmittedBatch {
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    #[must_use]
    pub fn participant_ids(&self) -> Vec<[u8; 32]> {
        self.members
            .iter()
            .map(|member| member.authorization.participant_id)
            .collect()
    }
}

pub fn admit_batch(
    submissions: &[EncryptedSubmissionV1],
    policy: &AdmissionPolicyV1,
) -> Result<AdmittedBatch, CryptoError> {
    let mut valid = BTreeMap::new();
    let mut nonces = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    for submission in submissions {
        if submission.verify_admission(policy).is_ok()
            && !valid.contains_key(&submission.authorization.participant_id)
            && nonces.insert(submission.authorization.nonce)
            && receipts.insert(submission.receipt)
        {
            valid
                .entry(submission.authorization.participant_id)
                .or_insert_with(|| submission.clone());
        }
    }
    if valid.len() < policy.minimum {
        return Err(CryptoError::InsufficientCrowd {
            valid: valid.len(),
            minimum: policy.minimum,
        });
    }
    Ok(AdmittedBatch {
        members: valid.into_values().collect(),
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::Side;

    fn signed_intent(epoch: [u8; 32]) -> (SigningKey, SignedIntentV1) {
        let trading = SigningKey::from_bytes(&[7; 32]);
        let body = IntentBodyV1::new(Side::Buy, 1, 100, epoch, [7; 32], [8; 16]).expect("intent");
        let signed = SignedIntentV1::sign(body, &trading);
        (trading, signed)
    }

    #[test]
    fn every_two_share_pair_recovers_while_one_duplicate_or_wrong_share_fails() {
        let epoch = [42; 32];
        let (trading, signed) = signed_intent(epoch);
        let dealer = EpochDealer::random().expect("dealer");
        let encrypted = dealer.public_keys().encrypt(&signed).expect("encrypt");
        let epoch_account = Pubkey::new_unique();
        let shares: Vec<_> = (0..3)
            .map(|index| {
                dealer
                    .share(epoch_account, index)
                    .decrypt(&encrypted)
                    .expect("share")
            })
            .collect();

        for share in &shares {
            assert_eq!(
                dealer.public_keys().recover(&encrypted, [share]),
                Err(CryptoError::InsufficientShares)
            );
        }
        for pair in [[0, 1], [0, 2], [1, 2]] {
            let recovered = dealer
                .public_keys()
                .recover(&encrypted, [&shares[pair[0]], &shares[pair[1]]])
                .expect("two shares");
            assert_eq!(recovered, signed);
        }
        assert_eq!(
            dealer
                .public_keys()
                .recover(&encrypted, [&shares[0], &shares[0]]),
            Err(CryptoError::DuplicateShare)
        );

        let wrong_dealer = EpochDealer::random().expect("wrong dealer");
        let wrong_share = wrong_dealer
            .share(epoch_account, 1)
            .decrypt(&encrypted)
            .expect("structural share");
        assert_eq!(
            dealer
                .public_keys()
                .recover(&encrypted, [&shares[0], &wrong_share]),
            Err(CryptoError::InvalidShare)
        );

        let recovered = dealer
            .public_keys()
            .recover(&encrypted, [&shares[0], &shares[1]])
            .expect("recover");
        assert_eq!(
            recovered.verify(&trading.verifying_key(), [41; 32], [7; 32]),
            Err(CryptoError::WrongEpoch)
        );
    }
}
