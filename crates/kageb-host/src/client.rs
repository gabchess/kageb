use std::{
    fmt,
    fs::OpenOptions,
    io::{self, Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    AccountJournal, EncryptedSubmissionV1, EpochPublicKeys, FundedAuthorizationV1, IntentBodyV1,
    PoolBalance, Side, SignedIntentV1,
};

const CLIENT_SCHEMA_VERSION: u8 = 1;
const MAX_CLIENT_REQUEST_LEN: usize = 16 * 1024;
const MAX_KEYPAIR_FILE_LEN: usize = 1_024;
const SOLANA_KEYPAIR_LEN: usize = 64;

pub struct PrepareOrderV1 {
    side: Side,
    limit_price: u64,
    epoch_id: [u8; 32],
    participant_id: [u8; 32],
    authorization: FundedAuthorizationV1,
    public_keys: EpochPublicKeys,
}

impl PrepareOrderV1 {
    pub fn new(
        side: Side,
        limit_price: u64,
        epoch_id: [u8; 32],
        participant_id: [u8; 32],
        authorization: FundedAuthorizationV1,
        public_keys: EpochPublicKeys,
    ) -> Result<Self, ClientPrepareError> {
        if limit_price == 0
            || authorization.epoch_id() != epoch_id
            || authorization.participant_id() != participant_id
        {
            return Err(ClientPrepareError::Request);
        }
        Ok(Self {
            side,
            limit_price,
            epoch_id,
            participant_id,
            authorization,
            public_keys,
        })
    }
}

pub struct PreparedOrderV1 {
    signed_intent: SignedIntentV1,
    submission: EncryptedSubmissionV1,
}

impl PreparedOrderV1 {
    #[must_use]
    pub const fn signed_intent(&self) -> &SignedIntentV1 {
        &self.signed_intent
    }

    #[must_use]
    pub const fn submission(&self) -> &EncryptedSubmissionV1 {
        &self.submission
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientPrepareError {
    Input,
    KeyFile,
    Request,
    Entropy,
    Output,
}

impl fmt::Display for ClientPrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Input => "input unavailable or too large",
            Self::KeyFile => "keypair file rejected",
            Self::Request => "request rejected",
            Self::Entropy => "OS randomness unavailable",
            Self::Output => "output unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ClientPrepareError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientPrepareRequest {
    schema_version: u8,
    side: ClientSide,
    limit_price: u64,
    epoch_id: String,
    participant_id: String,
    funded_authorization_base64: String,
    epoch_public_keys_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientAccountRequest {
    schema_version: u8,
    participant_id: String,
    base_atoms: u64,
    quote_atoms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientResultRequest {
    schema_version: u8,
    participant_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClientEpochView {
    schema_version: u8,
    epoch_id: String,
    base_mint: String,
    quote_mint: String,
    base_lot_atoms: u64,
    quote_atoms_per_lot: u64,
    minimum_count: u32,
    keyper_threshold: u8,
    lock_deadline: i64,
    abort_deadline: i64,
    epoch_public_keys_base64: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ClientSide {
    Buy,
    Sell,
}

impl From<ClientSide> for Side {
    fn from(side: ClientSide) -> Self {
        match side {
            ClientSide::Buy => Self::Buy,
            ClientSide::Sell => Self::Sell,
        }
    }
}

#[derive(Serialize)]
struct ClientPrepareResponse {
    schema_version: u8,
    epoch_id: String,
    participant_id: String,
    trading_key: String,
    ciphertext_sha256_base64: String,
    submission_sha256_base64: String,
    encrypted_submission_base64: String,
}

#[derive(Serialize)]
struct ClientAccountResponse {
    schema_version: u8,
    participant_id: String,
    trading_key: String,
    base_atoms: u64,
    quote_atoms: u64,
}

#[derive(Serialize)]
struct ClientResultResponse {
    schema_version: u8,
    participant_id: String,
    epoch_id: String,
    base_atoms: u64,
    quote_atoms: u64,
}

pub fn handle_client_prepare(keypair_path: &Path) -> Result<(), ClientPrepareError> {
    let encoded_request = read_request()?;
    let response = prepare_submission(&encoded_request, keypair_path)?;
    write_response(&response)
}

pub fn handle_client_account(
    state_path: &Path,
    keypair_path: &Path,
) -> Result<(), ClientPrepareError> {
    let encoded = read_request()?;
    let request: ClientAccountRequest =
        serde_json::from_slice(&encoded).map_err(|_| ClientPrepareError::Request)?;
    if request.schema_version != CLIENT_SCHEMA_VERSION
        || request.base_atoms == 0
        || request.quote_atoms == 0
    {
        return Err(ClientPrepareError::Request);
    }
    let participant_id = decode_base58_32(&request.participant_id)?;
    let trading_key = read_trading_key(keypair_path)?;
    AccountJournal::open(state_path)
        .and_then(|mut journal| {
            journal.register(
                participant_id,
                trading_key.verifying_key(),
                PoolBalance::new(request.base_atoms, request.quote_atoms),
            )
        })
        .map_err(|_| ClientPrepareError::Request)?;
    write_response(&ClientAccountResponse {
        schema_version: CLIENT_SCHEMA_VERSION,
        participant_id: bs58::encode(participant_id).into_string(),
        trading_key: bs58::encode(trading_key.verifying_key().to_bytes()).into_string(),
        base_atoms: request.base_atoms,
        quote_atoms: request.quote_atoms,
    })
}

pub fn handle_client_result(
    state_path: &Path,
    keypair_path: &Path,
) -> Result<(), ClientPrepareError> {
    let encoded = read_request()?;
    let request: ClientResultRequest =
        serde_json::from_slice(&encoded).map_err(|_| ClientPrepareError::Request)?;
    if request.schema_version != CLIENT_SCHEMA_VERSION {
        return Err(ClientPrepareError::Request);
    }
    let participant_id = decode_base58_32(&request.participant_id)?;
    let trading_key = read_trading_key(keypair_path)?;
    let result = AccountJournal::open(state_path)
        .and_then(|mut journal| journal.query_result(participant_id, trading_key.verifying_key()))
        .map_err(|_| ClientPrepareError::Request)?;
    let balance = result.balance();
    write_response(&ClientResultResponse {
        schema_version: CLIENT_SCHEMA_VERSION,
        participant_id: bs58::encode(participant_id).into_string(),
        epoch_id: bs58::encode(result.epoch_id()).into_string(),
        base_atoms: balance.base_atoms,
        quote_atoms: balance.quote_atoms,
    })
}

pub fn handle_client_epoch() -> Result<(), ClientPrepareError> {
    let encoded = read_request()?;
    let request: ClientEpochView =
        serde_json::from_slice(&encoded).map_err(|_| ClientPrepareError::Request)?;
    let epoch_id = decode_base58_32(&request.epoch_id)?;
    let base_mint = decode_base58_32(&request.base_mint)?;
    let quote_mint = decode_base58_32(&request.quote_mint)?;
    let public_keys = decode_canonical_base64(&request.epoch_public_keys_base64)?;
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClientPrepareError::Request)?
            .as_secs(),
    )
    .map_err(|_| ClientPrepareError::Request)?;
    if request.schema_version != CLIENT_SCHEMA_VERSION
        || epoch_id == [0; 32]
        || base_mint == [0; 32]
        || quote_mint == [0; 32]
        || base_mint == quote_mint
        || request.base_lot_atoms == 0
        || request.quote_atoms_per_lot == 0
        || request.minimum_count < 4
        || request.keyper_threshold != 2
        || request.lock_deadline <= now
        || request.abort_deadline <= request.lock_deadline
        || EpochPublicKeys::decode_wire(&public_keys).is_err()
    {
        return Err(ClientPrepareError::Request);
    }
    write_response(&request)
}

fn read_request() -> Result<Zeroizing<Vec<u8>>, ClientPrepareError> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_CLIENT_REQUEST_LEN + 1));
    io::stdin()
        .take((MAX_CLIENT_REQUEST_LEN + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|_| ClientPrepareError::Input)?;
    if encoded.is_empty() || encoded.len() > MAX_CLIENT_REQUEST_LEN {
        return Err(ClientPrepareError::Input);
    }
    Ok(encoded)
}

fn write_response(response: &impl Serialize) -> Result<(), ClientPrepareError> {
    let mut encoded = serde_json::to_vec(response).map_err(|_| ClientPrepareError::Output)?;
    encoded.push(b'\n');
    io::stdout()
        .write_all(&encoded)
        .map_err(|_| ClientPrepareError::Output)
}

fn prepare_submission(
    encoded_request: &[u8],
    keypair_path: &Path,
) -> Result<ClientPrepareResponse, ClientPrepareError> {
    let request: ClientPrepareRequest =
        serde_json::from_slice(encoded_request).map_err(|_| ClientPrepareError::Request)?;
    if request.schema_version != CLIENT_SCHEMA_VERSION || request.limit_price == 0 {
        return Err(ClientPrepareError::Request);
    }

    let epoch_id = decode_base58_32(&request.epoch_id)?;
    let participant_id = decode_base58_32(&request.participant_id)?;
    let authorization_wire = decode_canonical_base64(&request.funded_authorization_base64)?;
    let authorization = FundedAuthorizationV1::decode(&authorization_wire)
        .map_err(|_| ClientPrepareError::Request)?;
    let public_keys_wire = decode_canonical_base64(&request.epoch_public_keys_base64)?;
    let public_keys =
        EpochPublicKeys::decode_wire(&public_keys_wire).map_err(|_| ClientPrepareError::Request)?;
    let trading_key = read_trading_key(keypair_path)?;
    let trading_public_key = trading_key.verifying_key().to_bytes();
    let mut receipt = random_bytes()?;
    if receipt == [0; 32] {
        receipt[0] = 1;
    }
    let prepared = prepare_order(
        PrepareOrderV1::new(
            request.side.into(),
            request.limit_price,
            epoch_id,
            participant_id,
            authorization,
            public_keys,
        )?,
        &trading_key,
        random_bytes()?,
        receipt,
    )?;
    let submission_wire = prepared.submission.encode_wire();
    let (_, ciphertext, _, _) = prepared.submission.into_wire_parts();

    Ok(ClientPrepareResponse {
        schema_version: CLIENT_SCHEMA_VERSION,
        epoch_id: bs58::encode(epoch_id).into_string(),
        participant_id: bs58::encode(participant_id).into_string(),
        trading_key: bs58::encode(trading_public_key).into_string(),
        ciphertext_sha256_base64: BASE64.encode(Sha256::digest(ciphertext)),
        submission_sha256_base64: BASE64.encode(Sha256::digest(&submission_wire)),
        encrypted_submission_base64: BASE64.encode(submission_wire),
    })
}

pub fn prepare_order(
    request: PrepareOrderV1,
    trading_key: &SigningKey,
    intent_nonce: [u8; 16],
    receipt: [u8; 32],
) -> Result<PreparedOrderV1, ClientPrepareError> {
    if receipt == [0; 32]
        || request.authorization.trading_key != trading_key.verifying_key().to_bytes()
    {
        return Err(ClientPrepareError::Request);
    }
    let body = IntentBodyV1::new(
        request.side,
        1,
        request.limit_price,
        request.epoch_id,
        request.participant_id,
        intent_nonce,
    )
    .map_err(|_| ClientPrepareError::Request)?;
    let signed_intent = SignedIntentV1::sign(body, trading_key);
    let encrypted = request
        .public_keys
        .encrypt(&signed_intent)
        .map_err(|_| ClientPrepareError::Request)?;
    let submission =
        EncryptedSubmissionV1::sign(request.authorization, encrypted, receipt, trading_key)
            .map_err(|_| ClientPrepareError::Request)?;
    Ok(PreparedOrderV1 {
        signed_intent,
        submission,
    })
}

fn decode_base58_32(encoded: &str) -> Result<[u8; 32], ClientPrepareError> {
    let decoded = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| ClientPrepareError::Request)?;
    let bytes =
        <[u8; 32]>::try_from(decoded.as_slice()).map_err(|_| ClientPrepareError::Request)?;
    if bs58::encode(bytes).into_string() != encoded {
        return Err(ClientPrepareError::Request);
    }
    Ok(bytes)
}

fn decode_canonical_base64(encoded: &str) -> Result<Vec<u8>, ClientPrepareError> {
    let decoded = BASE64
        .decode(encoded)
        .map_err(|_| ClientPrepareError::Request)?;
    if BASE64.encode(&decoded) != encoded {
        return Err(ClientPrepareError::Request);
    }
    Ok(decoded)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], ClientPrepareError> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| ClientPrepareError::Entropy)?;
    Ok(bytes)
}

fn read_trading_key(path: &Path) -> Result<SigningKey, ClientPrepareError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| ClientPrepareError::KeyFile)?;
    let metadata = file.metadata().map_err(|_| ClientPrepareError::KeyFile)?;
    if !metadata.is_file() || metadata.len() > MAX_KEYPAIR_FILE_LEN as u64 {
        return Err(ClientPrepareError::KeyFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(ClientPrepareError::KeyFile);
        }
    }

    let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_KEYPAIR_FILE_LEN + 1));
    file.take((MAX_KEYPAIR_FILE_LEN + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|_| ClientPrepareError::KeyFile)?;
    if encoded.is_empty() || encoded.len() > MAX_KEYPAIR_FILE_LEN {
        return Err(ClientPrepareError::KeyFile);
    }
    let keypair_bytes = Zeroizing::new(
        serde_json::from_slice::<Vec<u8>>(&encoded).map_err(|_| ClientPrepareError::KeyFile)?,
    );
    if keypair_bytes.len() != SOLANA_KEYPAIR_LEN {
        return Err(ClientPrepareError::KeyFile);
    }

    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(&keypair_bytes[..32]);
    let signing_key = SigningKey::from_bytes(&seed);
    if signing_key.verifying_key().to_bytes() != keypair_bytes[32..] {
        return Err(ClientPrepareError::KeyFile);
    }
    Ok(signing_key)
}
