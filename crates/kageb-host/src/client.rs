use std::{
    fmt,
    fs::OpenOptions,
    io::{self, Read, Write},
    path::Path,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    EncryptedSubmissionV1, EpochPublicKeys, FundedAuthorizationV1, IntentBodyV1, Side,
    SignedIntentV1,
};

const CLIENT_SCHEMA_VERSION: u8 = 1;
const MAX_CLIENT_REQUEST_LEN: usize = 16 * 1024;
const MAX_KEYPAIR_FILE_LEN: usize = 1_024;
const SOLANA_KEYPAIR_LEN: usize = 64;

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

pub fn handle_client_prepare(keypair_path: &Path) -> Result<(), ClientPrepareError> {
    let mut encoded_request = Zeroizing::new(Vec::with_capacity(MAX_CLIENT_REQUEST_LEN + 1));
    io::stdin()
        .take((MAX_CLIENT_REQUEST_LEN + 1) as u64)
        .read_to_end(&mut encoded_request)
        .map_err(|_| ClientPrepareError::Input)?;
    if encoded_request.is_empty() || encoded_request.len() > MAX_CLIENT_REQUEST_LEN {
        return Err(ClientPrepareError::Input);
    }

    let response = prepare_submission(&encoded_request, keypair_path)?;
    let mut encoded_response =
        serde_json::to_vec(&response).map_err(|_| ClientPrepareError::Output)?;
    encoded_response.push(b'\n');
    io::stdout()
        .write_all(&encoded_response)
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
    if authorization.epoch_id() != epoch_id || authorization.participant_id() != participant_id {
        return Err(ClientPrepareError::Request);
    }

    let public_keys_wire = decode_canonical_base64(&request.epoch_public_keys_base64)?;
    let public_keys =
        EpochPublicKeys::decode_wire(&public_keys_wire).map_err(|_| ClientPrepareError::Request)?;
    let trading_key = read_trading_key(keypair_path)?;
    let trading_public_key = trading_key.verifying_key().to_bytes();
    if authorization.trading_key != trading_public_key {
        return Err(ClientPrepareError::Request);
    }

    let body = IntentBodyV1::new(
        request.side.into(),
        1,
        request.limit_price,
        epoch_id,
        participant_id,
        random_bytes()?,
    )
    .map_err(|_| ClientPrepareError::Request)?;
    let signed_intent = SignedIntentV1::sign(body, &trading_key);
    let encrypted = public_keys
        .encrypt(&signed_intent)
        .map_err(|_| ClientPrepareError::Request)?;
    let ciphertext_hash = Sha256::digest(encrypted.as_bytes());
    let mut receipt = random_bytes()?;
    if receipt == [0; 32] {
        receipt[0] = 1;
    }
    let submission = EncryptedSubmissionV1::sign(authorization, encrypted, receipt, &trading_key)
        .map_err(|_| ClientPrepareError::Request)?;
    let submission_wire = submission.encode_wire();

    Ok(ClientPrepareResponse {
        schema_version: CLIENT_SCHEMA_VERSION,
        epoch_id: bs58::encode(epoch_id).into_string(),
        participant_id: bs58::encode(participant_id).into_string(),
        trading_key: bs58::encode(trading_public_key).into_string(),
        ciphertext_sha256_base64: BASE64.encode(ciphertext_hash),
        submission_sha256_base64: BASE64.encode(Sha256::digest(&submission_wire)),
        encrypted_submission_base64: BASE64.encode(submission_wire),
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
