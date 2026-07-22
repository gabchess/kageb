use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
    process::{Command, Output, Stdio},
};

use bincode::Options;
use serde::{Deserialize, Serialize};
use solana_program::pubkey::Pubkey;
use threshold_crypto::{
    serde_impl::SerdeSecret, PublicKeyShare, SecretKeyShare, SignatureShare, PK_SIZE, SIG_SIZE,
};
use zeroize::Zeroizing;

use crate::{
    KeyperSecretShare, LockApprovalV1, LockJournal, LockPackageV1, ProgramClient, ReferenceKeyper,
};
use ed25519_dalek::SigningKey;

const REQUEST_VERSION: u8 = 1;
const REQUEST_LEN: usize = 73;
const RESPONSE_LEN: usize = 1 + 8 + PK_SIZE + SIG_SIZE;
const BOUND_SHARE_LEN: usize = 73;
const SIGN_LOCK_PREFIX_LEN: usize = BOUND_SHARE_LEN + 4;
const SIGN_LOCK_RESPONSE_LEN: usize = 129;
const MAX_SIGN_LOCK_REQUEST_LEN: usize = 64 * 1024;
const KEYPER_RPC_CONFIG: &str = "keyper-rpc-url";
const KEYPER_ATTESTATION_KEY: &str = "keyper-attestation-key";
const RELEASE_PREFIX_LEN: usize = BOUND_SHARE_LEN + 8;
const MAX_RELEASE_REQUEST_LEN: usize = 64 * 1024;
const MAX_SETTLEMENT_REQUEST_LEN: usize = 128 * 1024;
const MAX_SETTLEMENT_FRAME_LEN: usize = BOUND_SHARE_LEN + MAX_SETTLEMENT_REQUEST_LEN;
const SETTLEMENT_STDIN_READ_LIMIT: usize = MAX_SETTLEMENT_FRAME_LEN + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyperProcessError {
    InsecureDirectory,
    Spawn,
    Input,
    ChildFailed,
    InvalidRequest,
    InvalidResponse,
    SecretLeak,
}

#[derive(Serialize)]
struct SelfTestRequestRef<'a> {
    version: u8,
    index: u64,
    challenge: [u8; 32],
    share: SerdeSecret<&'a SecretKeyShare>,
}

#[derive(Deserialize)]
struct SelfTestRequest {
    version: u8,
    index: u64,
    challenge: [u8; 32],
    share: SerdeSecret<SecretKeyShare>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyperSelfTestResponse {
    index: usize,
    public_key_share: [u8; PK_SIZE],
    signature: [u8; SIG_SIZE],
}

impl KeyperSelfTestResponse {
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    #[must_use]
    pub const fn public_key_share(&self) -> [u8; PK_SIZE] {
        self.public_key_share
    }

    #[must_use]
    pub fn verify(&self, challenge: [u8; 32]) -> bool {
        let Ok(public_key) = PublicKeyShare::from_bytes(self.public_key_share) else {
            return false;
        };
        let Ok(signature) = SignatureShare::from_bytes(self.signature) else {
            return false;
        };
        public_key.verify(&signature, challenge)
    }
}

pub fn run_keyper_self_test(
    executable: impl AsRef<Path>,
    private_directory: impl AsRef<Path>,
    share: &KeyperSecretShare,
    challenge: [u8; 32],
) -> Result<KeyperSelfTestResponse, KeyperProcessError> {
    verify_private_directory(private_directory.as_ref())?;
    let index = u64::try_from(share.index()).map_err(|_| KeyperProcessError::Input)?;
    let request = SelfTestRequestRef {
        version: REQUEST_VERSION,
        index,
        challenge,
        share: SerdeSecret(share.secret()),
    };
    let encoded = Zeroizing::new(
        codec()
            .serialize(&request)
            .map_err(|_| KeyperProcessError::Input)?,
    );
    if encoded.len() != REQUEST_LEN {
        return Err(KeyperProcessError::Input);
    }
    let secret_bytes = Zeroizing::new(
        codec()
            .serialize(&SerdeSecret(share.secret()))
            .map_err(|_| KeyperProcessError::Input)?,
    );

    let mut child = Command::new(executable.as_ref())
        .args(["keyper", "self-test"])
        .env_clear()
        .current_dir(private_directory.as_ref())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| KeyperProcessError::Spawn)?;
    let mut stdin = child.stdin.take().ok_or(KeyperProcessError::Spawn)?;
    let write_result = stdin.write_all(&encoded).and_then(|()| stdin.flush());
    drop(stdin);
    write_result.map_err(|_| KeyperProcessError::Input)?;

    let output = child
        .wait_with_output()
        .map_err(|_| KeyperProcessError::ChildFailed)?;
    if !output.status.success() {
        return Err(KeyperProcessError::ChildFailed);
    }
    if contains_bytes(&output.stdout, &secret_bytes)
        || contains_bytes(&output.stderr, &secret_bytes)
    {
        return Err(KeyperProcessError::SecretLeak);
    }
    if !output.stderr.is_empty() {
        return Err(KeyperProcessError::InvalidResponse);
    }
    let response = decode_response(&output.stdout)?;
    if response.index != share.index() || !response.verify(challenge) {
        return Err(KeyperProcessError::InvalidResponse);
    }
    Ok(response)
}

pub fn run_keyper_sign_lock(
    executable: impl AsRef<Path>,
    private_directory: impl AsRef<Path>,
    share: &KeyperSecretShare,
    expected_keyper: Pubkey,
    package: &LockPackageV1,
) -> Result<LockApprovalV1, KeyperProcessError> {
    verify_private_directory(private_directory.as_ref())?;
    let expected_digest = package.lock_payload().digest();
    let package = package
        .encode_wire()
        .map_err(|_| KeyperProcessError::Input)?;
    let package_len = u32::try_from(package.len()).map_err(|_| KeyperProcessError::Input)?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(SIGN_LOCK_PREFIX_LEN + package.len()));
    let secret_bytes = append_bound_share(&mut encoded, share)?;
    encoded.extend_from_slice(&package_len.to_le_bytes());
    encoded.extend_from_slice(&package);
    if encoded.len() > MAX_SIGN_LOCK_REQUEST_LEN {
        return Err(KeyperProcessError::Input);
    }
    let output = run_one_shot(
        executable.as_ref(),
        private_directory.as_ref(),
        "sign-lock",
        &encoded,
        &secret_bytes,
    )?;
    if !output.status.success() {
        return Err(KeyperProcessError::ChildFailed);
    }
    if !output.stderr.is_empty() || output.stdout.len() != SIGN_LOCK_RESPONSE_LEN {
        return Err(KeyperProcessError::InvalidResponse);
    }
    let approval = LockApprovalV1::from_parts(
        output.stdout[1..33]
            .try_into()
            .map_err(|_| KeyperProcessError::InvalidResponse)?,
        output.stdout[33..65]
            .try_into()
            .map_err(|_| KeyperProcessError::InvalidResponse)?,
        output.stdout[65..129]
            .try_into()
            .map_err(|_| KeyperProcessError::InvalidResponse)?,
    );
    if output.stdout[0] != REQUEST_VERSION {
        return Err(KeyperProcessError::InvalidResponse);
    }
    validate_lock_approval(expected_keyper, expected_digest, &approval)?;
    Ok(approval)
}

pub fn run_keyper_release_share(
    executable: impl AsRef<Path>,
    private_directory: impl AsRef<Path>,
    share: &KeyperSecretShare,
    package: &LockPackageV1,
    member_index: usize,
) -> Result<crate::ReleasedShareV1, KeyperProcessError> {
    verify_private_directory(private_directory.as_ref())?;
    let package_bytes = package
        .encode_wire()
        .map_err(|_| KeyperProcessError::Input)?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(RELEASE_PREFIX_LEN + package_bytes.len()));
    let secret_bytes = append_bound_share(&mut encoded, share)?;
    encoded.extend_from_slice(
        &u32::try_from(member_index)
            .map_err(|_| KeyperProcessError::Input)?
            .to_le_bytes(),
    );
    encoded.extend_from_slice(
        &u32::try_from(package_bytes.len())
            .map_err(|_| KeyperProcessError::Input)?
            .to_le_bytes(),
    );
    encoded.extend_from_slice(&package_bytes);
    if encoded.len() > MAX_RELEASE_REQUEST_LEN {
        return Err(KeyperProcessError::Input);
    }
    let output = run_one_shot(
        executable.as_ref(),
        private_directory.as_ref(),
        "release-share",
        &encoded,
        &secret_bytes,
    )?;
    if !output.status.success() {
        return Err(KeyperProcessError::ChildFailed);
    }
    if !output.stderr.is_empty() {
        return Err(KeyperProcessError::InvalidResponse);
    }
    let released = crate::ReleasedShareV1::decode_wire(&output.stdout)
        .map_err(|_| KeyperProcessError::InvalidResponse)?;
    let submission = package
        .submissions
        .get(member_index)
        .ok_or(KeyperProcessError::Input)?;
    if released.index() != share.index()
        || released.epoch_account() != package.epoch_account()
        || released.lock_digest() != package.lock_payload().digest()
        || !released.verify(&package.epoch_public_keys, submission)
    {
        return Err(KeyperProcessError::InvalidResponse);
    }
    Ok(released)
}

pub fn run_keyper_sign_settlement(
    executable: impl AsRef<Path>,
    private_directory: impl AsRef<Path>,
    share: &KeyperSecretShare,
    expected_keyper: Pubkey,
    request: &crate::SettlementRequestV1,
) -> Result<crate::SettlementApprovalV1, KeyperProcessError> {
    verify_private_directory(private_directory.as_ref())?;
    let request_bytes = request
        .encode_wire()
        .map_err(|_| KeyperProcessError::Input)?;
    if request_bytes.len() > MAX_SETTLEMENT_REQUEST_LEN {
        return Err(KeyperProcessError::Input);
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(BOUND_SHARE_LEN + request_bytes.len()));
    let secret_bytes = append_bound_share(&mut encoded, share)?;
    encoded.extend_from_slice(&request_bytes);
    if encoded.len() > MAX_SETTLEMENT_FRAME_LEN {
        return Err(KeyperProcessError::Input);
    }
    let output = run_one_shot(
        executable.as_ref(),
        private_directory.as_ref(),
        "sign-settlement",
        &encoded,
        &secret_bytes,
    )?;
    if !output.status.success() {
        return Err(KeyperProcessError::ChildFailed);
    }
    if !output.stderr.is_empty() {
        return Err(KeyperProcessError::InvalidResponse);
    }
    let approval = crate::SettlementApprovalV1::decode_wire(&output.stdout)
        .map_err(|_| KeyperProcessError::InvalidResponse)?;
    if approval.keyper_key() != expected_keyper.to_bytes()
        || approval.digest() != request.settlement_digest
        || !approval.verify()
        || share.index() >= 3
    {
        return Err(KeyperProcessError::InvalidResponse);
    }
    Ok(approval)
}

fn append_bound_share(
    encoded: &mut Vec<u8>,
    share: &KeyperSecretShare,
) -> Result<Zeroizing<Vec<u8>>, KeyperProcessError> {
    let secret_bytes = Zeroizing::new(
        codec()
            .serialize(&SerdeSecret(share.secret()))
            .map_err(|_| KeyperProcessError::Input)?,
    );
    encoded.push(REQUEST_VERSION);
    encoded.extend_from_slice(share.epoch_account().as_ref());
    encoded.extend_from_slice(
        &u64::try_from(share.index())
            .map_err(|_| KeyperProcessError::Input)?
            .to_le_bytes(),
    );
    encoded.extend_from_slice(&secret_bytes);
    if encoded.len() != BOUND_SHARE_LEN {
        return Err(KeyperProcessError::Input);
    }
    Ok(secret_bytes)
}

fn decode_bound_share(encoded: &[u8]) -> Result<KeyperSecretShare, KeyperProcessError> {
    if encoded.len() != BOUND_SHARE_LEN || encoded[0] != REQUEST_VERSION {
        return Err(KeyperProcessError::InvalidRequest);
    }
    let epoch_account = Pubkey::new_from_array(
        encoded[1..33]
            .try_into()
            .map_err(|_| KeyperProcessError::InvalidRequest)?,
    );
    let index = usize::try_from(u64::from_le_bytes(
        encoded[33..41]
            .try_into()
            .map_err(|_| KeyperProcessError::InvalidRequest)?,
    ))
    .map_err(|_| KeyperProcessError::InvalidRequest)?;
    let secret: SerdeSecret<SecretKeyShare> = codec()
        .deserialize(&encoded[41..])
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    Ok(KeyperSecretShare::from_secret(
        epoch_account,
        index,
        secret.into_inner(),
    ))
}

fn run_one_shot(
    executable: &Path,
    private_directory: &Path,
    operation: &str,
    encoded: &[u8],
    secret_bytes: &[u8],
) -> Result<Output, KeyperProcessError> {
    let mut child = Command::new(executable)
        .args(["keyper", operation])
        .env_clear()
        .current_dir(private_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| KeyperProcessError::Spawn)?;
    let mut stdin = child.stdin.take().ok_or(KeyperProcessError::Spawn)?;
    stdin
        .write_all(encoded)
        .and_then(|()| stdin.flush())
        .map_err(|_| KeyperProcessError::Input)?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|_| KeyperProcessError::ChildFailed)?;
    if contains_bytes(executable.as_os_str().as_encoded_bytes(), secret_bytes)
        || contains_bytes(
            private_directory.as_os_str().as_encoded_bytes(),
            secret_bytes,
        )
        || contains_bytes(operation.as_bytes(), secret_bytes)
        || contains_bytes(&output.stdout, secret_bytes)
        || contains_bytes(&output.stderr, secret_bytes)
        || directory_contains_bytes(private_directory, secret_bytes)?
    {
        return Err(KeyperProcessError::SecretLeak);
    }
    Ok(output)
}

fn directory_contains_bytes(path: &Path, needle: &[u8]) -> Result<bool, KeyperProcessError> {
    for entry in fs::read_dir(path).map_err(|_| KeyperProcessError::Input)? {
        let entry = entry.map_err(|_| KeyperProcessError::Input)?;
        let file_type = entry.file_type().map_err(|_| KeyperProcessError::Input)?;
        if file_type.is_symlink() {
            return Err(KeyperProcessError::Input);
        }
        if file_type.is_dir() {
            if directory_contains_bytes(&entry.path(), needle)? {
                return Ok(true);
            }
        } else if file_type.is_file() {
            let bytes = fs::read(entry.path()).map_err(|_| KeyperProcessError::Input)?;
            if contains_bytes(&bytes, needle) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn validate_lock_approval(
    expected_keyper: Pubkey,
    expected_digest: [u8; 32],
    approval: &LockApprovalV1,
) -> Result<(), KeyperProcessError> {
    if approval.keyper_key() != expected_keyper.to_bytes()
        || approval.digest() != expected_digest
        || !approval.verify()
    {
        return Err(KeyperProcessError::InvalidResponse);
    }
    Ok(())
}

#[doc(hidden)]
pub fn handle_keyper_self_test() -> Result<(), KeyperProcessError> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(REQUEST_LEN + 1));
    io::stdin()
        .take((REQUEST_LEN + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    if encoded.len() != REQUEST_LEN {
        return Err(KeyperProcessError::InvalidRequest);
    }
    let request: SelfTestRequest = codec()
        .deserialize(&encoded)
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    if request.version != REQUEST_VERSION {
        return Err(KeyperProcessError::InvalidRequest);
    }
    let index = usize::try_from(request.index).map_err(|_| KeyperProcessError::InvalidRequest)?;
    let public_key_share = request.share.public_key_share().to_bytes();
    let signature = request.share.sign(request.challenge).to_bytes();
    let response = KeyperSelfTestResponse {
        index,
        public_key_share,
        signature,
    };
    io::stdout()
        .write_all(&encode_response(&response))
        .and_then(|()| io::stdout().flush())
        .map_err(|_| KeyperProcessError::InvalidResponse)
}

#[doc(hidden)]
pub fn handle_keyper_sign_lock() -> Result<(), KeyperProcessError> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_SIGN_LOCK_REQUEST_LEN + 1));
    io::stdin()
        .take((MAX_SIGN_LOCK_REQUEST_LEN + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    if encoded.len() < SIGN_LOCK_PREFIX_LEN || encoded.len() > MAX_SIGN_LOCK_REQUEST_LEN {
        return Err(KeyperProcessError::InvalidRequest);
    }
    if encoded[0] != REQUEST_VERSION {
        return Err(KeyperProcessError::InvalidRequest);
    }
    let secret = decode_bound_share(&encoded[..BOUND_SHARE_LEN])?;
    let index = secret.index();
    let package_len = u32::from_le_bytes(
        encoded[BOUND_SHARE_LEN..SIGN_LOCK_PREFIX_LEN]
            .try_into()
            .map_err(|_| KeyperProcessError::InvalidRequest)?,
    ) as usize;
    if SIGN_LOCK_PREFIX_LEN
        .checked_add(package_len)
        .ok_or(KeyperProcessError::InvalidRequest)?
        != encoded.len()
    {
        return Err(KeyperProcessError::InvalidRequest);
    }
    let package = LockPackageV1::decode_wire(&encoded[SIGN_LOCK_PREFIX_LEN..])
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    let signing_seed = read_keyper_attestation_key()?;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let rpc_url = read_keyper_rpc_url().map_err(|_| KeyperProcessError::InvalidRequest)?;
    let confirmed = ProgramClient::new(rpc_url)
        .fetch_confirmed_open_epoch(package.epoch_account())
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    let journal_path = std::env::current_dir()
        .map_err(|_| KeyperProcessError::InvalidRequest)?
        .join("keyper-locks.bin");
    let journal =
        LockJournal::open(journal_path).map_err(|_| KeyperProcessError::InvalidRequest)?;
    let mut keyper = ReferenceKeyper::new(index, signing_key, journal);
    let approval = keyper
        .sign_lock(&package, &confirmed, &secret)
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    let mut response = [0_u8; SIGN_LOCK_RESPONSE_LEN];
    response[0] = REQUEST_VERSION;
    response[1..33].copy_from_slice(&approval.keyper_key());
    response[33..65].copy_from_slice(&approval.digest());
    response[65..129].copy_from_slice(&approval.signature());
    io::stdout()
        .write_all(&response)
        .and_then(|()| io::stdout().flush())
        .map_err(|_| KeyperProcessError::InvalidResponse)
}

#[doc(hidden)]
pub fn handle_keyper_release_share() -> Result<(), KeyperProcessError> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_RELEASE_REQUEST_LEN + 1));
    io::stdin()
        .take((MAX_RELEASE_REQUEST_LEN + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    if encoded.len() < RELEASE_PREFIX_LEN
        || encoded.len() > MAX_RELEASE_REQUEST_LEN
        || encoded[0] != REQUEST_VERSION
    {
        return Err(KeyperProcessError::InvalidRequest);
    }
    let secret = decode_bound_share(&encoded[..BOUND_SHARE_LEN])?;
    let index = secret.index();
    let member_index = u32::from_le_bytes(
        encoded[BOUND_SHARE_LEN..BOUND_SHARE_LEN + 4]
            .try_into()
            .map_err(|_| KeyperProcessError::InvalidRequest)?,
    ) as usize;
    let package_len = u32::from_le_bytes(
        encoded[BOUND_SHARE_LEN + 4..RELEASE_PREFIX_LEN]
            .try_into()
            .map_err(|_| KeyperProcessError::InvalidRequest)?,
    ) as usize;
    if RELEASE_PREFIX_LEN.checked_add(package_len) != Some(encoded.len()) {
        return Err(KeyperProcessError::InvalidRequest);
    }
    let package = LockPackageV1::decode_wire(&encoded[RELEASE_PREFIX_LEN..])
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    if secret.epoch_account() != package.epoch_account() || secret.index() != index {
        return Err(KeyperProcessError::InvalidRequest);
    }
    let rpc_url = read_keyper_rpc_url()?;
    let confirmed = ProgramClient::new(rpc_url)
        .fetch_confirmed_lock(package.epoch_account())
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    let signing_seed = read_keyper_attestation_key()?;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let journal = LockJournal::open(
        std::env::current_dir()
            .map_err(|_| KeyperProcessError::InvalidRequest)?
            .join("keyper-locks.bin"),
    )
    .map_err(|_| KeyperProcessError::InvalidRequest)?;
    let keyper = ReferenceKeyper::new(index, signing_key, journal);
    let released = keyper
        .release_share(&package, &confirmed, &secret, member_index)
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    let response = released
        .encode_wire()
        .map_err(|_| KeyperProcessError::InvalidResponse)?;
    io::stdout()
        .write_all(&response)
        .and_then(|()| io::stdout().flush())
        .map_err(|_| KeyperProcessError::InvalidResponse)
}

#[doc(hidden)]
pub fn handle_keyper_sign_settlement() -> Result<(), KeyperProcessError> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(SETTLEMENT_STDIN_READ_LIMIT));
    io::stdin()
        .take(SETTLEMENT_STDIN_READ_LIMIT as u64)
        .read_to_end(&mut encoded)
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    if encoded.len() <= BOUND_SHARE_LEN || encoded.len() > MAX_SETTLEMENT_FRAME_LEN {
        return Err(KeyperProcessError::InvalidRequest);
    }
    let secret = decode_bound_share(&encoded[..BOUND_SHARE_LEN])?;
    let request = crate::SettlementRequestV1::decode_wire(&encoded[BOUND_SHARE_LEN..])
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    let rpc_url = read_keyper_rpc_url()?;
    let confirmed = ProgramClient::new(rpc_url)
        .fetch_confirmed_lock(request.package.epoch_account())
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    let signing_seed = read_keyper_attestation_key()?;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let journal = LockJournal::open(
        std::env::current_dir()
            .map_err(|_| KeyperProcessError::InvalidRequest)?
            .join("keyper-locks.bin"),
    )
    .map_err(|_| KeyperProcessError::InvalidRequest)?;
    let pool = confirmed
        .pool
        .as_ref()
        .ok_or(KeyperProcessError::InvalidRequest)?;
    let index = pool
        .keypers
        .iter()
        .position(|key| key.to_bytes() == signing_key.verifying_key().to_bytes())
        .ok_or(KeyperProcessError::InvalidRequest)?;
    let keyper = ReferenceKeyper::new(index, signing_key, journal);
    let approval = keyper
        .sign_settlement(&request, &confirmed, &secret)
        .map_err(|_| KeyperProcessError::InvalidRequest)?;
    io::stdout()
        .write_all(&approval.encode_wire())
        .and_then(|()| io::stdout().flush())
        .map_err(|_| KeyperProcessError::InvalidResponse)
}

fn encode_response(response: &KeyperSelfTestResponse) -> [u8; RESPONSE_LEN] {
    let mut encoded = [0_u8; RESPONSE_LEN];
    encoded[0] = REQUEST_VERSION;
    encoded[1..9].copy_from_slice(&(response.index as u64).to_le_bytes());
    encoded[9..9 + PK_SIZE].copy_from_slice(&response.public_key_share);
    encoded[9 + PK_SIZE..].copy_from_slice(&response.signature);
    encoded
}

fn decode_response(encoded: &[u8]) -> Result<KeyperSelfTestResponse, KeyperProcessError> {
    if encoded.len() != RESPONSE_LEN || encoded[0] != REQUEST_VERSION {
        return Err(KeyperProcessError::InvalidResponse);
    }
    let index = usize::try_from(u64::from_le_bytes(
        encoded[1..9]
            .try_into()
            .map_err(|_| KeyperProcessError::InvalidResponse)?,
    ))
    .map_err(|_| KeyperProcessError::InvalidResponse)?;
    let response = KeyperSelfTestResponse {
        index,
        public_key_share: encoded[9..9 + PK_SIZE]
            .try_into()
            .map_err(|_| KeyperProcessError::InvalidResponse)?,
        signature: encoded[9 + PK_SIZE..]
            .try_into()
            .map_err(|_| KeyperProcessError::InvalidResponse)?,
    };
    if PublicKeyShare::from_bytes(response.public_key_share).is_err()
        || SignatureShare::from_bytes(response.signature).is_err()
    {
        return Err(KeyperProcessError::InvalidResponse);
    }
    Ok(response)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn verify_private_directory(path: &Path) -> Result<(), KeyperProcessError> {
    let metadata = fs::metadata(path).map_err(|_| KeyperProcessError::InsecureDirectory)?;
    if !metadata.is_dir() {
        return Err(KeyperProcessError::InsecureDirectory);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyperProcessError::InsecureDirectory);
        }
    }
    Ok(())
}

fn read_keyper_rpc_url() -> Result<String, KeyperProcessError> {
    let path = Path::new(KEYPER_RPC_CONFIG);
    let metadata = fs::symlink_metadata(path).map_err(|_| KeyperProcessError::InvalidRequest)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(KeyperProcessError::InvalidRequest);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyperProcessError::InvalidRequest);
        }
    }
    let url = fs::read_to_string(path).map_err(|_| KeyperProcessError::InvalidRequest)?;
    let url = url.trim();
    if url.is_empty() || url.len() > 2_048 || url.chars().any(char::is_whitespace) {
        return Err(KeyperProcessError::InvalidRequest);
    }
    Ok(url.to_owned())
}

fn read_keyper_attestation_key() -> Result<Zeroizing<[u8; 32]>, KeyperProcessError> {
    let path = Path::new(KEYPER_ATTESTATION_KEY);
    let metadata = fs::symlink_metadata(path).map_err(|_| KeyperProcessError::InvalidRequest)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != 32 {
        return Err(KeyperProcessError::InvalidRequest);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyperProcessError::InvalidRequest);
        }
    }
    let bytes = Zeroizing::new(fs::read(path).map_err(|_| KeyperProcessError::InvalidRequest)?);
    let seed =
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| KeyperProcessError::InvalidRequest)?;
    Ok(Zeroizing::new(seed))
}

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(REQUEST_LEN as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn parent_rejects_a_valid_keyper_signature_over_the_wrong_lock_digest() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let expected_digest = [8; 32];
        let wrong_digest = [9; 32];
        let approval = LockApprovalV1::from_parts(
            signing_key.verifying_key().to_bytes(),
            wrong_digest,
            signing_key.sign(&wrong_digest).to_bytes(),
        );

        assert_eq!(
            validate_lock_approval(
                Pubkey::new_from_array(signing_key.verifying_key().to_bytes()),
                expected_digest,
                &approval,
            ),
            Err(KeyperProcessError::InvalidResponse)
        );
    }

    #[test]
    fn settlement_stdin_limit_includes_the_bound_share_and_oversize_byte() {
        assert_eq!(
            SETTLEMENT_STDIN_READ_LIMIT,
            BOUND_SHARE_LEN + MAX_SETTLEMENT_REQUEST_LEN + 1
        );
    }
}
