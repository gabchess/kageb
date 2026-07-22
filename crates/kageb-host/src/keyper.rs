use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
    process::{Command, Stdio},
};

use bincode::Options;
use serde::{Deserialize, Serialize};
use threshold_crypto::{
    serde_impl::SerdeSecret, PublicKeyShare, SecretKeyShare, SignatureShare, PK_SIZE, SIG_SIZE,
};
use zeroize::Zeroizing;

use crate::KeyperSecretShare;

const REQUEST_VERSION: u8 = 1;
const REQUEST_LEN: usize = 73;
const RESPONSE_LEN: usize = 1 + 8 + PK_SIZE + SIG_SIZE;

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

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(REQUEST_LEN as u64)
}
