use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::SigningKey;
use kageb::{
    AdmissionPolicyV1, EncryptedSubmissionV1, EpochDealer, EpochPublicKeys, PoolBalance,
    ReservationJournal, ReservationRecord, SuspensionRegistry,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_keypair::Keypair;
use tempfile::{tempdir, TempDir};

#[cfg(unix)]
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientOutput {
    schema_version: u8,
    epoch_id: String,
    participant_id: String,
    trading_key: String,
    ciphertext_sha256_base64: String,
    submission_sha256_base64: String,
    encrypted_submission_base64: String,
}

struct Fixture {
    _directory: TempDir,
    keypair_path: PathBuf,
    request: Value,
    policy: AdmissionPolicyV1,
    epoch_public_keys_wire: Vec<u8>,
    epoch_id: [u8; 32],
    participant_id: [u8; 32],
    trading_public_key: [u8; 32],
}

fn fixture() -> Fixture {
    let directory = tempdir().expect("tempdir");
    let epoch_id = [42; 32];
    let participant_id = [17; 32];
    let trading = Keypair::new_from_array([7; 32]);
    let trading_bytes = trading.to_bytes();
    let trading_public_key = trading_bytes[32..].try_into().expect("public key");
    let operator = SigningKey::from_bytes(&[90; 32]);

    let mut journal =
        ReservationJournal::open(directory.path().join("reservations.bin")).expect("journal");
    let reserved = journal
        .reserve(
            ReservationRecord::new([8; 32], participant_id, 2, 100).expect("record"),
            PoolBalance::new(2, 100),
        )
        .expect("reservation");
    let authorization = SuspensionRegistry::open(directory.path().join("suspensions.bin"))
        .expect("registry")
        .issue_authorization(
            reserved,
            epoch_id,
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            &operator,
            1_000,
        )
        .expect("authorization");
    let dealer = EpochDealer::random().expect("dealer");
    let epoch_public_keys_wire = dealer
        .public_keys()
        .encode_wire()
        .expect("public keys wire");
    let keypair_path = directory.path().join("trading-keypair.json");
    write_keypair(&keypair_path, &trading, 0o600);

    let request = json!({
        "schema_version": 1,
        "side": "buy",
        "limit_price": 100,
        "epoch_id": bs58::encode(epoch_id).into_string(),
        "participant_id": bs58::encode(participant_id).into_string(),
        "funded_authorization_base64": BASE64.encode(authorization.encode()),
        "epoch_public_keys_base64": BASE64.encode(&epoch_public_keys_wire),
    });
    let policy =
        AdmissionPolicyV1::new(epoch_id, operator.verifying_key(), 1, 2, 100, 500).expect("policy");

    Fixture {
        _directory: directory,
        keypair_path,
        request,
        policy,
        epoch_public_keys_wire,
        epoch_id,
        participant_id,
        trading_public_key,
    }
}

fn write_keypair(path: &Path, keypair: &Keypair, mode: u32) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    let mut file = options.open(path).expect("create keypair");
    serde_json::to_writer(&mut file, &keypair.to_bytes().to_vec()).expect("write keypair");
    file.flush().expect("flush keypair");
}

fn run_client(keypair_path: &Path, request: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kageb"))
        .args(["client", "prepare", "--keypair"])
        .arg(keypair_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn client");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(request)
        .expect("write request");
    child.wait_with_output().expect("client output")
}

#[test]
fn client_prepare_help_publishes_the_exact_no_secret_schema() {
    let output = Command::new(env!("CARGO_BIN_EXE_kageb"))
        .args(["client", "prepare", "--help"])
        .output()
        .expect("client help");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).expect("UTF-8 help");
    for field in [
        "schema_version",
        "side",
        "limit_price",
        "epoch_id",
        "participant_id",
        "funded_authorization_base64",
        "epoch_public_keys_base64",
        "trading_key",
        "ciphertext_sha256_base64",
        "submission_sha256_base64",
        "encrypted_submission_base64",
    ] {
        assert!(help.contains(field), "help omitted {field}");
    }
    assert!(help.contains("maximum 16384 bytes"));
    assert!(!help.contains("DO_NOT_ECHO_MARKER"));
}

#[test]
fn client_prepares_roundtrippable_admissible_submission() {
    let fixture = fixture();
    let request = serde_json::to_vec(&fixture.request).expect("request JSON");
    let output = run_client(&fixture.keypair_path, &request);
    assert!(
        output.status.success(),
        "client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let response: ClientOutput = serde_json::from_slice(&output.stdout).expect("strict response");
    assert_eq!(response.schema_version, 1);
    assert_eq!(
        response.epoch_id,
        bs58::encode(fixture.epoch_id).into_string()
    );
    assert_eq!(
        response.participant_id,
        bs58::encode(fixture.participant_id).into_string()
    );
    assert_eq!(
        response.trading_key,
        bs58::encode(fixture.trading_public_key).into_string()
    );

    let public_keys =
        EpochPublicKeys::decode_wire(&fixture.epoch_public_keys_wire).expect("decode public keys");
    assert_eq!(
        public_keys.encode_wire().expect("re-encode public keys"),
        fixture.epoch_public_keys_wire
    );
    let wire = BASE64
        .decode(&response.encrypted_submission_base64)
        .expect("submission base64");
    let submission = EncryptedSubmissionV1::decode_wire(&wire).expect("submission wire");
    assert_eq!(submission.encode_wire(), wire);
    assert!(submission.verify_admission(&fixture.policy).is_ok());

    let (_, ciphertext, _, _) = submission.into_wire_parts();
    assert_eq!(
        response.ciphertext_sha256_base64,
        BASE64.encode(Sha256::digest(ciphertext))
    );
    assert_eq!(
        response.submission_sha256_base64,
        BASE64.encode(Sha256::digest(&wire))
    );
}

#[test]
fn client_accepts_the_sell_side() {
    let mut fixture = fixture();
    fixture.request["side"] = json!("sell");
    let output = run_client(
        &fixture.keypair_path,
        &serde_json::to_vec(&fixture.request).expect("request"),
    );
    assert!(
        output.status.success(),
        "sell request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: ClientOutput = serde_json::from_slice(&output.stdout).expect("strict response");
    let wire = BASE64
        .decode(response.encrypted_submission_base64)
        .expect("submission base64");
    let submission = EncryptedSubmissionV1::decode_wire(&wire).expect("submission wire");
    assert!(submission.verify_admission(&fixture.policy).is_ok());
}

#[test]
fn client_rejects_unknown_oversize_and_malformed_requests() {
    let fixture = fixture();
    let mut unknown = fixture.request.clone();
    unknown["unknown"] = json!(true);
    for request in [
        serde_json::to_vec(&unknown).expect("unknown request"),
        vec![b' '; 16 * 1024 + 1],
        br#"{"schema_version":1"#.to_vec(),
    ] {
        let output = run_client(&fixture.keypair_path, &request);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn client_rejects_invalid_economics_encodings_and_context_mismatches() {
    let fixture = fixture();
    let mut invalid_requests = Vec::new();

    let mut zero_price = fixture.request.clone();
    zero_price["limit_price"] = json!(0);
    invalid_requests.push(zero_price);

    let mut invalid_side = fixture.request.clone();
    invalid_side["side"] = json!("hold");
    invalid_requests.push(invalid_side);

    let mut noncanonical_epoch = fixture.request.clone();
    noncanonical_epoch["epoch_id"] = json!("not-base58!");
    invalid_requests.push(noncanonical_epoch);

    let mut wrong_epoch = fixture.request.clone();
    wrong_epoch["epoch_id"] = json!(bs58::encode([41; 32]).into_string());
    invalid_requests.push(wrong_epoch);

    let mut wrong_participant = fixture.request.clone();
    wrong_participant["participant_id"] = json!(bs58::encode([6; 32]).into_string());
    invalid_requests.push(wrong_participant);

    let mut invalid_authorization = fixture.request.clone();
    invalid_authorization["funded_authorization_base64"] = json!("AA==");
    invalid_requests.push(invalid_authorization);

    let mut invalid_public_keys = fixture.request.clone();
    invalid_public_keys["epoch_public_keys_base64"] = json!("AA==");
    invalid_requests.push(invalid_public_keys);

    for request in invalid_requests {
        let output = run_client(
            &fixture.keypair_path,
            &serde_json::to_vec(&request).expect("request"),
        );
        assert!(!output.status.success(), "accepted {request}");
        assert!(output.stdout.is_empty());
    }

    let wrong_key_path = fixture._directory.path().join("wrong-keypair.json");
    write_keypair(&wrong_key_path, &Keypair::new_from_array([6; 32]), 0o600);
    let output = run_client(
        &wrong_key_path,
        &serde_json::to_vec(&fixture.request).expect("request"),
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn client_requires_a_private_regular_non_symlink_key_file() {
    let fixture = fixture();
    let request = serde_json::to_vec(&fixture.request).expect("request");

    fs::set_permissions(&fixture.keypair_path, fs::Permissions::from_mode(0o644))
        .expect("public permissions");
    assert!(!run_client(&fixture.keypair_path, &request).status.success());
    fs::set_permissions(&fixture.keypair_path, fs::Permissions::from_mode(0o600))
        .expect("private permissions");

    fs::set_permissions(&fixture.keypair_path, fs::Permissions::from_mode(0o400))
        .expect("read-only permissions");
    assert!(!run_client(&fixture.keypair_path, &request).status.success());
    fs::set_permissions(&fixture.keypair_path, fs::Permissions::from_mode(0o600))
        .expect("exact private permissions");

    let symlink_path = fixture._directory.path().join("keypair-link.json");
    symlink(&fixture.keypair_path, &symlink_path).expect("keypair symlink");
    assert!(!run_client(&symlink_path, &request).status.success());

    assert!(!run_client(fixture._directory.path(), &request)
        .status
        .success());

    let malformed_path = fixture._directory.path().join("malformed-keypair.json");
    let mut malformed = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&malformed_path)
        .expect("malformed keypair");
    malformed.write_all(b"[1,2,3]").expect("write malformed");
    assert!(!run_client(&malformed_path, &request).status.success());
}

#[test]
fn client_diagnostics_do_not_echo_request_path_or_secret() {
    let fixture = fixture();
    let request = br#"{"schema_version":1,"secret-marker":"DO_NOT_ECHO_MARKER"}"#;
    let output = run_client(&fixture.keypair_path, request);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let stderr = String::from_utf8(output.stderr).expect("UTF-8 diagnostics");
    assert!(!stderr.contains("DO_NOT_ECHO_MARKER"));
    assert!(!stderr.contains(fixture.keypair_path.to_str().expect("UTF-8 path")));
    assert!(!stderr.contains(&bs58::encode([7; 32]).into_string()));
    assert!(!stderr.contains(&BASE64.encode([7; 32])));

    let output = run_client(
        &fixture.keypair_path,
        &serde_json::to_vec(&fixture.request).expect("request"),
    );
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 response");
    assert!(!stdout.contains(fixture.keypair_path.to_str().expect("UTF-8 path")));
    assert!(!stdout.contains(&bs58::encode([7; 32]).into_string()));
    assert!(!stdout.contains(&BASE64.encode([7; 32])));
    assert!(!stdout.contains(&serde_json::to_string(&vec![7; 32]).expect("secret JSON")));
}
