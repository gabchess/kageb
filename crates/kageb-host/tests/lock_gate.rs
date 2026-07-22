use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::SigningKey;
use kageb::{
    run_keyper_sign_lock, BalanceRecordV1, EncryptedSubmissionV1, EpochDealer,
    FundedAuthorizationV1, IntentBodyV1, KeyperProcessError, LockJournal, LockPackageV1,
    LockValidationError, PoolBalance, ProgramClient, ReferenceKeyper, ReservationJournal,
    ReservationRecord, Side, SignedBalanceSnapshotV1, SignedIntentV1,
};
use kageb_program::{
    epoch_address, pool_address,
    state::{EpochStateV1, EpochTerminalState, PoolStateV1},
    vault_authority_address,
    wire::EpochConfigurationV1,
    ID,
};
use serde_json::{json, Value};
use solana_program::{clock::Clock, pubkey::Pubkey, sysvar};
use tempfile::tempdir;

static RPC_TEST: Mutex<()> = Mutex::new(());
static MOCK_RPC: OnceLock<MockRpc> = OnceLock::new();

fn serial_rpc_test() -> std::sync::MutexGuard<'static, ()> {
    RPC_TEST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn mock_rpc(package: &LockPackageV1, operator: &SigningKey) -> &'static MockRpc {
    MOCK_RPC.get_or_init(|| MockRpc::start(package, operator))
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn submission(
    id: u8,
    epoch_id: [u8; 32],
    dealer: &EpochDealer,
    operator: &SigningKey,
) -> EncryptedSubmissionV1 {
    let trader = key(id);
    let directory = tempdir().unwrap();
    let mut reservations = ReservationJournal::open(directory.path().join("r.bin")).unwrap();
    let reserved = reservations
        .reserve(
            ReservationRecord::new([id; 32], [id; 32], 1, 100).unwrap(),
            PoolBalance::new(1, 100),
        )
        .unwrap();
    let authorization =
        FundedAuthorizationV1::sign(reserved, epoch_id, trader.verifying_key(), operator, 1_000);
    let body = IntentBodyV1::new(Side::Buy, 1, 100, epoch_id, [id; 32], [id; 16]).unwrap();
    let encrypted = dealer
        .public_keys()
        .encrypt(&SignedIntentV1::sign(body, &trader))
        .unwrap();
    EncryptedSubmissionV1::sign(authorization, encrypted, [id + 20; 32], &trader).unwrap()
}

fn valid_package() -> (LockPackageV1, SigningKey, [SigningKey; 3]) {
    let operator = key(90);
    let attesters = [key(70), key(71), key(72)];
    let epoch_id = [42; 32];
    let base_mint = Pubkey::new_from_array([2; 32]);
    let quote_mint = Pubkey::new_from_array([3; 32]);
    let (pool, _) = pool_address(
        &Pubkey::new_from_array(operator.verifying_key().to_bytes()),
        &base_mint,
        &quote_mint,
    );
    let (epoch_account, _) = epoch_address(&pool, &epoch_id);
    let dealer = EpochDealer::random().unwrap();
    let submissions: Vec<_> = (1..=4)
        .map(|id| submission(id, epoch_id, &dealer, &operator))
        .collect();
    let balances: Vec<_> = (1..=4)
        .map(|id| BalanceRecordV1::new([id; 32], 1, 100, 1, 100).unwrap())
        .collect();
    let snapshot = SignedBalanceSnapshotV1::sign(epoch_id, &balances, &operator).unwrap();
    let config = EpochConfigurationV1 {
        pool,
        epoch_id,
        base_mint,
        quote_mint,
        base_lot_atoms: 1,
        quote_atoms_per_lot: 100,
        minimum_count: 4,
        lock_threshold: 2,
        settlement_threshold: 2,
        keypers: attesters
            .each_ref()
            .map(|key| Pubkey::new_from_array(key.verifying_key().to_bytes())),
        lock_deadline: 900,
        abort_deadline: 1_000,
    };
    let package = LockPackageV1::new(
        epoch_account,
        config,
        submissions,
        balances,
        snapshot,
        [9; 32],
    )
    .unwrap();
    (package, operator, attesters)
}

struct MockRpc {
    url: String,
    stop: Arc<AtomicBool>,
    requests: Arc<std::sync::atomic::AtomicUsize>,
    errors: Arc<Mutex<Vec<String>>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl MockRpc {
    fn start(package: &LockPackageV1, operator: &SigningKey) -> Self {
        Self::start_with(package, operator, 800, false)
    }

    fn start_with(
        package: &LockPackageV1,
        operator: &SigningKey,
        timestamp: i64,
        locked: bool,
    ) -> Self {
        let configuration = package.configuration;
        let (_, pool_bump) = pool_address(
            &Pubkey::new_from_array(operator.verifying_key().to_bytes()),
            &configuration.base_mint,
            &configuration.quote_mint,
        );
        let (_, vault_bump) = vault_authority_address(&configuration.pool);
        let pool = PoolStateV1 {
            pool_bump,
            vault_bump,
            lock_threshold: configuration.lock_threshold,
            settlement_threshold: configuration.settlement_threshold,
            operator: Pubkey::new_from_array(operator.verifying_key().to_bytes()),
            base_mint: configuration.base_mint,
            quote_mint: configuration.quote_mint,
            pool_base_vault: Pubkey::new_unique(),
            pool_quote_vault: Pubkey::new_unique(),
            venue_authority: Pubkey::new_unique(),
            venue_base_account: Pubkey::new_unique(),
            venue_quote_account: Pubkey::new_unique(),
            keypers: configuration.keypers,
            base_lot_atoms: configuration.base_lot_atoms,
        };
        let (_, epoch_bump) = epoch_address(&configuration.pool, &configuration.epoch_id);
        let mut epoch = EpochStateV1 {
            epoch_bump,
            terminal_state: EpochTerminalState::Open,
            residual_side: 0,
            pool: configuration.pool,
            epoch_id: configuration.epoch_id,
            configuration_hash: configuration.digest(),
            pre_balance_root: [0; 32],
            member_root: [0; 32],
            lock_digest: [0; 32],
            result_commitment: [0; 32],
            settlement_digest: [0; 32],
            lock_nonce: [0; 32],
            settlement_nonce: [0; 32],
            member_count: 0,
            minimum_count: configuration.minimum_count,
            residual_lots: 0,
            base_lot_atoms: configuration.base_lot_atoms,
            quote_atoms_per_lot: configuration.quote_atoms_per_lot,
            lock_deadline: configuration.lock_deadline,
            abort_deadline: configuration.abort_deadline,
        };
        if locked {
            let payload = package.lock_payload();
            epoch.terminal_state = EpochTerminalState::Locked;
            epoch.pre_balance_root = payload.pre_balance_root;
            epoch.member_root = payload.member_root;
            epoch.lock_digest = payload.digest();
            epoch.lock_nonce = payload.lock_nonce;
            epoch.member_count = payload.member_count;
        }
        let clock = Clock {
            slot: 500,
            unix_timestamp: timestamp,
            ..Clock::default()
        };
        let epoch_account = encoded_account(ID, &epoch.encode());
        let accounts = vec![
            epoch_account.clone(),
            encoded_account(ID, &pool.encode()),
            encoded_account(sysvar::ID, &bincode::serialize(&clock).unwrap()),
        ];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&requests);
        let thread_errors = Arc::clone(&errors);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread_requests.fetch_add(1, Ordering::Relaxed);
                        let epoch_account = epoch_account.clone();
                        let accounts = accounts.clone();
                        let errors = Arc::clone(&thread_errors);
                        thread::spawn(move || {
                            if let Err(error) = serve_rpc(stream, &epoch_account, &accounts) {
                                errors.lock().unwrap().push(error);
                            }
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            url,
            stop,
            requests,
            errors,
            thread: Some(thread),
        }
    }

    fn confirmed_open_epoch(&self, epoch: Pubkey) -> kageb::ConfirmedOpenEpoch {
        ProgramClient::new(&self.url)
            .fetch_confirmed_open_epoch(epoch)
            .unwrap()
    }

    fn configure_rpc(&self, directory: &std::path::Path) {
        let path = directory.join("keyper-rpc-url");
        fs::write(&path, &self.url).unwrap();
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn configure_keyper(&self, directory: &std::path::Path, signing_key: &SigningKey) {
        self.configure_rpc(directory);
        let path = directory.join("keyper-attestation-key");
        fs::write(&path, signing_key.to_bytes()).unwrap();
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }

    fn errors(&self) -> Vec<String> {
        self.errors.lock().unwrap().clone()
    }
}

impl Drop for MockRpc {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn encoded_account(owner: Pubkey, data: &[u8]) -> Value {
    json!({
        "data": [BASE64.encode(data), "base64"],
        "executable": false,
        "lamports": 1,
        "owner": owner.to_string(),
        "rentEpoch": 0,
        "space": data.len(),
    })
}

fn serve_rpc(mut stream: TcpStream, epoch: &Value, accounts: &[Value]) -> Result<(), String> {
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("connection closed before request".to_owned());
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if request.len() >= header_end + 4 + content_length {
                break;
            }
        }
    }
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Err("request headers were incomplete".to_owned());
    };
    let body: Value = serde_json::from_slice(&request[header_end + 4..])
        .map_err(|error| format!("invalid JSON-RPC body: {error}"))?;
    let value = match body["method"].as_str() {
        Some("getAccountInfo") => epoch.clone(),
        Some("getMultipleAccounts") => Value::Array(accounts.to_vec()),
        method => return Err(format!("unexpected RPC method: {method:?}")),
    };
    let response = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "result": {"context": {"slot": 500}, "value": value},
        "id": body["id"],
    }))
    .map_err(|error| error.to_string())?;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        response.len()
    )
    .map_err(|error| error.to_string())?;
    stream
        .write_all(&response)
        .and_then(|()| stream.flush())
        .map_err(|error| error.to_string())
}

#[test]
fn keyper_validates_and_journals_before_signing_one_lock_digest() {
    let _serial = serial_rpc_test();
    let (package, operator, attesters) = valid_package();
    let rpc = mock_rpc(&package, &operator);
    let confirmed = rpc.confirmed_open_epoch(package.epoch_account());
    let directory = tempdir().unwrap();
    let path = directory.path().join("locks.bin");
    let journal = LockJournal::open(&path).unwrap();
    let mut keyper = ReferenceKeyper::new(0, attesters[0].clone(), journal);

    let approval = keyper.sign_lock(&package, &confirmed).unwrap();
    assert!(approval.verify());
    assert_eq!(approval.digest(), package.lock_payload().digest());
    assert_eq!(
        LockJournal::open(&path)
            .unwrap()
            .digest(package.epoch_account()),
        Some(approval.digest())
    );

    let mut conflicting = package.clone();
    conflicting.lock_nonce = [10; 32];
    assert_eq!(
        keyper.sign_lock(&conflicting, &confirmed),
        Err(LockValidationError::ConflictingLock)
    );
}

#[test]
fn keyper_rejects_crowd_substitution_and_corrupt_journal() {
    let _serial = serial_rpc_test();
    let (package, operator, attesters) = valid_package();
    let rpc = mock_rpc(&package, &operator);
    let confirmed = rpc.confirmed_open_epoch(package.epoch_account());
    let directory = tempdir().unwrap();
    let path = directory.path().join("locks.bin");
    let mut keyper =
        ReferenceKeyper::new(0, attesters[0].clone(), LockJournal::open(&path).unwrap());

    let mut wrong_root = package.clone();
    wrong_root.member_root[0] ^= 1;
    assert_eq!(
        keyper.sign_lock(&wrong_root, &confirmed),
        Err(LockValidationError::MemberRootMismatch)
    );

    let mut wrong_count = package.clone();
    wrong_count.member_count = 5;
    assert_eq!(
        keyper.sign_lock(&wrong_count, &confirmed),
        Err(LockValidationError::MemberCountMismatch)
    );

    let mut stale = package.clone();
    stale.configuration.lock_deadline = 700;
    assert_eq!(
        keyper.sign_lock(&stale, &confirmed),
        Err(LockValidationError::InvalidConfiguration)
    );

    keyper.sign_lock(&package, &confirmed).unwrap();
    let mut bytes = fs::read(&path).unwrap();
    bytes.truncate(bytes.len() - 1);
    fs::write(&path, bytes).unwrap();
    assert!(matches!(
        LockJournal::open(&path),
        Err(LockValidationError::CorruptJournal)
    ));
}

#[test]
fn keyper_recomputes_every_lock_input_before_signing() {
    let _serial = serial_rpc_test();
    let (package, operator, attesters) = valid_package();
    let rpc = mock_rpc(&package, &operator);
    let confirmed = rpc.confirmed_open_epoch(package.epoch_account());

    let rejection = |candidate: &LockPackageV1| {
        let directory = tempdir().unwrap();
        let mut keyper = ReferenceKeyper::new(
            0,
            attesters[0].clone(),
            LockJournal::open(directory.path().join("locks.bin")).unwrap(),
        );
        keyper.sign_lock(candidate, &confirmed)
    };

    let mut bad_authorization = package.clone();
    bad_authorization.submissions[0] = submission(
        99,
        package.configuration.epoch_id,
        &EpochDealer::random().unwrap(),
        &key(91),
    );
    assert_eq!(
        rejection(&bad_authorization),
        Err(LockValidationError::InvalidSubmission)
    );

    let mut bad_outer_signature = package.clone();
    let (authorization, ciphertext, receipt, mut signature) =
        bad_outer_signature.submissions[0].clone().into_wire_parts();
    signature[0] ^= 1;
    bad_outer_signature.submissions[0] =
        EncryptedSubmissionV1::from_wire_parts(authorization, ciphertext, receipt, signature);
    assert_eq!(
        rejection(&bad_outer_signature),
        Err(LockValidationError::InvalidSubmission)
    );

    let mut invalid_ciphertext = package.clone();
    let (authorization, mut ciphertext, receipt, signature) =
        invalid_ciphertext.submissions[0].clone().into_wire_parts();
    ciphertext[0] ^= 1;
    invalid_ciphertext.submissions[0] =
        EncryptedSubmissionV1::from_wire_parts(authorization, ciphertext, receipt, signature);
    assert_eq!(
        rejection(&invalid_ciphertext),
        Err(LockValidationError::InvalidSubmission)
    );

    let mut duplicate_participant = package.clone();
    duplicate_participant.submissions[1] = duplicate_participant.submissions[0].clone();
    assert_eq!(
        rejection(&duplicate_participant),
        Err(LockValidationError::DuplicateParticipant)
    );

    let mut false_balance_root = package.clone();
    let mut changed_balances: Vec<_> = (1..=4)
        .map(|id| BalanceRecordV1::new([id; 32], 1, 100, 1, 100).unwrap())
        .collect();
    changed_balances[0] = BalanceRecordV1::new([1; 32], 2, 100, 1, 100).unwrap();
    false_balance_root.balance_snapshot =
        SignedBalanceSnapshotV1::sign(package.configuration.epoch_id, &changed_balances, &operator)
            .unwrap();
    assert_eq!(
        rejection(&false_balance_root),
        Err(LockValidationError::InvalidSnapshot)
    );

    let mut tampered_pre_balance_root = package.clone();
    tampered_pre_balance_root.pre_balance_root[0] ^= 1;
    assert_eq!(
        rejection(&tampered_pre_balance_root),
        Err(LockValidationError::InvalidBalance)
    );

    let mut duplicate_keyper = package.clone();
    duplicate_keyper.configuration.keypers[1] = duplicate_keyper.configuration.keypers[0];
    assert_eq!(
        rejection(&duplicate_keyper),
        Err(LockValidationError::InvalidConfiguration)
    );

    let mut same_mint = package.clone();
    same_mint.configuration.quote_mint = same_mint.configuration.base_mint;
    assert_eq!(
        rejection(&same_mint),
        Err(LockValidationError::InvalidConfiguration)
    );

    let wrong_keyper_directory = tempdir().unwrap();
    let mut wrong_keyper = ReferenceKeyper::new(
        0,
        key(69),
        LockJournal::open(wrong_keyper_directory.path().join("locks.bin")).unwrap(),
    );
    assert_eq!(
        wrong_keyper.sign_lock(&package, &confirmed),
        Err(LockValidationError::WrongKeyper)
    );
}

#[test]
fn one_shot_keyper_process_validates_journals_and_signs() {
    let _serial = serial_rpc_test();
    let (package, operator, attesters) = valid_package();
    let rpc = mock_rpc(&package, &operator);
    let directory = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    rpc.configure_keyper(directory.path(), &attesters[1]);

    let approval = run_keyper_sign_lock(
        env!("CARGO_BIN_EXE_kageb"),
        directory.path(),
        1,
        package.configuration.keypers[1],
        &package,
    )
    .unwrap_or_else(|error| {
        panic!(
            "{error:?}; RPC requests: {}; server errors: {:?}",
            rpc.request_count(),
            rpc.errors()
        )
    });

    assert!(approval.verify());
    assert_eq!(approval.digest(), package.lock_payload().digest());
    assert!(directory.path().join("keyper-locks.bin").is_file());
    assert!(directory.path().join("keyper-locks.initialized").is_file());

    let repeated = run_keyper_sign_lock(
        env!("CARGO_BIN_EXE_kageb"),
        directory.path(),
        1,
        package.configuration.keypers[1],
        &package,
    )
    .unwrap();
    assert_eq!(repeated.digest(), approval.digest());

    let mut conflicting = package.clone();
    conflicting.lock_nonce = [10; 32];
    assert_eq!(
        run_keyper_sign_lock(
            env!("CARGO_BIN_EXE_kageb"),
            directory.path(),
            1,
            package.configuration.keypers[1],
            &conflicting,
        ),
        Err(KeyperProcessError::ChildFailed)
    );

    for artifact in ["keyper-locks.bin", "keyper-locks.initialized"] {
        let bytes = fs::read(directory.path().join(artifact)).unwrap();
        assert!(!bytes
            .windows(attesters[1].to_bytes().len())
            .any(|window| window == attesters[1].to_bytes()));
    }
}

#[test]
fn initialized_keyper_fails_closed_when_either_journal_file_is_missing() {
    let _serial = serial_rpc_test();
    let (package, operator, attesters) = valid_package();
    let rpc = mock_rpc(&package, &operator);

    for missing in ["keyper-locks.bin", "keyper-locks.initialized"] {
        let directory = tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        rpc.configure_keyper(directory.path(), &attesters[0]);
        run_keyper_sign_lock(
            env!("CARGO_BIN_EXE_kageb"),
            directory.path(),
            0,
            package.configuration.keypers[0],
            &package,
        )
        .unwrap();
        fs::remove_file(directory.path().join(missing)).unwrap();
        assert_eq!(
            run_keyper_sign_lock(
                env!("CARGO_BIN_EXE_kageb"),
                directory.path(),
                0,
                package.configuration.keypers[0],
                &package,
            ),
            Err(KeyperProcessError::ChildFailed)
        );
    }
}

#[test]
fn keyper_rejects_bad_checksum_and_unsupported_journal_version() {
    let _serial = serial_rpc_test();
    let (package, operator, attesters) = valid_package();
    let rpc = mock_rpc(&package, &operator);
    let confirmed = rpc.confirmed_open_epoch(package.epoch_account());

    for corrupt in ["checksum", "version"] {
        let directory = tempdir().unwrap();
        let path = directory.path().join("locks.bin");
        let mut keyper =
            ReferenceKeyper::new(0, attesters[0].clone(), LockJournal::open(&path).unwrap());
        keyper.sign_lock(&package, &confirmed).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        if corrupt == "checksum" {
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        } else {
            bytes[6] ^= 1;
        }
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            LockJournal::open(&path),
            Err(LockValidationError::CorruptJournal)
        ));
    }
}

#[test]
fn stale_lock_inode_does_not_strand_the_journal_after_a_crash() {
    let directory = tempdir().unwrap();
    let journal = directory.path().join("locks.bin");
    fs::write(journal.with_extension("lock"), b"stale process marker").unwrap();

    LockJournal::open(&journal).unwrap();
    assert!(journal.is_file());
}

#[test]
fn one_shot_keyper_requires_its_own_rpc_configuration_before_journaling() {
    let _serial = serial_rpc_test();
    let (package, _operator, _attesters) = valid_package();
    let directory = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(
        run_keyper_sign_lock(
            env!("CARGO_BIN_EXE_kageb"),
            directory.path(),
            0,
            package.configuration.keypers[0],
            &package,
        ),
        Err(KeyperProcessError::ChildFailed)
    );
    assert!(!directory.path().join("keyper-locks.bin").exists());
}

#[test]
fn one_shot_keyper_requires_its_own_attestation_key_before_journaling() {
    let _serial = serial_rpc_test();
    let (package, operator, _attesters) = valid_package();
    let rpc = mock_rpc(&package, &operator);
    let directory = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    rpc.configure_rpc(directory.path());

    assert_eq!(
        run_keyper_sign_lock(
            env!("CARGO_BIN_EXE_kageb"),
            directory.path(),
            0,
            package.configuration.keypers[0],
            &package,
        ),
        Err(KeyperProcessError::ChildFailed)
    );
    assert!(!directory.path().join("keyper-locks.bin").exists());
}

#[test]
fn confirmed_lock_is_created_only_from_a_confirmed_rpc_read_of_the_locked_epoch() {
    let _serial = serial_rpc_test();
    let (package, operator, _attesters) = valid_package();
    let locked_rpc = MockRpc::start_with(&package, &operator, 800, true);
    let confirmed = ProgramClient::new(&locked_rpc.url)
        .fetch_confirmed_lock(package.epoch_account())
        .unwrap();
    assert_eq!(confirmed.epoch_account(), package.epoch_account());
    assert_eq!(confirmed.lock_digest(), package.lock_payload().digest());
    assert_eq!(confirmed.member_root(), package.lock_payload().member_root);

    let open_rpc = MockRpc::start_with(&package, &operator, 800, false);
    assert!(ProgramClient::new(&open_rpc.url)
        .fetch_confirmed_lock(package.epoch_account())
        .is_err());
}

#[test]
fn confirmed_open_epoch_rejects_the_exact_lock_deadline() {
    let _serial = serial_rpc_test();
    let (package, operator, _attesters) = valid_package();
    let rpc = MockRpc::start_with(
        &package,
        &operator,
        package.configuration.lock_deadline,
        false,
    );
    assert!(ProgramClient::new(&rpc.url)
        .fetch_confirmed_open_epoch(package.epoch_account())
        .is_err());
}

#[cfg(unix)]
#[test]
fn one_shot_keyper_rejects_a_group_readable_working_directory() {
    let _serial = serial_rpc_test();
    let (package, _operator, _attesters) = valid_package();
    let directory = tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        run_keyper_sign_lock(
            env!("CARGO_BIN_EXE_kageb"),
            directory.path(),
            0,
            package.configuration.keypers[0],
            &package,
        ),
        Err(KeyperProcessError::InsecureDirectory)
    );
}
