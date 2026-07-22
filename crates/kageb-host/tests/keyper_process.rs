use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use kageb::{run_keyper_self_test, EpochDealer};
use solana_program::pubkey::Pubkey;
use tempfile::tempdir;

#[test]
fn one_shot_keyper_receives_one_share_only_through_stdin() {
    let dealer = EpochDealer::random().expect("dealer");
    let share = dealer.share(Pubkey::new_unique(), 1);
    let directory = tempdir().expect("tempdir");
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private permissions");
    let before = fs::read_dir(directory.path())
        .expect("read tempdir")
        .count();

    let response = run_keyper_self_test(
        env!("CARGO_BIN_EXE_kageb"),
        directory.path(),
        &share,
        [55; 32],
    )
    .expect("self-test");

    assert_eq!(response.index(), 1);
    assert_eq!(response.public_key_share(), share.public_key_bytes());
    assert!(response.verify([55; 32]));
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("read tempdir")
            .count(),
        before
    );
}

#[test]
fn post_lock_keyper_operations_reject_missing_one_shot_requests() {
    for operation in ["release-share", "sign-settlement"] {
        let output = Command::new(env!("CARGO_BIN_EXE_kageb"))
            .args(["keyper", operation])
            .output()
            .expect("run keyper command");
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)
            .expect("utf8")
            .contains("request rejected"));
    }
}

#[test]
fn keyper_rejects_input_larger_than_the_fixed_request() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kageb"))
        .args(["keyper", "self-test"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn keyper");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&[0; 74])
        .expect("bounded input");
    assert!(!child.wait().expect("wait").success());
}

#[test]
fn sign_lock_rejects_input_over_the_protocol_limit() {
    let directory = tempdir().expect("tempdir");
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private permissions");
    let mut child = Command::new(env!("CARGO_BIN_EXE_kageb"))
        .args(["keyper", "sign-lock"])
        .current_dir(directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn keyper");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&vec![0; 64 * 1024 + 1])
        .expect("bounded input");
    assert!(!child.wait().expect("wait").success());
    assert_eq!(fs::read_dir(directory.path()).expect("read dir").count(), 0);
}
