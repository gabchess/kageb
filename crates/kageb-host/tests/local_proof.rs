use std::process::Command;

#[cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

#[cfg(unix)]
fn write_executable(path: &Path) {
    fs::write(path, "#!/bin/sh\nexit 0\n").expect("executable fixture");
    let mut permissions = fs::metadata(path).expect("fixture metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("executable fixture permissions");
}

#[cfg(unix)]
#[test]
fn local_demo_resolves_cargo_from_cargo_home_when_path_has_none() {
    let cargo_home = tempfile::tempdir().expect("cargo home");
    let empty_home = tempfile::tempdir().expect("empty home");
    let empty_path = tempfile::tempdir().expect("empty path");
    let bin = cargo_home.path().join("bin");
    fs::create_dir(&bin).expect("cargo bin directory");
    let cargo = bin.join("cargo");
    write_executable(&cargo);

    let output = Command::new(env!("CARGO_BIN_EXE_kageb"))
        .args(["demo", "local"])
        .env_remove("CARGO")
        .env("CARGO_HOME", cargo_home.path())
        .env("HOME", empty_home.path())
        .env("PATH", empty_path.path())
        .output()
        .expect("run local proof");

    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error output");
    assert!(
        stderr.contains("solana-test-validator was not found"),
        "cargo fallback did not advance tool resolution:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn local_demo_resolves_cargo_from_home_when_other_sources_have_none() {
    let home = tempfile::tempdir().expect("home");
    let empty_path = tempfile::tempdir().expect("empty path");
    let bin = home.path().join(".cargo/bin");
    fs::create_dir_all(&bin).expect("home cargo bin directory");
    write_executable(&bin.join("cargo"));

    let output = Command::new(env!("CARGO_BIN_EXE_kageb"))
        .args(["demo", "local"])
        .env_remove("CARGO")
        .env_remove("CARGO_HOME")
        .env("HOME", home.path())
        .env("PATH", empty_path.path())
        .output()
        .expect("run local proof");

    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error output");
    assert!(
        stderr.contains("solana-test-validator was not found"),
        "home cargo fallback did not advance tool resolution:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn local_demo_rejects_a_non_executable_explicit_cargo_before_path() {
    let explicit = tempfile::NamedTempFile::new().expect("explicit cargo");
    let path = tempfile::tempdir().expect("path");
    let empty_home = tempfile::tempdir().expect("empty home");
    write_executable(&path.path().join("cargo"));

    let output = Command::new(env!("CARGO_BIN_EXE_kageb"))
        .args(["demo", "local"])
        .env("CARGO", explicit.path())
        .env_remove("CARGO_HOME")
        .env("HOME", empty_home.path())
        .env("PATH", path.path())
        .output()
        .expect("run local proof");

    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error output");
    assert!(
        stderr.contains("CARGO") && stderr.contains("not executable"),
        "explicit CARGO was not validated before PATH:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn local_demo_reports_every_supported_cargo_source_when_none_exist() {
    let empty_path = tempfile::tempdir().expect("empty path");
    let output = Command::new(env!("CARGO_BIN_EXE_kageb"))
        .args(["demo", "local"])
        .env_remove("CARGO")
        .env_remove("CARGO_HOME")
        .env_remove("HOME")
        .env("PATH", empty_path.path())
        .output()
        .expect("run local proof");

    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error output");
    for source in [
        "Set CARGO",
        "add cargo to PATH",
        "CARGO_HOME/bin",
        "HOME/.cargo/bin",
    ] {
        assert!(
            stderr.contains(source),
            "missing {source} recovery hint:\n{stderr}"
        );
    }
}

#[test]
fn collapsed_local_proof_runs_real_validator_keypers_and_aggregate_settlement() {
    let output = Command::new(env!("CARGO_BIN_EXE_kageb"))
        .args(["demo", "local"])
        .output()
        .expect("run local proof");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 proof output");
    assert_eq!(
        stdout,
        concat!(
            "WARNING: synthetic assets only; this prototype is not safe for real funds.\n",
            "WAIT: crowd 3/4\n",
            "LOCKED: crowd 4/4\n",
            "REFUSED: one share\n",
            "QUORUM: all 3 two-share paths agree\n",
            "SETTLED: one aggregate\n",
            "RESULTS: authenticated balances persisted\n",
            "BALANCED: zero residual; no venue leg\n",
            "EXPIRED: underfilled; reservations released\n",
            "ABORTED: invalid reveal; trading key suspended\n",
            "OBSERVER: direct 4 orders; KageB 1 aggregate\n",
            "It does not prove unique humans, production anonymity, private funding or withdrawal, a trustless exchange, protection from the KageB operator, or safe use with real funds.\n",
        )
    );
}
