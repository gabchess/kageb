use std::{fs, process::Command};

#[test]
fn verify_evidence_cli_rejects_private_or_unknown_fields_before_rpc() {
    let directory = tempfile::tempdir().unwrap();
    let evidence = directory.path().join("evidence.json");
    fs::write(
        &evidence,
        r#"{"schema_version":1,"content":{"plaintext_orders":["buy"]},"evidence_sha256":"00"}"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_kageb"))
        .args([
            "verify",
            "evidence",
            evidence.to_str().unwrap(),
            "--rpc",
            "http://127.0.0.1:1",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("parse evidence: InvalidSchema"), "{stderr}");
    assert!(!stderr.contains("plaintext_orders"), "{stderr}");
}

#[test]
fn devnet_cli_requires_the_fixed_program_and_explicit_paths() {
    let output = Command::new(env!("CARGO_BIN_EXE_kageb"))
        .args(["demo", "devnet"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr
        .contains("kageb demo devnet --payer <path> --program <id> --out <path> [--rpc <url>]"));
    assert!(!stderr.contains("safe for real funds"));
}

#[test]
fn devnet_cli_rejects_a_substituted_program_before_reading_secrets() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kageb"))
        .args([
            "demo",
            "devnet",
            "--payer",
            directory.path().join("missing.json").to_str().unwrap(),
            "--program",
            "11111111111111111111111111111111",
            "--out",
            directory.path().join("evidence.json").to_str().unwrap(),
            "--rpc",
            "http://127.0.0.1:1",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("fixed program ID"), "{stderr}");
    assert!(!stderr.contains("missing.json"), "{stderr}");
}

#[test]
fn private_devnet_runtime_directory_is_ignored() {
    let ignore =
        fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.gitignore")).unwrap();
    assert!(ignore.lines().any(|line| line == "/.kageb-private/"));
}
