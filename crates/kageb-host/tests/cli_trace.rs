use std::process::Command;

#[test]
fn trace_command_explains_the_public_difference_without_a_privacy_score() {
    let output = Command::new(env!("CARGO_BIN_EXE_kageb"))
        .arg("trace")
        .output()
        .expect("run kageb trace");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("DIRECT: 4 wallet-linked orders visible"));
    assert!(stdout.contains("KAGEB: 0 individual orders visible"));
    assert!(stdout.contains("pool aggregate: BUY 2 lots"));
    assert!(stdout.contains("no decoy trades"));
    assert!(!stdout.contains('%'));
}
