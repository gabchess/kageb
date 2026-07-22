use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [group, command] if group == "keyper" && command == "self-test" => {
            match kageb::handle_keyper_self_test() {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            }
        }
        [group, command] if group == "keyper" && command == "sign-lock" => {
            match kageb::handle_keyper_sign_lock() {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("sign-lock request rejected: {error:?}");
                    ExitCode::FAILURE
                }
            }
        }
        [group, command] if group == "keyper" && command == "release-share" => {
            match kageb::handle_keyper_release_share() {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("release-share request rejected: {error:?}");
                    ExitCode::FAILURE
                }
            }
        }
        [group, command] if group == "keyper" && command == "sign-settlement" => {
            match kageb::handle_keyper_sign_settlement() {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("sign-settlement request rejected: {error:?}");
                    ExitCode::FAILURE
                }
            }
        }
        [command] if command == "trace" => match kageb::trace_fixture() {
            Ok(output) => {
                print!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("trace failed: {error:?}");
                ExitCode::FAILURE
            }
        },
        [group, command] if group == "demo" && command == "local" => match kageb::local_proof() {
            Ok(output) => {
                print!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("local demo failed: {error}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("usage: kageb trace | kageb demo local");
            ExitCode::from(2)
        }
    }
}
