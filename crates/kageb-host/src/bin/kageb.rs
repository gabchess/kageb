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
        [group, command]
            if group == "keyper"
                && matches!(command.as_str(), "release-share" | "sign-settlement") =>
        {
            eprintln!("unsupported until a confirmed onchain lock exists");
            ExitCode::from(3)
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
        _ => {
            eprintln!("usage: kageb trace");
            ExitCode::from(2)
        }
    }
}
