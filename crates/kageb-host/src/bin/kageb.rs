use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
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
