use std::{env, path::Path, process::ExitCode};

const DEFAULT_DEVNET_RPC: &str = "https://api.devnet.solana.com";
const USAGE: &str = "usage: kageb trace | kageb demo local | \
kageb demo devnet --payer <path> --program <id> --out <path> [--rpc <url>] | \
kageb verify evidence <path> [--rpc <url>]";

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
        [group, command, path] if group == "verify" && command == "evidence" => {
            verify_evidence(path, DEFAULT_DEVNET_RPC)
        }
        [group, command, path, flag, rpc]
            if group == "verify" && command == "evidence" && flag == "--rpc" =>
        {
            verify_evidence(path, rpc)
        }
        [group, command, payer_flag, payer, program_flag, program, out_flag, out]
            if group == "demo"
                && command == "devnet"
                && payer_flag == "--payer"
                && program_flag == "--program"
                && out_flag == "--out" =>
        {
            demo_devnet(payer, program, out, DEFAULT_DEVNET_RPC)
        }
        [group, command, payer_flag, payer, program_flag, program, out_flag, out, rpc_flag, rpc]
            if group == "demo"
                && command == "devnet"
                && payer_flag == "--payer"
                && program_flag == "--program"
                && out_flag == "--out"
                && rpc_flag == "--rpc" =>
        {
            demo_devnet(payer, program, out, rpc)
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn verify_evidence(path: &str, rpc: &str) -> ExitCode {
    match kageb::verify_evidence_file(Path::new(path), rpc) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn demo_devnet(payer: &str, program: &str, out: &str, rpc: &str) -> ExitCode {
    eprintln!("WARNING: synthetic assets only; this prototype is not safe for real funds.");
    match kageb::devnet_proof(Path::new(payer), program, Path::new(out), rpc) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("devnet demo failed: {error}");
            ExitCode::FAILURE
        }
    }
}
