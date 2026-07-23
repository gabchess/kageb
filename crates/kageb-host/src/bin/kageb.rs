use std::{env, path::Path, process::ExitCode};

const DEFAULT_DEVNET_RPC: &str = "https://api.devnet.solana.com";
const USAGE: &str = "usage: kageb client account --state <path> --keypair <path> | \
kageb client epoch | kageb client prepare --keypair <path> | \
kageb client result --state <path> --keypair <path> | kageb trace | kageb demo local | \
kageb demo devnet --payer <path> --program <id> --out <path> \
[--checkpoint-artifact <path>] [--rpc <url>] | \
kageb verify evidence <path> [--checkpoint-artifact <path>] [--rpc <url>]";
const CLIENT_PREPARE_HELP: &str = r#"usage: kageb client prepare --keypair <path>

Reads one JSON object from stdin (maximum 16384 bytes; unknown fields rejected).

Request schema v1:
{
  "schema_version": 1,
  "side": "buy" | "sell",
  "limit_price": <nonzero u64>,
  "epoch_id": "<canonical base58 encoding of 32 bytes>",
  "participant_id": "<canonical base58 encoding of 32 bytes>",
  "funded_authorization_base64": "<canonical padded base64 wire>",
  "epoch_public_keys_base64": "<canonical padded base64 wire>"
}

Response schema v1:
{
  "schema_version": 1,
  "epoch_id": "<canonical base58 encoding of 32 bytes>",
  "participant_id": "<canonical base58 encoding of 32 bytes>",
  "trading_key": "<canonical base58 encoding of 32 bytes>",
  "ciphertext_sha256_base64": "<canonical padded base64 digest>",
  "submission_sha256_base64": "<canonical padded base64 digest>",
  "encrypted_submission_base64": "<canonical padded base64 wire>"
}

The authorization epoch, participant, and trading key must match the request and keypair.
The coordinator remains authoritative for admission.
The keypair must be an exact regular non-symlink Solana JSON key file with Unix mode 0600.
"#;
const CLIENT_ACCOUNT_HELP: &str = r#"usage: kageb client account --state <path> --keypair <path>

Reads JSON schema v1 from stdin:
{"schema_version":1,"participant_id":"<base58 32 bytes>","base_atoms":<nonzero u64>,"quote_atoms":<nonzero u64>}

Returns JSON schema v1 with participant_id, trading_key, base_atoms, and quote_atoms.
The keypair must be an exact regular non-symlink Solana JSON key file with Unix mode 0600.
"#;
const CLIENT_EPOCH_HELP: &str = r#"usage: kageb client epoch

Reads and validates one coordinator epoch JSON object from stdin, then returns the same schema_version 1:
epoch_id, base_mint, quote_mint, base_lot_atoms, quote_atoms_per_lot, minimum_count,
keyper_threshold, lock_deadline, abort_deadline, and epoch_public_keys_base64.
"#;
const CLIENT_RESULT_HELP: &str = r#"usage: kageb client result --state <path> --keypair <path>

Reads JSON schema v1 from stdin:
{"schema_version":1,"participant_id":"<base58 32 bytes>"}

Returns JSON schema v1 with participant_id, epoch_id, base_atoms, and quote_atoms.
Only the trading key registered for the participant can read the result.
"#;

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [group, command, help] if group == "client" && command == "account" && help == "--help" => {
            print!("{CLIENT_ACCOUNT_HELP}");
            ExitCode::SUCCESS
        }
        [group, command, help] if group == "client" && command == "epoch" && help == "--help" => {
            print!("{CLIENT_EPOCH_HELP}");
            ExitCode::SUCCESS
        }
        [group, command, help] if group == "client" && command == "prepare" && help == "--help" => {
            print!("{CLIENT_PREPARE_HELP}");
            ExitCode::SUCCESS
        }
        [group, command, help] if group == "client" && command == "result" && help == "--help" => {
            print!("{CLIENT_RESULT_HELP}");
            ExitCode::SUCCESS
        }
        [group, command, keypair_flag, keypair]
            if group == "client" && command == "prepare" && keypair_flag == "--keypair" =>
        {
            match kageb::handle_client_prepare(Path::new(keypair)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("client prepare rejected: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [group, command] if group == "client" && command == "epoch" => {
            match kageb::handle_client_epoch() {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("client epoch rejected: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [group, command, state_flag, state, keypair_flag, keypair]
            if group == "client"
                && command == "account"
                && state_flag == "--state"
                && keypair_flag == "--keypair" =>
        {
            match kageb::handle_client_account(Path::new(state), Path::new(keypair)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("client account rejected: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        [group, command, state_flag, state, keypair_flag, keypair]
            if group == "client"
                && command == "result"
                && state_flag == "--state"
                && keypair_flag == "--keypair" =>
        {
            match kageb::handle_client_result(Path::new(state), Path::new(keypair)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("client result rejected: {error}");
                    ExitCode::FAILURE
                }
            }
        }
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
        [group, command, path, checkpoint_flag, checkpoint]
            if group == "verify"
                && command == "evidence"
                && checkpoint_flag == "--checkpoint-artifact" =>
        {
            verify_evidence_with_checkpoint(path, checkpoint, DEFAULT_DEVNET_RPC)
        }
        [group, command, path, checkpoint_flag, checkpoint, rpc_flag, rpc]
            if group == "verify"
                && command == "evidence"
                && checkpoint_flag == "--checkpoint-artifact"
                && rpc_flag == "--rpc" =>
        {
            verify_evidence_with_checkpoint(path, checkpoint, rpc)
        }
        [group, command, payer_flag, payer, program_flag, program, out_flag, out]
            if group == "demo"
                && command == "devnet"
                && payer_flag == "--payer"
                && program_flag == "--program"
                && out_flag == "--out" =>
        {
            demo_devnet(payer, program, out, DEFAULT_DEVNET_RPC, None)
        }
        [group, command, payer_flag, payer, program_flag, program, out_flag, out, rpc_flag, rpc]
            if group == "demo"
                && command == "devnet"
                && payer_flag == "--payer"
                && program_flag == "--program"
                && out_flag == "--out"
                && rpc_flag == "--rpc" =>
        {
            demo_devnet(payer, program, out, rpc, None)
        }
        [group, command, payer_flag, payer, program_flag, program, out_flag, out, checkpoint_flag, checkpoint]
            if group == "demo"
                && command == "devnet"
                && payer_flag == "--payer"
                && program_flag == "--program"
                && out_flag == "--out"
                && checkpoint_flag == "--checkpoint-artifact" =>
        {
            demo_devnet(payer, program, out, DEFAULT_DEVNET_RPC, Some(checkpoint))
        }
        [group, command, payer_flag, payer, program_flag, program, out_flag, out, checkpoint_flag, checkpoint, rpc_flag, rpc]
            if group == "demo"
                && command == "devnet"
                && payer_flag == "--payer"
                && program_flag == "--program"
                && out_flag == "--out"
                && checkpoint_flag == "--checkpoint-artifact"
                && rpc_flag == "--rpc" =>
        {
            demo_devnet(payer, program, out, rpc, Some(checkpoint))
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

fn verify_evidence_with_checkpoint(path: &str, checkpoint: &str, rpc: &str) -> ExitCode {
    match kageb::verify_evidence_file_with_checkpoint(Path::new(path), Path::new(checkpoint), rpc) {
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

fn demo_devnet(
    payer: &str,
    program: &str,
    out: &str,
    rpc: &str,
    checkpoint: Option<&str>,
) -> ExitCode {
    eprintln!("WARNING: synthetic assets only; this prototype is not safe for real funds.");
    match kageb::devnet_proof(
        Path::new(payer),
        program,
        Path::new(out),
        rpc,
        checkpoint.map(Path::new),
    ) {
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
