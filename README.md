# KageB

**Four real orders go in. One group trade comes out. No fake trades.**

KageB is a Solana reference prototype for traders who do not want each order to travel beside their public wallet. A trader encrypts a one-lot buy or sell on their own machine. KageB waits for four admitted participant IDs with two-sided funding, locks the group, then sends only the net result to the market.

The public settlement trace shows the group result. It does not show which accepted participant chose buy or sell.

> **Prototype warning:** KageB uses synthetic, zero-decimal assets on Devnet. It is custodial, upgradeable, and not safe for real funds.

## See the difference

```sh
cargo run --release --locked -p kageb-host --bin kageb -- trace
```

```text
DIRECT: 4 wallet-linked orders visible
wallet 0b0b0b0b: BUY 1 lots
wallet 0c0c0c0c: SELL 1 lots
wallet 0d0d0d0d: BUY 1 lots
wallet 0e0e0e0e: BUY 1 lots

KAGEB: 0 individual orders visible
pool aggregate: BUY 2 lots | pool 09090909 | venue 08080808 | member root 171a36c7 | result commitment 60432e36 | keyper approvals 0

4 real orders, one pooled result, no decoy trades.
```

This is a fixed local comparison, not the Devnet proof. Run the full proof below to exercise the Solana program.

## How it works

KageB takes its name from Naruto's Kage Bunshin. Think of each order as one sealed scroll in a crowd. The chain sees the crowd move, not the choice inside each scroll. Unlike the anime technique, KageB does not create fake trades.

1. Each participant funds and reserves one base lot **and** enough quote for one lot. KageB needs both sides so the public funding step does not reveal the order side. The assets remain in custodial pool vaults because v0.1 has no withdrawal or refund instruction.
2. The trader signs and encrypts a fixed-size order on their own machine.
3. KageB refuses to lock until at least four valid participants are present.
4. Two of three reference keypers approve the lock before shares can open the orders.
5. Opposing orders cancel inside the pool. Only the group residual reaches the fixed venue.
6. Two keypers approve the result before the program moves the aggregate token legs.

The scroll analogy ends at the public chain boundary. The operator and a threshold of keypers can recover order contents after lock. Funding addresses and token transfers remain public.

## Run the local proof

Requirements:

- Rust 1.95.0 for host builds. SBF builds use the Solana platform toolchain's Rust 1.89.0.
- Solana CLI 4.0.1 and `cargo-build-sbf` 4.0.0
- A local validator that can bind to `127.0.0.1`

```sh
./scripts/check-local-demo.sh
```

The proof builds fresh SBF programs, starts a local validator, and checks the exact result:

```text
WARNING: synthetic assets only; this prototype is not safe for real funds.
WAIT: crowd 3/4
LOCKED: crowd 4/4
REFUSED: one share
QUORUM: all 3 two-share paths agree
SETTLED: one aggregate
RESULTS: authenticated balances persisted
BALANCED: zero residual; no venue leg
EXPIRED: underfilled; reservations released
ABORTED: invalid reveal; trading key suspended
OBSERVER: direct 4 orders; KageB 1 aggregate
It does not prove unique humans, production anonymity, private funding or withdrawal, a trustless exchange, protection from the KageB operator, or safe use with real funds.
```

## Verify the Devnet proof

The public evidence records four two-sided funding events from distinct authorities, a 4-of-4 crowd lock, a 2-of-3 keyper quorum, and one aggregate `BUY 2 lots` settlement. It does not claim those authorities belong to four people.

Full source verification needs Docker and `solana-verify` 0.5.1. KageB builds the cited commit inside the official Solana 4.0.1 verifiable-build image pinned in [`verifiable-build.json`](verifiable-build.json).

```sh
cargo install solana-verify --version 0.5.1 --locked
./scripts/verify-public-evidence.sh
```

The verifier checks the content hash, fetches finalized Devnet transactions and accounts, validates the instruction allowlist and token conservation, checks the provisional upgrade authority, rebuilds the recorded public commit in the pinned container, and compares every byte with the deployed executable.

Expected result:

```text
VERIFIED: evidence 212967621d66c2e2b36ca5829a2fa6de25d6b3ab4141ceaa4b385d4978bc673f settlement 5umEQVm3nw9iF1N9fKzJA5wRz2ast2a8xG7ysPUfiTBmmTWQFXja7xaDqJQgYYNvuoiAiqsFnMFFdo28o6u7ToZe
```

- Program: [`HbMyCP5GxicksRpSVrchRTJTznP3zTrzCMb7FmZNRa77`](https://explorer.solana.com/address/HbMyCP5GxicksRpSVrchRTJTznP3zTrzCMb7FmZNRa77?cluster=devnet)
- Lock: [`CwnRT1Saa7auaCfBigBhn8prTAyxgS6eLnNRgEyjXZXqgebYBtsiqSMBvgwgN21tQECfNRS31z4dudaUH23kXbZ`](https://explorer.solana.com/tx/CwnRT1Saa7auaCfBigBhn8prTAyxgS6eLnNRgEyjXZXqgebYBtsiqSMBvgwgN21tQECfNRS31z4dudaUH23kXbZ?cluster=devnet)
- Aggregate settlement: [`5umEQVm3nw9iF1N9fKzJA5wRz2ast2a8xG7ysPUfiTBmmTWQFXja7xaDqJQgYYNvuoiAiqsFnMFFdo28o6u7ToZe`](https://explorer.solana.com/tx/5umEQVm3nw9iF1N9fKzJA5wRz2ast2a8xG7ysPUfiTBmmTWQFXja7xaDqJQgYYNvuoiAiqsFnMFFdo28o6u7ToZe?cluster=devnet)
- Evidence: [`evidence/devnet.json`](evidence/devnet.json)

The evidence is content-addressed and tamper-evident. It is not signed evidence. The deployed program retains a provisional upgrade authority, so the deployment is not immutable.

## What the proof means

For the declared four-member Devnet epoch, a public observer can verify four two-sided funding events, one crowd lock, and one aggregate market-facing settlement. The accepted participants' individual buy or sell choices do not appear in that public settlement trace.

The proof does **not** show:

- who the participants are or whether four keys belong to four people;
- private funding, deposits, withdrawals, or network metadata;
- protection from the operator or a colluding keyper threshold;
- safe liveness if the operator, venue, or keypers stop;
- a trustless exchange, price discovery, partial fills, variable size, or fees;
- production anonymity or safety for real assets.

If an observer already knows every other participant's order, the aggregate can reveal the remaining order. Crowd size is a condition for the demo, not a guarantee of anonymity.

## Build on KageB

The workspace exposes Rust protocol building blocks and a reference implementation, not a hosted service or complete trading SDK.

- `kageb-host`, imported as `kageb`, provides intent, threshold-encryption, admission, ledger, lock, keyper, observer, and evidence types.
- `kageb-program` provides the Solana instructions, program state, PDAs, and v1 wire types.
- The four `kageb client` commands form the reference bot boundary: `account` registers local funded state, `epoch` checks the shape and deadline of coordinator-supplied crowd terms, `prepare` signs and encrypts locally, and `result` returns a persisted balance only to the registered trading key. Each command accepts strict versioned JSON on standard input. Run any command with `--help` for its exact contract, then see [the protocol guide](docs/protocol.md#client-boundary).

The v0.1 API can change. These commands share a local reference state file scoped to one pool; an operator must use a separate state file for each pool. They are not a hosted coordinator or remote authentication protocol. An operator still needs to provide a funded authorization and epoch public keys, admit submissions, run the keyper set, and submit lock and settlement transactions.

## Protocol limits

KageB v0.1 deliberately keeps the market model small:

- exactly one lot per order;
- one operator-set fixed price per epoch;
- classic SPL Token with zero-decimal synthetic mints;
- at least four admitted participant IDs and at most 64 host-side members;
- three configured keypers with a 2-of-3 lock and settlement threshold;
- one aggregate residual sent to one fixed venue;
- no deposit, withdrawal, refund, order-book, fee, or production key-management service.

Read [the protocol guide](docs/protocol.md) for the state machine and [SECURITY.md](SECURITY.md) for the trust boundary and reporting policy.

## Repository checks

```sh
./scripts/ci.sh
```

This runs formatting, clippy, tests, docs, SBF builds, the local proof, toolchain checks, license checks, and the public-file scanner. The Devnet verifier is a separate networked check.

Build the deployable, reproducible SBF artifact with:

```sh
cargo install solana-verify --version 0.5.1 --locked
./scripts/verifiable-build.sh
```

Do not deploy the output of a plain `cargo build-sbf` command. Solana program builds can differ across host systems. The Devnet evidence binds the pinned container output to the public source commit and ProgramData bytes.

## License

MIT
