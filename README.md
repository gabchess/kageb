# KageB

**Four real orders go in. One group trade comes out. No fake trades.**

KageB is a Solana reference prototype for traders who do not want each order to travel beside their public wallet. A trader encrypts a one-lot buy or sell on their own machine. KageB waits for four funded participants, locks the group, then sends only the net result to the market.

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
SETTLED: one aggregate
BALANCED: zero residual; no venue leg
ABORTED: invalid reveal; trading key suspended
OBSERVER: direct 4 orders; KageB 1 aggregate
It does not prove unique humans, production anonymity, private funding or withdrawal, a trustless exchange, protection from the KageB operator, or safe use with real funds.
```

## Verify the Devnet proof

The public evidence records four funded participants, a 4-of-4 crowd lock, a 2-of-3 keyper quorum, and one aggregate `BUY 2 lots` settlement.

```sh
./scripts/verify-public-evidence.sh
```

The verifier does more than parse JSON. It checks the content hash, fetches finalized Devnet transactions and accounts, validates the instruction allowlist and token conservation, checks the provisional upgrade authority, rebuilds the recorded public commit, and compares its SBF executable hash with the deployed executable.

Expected result:

```text
VERIFIED: evidence 93e0431db99e154382af2fadba6a9e60bd1bfea50096e115401a3e601d8f2198 settlement 3k8Usa12jhcQPxGYkjsqE5T9Ens4h3RHoiL8yH5cqfkoHmac7q6bch97FTfxetSAyLL2cNp41eF4g2uQcvqUM6D5
```

- Program: [`HbMyCP5GxicksRpSVrchRTJTznP3zTrzCMb7FmZNRa77`](https://explorer.solana.com/address/HbMyCP5GxicksRpSVrchRTJTznP3zTrzCMb7FmZNRa77?cluster=devnet)
- Lock: [`4N1kxRiW7KZ4G8WN5WqPkSG6aX1y8xHYMoWZ5cBeYQk3Dr5pMjBsWEiwTtMm2QYLQMyHrVD9BMmq8pZWnx8TAxRt`](https://explorer.solana.com/tx/4N1kxRiW7KZ4G8WN5WqPkSG6aX1y8xHYMoWZ5cBeYQk3Dr5pMjBsWEiwTtMm2QYLQMyHrVD9BMmq8pZWnx8TAxRt?cluster=devnet)
- Aggregate settlement: [`3k8Usa12jhcQPxGYkjsqE5T9Ens4h3RHoiL8yH5cqfkoHmac7q6bch97FTfxetSAyLL2cNp41eF4g2uQcvqUM6D5`](https://explorer.solana.com/tx/3k8Usa12jhcQPxGYkjsqE5T9Ens4h3RHoiL8yH5cqfkoHmac7q6bch97FTfxetSAyLL2cNp41eF4g2uQcvqUM6D5?cluster=devnet)
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
- The `kageb client prepare` command is the bot-facing boundary. It accepts strict versioned JSON on standard input, signs and encrypts locally, and emits only an encrypted submission plus public identifiers. See [the protocol guide](docs/protocol.md#client-boundary) for the schema and example.

The v0.1 API can change. An operator still needs to provide a funded authorization and epoch public keys, admit submissions, run the keyper set, and submit lock and settlement transactions.

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

## License

MIT
