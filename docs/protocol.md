# KageB protocol guide

KageB v0.1 pools fixed-size encrypted orders. It waits for a declared crowd, opens the orders only after an onchain lock, nets opposing sides, and settles one aggregate residual.

## State flow

```text
OPEN -> LOCKED -> SETTLED
  |        |
  |        +-> ABORTED
  +----------> EXPIRED
```

1. The operator initializes a pool with fixed synthetic base and quote mints, a fixed venue, three keypers, and 2-of-3 thresholds.
2. The operator opens an epoch with a fixed lot size, quote price, minimum crowd, and deadlines.
3. Each participant transfers one base lot and enough quote for one lot to the pool vaults. The operator signs a funded authorization for the participant and epoch.
4. The participant signs a one-lot intent and encrypts it under the epoch threshold key on their own machine.
5. The host admits valid encrypted submissions. Duplicate participant IDs, nonces, receipts, and trading keys are rejected.
6. At least two keypers approve a package with at least four admitted participant IDs. The program records the lock digest and member commitment.
7. At least two valid shares recover each locked order. Limits and balances are checked against the frozen package.
8. Buys and sells net inside the pool. Only the residual goes to the fixed venue.
9. At least two keypers approve the result commitment. The program verifies their Ed25519 instructions, the venue signature, accounts, and token deltas before settlement.

No decryption share is accepted before a confirmed lock. One share is not enough to recover an order.

## What is public

| Public on Solana | Kept out of the public settlement trace |
| --- | --- |
| Funding authorities and two-sided token transfers | Each accepted participant's buy or sell side |
| Pool, epoch, vault, venue, mint, and keyper addresses | Signed intent bytes |
| Crowd count, lock digest, member commitment, and result commitment | Threshold-encryption randomness and secret shares |
| Aggregate residual and token balance changes | Host reservation records |
| Program code, ProgramData account, and upgrade authority | The mapping from participant ID to an opened order |

The operator and a colluding keyper threshold can recover locked order contents. The protocol makes a claim about the public trace, not about every observer.

## Fixed market model

The encrypted order begins with a fixed 128-byte v1 body containing:

- a one-byte version;
- a buy or sell side;
- exactly one lot;
- a nonzero limit price;
- a 32-byte epoch ID;
- a 32-byte participant ID;
- a 16-byte client nonce;
- zero-filled padding.

The trader adds a 64-byte Ed25519 signature before threshold encryption. The separate funded authorization binds the epoch, participant, trading public key, authorization nonce, reserved base and quote amounts, and expiry slot to the operator's signature.

The epoch fixes `base_lot_atoms` and `quote_atoms_per_lot`. A buy is eligible when its limit is at least the epoch price. A sell is eligible when its limit is at most the epoch price. The host ledger applies every valid internal fill and returns one residual:

```text
residual lots = buy lots - sell lots
```

A positive residual buys base from the venue. A negative residual sells base. Zero residual moves no venue tokens.

## Crowd and keyper rules

- The chain requires a configured minimum of at least four participant IDs.
- The host limits a batch to 64 members.
- Participant IDs must be distinct, but they do not prove unique people.
- Three keypers are fixed in the pool configuration.
- Two distinct configured keypers must approve lock and settlement.
- The reference implementation uses a trusted dealer. It does not implement distributed key generation.
- A malformed reveal or an order that contradicts the locked package aborts the full epoch and suspends the offending trading key in the host registry.

## Client boundary

The bot-facing command performs the secret-bearing step locally:

```text
JSON request on stdin -> sign fixed intent -> threshold encrypt -> JSON response on stdout
```

The JSON request contains the public epoch data, a funded authorization, and the participant's chosen side and limit. The `--keypair` flag names a local Solana-format trading keypair. The response contains an encrypted submission and public hashes. It does not echo the order side, limit, keypair path, secret key, signed intent, or plaintext intent.

```sh
kageb client prepare --keypair ./trading-keypair.json < request.json > submission.json
```

The keypair file must be a regular, non-symlink Solana JSON keypair file. On Unix, its mode must be exactly `0600`.

The strict v1 request is:

```json
{
  "schema_version": 1,
  "side": "buy",
  "limit_price": 100,
  "epoch_id": "<base58 32-byte epoch ID>",
  "participant_id": "<base58 32-byte participant ID>",
  "funded_authorization_base64": "<base64 funded authorization wire bytes>",
  "epoch_public_keys_base64": "<base64 epoch public-key wire bytes>"
}
```

`side` is `buy` or `sell`. `limit_price` must be nonzero. The strict v1 response is:

```json
{
  "schema_version": 1,
  "epoch_id": "<base58 32-byte epoch ID>",
  "participant_id": "<base58 32-byte participant ID>",
  "trading_key": "<base58 Ed25519 public key>",
  "ciphertext_sha256_base64": "<base64 SHA-256 digest>",
  "submission_sha256_base64": "<base64 SHA-256 digest>",
  "encrypted_submission_base64": "<base64 encrypted submission wire bytes>"
}
```

Input is capped at 16 KiB, rejects unknown fields and noncanonical encodings, and must match the authorization's epoch, participant, and trading key. Diagnostics do not echo the request, local path, or key bytes.

The client checks the authorization's structure and context. The coordinator still verifies its operator signature, funding policy, and expiry during admission. The epoch public-key wire has no epoch ID of its own, so v0.1 relies on the coordinator to distribute the correct set for the requested epoch.

This is one client adapter, not a hosted API. The operator transport, authorization endpoint, submission relay, remote keyper service, and trading venue integration remain outside v0.1.

## Onchain instructions

The program exposes six instructions:

1. `InitializePool`
2. `CreateEpoch`
3. `LockEpoch`
4. `SettleEpoch`
5. `ExpireEpoch`
6. `AbortEpoch`

The program enforces PDAs, owners, signers, fixed account order, pool and epoch state transitions, exact mint and vault relationships, keyper quorum, venue authority, digest equality, and aggregate token conservation. It does not decrypt orders or validate individual limits onchain. Keypers sign those offchain checks.

Abort and expiry change epoch state. They do not transfer or refund tokens.

## Evidence contract

[`evidence/devnet.json`](../evidence/devnet.json) is a strict v1 document. Unknown fields fail. Its content hash covers the canonical serialized content, including:

- the public source commit, Solana Verify version, and pinned build-image digest;
- verifiable-build and deployed SBF hashes;
- program, ProgramData, loader, slot, and upgrade authority;
- four funding transactions, one lock, and one settlement;
- all relevant accounts and protocol configuration;
- lock, membership, result, and settlement commitments;
- before and after pool and venue token balances;
- the exact decoded instruction allowlist.

The standalone verifier fetches finalized Devnet state, checks transaction order, reconstructs the allowed instructions, checks balance conservation and program identity, rebuilds the recorded source commit in the pinned container, and compares every SBF byte with ProgramData.

The file is content-addressed and tamper-evident. A hash is not a signature. The proof remains scoped to the recorded run and observer model.

## Failure and liveness

- Fewer than four valid participants leaves the epoch open until expiry.
- Fewer than two keyper approvals prevents lock or settlement.
- A bad reveal aborts the epoch.
- An unavailable operator or venue can halt progress.
- Abort and expiry do not refund assets in v0.1.
- The Devnet deployment can change while its upgrade authority remains set.

These are explicit prototype limits, not hidden recovery paths.
