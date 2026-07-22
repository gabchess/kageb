# Security policy

KageB v0.1 is a research prototype for synthetic assets on Solana Devnet. Do not use it with real funds.

## What KageB protects

Under the declared demo observer, an accepted participant's buy or sell choice is absent from the public lock and settlement trace. The chain shows two-sided funding, a group lock, commitments, and one aggregate residual.

KageB does not hide funding addresses, token transfers, withdrawals, network metadata, or the group result. It does not protect an order from the operator and a colluding decryption threshold after lock.

## Trust boundary

- **Operator:** Chooses the epoch configuration and fixed price, signs funded authorizations and balance snapshots, and controls the custodial host ledger.
- **Keypers:** Two of three approve lock and settlement. The reference demo uses a trusted dealer and is not a distributed key generation system.
- **Venue:** Signs the aggregate settlement and must remain live. KageB does not prove the venue price.
- **Program authority:** The Devnet program remains upgradeable under the authority recorded in the evidence bundle.
- **Participants:** Participant IDs are distinct keys, not proof of distinct people. A malicious valid submission can cause the epoch to abort during reveal.
- **Client inputs:** The local client checks that the authorization names the requested epoch, participant, and trading key. The coordinator still checks the operator signature, funding policy, and expiry. The epoch public-key wire does not carry an epoch ID, so v0.1 relies on the coordinator to publish the right key set.

## Known limits

- Synthetic, zero-decimal classic SPL Token assets only.
- Custodial pool vaults and host ledger.
- No deposit, withdrawal, refund, or recovery instruction.
- One lot at one operator-set price, with no fees, partial fills, or price discovery.
- Public two-sided funding reserves one base lot and enough quote for one lot before the private side is chosen.
- No protection when an observer knows all but one member's order.
- No production key storage, distributed key generation, HSM, TEE, remote keyper network, or denial-of-service defense.
- No client-side cryptographic binding between an epoch ID and the supplied epoch public-key set.
- No claim of anonymity, unlinkability, Sybil resistance, immutability, or mainnet safety.

## Dependency audit scope

CI scans the locked dependency graph against RustSec. Two advisories are scoped out only after CI proves their affected versions are absent from KageB's normal and build dependency tree:

- `RUSTSEC-2024-0344` (`curve25519-dalek` 3.2.0) enters through `solana-program-test`.
- `RUSTSEC-2022-0093` (`ed25519-dalek` 1.0.1) enters through `solana-program-test`.

Those crates run in tests, not in the KageB client, coordinator, keyper, or onchain program. The production graph still includes old dependencies from `threshold_crypto` 0.4. Its `failure` use derives `Fail`, which RustSec excludes from `RUSTSEC-2019-0036`, and KageB installs no custom logger required by `RUSTSEC-2026-0097`. This is still maintenance debt and one reason v0.1 is limited to synthetic assets on Devnet.

The evidence verifier proves one recorded run under this boundary. It does not audit all future code or deployments.

## Build trust

The Devnet executable comes from `solana-verify` 0.5.1 and the official Solana 4.0.1 verifiable-build image pinned by digest in `verifiable-build.json`. The verifier rebuilds the cited public commit in that container and requires an exact ProgramData match. This proves source identity, not code safety. The build still trusts the pinned container and its installed tools.

## Report a vulnerability

Do not post secrets or working exploit details in a public issue. Open a short issue asking for a private contact channel, without the sensitive details. Include the affected commit, component, and impact once a private channel is agreed.

Please do not test against accounts or assets you do not own.
