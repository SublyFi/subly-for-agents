# A402-Solana (Subly)

Privacy-focused x402 payment protocol on Solana using AWS Nitro Enclaves.

## Language

- Communicate with the user in Japanese
- All code, comments, commit messages, and variable names in English

## Architecture Overview

A402-Solana implements sender anonymity for x402 payments via a TEE-based vault:

- **On-chain Program** (Anchor/Rust): Escrow, batch settlement, force-settle dispute resolution
- **Nitro Enclave** (Rust): Facilitator API (`/verify`, `/settle`, `/cancel`, `/attestation`), client balance management, batch construction, receipt signing
- **Parent Instance** (Rust): L4 ingress/egress relay, KMS proxy, encrypted snapshot/WAL storage (untrusted)
- **Receipt Watchtower** (Rust): Stores latest ParticipantReceipts, submits force-settle challenges
- **Client SDK** (TypeScript): `A402Client` — deposit, withdraw, fetch (x402-compatible), attestation verification, audit tool
- **Provider Middleware** (TypeScript/Express): x402 HTTP 402 envelope with `a402-svm-v1` scheme

## Development Phases

Implementation follows phased approach. Always check which phase is currently active before implementing.

- **Phase 1**: Vault + Custom Facilitator + Batch Settlement (Nitro MVP)
- **Phase 2**: Audit Records + Selective Disclosure (ElGamal + hierarchical key derivation)
- **Phase 3**: Atomic Service Channels + Provider TEE (Ed25519 adaptor signatures)
- **Phase 4**: Force Settlement + Dispute Resolution + Receipt Watchtower
- **Phase 5**: Arcium MXE Integration
- **Phase 6**: Deposit Privacy (Token-2022 Confidential Transfer)

## Tech Stack

| Component | Technology |
|-----------|-----------|
| On-chain program | Anchor (Rust) |
| Enclave runtime | Rust (rustls + hyper) |
| Client SDK | TypeScript |
| Provider middleware | TypeScript + Express |
| Tests | TypeScript (anchor test) |
| Local validator | Surfpool (`surfpool start`) |
| Target networks | Localnet → Devnet → Mainnet |

## Project Structure

```
a402-solana/
├── programs/a402_vault/src/     # Anchor program
├── enclave/src/                 # Nitro Enclave facilitator (Rust)
├── parent/src/                  # Untrusted parent relay (Rust)
├── watchtower/src/              # Receipt Watchtower (Rust)
├── sdk/src/                     # Client SDK (TypeScript)
├── encrypted-ixs/src/           # Phase 5 Arcium circuits
├── infra/                       # Terraform + Nitro build
└── tests/                       # All test files
```

## Build & Test Commands

```bash
# Build the Anchor program
anchor build

# Run all tests (MUST run after every implementation change)
anchor test

# Start local validator with surfpool
surfpool start

# Deploy to devnet
anchor deploy --provider.cluster devnet
```

## Development Rules

### Always Test

After implementing any feature or fix, **always run tests before considering the work done**. Use `anchor test` to execute the test suite. If tests fail, fix them before moving on.

### Testing Strategy

1. **Local first**: Use surfpool for local testing during development
2. **Devnet after**: Deploy and test on devnet only after local tests pass
3. **Test coverage**: Every new instruction or API endpoint must have corresponding tests

### Anchor Program Guidelines

- Use Anchor framework for all Solana program development
- Account structs should include all fields from the design doc (future phases included) to avoid realloc migrations
- PDA seeds follow the convention in `docs/a402-solana-design.md` section 6.2
- Status guards: check `VaultStatus` for every instruction per the guard matrix in section 6.3
- Ed25519 signature verification uses the `Ed25519Program` precompile + `sysvar::instructions`

### TypeScript Guidelines

- Client SDK and tests in TypeScript
- Express for provider middleware / API endpoints
- Use `@solana/web3.js` and `@coral-xyz/anchor` for Solana interactions
- Tests use Mocha + Chai (Anchor standard)

### Security

- Never expose plaintext secrets, vault signer seeds, or snapshot keys outside TEE
- Parent instance is untrusted — no TLS termination, no request parsing
- WAL must be durably appended before returning success responses from `/verify` or `/settle`
- `vault_signer_pubkey` is never rotated in-place — deploy a new vault and migrate
- Validate at system boundaries: client signatures, provider auth, on-chain instruction args

## Key Design Documents

All protocol details are in `docs/`:

- `a402-solana-design.md` — Full architecture, account structs, instructions, client SDK, phases
- `a402-svm-v1-protocol.md` — Wire protocol: PAYMENT-REQUIRED/SIGNATURE/RESPONSE schemas, facilitator API, state machine, batch settlement
- `a402-nitro-deployment.md` — Nitro Enclave deployment, KMS bootstrap, persistence, incident response

**Always consult these docs before implementing.** They are the source of truth for protocol behavior.

## Progress Tracking

Record implementation progress and important decisions in `.claude/MEMORY.md`.

- When each phase is completed, record what was implemented, test results, and remaining issues
- Record important design decisions, such as library selection rationale or deviations from the design documents
- At the start of a new conversation, read `.claude/MEMORY.md` to understand the previous implementation state

## Key Constants

```
BATCH_WINDOW_SEC = 120
MAX_SETTLEMENT_DELAY_SEC = 900
MAX_SETTLEMENTS_PER_TX = 20
DISPUTE_WINDOW = 24 hours
SNAPSHOT_EVERY_N_EVENTS = 1000
SNAPSHOT_EVERY_SEC = 30
MIN_ANONYMITY_WINDOW_SEC = 60   # default; override via A402_MIN_ANONYMITY_WINDOW_SEC
MIN_BATCH_PROVIDERS = 1          # default; raise via A402_MIN_BATCH_PROVIDERS for k-anonymity
```
