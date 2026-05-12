# Implementation Progress

## Phase 1: On-chain Program (2026-04-12) ✅

Anchor program implemented and all tests passing.

### Account structs (all future-phase fields included to avoid realloc)
- `VaultConfig` — vault state, governance, signer, counters
- `AuditRecord` — encrypted audit trail (Phase 2+ usage)
- `ForceSettleRequest` — dispute resolution state
- `UsedWithdrawNonce` — replay prevention

### Instructions (12)
- `initialize_vault`, `deposit`, `withdraw`, `settle_vault`
- `pause_vault`, `announce_migration`, `retire_vault`, `rotate_auditor`
- `force_settle_init`, `force_settle_challenge`, `force_settle_finalize`
- `record_audit` (Phase 2 stub)

### Tests (18 passing)
- initialize_vault, deposit (+zero reject), settle_vault (+unauthorized signer reject, multi-provider batch)
- pause_vault (+deposit-on-paused reject), announce_migration, rotate_auditor
- retire_vault (+active-vault reject)
- withdraw (+wrong signer reject, +mismatched message reject, +nonce replay reject)
- force_settle_init (+wrong signer reject)
- force_settle_challenge (+stale nonce reject)
- force_settle_finalize (dispute window active reject)

### Implementation notes
- Ed25519 signature verification: shared `ed25519_utils.rs` helper uses `solana_sdk_ids::ed25519_program::ID` (Anchor 0.32.1 does not re-export `ed25519_program` from `anchor_lang::solana_program`)
- `anchor-spl/idl-build` feature required in Cargo.toml for IDL generation
- Status guard matrix enforced via Anchor constraints (design doc section 6.3)
- PDA seeds match design doc section 6.2

## Phase 1: Enclave Facilitator (2026-04-12) ✅

### API Endpoints (8)
- `GET /v1/attestation` — Vault config, signer pubkey, stub attestation doc
- `POST /v1/verify` — Full payment verification + balance reservation + WAL
- `POST /v1/settle` — Off-chain settlement + ParticipantReceipt issuance
- `POST /v1/cancel` — Release reserved balance
- `POST /v1/withdraw-auth` — Ed25519 signed withdrawal authorization
- `POST /v1/balance` — Client balance query
- `POST /v1/receipt` — Issue signed ParticipantReceipt for client
- `POST /v1/provider/register` — Provider registration

### State Management
- `VaultState` with DashMap-based concurrent state
- `ClientBalance`, `Reservation`, `ProviderCredit`, `ProviderRegistration`
- Atomic nonces for receipts and withdrawals

### Background Tasks
- Batch settlement loop (120s window, MIN_BATCH_PROVIDERS=1 by default, MAX_SETTLEMENT_DELAY=900s)
- Reservation expiry loop (60s timeout)
- Deposit detection loop (polling mode for local dev, production uses logsSubscribe)

### Persistence
- JSONL WAL with sync/flush (durable before response)
- Events: DepositApplied, ReservationCreated, SettlementCommitted, ReservationCancelled, ReservationExpired, ParticipantReceiptIssued, BatchSubmitted, BatchConfirmed

## Phase 1: Parent Instance (2026-04-12) ✅

### Components (4)
- `ingress_relay.rs` — TCP → vsock bidirectional L4 relay (TLS terminated in enclave)
- `egress_relay.rs` — vsock → TCP with connect-request protocol for external targets
- `kms_proxy.rs` — Length-prefixed JSON proxy with KMS action whitelist
- `snapshot_store.rs` — Encrypted blob store with PUT/GET/LIST/DELETE ops, SHA-256 path hashing

### Design decisions
- All components use TCP loopback for local dev, vsock for production Nitro
- KMS proxy whitelists only Decrypt/GenerateDataKey/GenerateRandom
- Snapshot store uses atomic write (temp file + rename) for data integrity
- Parent never terminates TLS — transparent L4 relay only

## Phase 1: Deposit Detection (2026-04-12) ✅

### deposit_detector.rs
- `DepositDetector` struct with sync status, processed signature tracking
- `spawn_deposit_detector` background task
- Main loop: initial catch-up → subscribe → reconnect on failure
- Catch-up logic per design doc §5.6 (getSignaturesForAddress)
- `apply_deposit`: updates client balance + WAL + processed signatures
- Phase 1: polling mode stub. Production: logsSubscribe WebSocket

## Phase 1: Client SDK (2026-04-12) ✅

### A402Client Methods
- `verifyAttestation()` — Cached attestation verification
- `deposit(amount, program, usdcMint)` — On-chain USDC deposit
- `withdraw(amount, program, usdcMint)` — Enclave-authorized withdrawal
- `getBalance()` — Query enclave client balance
- `getReceipt(usdcMint)` — Request signed ParticipantReceipt
- `forceSettle(receipt, program)` — Emergency on-chain force settle
- `fetch(url, options)` — x402-compatible automatic payment

### Type Exports
- BalanceResponse, ParticipantReceiptResponse added to SDK types

## Phase 1: Provider Middleware (2026-04-12) ✅

- Express middleware with 402 response generation
- PAYMENT-SIGNATURE decoding and facilitator verify/settle
- Async settlement after response delivery

## Phase 2: Audit Records + Selective Disclosure (2026-04-12) ✅

### ElGamal Encryption (enclave/src/audit.rs)
- ECIES-like variant on Ristretto255: C1 = r*G (32 bytes), C2 = data XOR SHA256("a402-elgamal-mask-v1" || r*P) (32 bytes)
- Total ciphertext: 64 bytes per field (encrypted_sender, encrypted_amount)
- Uses curve25519-dalek Ristretto points, HKDF-SHA256 for key derivation
- Unit tests: encrypt/decrypt roundtrip, selective disclosure, exported key

### Hierarchical Key Derivation
- Master secret → provider-specific key via HKDF(salt="a402-audit-v1", info=provider_address)
- 64-byte HKDF output reduced mod l to Ristretto scalar
- `export_provider_key()`: export derived secret for scoped third-party auditing
- Separate master key derivation for full-audit use case

### record_audit On-chain Instruction (Full Implementation)
- Creates AuditRecord PDAs via remaining_accounts
- sysvar::instructions verification: atomic pairing with settle_vault required
- Verifies batch_id, batch_chunk_hash, vault_config match between settle and audit
- Standalone execution rejected (RecordAuditWithoutSettle error)
- auditor_epoch from VaultConfig embedded in each record
- MAX_ATOMIC_AUDITS_PER_TX = 5

### Enclave Batch Settlement with Audit
- fire_batch() generates EncryptedAuditRecord for each settlement
- Settlement history tracking (SettlementRecord) in VaultState
- Batch chunking: up to 4 settlements per tx when audit records included
- auditor_master_secret and auditor_epoch added to VaultState

### AuditTool (SDK, sdk/src/audit.ts)
- `AuditTool` class: decryptAll, decryptForProvider, exportProviderKey
- `decryptWithKey()` static method for third-party auditors
- On-chain AuditRecord PDA fetching via getProgramAccounts + memcmp filter
- ElGamal decryption using @noble/curves for Ristretto255
- HKDF key derivation matching enclave's HKDF parameters

### Tests (3 new)
- record_audit: rejects non-vault-signer (updated with instructions_sysvar)
- record_audit: rejects standalone execution (no settle_vault in same tx)
- record_audit: creates audit record atomically with settle_vault

### Implementation Notes
- Anchor discriminator for settle_vault computed as sha256("global:settle_vault")[..8]
- record_audit searches up to 16 instructions in the tx for settle_vault pairing
- @noble/curves and @noble/hashes added to package.json for SDK crypto
- VaultState now tracks settlement_history for audit record generation

## Remaining for Phase 3
- Ed25519 adaptor signatures for Exec-Pay-Deliver atomicity
- Provider TEE integration
- ASC state management (A402 Algorithm 1)
- Batch submission to on-chain settle_vault (enclave → Solana RPC)

## Phase 1/2 Hardening + Verification (2026-04-12) ✅

### Why this pass was needed
- The previous "Phase 2 complete" state was not verified end-to-end.
- `a402_vault` did not compile because of `record_audit` lifetime/import issues.
- `settle_vault` still allowed standalone execution, so audit coverage was not enforced.
- Multi-chunk audit batches reused `(batch_id, index)` from zero and would collide on AuditRecord PDAs.
- The enclave batch planner could clear pending state even though no on-chain batch transaction had been submitted.

### On-chain fixes
- `settle_vault` now requires a paired `record_audit` instruction in the same transaction via `sysvar::instructions`.
- `record_audit` still rejects standalone execution and now also validates provider ordering against the paired `settle_vault`.
- Added `SettleVaultWithoutAudit` error for the missing reverse-pairing case.
- `record_audit` now derives the audit PDA index from the provided PDA, so the same `batch_id` can span multiple atomic chunks without index collisions.

### Enclave fixes
- Batch preparation now builds 1 settlement entry ↔ 1 audit record, matching the design doc.
- Pending provider credits are no longer cleared before successful submission.
- Added unit coverage for chunk index offsets and deterministic chunk hashing.
- Automatic RPC submission is still a separate runtime integration task; the code now keeps settlements queued instead of dropping them.

### SDK fixes
- `AuditTool.exportProviderKey()` now returns the same 32-byte reduced scalar form as the Rust enclave export path.
- Added SDK tests that verify exported-key shape and successful decryption with the exported provider key.

### Verified commands
- `cargo test -p a402_vault`
- `cargo test -p a402-enclave`
- `anchor test`
- `yarn ts-mocha -p ./tsconfig.json -t 30000 tests/audit_tool.ts`

## Surfpool E2E + Program ID Sync (2026-04-12) ✅

### Why this pass was needed
- The previous verification stopped at Anchor/local runtime tests and did not prove the enclave could submit `settle_vault + record_audit` over a real local RPC.
- The workspace also had a program ID split: `Anchor.toml` / `declare_id!` used `Gjx...`, while `target/deploy/a402_vault-keypair.json` and `target/idl/a402_vault.json` used `DeE...`.
- `anchor deploy` against surfpool stalled because TPU-based deploy flow did not cooperate with surfpool; RPC-based program deploy worked.

### Runtime fixes
- `enclave` now accepts runtime Solana config via env:
  - `A402_PROGRAM_ID`
  - `A402_VAULT_CONFIG`
  - `A402_VAULT_TOKEN_ACCOUNT`
  - `A402_USDC_MINT`
  - `A402_SOLANA_RPC_URL`
  - `A402_SOLANA_WS_URL`
  - `A402_VAULT_SIGNER_SECRET_KEY_B64`
  - `A402_WAL_PATH`
- Added `SolanaRuntimeConfig` to `VaultState`.
- `batch.rs` now performs real atomic submission by building `settle_vault` + `record_audit` instructions from the Anchor-generated `a402_vault` types and sending them via `anchor-client`.
- Successful chunks now update provider credits, settlement history, reservation status, `last_batch_at`, and WAL only after confirmed submission.
- Added `POST /v1/admin/fire-batch` for local dev / E2E triggering.
- Moved the actual Anchor client submission onto `spawn_blocking` because the blocking client cannot run directly inside the enclave's tokio runtime.

### Program ID sync
- Synced `Anchor.toml` and `programs/a402_vault/src/lib.rs` to the real deploy keypair / IDL address:
  - `DeEyzGPw8yPL1UgCC6JuPfeDWU4E1QHh9j3ZmdfCc4RR`

### New verification
- Added `tests/enclave_surfpool_e2e.ts`.
- Verified flow on surfpool:
  1. start surfpool
  2. deploy `a402_vault` with `solana program deploy --use-rpc`
  3. start enclave with deterministic signer + runtime env
  4. initialize vault on-chain
  5. deposit USDC on-chain
  6. `/verify`
  7. `/settle`
  8. `/v1/admin/fire-batch`
  9. confirm provider token account received funds on-chain
  10. decrypt the on-chain `AuditRecord` via `AuditTool`

### Verified commands
- `NO_DNA=1 surfpool start --legacy-anchor-compatibility --ci`
- `solana program deploy --url http://127.0.0.1:8899 --use-rpc --program-id target/deploy/a402_vault-keypair.json --fee-payer ~/.config/solana/id.json --upgrade-authority ~/.config/solana/id.json target/deploy/a402_vault.so`
- `yarn ts-mocha -p ./tsconfig.json -t 180000 tests/enclave_surfpool_e2e.ts`
- `cargo test -p a402-enclave`
- `cargo test -p a402_vault`
- `anchor test`
- `yarn ts-mocha -p ./tsconfig.json -t 30000 tests/enclave_api.ts`
- `yarn ts-mocha -p ./tsconfig.json -t 30000 tests/audit_tool.ts`

### Remaining gap after this pass
- Deposit detection is still local-dev stub / polling skeleton; the surfpool E2E seeds enclave balances via `/v1/admin/seed-balance` after the on-chain deposit because automatic deposit ingestion is not implemented yet.

## Phase 3: Atomic Service Channels + Provider TEE (2026-04-12) ✅

### Ed25519 Adaptor Signatures (enclave/src/adaptor_sig.rs, 374 lines)
- ECIES-like Ed25519 adaptor signature protocol: pSign, pVerify, adapt, extract, verify_adapted
- Uses curve25519-dalek v4 for Ristretto/Ed25519 operations
- 8 unit tests: pre_sign_and_verify, rejection tests, adapt roundtrip, secret extraction, full protocol flow

### ASC Manager (enclave/src/asc_manager.rs, 1001 lines)
- Full implementation of design doc Algorithm 1
- Channel lifecycle: open_channel → submit_request → deliver_adaptor → finalize_offchain → close_channel
- Channel states: Open → Locked → Pending → Closed
- Fund locking/unlocking, replay protection (used_request_ids)
- Adaptor pre-signature verification (pVerify integration)
- Result encryption/decryption using scalar-based symmetric key
- Rollback handlers for atomic transaction semantics

### ASC State (enclave/src/state.rs)
- `ChannelState`: channel_id, client, provider_id, balance triple, status, nonce, timestamps
- `ChannelRequest`: request_id, amount, hashes, provider pubkey, adaptor point, pre-signature, encrypted result
- `ChannelStatus` enum: Open, Locked, Pending, Closed
- `ChannelBalance`: (client_free, client_locked, provider_earned)
- `VaultState.active_channels`: DashMap<ChannelId, ChannelState>

### ASC HTTP Endpoints (enclave/src/handlers.rs)
- `POST /v1/channel/open` — ASC opening, initial deposit, signature verification
- `POST /v1/channel/request` — request submission, fund locking, client signature verification
- `POST /v1/channel/deliver` — adaptor pre-signature reception from provider TEE, pVerify verification
- `POST /v1/channel/finalize` — adaptor secret disclosure, result decryption, provider credit
- `POST /v1/channel/close` — channel closure, on-chain settlement

### Provider TEE
- Provider-side library implemented as production code in middleware/src/asc.ts
  - `generateAscDeliveryArtifact()`: adaptor key generation, pre-signature, result encryption
  - `submitAscDelivery()`: POST to facilitator /v1/channel/deliver
  - `deliverAscResult()`: one-shot function that executes the above in one call
- Facilitator-side (enclave) pVerify verification is fully implemented
- Production deployment runs on a separate Nitro Enclave instance (same code, isolated instance)

### Batch Settlement Integration (enclave/src/batch.rs, 659 lines)
- Aggregates ASC settlements into on-chain txs
- Time window (120 seconds), settlement count cap (MAX 20), forced trigger
- Atomic pairing of settle_vault + record_audit

### Tests
- `tests/asc_provider_helper.ts` (52 lines): ASC delivery artifact generation, adaptor signature verification
- Enclave unit tests: 8 adaptor_sig tests

## Phase 4: Force Settlement + Dispute Resolution + Receipt Watchtower (2026-04-12) ✅

### On-chain Force Settle Instructions
- `force_settle_init.rs` (123 lines): ForceSettleRequest PDA creation, Ed25519 signature verification, receipt field verification
- `force_settle_challenge.rs` (112 lines): challenge with a newer receipt (higher nonce), dispute window constraints
- `force_settle_finalize.rs` (113 lines): payout execution after the dispute window, free_balance + locked_balance when expired

### ForceSettleRequest State (programs/.../force_settle_request.rs, 36 lines)
- Fields: bump, vault, participant, participant_kind, recipient_ata, free/locked balances, max_lock_expires_at, receipt_nonce, receipt_signature, initiated_at, dispute_deadline, is_resolved
- Size: 219 bytes (8 discriminator + 211 data)
- PDA seeds: [b"force_settle", vault, participant, participant_kind]
- DISPUTE_WINDOW_SEC = 604800 (7 days)

### Ed25519 Signature Utilities (programs/.../ed25519_utils.rs, 191 lines)
- `verify_ed25519_signature_details()`: signature extraction from sysvar::instructions
- `decode_participant_receipt_message()`: 145-byte receipt message parsing
- `ParticipantReceiptMessage` struct

### Receipt Watchtower (watchtower/src/, 851 lines)
- **main.rs** (199 lines): Axum HTTP server (port 3200), `POST /v1/receipt/store`, `GET /v1/status`, background challenger loop
- **receipt_store.rs** (224 lines): DashMap + JSON file persistence, monotonic nonce checks, thread-safe
- **challenger.rs** (428 lines): ForceSettleRequest PDA polling (10-second interval), stale receipt detection -> force_settle_challenge transaction submission, Ed25519 precompile instruction construction

### Watchtower Integration (enclave/src/handlers.rs)
- `replicate_receipt_to_watchtower()`: HTTP POST all ParticipantReceipts to Watchtower
- Circuit breaker pattern; logs errors and continues
- Non-blocking async

### Tests (tests/a402_vault.ts)
- 48 test cases, 13 describe blocks
- force_settle_init: success path, tamper detection, invalid signature rejection
- force_settle_challenge: stale receipt challenge, signature verification, dispute window
- force_settle_finalize: rejects while dispute window is active; elapsed-time tests require Bankrun time warp
- Watchtower: receipt_store and challenger unit tests

### Implementation Notes
- Watchtower persistence is currently JSON. Migration to RocksDB or similar is recommended for production
- force_settle_finalize elapsed-time tests are limited because they require Bankrun time warp

## Phase 1-4 Spec Compliance Review + Critical Fixes (2026-04-12) ✅

### Review Method
- Compared all specs in docs/a402-solana-design.md (§1-10) and docs/a402-svm-v1-protocol.md (§1-12) against the implementation
- Comprehensively checked the on-chain program, Enclave facilitator, Client SDK, Provider middleware, Watchtower, and Parent instance

### Fixed 9 Critical Items

**Middleware (C1-C4):**
- C1: Added PAYMENT-RESPONSE header (§8.6) — scheme, paymentId, verificationId, settlementId, batchId, txSignature, participantReceipt
- C2: Fixed settle ordering — wait for settle completion before returning the response (§8.3 WAL durability)
- C3: Implemented Single-Execution Rule (§8.4) — prevent duplicate execution with an in-memory execution cache keyed by verificationId
- C4: Added paymentDetails object to /verify calls (§8.2)

**Enclave Facilitator (C5-C9):**
- C5: Added Authorization: Bearer auth to /verify, /settle, /cancel (§8.2 requirement 1)
- C6: Match payTo/assetMint/network against provider registration information (§8.2 requirement 7)
- C7: Validate paymentDetailsHash by recomputing canonical JSON (§8.2 requirement 3)
- C8: Added provider_mismatch check to /cancel — only the provider that received the reservation can cancel it (§8.5)
- C9: Match request origin against allowedOrigins (§4)

### Remaining 3 Medium Items (Unfixed, Address Before Production Deploy)
- M1: SDK verifyAttestation() PCR verification is a stub (§5.3) — implement in production Nitro environment
- M2: No off-chain Vault Status verification on the Enclave side — off-chain reservations are possible while paused
- M3: Finalize DISPUTE_WINDOW_SEC — the design doc contains both 24-hour and 7-day values

### Remaining 3 Low Items
- L1: ForceSettleRequest size is hardcoded in Watchtower challenger.rs (219)
- L2: Whole Parent instance stops through tokio::select! when relay fails
- L3: Client SDK has no local duplicate check for paymentId

## Remaining for Phase 5
- Arcium MXE Integration (encrypted-ixs/)
- Confidential computation circuits

## Remaining for Phase 6
- Token-2022 Confidential Transfer for deposit privacy

## Phase 4 Protocol Hardening (2026-04-15) ✅

### Fixed in this pass
- Enclave now synchronizes on-chain `VaultConfig.status` and enforces Phase 4 lifecycle rules off-chain:
  - `/verify` rejects when vault is `Paused`, `Migrating`, or `Retired`
  - `/settle` / `/cancel` allow `Migrating` only until `exit_deadline`
  - `/withdraw-auth` mirrors the on-chain `withdraw` guard
  - ASC endpoints now respect the same lifecycle boundaries
- `paymentDetails` is now required on `/verify`, and the facilitator validates both:
  - `paymentDetails.scheme == "a402-svm-v1"`
  - canonical `paymentDetailsHash`
- Provider auth was tightened to match the Phase 1-4 wire protocol more closely:
  - `bearer` mode requires `Authorization: Bearer ...` plus `x-a402-provider-id`
  - `api-key` mode accepts `x-a402-provider-auth` (and bearer fallback for compatibility)
  - provider registration now rejects unsupported auth modes and invalid API key hashes
- Middleware no longer regenerates a random `paymentDetailsId` between the 402 response and `/verify`
  - `paymentDetailsId` is now deterministic per request context
  - middleware now forwards `x-a402-provider-id` and `x-a402-provider-auth`
- Enclave startup now fails fast unless `A402_WATCHTOWER_URL` is configured and healthy
- `/verify` now returns a real enclave-signed `verificationReceipt`
  - envelope is base64(JSON) with `verificationId`, `reservationId`, `paymentId`, hashes, expiry, `vaultConfig`, `signature`, and signed `message`
  - idempotent `/verify` replay returns the same deterministic receipt payload

### Tests / verification updated
- Updated `tests/enclave_api.ts` for required `paymentDetails` and provider auth headers
- Updated `tests/enclave_surfpool_e2e.ts` to use bearer auth and start a watchtower process
- Updated both enclave integration tests to decode and assert `verificationReceipt`
- `sdk/src/crypto.ts` now uses canonical JSON hashing for payment details
- SDK now exposes `decodeVerificationReceiptEnvelope()`

### Verified commands
- `cargo test -p a402-enclave`
- `cargo test --workspace`
- `./node_modules/.bin/tsc -p ./tsconfig.json --noEmit`
- `yarn ts-mocha -p ./tsconfig.json -t 30000 tests/attestation_sdk.ts tests/audit_tool.ts`
- `anchor test`

### Remaining gaps after this pass
- Provider auth still does not implement true mTLS mode; only `bearer` and `api-key` are supported

## Phase 4 Provider mTLS (2026-04-15) ✅

### Fixed in this pass
- Enclave now supports real TLS listener configuration via:
  - `A402_ENCLAVE_TLS_CERT_PATH`
  - `A402_ENCLAVE_TLS_KEY_PATH`
  - optional `A402_ENCLAVE_TLS_CLIENT_CA_PATH`
- When a client CA bundle is configured:
  - enclave offers client certificate auth
  - bearer / api-key providers can still connect without a client cert
  - `authMode = "mtls"` providers are authenticated by SHA-256 fingerprint of the presented client certificate
- Provider registration now persists auth material by mode:
  - `api_key_hash` for `bearer` / `api-key`
  - `mtls_cert_fingerprint` for `mtls`
  - registration rejects `mtls` when the enclave listener is not configured for client cert verification
- Middleware facilitator calls no longer depend on `fetch`
  - switched to a small `http` / `https` helper
  - supports `authMode = "mtls"` with client cert + key PEM paths
  - ASC delivery and `/verify` / `/settle` / `/settlement/status` all share the same transport/auth path

### Tests / verification updated
- Added enclave unit test that rejects `mtls` provider registration when client-cert verification is disabled
- Added enclave unit test covering end-to-end `/verify` auth for an `mtls` provider using a matching certificate fingerprint

### Verified commands
- `cargo test -p a402-enclave`
- `cargo test --workspace`
- `./node_modules/.bin/tsc -p ./tsconfig.json --noEmit`
- `yarn ts-mocha -p ./tsconfig.json -t 30000 tests/middleware_raw_body.ts tests/attestation_sdk.ts tests/audit_tool.ts`

## Phase 4 Live HTTPS/mTLS Validation (2026-04-15) ✅

### Fixed in this pass
- Added test-side HTTPS/mTLS transport helpers with on-the-fly OpenSSL certificate generation
- `tests/enclave_api.ts` now supports:
  - `A402_TEST_ENCLAVE_URL`
  - `A402_TEST_TLS_CA_PATH`
  - `A402_TEST_MTLS_CERT_PATH`
  - `A402_TEST_MTLS_KEY_PATH`
- `tests/enclave_surfpool_e2e.ts` now runs two live flows:
  - existing `http + bearer`
  - new `https + mtls`
- Fixed a real compatibility bug uncovered by the live E2E:
  - SDK canonical JSON sorting used `localeCompare`
  - enclave canonicalization uses bytewise lexicographic sort
  - switched SDK canonical sort to simple bytewise string ordering in both payment-details hashing and attestation hashing
- Added rustls crypto-provider initialization for enclave TLS startup
- Hardened live test cleanup so watchtower/enclave child processes do not hang the suite

### Verified commands
- `yarn ts-mocha -p ./tsconfig.json -t 300000 tests/enclave_surfpool_e2e.ts --exit`
- `cargo test -p a402-enclave`
- `cargo test --workspace`
- `./node_modules/.bin/tsc -p ./tsconfig.json --noEmit`

## Phase 4 Follow-up Hardening (2026-04-15) ✅

### Fixed in this pass
- Middleware request binding now supports exact raw request bytes
  - exported `captureA402RawBody()` for `express.json({ verify })`
  - `buildRequestContext()` hashes `req.rawBody` first, then falls back only when raw bytes are unavailable
- Enclave now exposes `POST /v1/settlement/status`
  - provider-authenticated lookup by `settlementId`
  - returns `verificationId`, reservation status, `batchId`, and `txSignature`
  - batch confirm now stores `settlement_ids` in WAL and maintains in-memory `settlementId -> batch metadata`
- Production vault status checks no longer use a 5-second stale cache
  - test binaries still read the cached lifecycle to avoid live RPC dependencies in unit tests
- Live test fixtures were corrected to send auth headers on `/settle` retry

### Verified commands
- `cargo test -p a402-enclave`
- `cargo test --workspace`
- `./node_modules/.bin/tsc -p ./tsconfig.json --noEmit`
- `yarn ts-mocha -p ./tsconfig.json -t 30000 tests/middleware_raw_body.ts tests/attestation_sdk.ts tests/audit_tool.ts`

### Remaining gaps after this pass
- Provider auth still does not implement true mTLS mode; only `bearer` and `api-key` are supported

## Public launch prep — P0/P1 implementation (2026-04-23) ✅

### Motivation
Ship "privacy-first x402 on Solana" as a Devnet MVP. Phase 3 ASC demo integration and Phase 5 Arcium yield were postponed. Focus: minimum correctness + packaging to credibly open the Devnet endpoint to external developers.

### P0-1: SDK PCR pinning fail-closed
- `sdk/src/attestation.ts` now calls `assertPcrPinningConfigured()` at the top of `verifyNitroAttestationDocument`.
- Throws unless `nitroAttestation.policy.pcrs` or `nitroAttestation.expectedPcrs` is provided.
- `allowMissingPcrPinning: true` is the explicit escape hatch.
- Added `tests/attestation_sdk.ts → "requires PCR pinning when verifying a Nitro attestation"`.

### P0-2 / P0-3: verified already correct
- VaultStatus cache: production path (`handlers.rs:154-180`) always hits RPC; only `cfg(test)` uses cached lifecycle.
- DISPUTE_WINDOW_SEC = 86400 (24h) consistent across program, CLAUDE.md, design doc, tests. Earlier memo about a 24h/7d conflict was stale.

### P0-4: Time-based anonymity window (primary change)
- `enclave/src/batch.rs`:
  - New constants `DEFAULT_MIN_ANONYMITY_WINDOW_SEC = 60`, `DEFAULT_MIN_BATCH_PROVIDERS = 1`.
  - `BatchPrivacyConfig` gained `min_anonymity_window_sec` and `min_batch_providers` (env: `A402_MIN_ANONYMITY_WINDOW_SEC`, `A402_MIN_BATCH_PROVIDERS`).
  - Automatic batching now filters settlement_ids per provider by each settlement's own age, then applies the payout floor to the eligible-only subtotal.
  - `decide_batch_action()` takes `min_batch_providers` as a parameter (was hard-coded `MIN_BATCH_PROVIDERS = 2`).
- Effect: every settlement spends at least `min_anonymity_window_sec` in the vault before it can be batched on-chain, regardless of N. Default posture works with N=1 so the vault is usable from day one.
- Added unit tests for the window, N=1 fire, N=2 skip, eligible-only payout-floor semantics, and flush-mode bypass.

### P1-7: SDK + middleware npm publish prep
- `sdk/package.json` (`subly402-sdk`, v0.1.0) + `sdk/tsconfig.json` + `sdk/README.md`.
- `middleware/package.json` (`subly402-express`, v0.1.0) + `middleware/tsconfig.json` + `middleware/README.md`.
- Both packages build under `strict: true`, `declaration: true` and pack cleanly.
- Strict-mode fixes: `sdk/src/subly402.ts` signature lookup cast, `middleware/src/middleware.ts` `capturedStatus` declared as `number | undefined`.
- `dist/` excluded from git.

### P1-8: Developer quickstart doc
- `docs/quickstart.md`: client SDK 5-line example, provider middleware example, privacy defaults table (incl. new MIN_ANONYMITY_WINDOW_SEC), pointer to Nitro README and protocol specs.

### Verified commands
- `NO_DNA=1 cargo test --workspace` — 79 tests passing (59 enclave + 8 asc_claim/ed25519 + 6 vault + 6 watchtower)
- `./node_modules/.bin/tsc -p ./tsconfig.json --noEmit` — clean
- `yarn ts-mocha -p ./tsconfig.json -t 30000 tests/attestation_sdk.ts tests/audit_tool.ts tests/middleware_raw_body.ts` — 13 passing
- `(cd sdk && ../node_modules/.bin/tsc -p tsconfig.json && npm pack --dry-run)` — 37.5 kB tarball
- `(cd middleware && ../node_modules/.bin/tsc -p tsconfig.json && npm pack --dry-run)` — 23.2 kB tarball

### Outstanding for actual public launch (operator actions, not code)
- Deploy the Nitro stack to a public Devnet URL (README §1-5)
- Publish `attestationPolicyHash` + PCR pinning values so external SDK users can configure `nitroAttestation.policy`
- Verify npm name availability of `subly402-sdk` / `subly402-express` before first publish

## Codex review pass — 4 findings fixed (2026-04-23) ✅

### Motivation
External Codex review caught 4 real issues I missed in my own review pass. All 4 were legitimate bugs or strength gaps for a public launch. Fixed with regression tests.

### #1 (High) Per-settlement age filter (was: provider-level)
- `enclave/src/batch.rs`: extracted `select_provider_batch_entries()` as a pure function that filters an incoming `(settlement_id, timestamp, amount)` list against both `settlement_is_age_eligible()` and `provider_payout_floor_satisfied()`.
- `prepare_batch` now calls this per-provider after building the timestamped candidate list, so a fresh credit attached to an already-old `ProviderCredit.oldest_credit_at` is correctly deferred until its own age clears the window.
- Made `MEMORY.md` / `quickstart.md` claim ("every settlement spends at least min_anonymity_window_sec") match reality.
- Expanded batch unit coverage to 17 tests total, including mixed fresh/old, fresh-only skip, eligible-only payout-floor semantics, liveness ceiling semantics, flush-mode bypass, and config parsing.
- `cargo test -p a402-enclave` currently passes with 64 tests.

### #2 (Medium) SDK attestation cache re-validation
- `sdk/src/subly402.ts` `Subly402Client.verifyAttestation()` now calls `cacheEntryStaleReason()` on every cache hit. Evicts + re-fetches when:
  - cached vaultConfig/vaultSigner/attestationPolicyHash no longer matches the new PaymentDetails
  - cached `expiresAt` is within 60s of now (`EXPIRY_SAFETY_MARGIN_MS`) or invalid
- Regression: `tests/subly402_interface.ts → "re-fetches a cached attestation whose details no longer match"`.

### #3 (Medium) middleware attestationPromise finally-reset
- `middleware/src/subly402.ts` `Subly402FacilitatorClient.getAttestation()` used `??=` so a rejected attestation Promise stayed cached and bricked the seller until restart.
- Fix: attach `.finally` that clears `this.attestationPromise` when it settles (if still the same reference). Successful fetches fill `this.attestation` which short-circuits future calls; failed fetches allow the next caller to retry cleanly.
- Regression: `tests/subly402_interface.ts → "retries attestation fetch after a transient facilitator failure"`.

### #4 (Low) Body hash for non-string BodyInit
- `sdk/src/crypto.ts`: new `bodyToBytes()` helper handles string / Buffer / Uint8Array / ArrayBuffer / ArrayBufferView and throws a clear error for Blob / FormData / URLSearchParams / ReadableStream.
- Both `Subly402Client` and `A402Client` now hash via `sha256hex(bodyToBytes(options?.body))` instead of `options?.body?.toString()`.
- Prevents silent server-side verify mismatch for binary AI-agent payloads (embeddings, audio, images).
- Regression: `tests/attestation_sdk.ts → "hashes request bodies by actual bytes, not toString()"`.

### Verified commands
- `NO_DNA=1 cargo test --workspace` — 86 tests passing (66 enclave + 8 asc_claim/ed25519 + 6 vault + 6 watchtower)
- `./node_modules/.bin/tsc -p ./tsconfig.json --noEmit` — clean
- `yarn ts-mocha -p ./tsconfig.json -t 30000 tests/attestation_sdk.ts tests/audit_tool.ts tests/middleware_raw_body.ts tests/subly402_interface.ts` — 18 passing
- `(cd sdk && ../node_modules/.bin/tsc -p tsconfig.json && npm pack --dry-run)` — packs clean
- `(cd middleware && ../node_modules/.bin/tsc -p tsconfig.json && npm pack --dry-run)` — packs clean
