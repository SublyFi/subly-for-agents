# A402-Solana Nitro Deployment Specification

> Version: 0.1.0
> Date: 2026-04-12
> Status: Draft
> Companion: [a402-solana-design.md](./a402-solana-design.md)

---

## 1. Goals

This document defines the deployment, recovery, and migration specification for operating the A402-Solana facilitator / vault runtime on AWS Nitro Enclaves.

Phase 1 goals:

- Keep request / response plaintext hidden from the parent instance
- Keep the vault signer / auditor secret / snapshot key hidden from the parent instance
- Pin the enclave identity by combining Nitro attestation with KMS policy
- Recover from encrypted snapshot / WAL after an enclave crash

Phase 1 non-goals:

- multi-active enclave consensus
- cross-region BFT replication
- Provider-side enclave deployment

---

## 2. Reference Topology

```text
                Internet
                    │
             TCP 443 passthrough
                    │
                  NLB
                    │
          ┌───────────────────────┐
          │ Parent EC2 Instance   │
          │                       │
          │ ingress_relay         │──vsock 8443──┐
          │ egress_relay          │◀─vsock 9443──┤
          │ kms_proxy supervisor  │◀─vsock 8000──┤
          │ snapshot_store        │◀─vsock 7000──┤
          └───────────────────────┘              │
                                                 ▼
                                      ┌────────────────────┐
                                      │ Nitro Enclave      │
                                      │ rustls/hyper       │
                                      │ facilitator        │
                                      │ vault state        │
                                      │ Solana signer      │
                                      │ KMS bootstrap      │
                                      └────────────────────┘
```

---

## 3. AWS Components

Minimum configuration:

- 1 x EC2 parent instance
- 1 x Nitro Enclave
- 1 x Network Load Balancer
- 1 x customer-managed KMS key for seed/state unwrap
- 1 x S3 bucket or encrypted EBS volume for snapshot/WAL
- 1 x Solana RPC provider
- 1 x Receipt Watchtower service

Recommended additions:

- CloudWatch logs / metrics
- separate watcher instance for Solana finality / force-settle monitoring
- second warm-standby parent instance

---

## 4. Parent / Enclave Responsibility Split

### Parent Instance

The parent instance is **untrusted**. Its responsibilities are limited to availability and relaying.

Allowed responsibilities:

- Relay TCP ingress to vsock
- Relay outbound TLS byte streams from the enclave to the internet
- Start the KMS proxy process
- Store encrypted snapshot / WAL blobs
- Perform health checks and process supervision

Forbidden responsibilities:

- TLS termination
- request body parsing
- Holding the Solana signer
- Running payment verification / settlement logic
- Holding snapshot plaintext

### Enclave

Secrets held by the enclave:

- vault signer seed
- auditor master secret
- decrypted snapshot / in-memory state
- Signing context for provider/client receipts

Logic executed by the enclave:

- `/attestation`, `/verify`, `/settle`, `/cancel`
- deposit detection
- batch construction / submission
- receipt generation
- snapshot/WAL encryption

### Receipt Watchtower

Receipt Watchtower is **required** for Phase 4 trust-minimized asset recovery.

Responsibilities:

- Store the latest `ParticipantReceipt` for each participant
- Monitor `force_settle_init`
- Send `force_settle_challenge` when a newer receipt is available

Allowed responsibilities:

- Store receipt metadata, including `freeBalance`, `lockedBalance`, `maxLockExpiresAt`, and `nonce`
- Watch Solana and submit challenge transactions

Forbidden responsibilities:

- facilitator signing
- Accessing request bodies
- Running payment verification logic

---

## 5. Ingress Path

### 5.1 Required Property

TLS between the client / provider and facilitator must terminate inside the enclave.

Therefore:

- Use **NLB TCP mode**
- **Do not use ALB**
- **ACM for Nitro Enclaves with nginx on parent** is also not used in Phase 1

Reasons:

- ALB decrypts HTTP/TLS before the parent
- ACM for Nitro + nginx can isolate the private key inside the enclave, but parent nginx still sees HTTP plaintext
- A402 privacy goals require hiding request path/body/payment payload from the parent

### 5.2 Listener Layout

- NLB: TCP/443 -> parent instance port 443
- parent `ingress_relay`: forwards TCP/443 as a raw byte stream to vsock/8443
- enclave: runs rustls + HTTP server on vsock/8443

---

## 6. Egress Path

Nitro Enclaves have no direct network access, so outbound traffic goes through the parent relay.

### 6.1 Traffic Classes

- Solana RPC HTTPS
- Solana WebSocket subscribe
- provider callback / provider verification traffic
- KMS bootstrap traffic

### 6.2 Rules

- Create TLS sessions inside the enclave
- The parent only provides a byte pipe to the destination IP/port
- Restrict outbound destinations with a parent firewall allowlist

Recommended allowlist:

- configured Solana RPC endpoint
- configured provider domains
- KMS / STS / Nitro-related AWS endpoints

---

## 7. Attestation and KMS Bootstrap

### 7.1 Build Artifacts

deployment artifact:

- signed EIF image
- enclave manifest
- attestation policy JSON

PCRs to pin at minimum:

- `PCR0`: image measurement
- `PCR1`: kernel / bootstrap measurement
- `PCR2`: application / filesystem-related measurement
- `PCR3`: role-specific runtime inputs
- `PCR8`: EIF signing certificate measurement

### 7.2 Attestation Policy Hash

The `attestation_policy_hash` pinned on-chain is the SHA-256 of the following canonical JSON.

```json
{
  "version": 1,
  "pcrs": {
    "0": "<hex>",
    "1": "<hex>",
    "2": "<hex>",
    "3": "<hex>",
    "8": "<hex>"
  },
  "eifSigningCertSha256": "<hex>",
  "kmsKeyArnSha256": "<hex>",
  "protocol": "subly402-svm-v1"
}
```

### 7.3 KMS Keys

Phase 1 uses at least two types of keys.

- `a402-root-key`
  - vault signer seed
  - auditor master secret
  - snapshot master key wrapping

- `a402-snapshot-data-key`
  - Content encryption for snapshot / WAL blobs

### 7.4 KMS Policy Requirements

KMS key policy is restricted by Nitro attestation condition keys.

Intent:

- The parent instance IAM role alone cannot decrypt
- A data key cannot be received without an attestation document produced by an attested enclave
- Anything outside the allowed PCR set and EIF signer is rejected

### 7.5 Bootstrap Sequence

1. The parent starts the enclave
2. The enclave generates an ephemeral bootstrap key pair
3. The enclave creates an attestation document
4. The enclave calls `Decrypt` or `GenerateDataKey` through kmstool / KMS proxy
5. KMS checks the attestation conditions and returns a response bound to the enclave public key
6. The enclave restores the vault signer seed and snapshot key material
7. The facilitator API becomes `ready` only after snapshot/WAL recovery is complete

Notes:

- The bootstrap document in step 3 binds the KMS recipient key and does not need to be identical to the `/v1/attestation` document returned to clients
- During serving, the facilitator generates a fresh runtime attestation document with NSM and binds `vault_signer`, `attestation_policy_hash`, and `snapshot_seqno` in `user_data`, plus the ingress TLS public key in `public_key`

---

## 8. Persistence Model

Because Nitro Enclaves have no persistent disk, state persistence has two layers.

- encrypted WAL
- encrypted snapshot

### 8.1 WAL Entry Types

Minimum required events:

- `DepositApplied`
- `ReservationCreated`
- `ReservationCancelled`
- `ReservationExpired`
- `SettlementCommitted`
- `ParticipantReceiptIssued`
- `ParticipantReceiptMirrored`
- `AuditorRotated`
- `BatchSubmitted`
- `BatchConfirmed`
- `MigrationAnnounced`

### 8.2 Commit Rule

Before returning `/verify` and `/settle` responses:

1. Generate the corresponding WAL entry
2. Encrypt it with the data key
3. Append it to the parent's `snapshot_store`
4. Receive the append ack
5. Return the success response only after that

Breaking this ordering can make receipts returned to providers/clients inconsistent with internal state after an enclave crash.

When issuing a `ParticipantReceipt`, additionally:

1. Record `ParticipantReceiptIssued` in the WAL
2. Sync to Receipt Watchtower and receive an ack
3. Record `ParticipantReceiptMirrored` in the WAL

Phase 4 stale receipt safety assumes this mirror step has completed durably.

### 8.3 Snapshot Rule

Recommended:

- `SNAPSHOT_EVERY_N_EVENTS = 1000`
- `SNAPSHOT_EVERY_SEC = 30`

Snapshots include:

- vault balances
- active reservations
- provider credit ledger
- current auditor epoch
- pending batch metadata
- latest participant receipt nonce
- last finalized Solana slot

### 8.4 Recovery Sequence

1. Load the latest complete snapshot
2. Replay WAL entries after the snapshot seqno in order
3. Reconcile in-flight batches with the Solana chain
4. Deposit catch-up: re-fetch deposits after `last_finalized_slot` and repair missed entries
   a. Fetch the deposit tx signature list with `getSignaturesForAddress(vault_token_account, { until: <last_processed_signature>, commitment: "finalized" })`
   b. For each signature, fetch `getTransaction(sig, { commitment: "finalized" })` and verify the deposit instruction's client signer / amount
   c. Skip txs already recorded in the WAL as `DepositApplied`
   d. Apply unrecorded deposits with `client_balances[client].free += amount` and append `DepositApplied` to the WAL
   e. Update `last_finalized_slot`
5. `/verify` and `/settle` return `503 recovering` until ready

This logic is shared with catch-up after WebSocket disconnect/reconnect during steady-state operation. See a402-solana-design.md §5.6.

---

## 9. Deployment Lifecycle

### 9.1 Initial Bootstrap

1. Create VPC, NLB, EC2, IAM, KMS, and S3/EBS with Terraform
2. Build the signed EIF
3. Finalize PCR values and `attestation_policy_hash`
4. Pin `vault_signer_pubkey` and `attestation_policy_hash` on-chain with `initialize_vault`
5. Start the enclave and send traffic after bootstrap/recovery completes

### 9.2 Upgrading Enclave Code

Code upgrades do not replace the signer directly on-chain.

Procedure:

1. Build a new EIF and finalize new PCRs
2. Deploy a new vault at a separate address
3. Send `announce_migration(successor_vault, exit_deadline)` to the old vault
4. Route new traffic to the new vault
5. Release client / provider balances in the old vault through participant force-settle or cooperative withdrawal
   - If the client receipt has `lockedBalance > 0`, that portion is recoverable after `maxLockExpiresAt`
6. Stop the old vault after the exit window

### 9.2.1 Auditor Rotation

Auditor key rotation is future-only.

1. Governance injects the new auditor master secret into the enclave over an attested admin channel
2. The enclave generates and presents the public key for the new secret
3. Governance sends `rotate_auditor(new_auditor_master_pubkey)`
4. Subsequent AuditRecords are encrypted with the new `auditor_epoch`
5. The auditor stores old epoch secrets for historical decryption

### 9.3 Warm Standby

Phase 1 HA only permits active/passive.

- Only the active enclave receives verify / settle traffic
- The standby enclave receives no traffic and only syncs snapshot blobs
- During failover, switch the NLB target only after the standby completes bootstrap + recovery

Active-active is forbidden until an attested replication protocol exists.

---

## 10. Monitoring

Minimum metrics:

- enclave bootstrap latency
- `/verify` p50 / p95 / error rate
- `/settle` p50 / p95 / error rate
- reservation queue size
- provider credit backlog
- oldest unsettled provider credit age
- snapshot lag
- WAL append latency
- Solana submission failures
- force-settle requests count
- `vault_insolvent` error count

Minimum alerts:

- attestation drift
- KMS decrypt failure
- recovery mode > 5 minutes
- batch settlement delay > `MAX_SETTLEMENT_DELAY_SEC`
- snapshot store write failure

---

## 11. Incident Response

### 11.1 Suspected Parent Compromise

Assumptions:

- Parent root compromise
- Relay process tampering
- Disk snapshot leak

Response:

1. Stop new verify / settle with `pause_vault()`
2. Confirm the enclave attestation and signer are unchanged
3. Bring up a new parent + new enclave on a separate host
4. Announce migration from the old vault

Expected property:

- Parent compromise alone does not leak the signer seed or snapshot plaintext

### 11.2 Suspected Enclave Compromise

Assumptions:

- attestation mismatch
- unexpected signer
- PCR drift

Response:

1. Cut traffic immediately
2. Run `pause_vault()`
3. Deploy a new vault and announce migration
4. Ask participants to use cooperative withdrawal / force-settle
5. Confirm Receipt Watchtower can continue stale receipt challenges
6. If `vault_insolvent` occurs, do not perform partial payouts; top up or move to a separate resolution procedure

### 11.3 KMS Outage

Assumptions:

- Running enclaves can continue
- Fresh restarts are impossible

Response:

- Do not stop the active enclave
- Reduce snapshot cadence and move to write-only mode, or run `pause_vault()` if needed

---

## 12. Security Checklist

- Use TCP passthrough on the NLB
- Do not terminate TLS on the parent
- Disable debug on the enclave
- Include the EIF signer certificate fingerprint in the attestation policy
- Make the KMS key policy attestation-conditioned
- Require durable WAL append before success responses
- Do not rotate `vault_signer_pubkey` in-place on-chain
- Bind provider auth credentials to facilitator registration
- Always store snapshot/WAL with envelope encryption
- Sync the latest `ParticipantReceipt` to Receipt Watchtower

---

## 13. Open Items

- Whether warm standby snapshot handoff should use S3 events or EBS snapshots
- How strict provider callback egress domain pinning should be
- Whether the attestation policy hash should include AMI hash or parent role hash
- How the egress relay should health-check long-lived WebSockets
