# A402-Solana: Privacy-Focused x402 Protocol Design Document

> Version: 0.4.0
> Date: 2026-04-12
> Status: Draft
> Reference: [A402 Paper](./a402.pdf) (arXiv:2603.01179v2)

---

## 1. Introduction

### 1.1 Background

x402 is an open standard that uses the HTTP 402 "Payment Required" status code to integrate blockchain-based payments into web services. It is widely adopted as infrastructure for "agentic commerce," where AI agents autonomously discover, use, and pay for services.

However, current x402 has a fundamental privacy problem. Because every USDC transfer is publicly visible on-chain, addresses linked to name services such as SNS or ENS can make **buyers identifiable to third parties**. In traditional commerce, third parties do not know what someone bought, but in x402, "who paid whom and how much" is fully public.

### 1.2 Purpose

This protocol (A402-Solana) closely follows the A402 paper architecture and provides the following on Solana:

1. **Sender anonymity**: hides the sender address from on-chain observers
2. **Selective disclosure**: only authorized auditors can decrypt sender information, with provider-level granularity
3. **x402 HTTP envelope compatibility**: preserves the communication shape of `HTTP 402` / `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE`

### 1.3 Design Philosophy

Following the A402 paper, the trust foundation is a TEE (Trusted Execution Environment).

- **Phase 1-4**: TEE-based - architecture as described in the paper
- **Phase 5**: Arcium MXE integration - additional privacy layer through encrypted on-chain balances

Reasons for taking a TEE-first approach:
- It maps directly to the A402 paper architecture and is easier to verify
- Code inside the TEE can be written in normal Rust/TypeScript, enabling faster development
- It avoids early design complexity caused by Arcium's stateless constraints
- Arcium can be introduced later as an additional privacy layer

### 1.4 Target Environment

Initial development and validation are performed on **Solana Devnet + AWS Nitro Enclaves-compatible EC2**. Mainnet migration is considered from Phase 4 onward.

### 1.5 Known Differences from the Paper

This design follows the A402 paper closely, but the following differences exist:

| Difference | A402 paper | This protocol | Reason |
|------|---------|------------|------|
| Adaptor Signatures | Schnorr (secp256k1) | Phase 1-2 use in-TEE reservations + Phase 3 introduces Ed25519 adaptor signatures | Solana uses Ed25519 and is incompatible with Schnorr adaptor signatures |
| Provider Integration | A402-specific protocol | Places the `subly402-svm-v1` scheme on the x402 HTTP envelope | Moves API integration toward HTTP 402 and lowers adoption cost |
| Service Provider TEE | S also runs inside a TEE | Phase 1-2 leave the provider service unchanged; Phase 3 supports Provider TEE | Phased rollout |
| Exec-Pay-Deliver | Cryptographically guaranteed | Not guaranteed in Phase 1-2. Fully guaranteed in Phase 3 | Constraint from the phased approach above |
| On-chain Attestation | TEE registered on-chain | Clients/watchers verify Nitro Attestation, and only the attestation policy hash is pinned on-chain | Directly verifying attestation proofs on Solana is impractical |
| TEE Runtime | Abstract TEE | Fixed to AWS Nitro Enclaves for implementation | Makes operations, key management, and recovery design concrete |
| Receipt Watchtower | Monitoring only during challenge period | Receipt mirroring is required. A permanent service performs stale receipt challenges when the enclave stops | Force-settle safety during enclave failure depends on the watchtower, so its role is larger than in the paper |
| Selective Disclosure | None, outside paper scope | Provider-level selective disclosure through ElGamal-encrypted AuditRecords + hierarchical key derivation | Added specifically to satisfy audit requirements |

### 1.6 Companion Specifications

- Wire protocol: [subly402-svm-v1-protocol.md](./a402-svm-v1-protocol.md)
- Nitro deployment / ops: [a402-nitro-deployment.md](./a402-nitro-deployment.md)

---

## 2. Privacy Model

### 2.1 Threat Model

**Protected against:**
- Third parties, including on-chain observers and blockchain explorer users

**Assumptions, aligned with A402 paper Section 3.2:**
- **Trusted Hardware**: the TEE guarantees code and data confidentiality and integrity. TEE internals remain protected even if the host OS or hypervisor is compromised
- **Nitro-specific Assumptions**:
  - The enclave starts with **debug disabled**, and the EIF signature plus PCR0/PCR1/PCR2/PCR3/PCR8 are pinned in advance
  - Because the enclave has no direct network or persistent disk, the parent instance is limited to vsock relay / KMS proxy / encrypted snapshot storage
  - KMS access is restricted by PCR conditions in the attestation document, so the parent instance alone cannot obtain private keys or snapshot decryption keys
- **Adversarial Parties**: protocol participants outside the TEE may be arbitrarily corrupt
  - Malicious clients: attempt double spending or free use
  - Malicious vault operator / parent instance: cannot modify code inside the TEE, but may try I/O blocking, reordering, replay, and DoS
  - Malicious service providers: may attempt message delay or tampering
- **Network Adversary**: fully asynchronous network where messages can be observed, modified, and delayed

### 2.2 What is Hidden

| Information | Third parties | Vault operator / Parent | Vault inside TEE | Auditor (master key) | Auditor (provider-specific key) |
|------|--------|--------------------|-----------|-----------------|---------------------|
| Sender address | Hidden | Hidden (TLS termination + TEE protection) | Known | Known | Known (target only) |
| Payment amount | Hidden | Hidden (TEE protection) | Known | Known | Known (target only) |
| Client balance | Hidden | Hidden (TEE protection) | Known | N/A | N/A |
| Vault-to-Provider transfers | Visible | Visible | Visible | Visible | Visible |
| Vault depositor list | Visible | Visible | Visible | Visible | Visible |

**Comparison with A402**: the previous design had the Relayer handle client information in plaintext. By terminating TLS inside the Nitro Enclave and limiting the parent instance to an L4 relay, **even the vault operator cannot access client information**, which is closer to the trust model in the A402 paper.

### 2.3 Anonymity Model

Mixer/pool-style anonymity, aligned with A402 paper Section 4.3 Privacy-Preserving Liquidity Vault:

```
N users deposit into the Vault -> anyone in the Vault can pay as one of those N users
-> A specific payment cannot be linked to a specific depositor
```

- Anonymity set size = N Vault depositors
- The initial deposit (client -> vault) is visible on-chain, but subsequent individual payments are anonymized
- During Vault Settlement, payments for N users are aggregated into one on-chain tx, leaving no trace of individual ASCs

### 2.4 Selective Disclosure (Hierarchical Key Derivation)

Hierarchical key derivation is used to control audit granularity by provider:

```
Master Auditor Secret (master secret key)
  │
  ├─ KDF(master_secret, provider_A_address) -> ElGamal key pair for Provider A
  ├─ KDF(master_secret, provider_B_address) -> ElGamal key pair for Provider B
  └─ KDF(master_secret, provider_C_address) -> ElGamal key pair for Provider C
```

Each AuditRecord is encrypted with the **ElGamal public key derived for the target provider**.

| Disclosure scenario | Key provided | Decryptable scope |
|------------|--------|-------------|
| Full transaction audit | Master secret key | All payments to all providers |
| Specific provider audit | Derived key for Provider A | Payments to Provider A only |
| Multiple provider audit | Derived keys for Provider A and B | Payments to A and B only |

### 2.5 Exec-Pay-Deliver Atomicity Constraints

In the A402 paper, Adaptor Signatures cryptographically guarantee Exec-Pay-Deliver atomicity: payment is finalized only for an executed service. This protocol achieves it in phases:

**Phase 1-2 (x402 HTTP envelope + enclave reservation model):**
- The Nitro Enclave verifies `PAYMENT-SIGNATURE` and finalizes internal balances after the Provider's `/settle`
- **Atomicity is not guaranteed**: the Provider may receive payment and fail to return the result
- This risk depends on the Provider trust model and remains until Provider TEE is introduced in Phase 3
- However, individual client-to-provider transfers do not appear on-chain, so the privacy goal is achieved

**Phase 3 (Atomic Exchange introduction):**
- Introduces a TEE on the Provider side and fully follows Algorithm 2 from the paper
- Provides cryptographic atomicity through Ed25519 adaptor signatures
- The Provider cannot receive payment unless it returns the result

### 2.6 Known Privacy Gaps

- **Initial deposit visibility**: deposit (client -> vault) transactions are public on-chain. Depositor addresses are visible as members of the anonymity set. This can be addressed in the future with Token-2022 Confidential Transfer.

---

## 3. System Architecture

### 3.1 Overview

```
 Client                          AWS Parent Instance                    Nitro Enclave
 ┌─────────────┐            ┌────────────────────────┐           ┌─────────────────────────┐
 │  A402 SDK   │──TLS──────▶│ L4 ingress relay       │──vsock───▶│ A402 Facilitator API    │
 │ verifyAtt   │            │ L4 egress relay        │◀─vsock───│ Vault state manager     │
 └──────┬──────┘            │ KMS proxy              │           │ Audit encryption        │
        │                   │ Encrypted snapshot I/O │           │ Solana signer           │
        │ HTTP 402 retry    └──────────┬─────────────┘           │ Remote Attestation      │
        ▼                              │                         └──────────┬──────────────┘
 ┌──────────────┐                      │                                    │
 │   Provider   │──/verify,/settle─────┘                                    │
 │ x402 endpoint│                                                           │
 └──────┬───────┘                                                           │
        │                                                                   │
        │                                                     TLS over L4 relay
        │                                                                   │
        ▼                                                                   ▼
 ┌──────────────────┐                                            ┌──────────────────┐
 │  Vault Program   │◀──────────────settle_vault─────────────────│ Solana RPC       │
 │  (Anchor)        │◀──────────────deposit/withdraw─────────────│ + WebSocket      │
 │ VaultConfig PDA  │                                            └──────────────────┘
 │ VaultToken PDA   │──── shared USDC pool
 │ AuditRecord[]    │──── encrypted audit trail
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │ Provider Token   │
 │ Accounts (USDC)  │
 └──────────────────┘
```

### 3.2 A402 Concept Mapping

| A402 (paper) | This protocol | Notes |
|------------|------------|------|
| Vault (U) - TEE-managed | Vault inside Nitro Enclave | Manages balances, ASC state, and signing keys inside the enclave |
| Client (C) | Client SDK + Solana Keypair | Verifies Nitro PCRs and vault signer via Remote Attestation |
| Service Provider (S) | x402 endpoint + custom facilitator configuration | Keeps the provider API itself unchanged and makes only the payment scheme A402-aware |
| On-chain Program (L) | Anchor Program on Solana | Escrow + Settlement + Dispute Resolution |
| Attested Runtime Policy | Nitro Enclave + governance-pinned attestation policy | Pins the attestation policy hash on Solana |
| Adaptor Signatures | Ed25519-based conditional signatures | Introduced in Phase 3 |
| Liquidity Vault | Shared Vault PDA + enclave-internal ledger | Individual balances exist only inside the enclave. On-chain state only has aggregate balances |
| Batch Settlement | `settle_vault` instruction | Aggregates ASC settlements for N users into one tx |
| Audit Log | ElGamal-encrypted AuditRecord PDA | Encrypted inside the enclave, then stored on-chain |
| Force Settlement | `force_settle_init` / `force_settle_finalize` | On-chain exit path during enclave failure |

### 3.3 Component Responsibilities

**Nitro Enclave (off-chain, runs inside TEE):**
- Client balance management (TEE memory + KMS-protected snapshot/WAL)
- ASC creation, state management, and closure, all off-chain
- Atomic Exchange, providing execute-pay-deliver atomicity in Phase 3
- ElGamal encryption of audit records with provider-specific derived keys
- A402 Facilitator API (`/verify` / `/settle` / `attestation`)
- Remote Attestation, allowing clients/watchers to verify TEE legitimacy
- Signing balance certificates and withdraw authorizations

**On-chain Program (Anchor):**
- USDC escrow management through the Vault Token Account
- Vault initialization and configuration
- Aggregate settlement, where the TEE submits one tx settling multiple clients
- Force settlement, an on-chain exit path plus dispute window during enclave failure
- Storage for encrypted audit records

**AWS Parent Instance (untrusted, but responsible for availability):**
- L4 ingress relay that forwards raw TCP to vsock without terminating TLS
- L4 egress relay from the enclave to Solana RPC / Provider HTTPS
- Nitro KMS proxy
- Persistence for encrypted snapshot / WAL (EBS/S3)

**Receipt Watchtower (required in Phase 4):**
- Stores the latest `ParticipantReceipt` issued by the enclave for each participant
- Can submit `force_settle_challenge` even when the enclave is stopped
- Only sees participant / recipient ATA / free balance / locked balance / max lock expiry / nonce and does not store individual purchase history

**Client SDK:**
- Remote Attestation verification for the TEE
- Vault deposit/withdraw
- x402-compatible fetch, internally generating a `subly402-svm-v1` payload
- Audit tool

---

## 4. x402 Compatibility

### 4.1 Design Principle

**The HTTP 402 envelope is preserved, but the payment scheme and facilitator are A402-specific.**

- The Provider's business API itself is unchanged
- The Provider returns `accepts[].scheme = "subly402-svm-v1"` in `PAYMENT-REQUIRED`
- The header shape of `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` remains x402-compatible
- Existing generic x402 Facilitators are not used; this uses the **custom A402 facilitator** inside the Nitro Enclave

### 4.2 Payment Flow

```
 Client SDK                Provider                  Nitro Enclave Facilitator
     │                        │                               │
     │ 1. HTTP Request        │                               │
     ├───────────────────────▶│                               │
     │                        │ 2. 402 PAYMENT-REQUIRED      │
     │                        │    scheme=subly402-svm-v1        │
     │◀───────────────────────┤                               │
     │ 3. verifyAttestation() │                               │
     ├───────────────────────────────────────────────────────▶│
     │◀───────────────────────────────────────────────────────┤
     │ 4. create opaque A402 payment authorization           │
     │    (request hash, provider, amount, expiry, client sig)│
     │                        │                               │
     │ 5. Retry + PAYMENT-SIGNATURE                           │
     ├───────────────────────▶│                               │
     │                        │ 6. /verify(payload)           │
     │                        ├──────────────────────────────▶│
     │                        │                               │
     │                        │ 7. reserve client balance     │
     │                        │    return verification OK     │
     │                        │◀──────────────────────────────┤
     │                        │ 8. Execute service            │
     │                        │ 9. /settle(result_hash, rid)  │
     │                        ├──────────────────────────────▶│
     │                        │                               │
     │                        │ 10. finalize provider credit  │
     │                        │     emit PAYMENT-RESPONSE     │
     │                        │◀──────────────────────────────┤
     │ 11. 200 + Response     │                               │
     │◀───────────────────────┤                               │
     │                        │                               │
     │                        │ 12. later: batch settle on-chain
```

**Key points:**
- The client sends **HTTP requests directly to the Provider**, like normal x402
- `PAYMENT-SIGNATURE` is not a raw Solana transfer tx, but an **opaque A402 authorization payload** that only the enclave can interpret
- The Provider performs `/verify` -> execute -> `/settle` like x402, but the counterparty is the Nitro Enclave facilitator
- On-chain, a later `settle_vault` performs an **aggregate transfer** from Vault to Provider

### 4.3 HTTP Header Compatibility

| Header | Existing x402 | This protocol | Difference |
|--------|---------|------------|------|
| `Authorization` | `SIWS <token>` | `SIWS <token>` | No change |
| `PAYMENT-REQUIRED` | 402 response | 402 response | `accepts[].scheme` is `subly402-svm-v1` |
| `PAYMENT-SIGNATURE` | Client-signed payment payload | Client-generated **opaque A402 authorization payload** | Not a raw transfer tx |
| `PAYMENT-RESPONSE` | tx hash, etc. | settle receipt / batch reference | Shape is preserved; semantics are A402-specific |

---

## 5. Nitro Enclave Design

### 5.1 TEE Platform

Recommended: **AWS Nitro Enclaves**
- Nitro Attestation Documents enable PCR-based Remote Attestation
- AWS KMS can control `Decrypt` / `GenerateDataKey` based on PCR conditions in the attestation document
- The enclave is memory-isolated from the parent EC2 and does not expose private keys or plaintext state to the parent instance
- Implementation can use Nitro Enclaves SDK / vsock / kmstool

**The design assumes Nitro-specific constraints:**
- The enclave has **no direct network**. All I/O goes through vsock
- The enclave has **no persistent storage**. State is stored externally as encrypted snapshot/WAL
- Debug mode must be disabled. PCR8 (EIF signature) is included in the production policy
- The parent instance is **untrusted** and is treated only as an availability layer

Alternative TEEs such as Intel TDX and AMD SEV-SNP are future targets and are out of scope for the first version

### 5.2 Internal State (TEE Memory)

Data managed inside the TEE and not exposed on-chain:

```rust
/// Internal state for the whole Vault
struct VaultState {
    /// Per-client balances, inside TEE only
    client_balances: HashMap<Pubkey, ClientBalance>,
    /// Active ASCs
    active_channels: HashMap<ChannelId, ChannelState>,
    /// Vault signing key restored from the KMS-protected encrypted seed
    vault_signer: Keypair,
    /// Auditor master secret, protected the same way
    auditor_master_secret: [u8; 32],
    /// Current active audit key epoch
    auditor_epoch: u32,
    /// Cumulative settlement amount by provider
    pending_settlements: HashMap<Pubkey, u64>,
    /// Balance certificate issuance counter
    receipt_nonce: u64,
    /// Replay-prevention nonce for normal withdraw
    withdraw_nonce: u64,
    /// Last persisted snapshot sequence
    snapshot_seqno: u64,
    /// Last applied finalized slot
    last_finalized_slot: u64,
}

/// Nitro persistence model:
/// - State never leaves the TEE in plaintext
/// - Each state transition is saved to EBS/S3 as encrypted WAL
/// - Encrypted snapshots are created periodically
/// - Decryption keys are restored inside the enclave through KMS
///   Decrypt/GenerateDataKey with Nitro attestation
```

struct ClientBalance {
    free: u64,       // Available balance
    locked: u64,     // Balance locked in ASCs
    max_lock_expires_at: i64, // Maximum expiry among currently locked reservations, or 0 if none
    total_deposited: u64,
    total_withdrawn: u64,
}

/// Compliant with A402 Algorithm 1
struct ChannelState {
    channel_id: ChannelId,
    client: Pubkey,
    provider: Pubkey,
    balance: ChannelBalance,  // (client_free, client_locked, provider_earned)
    status: ChannelStatus,    // Open, Locked, Pending, Closed
    nonce: u64,               // monotonic state counter
}
```

**I/O separation on Nitro:**

- **ingress**: TLS from clients/providers is not terminated on the parent; an L4 relay forwards it over vsock and TLS terminates inside the enclave
- **egress**: traffic from the enclave to Solana RPC / Provider HTTPS also goes through the parent's L4 egress relay while TLS is established inside the enclave
- **persistence**: only encrypted WAL / snapshots are stored on the parent instance or S3/EBS

This gives the parent instance control over communication availability, but it cannot read plaintext payloads, private keys, or internal state.

### 5.3 TEE Registration & Remote Attestation

In A402 paper Algorithm 1 (lines 12-15), both the Vault and Provider perform TEE Registration on-chain. However, directly verifying a Nitro AttestationDocument inside a Solana on-chain program is impractical from a compute unit perspective.

**This protocol's approach: pin the attestation policy hash on-chain, and let clients/watchers verify it**

```
1. Client → TEE: attestation request
2. TEE: σ_att = Attest(vault_signer_pubkey || tls_pubkey || manifest_hash || snapshot_seqno)
   (AWS Nitro: AttestationDocument with PCR values + user_data/public_key)
3. TEE → Client: σ_att + vault_signer_pubkey + attestation_policy
4. Client: VerifyAtt(σ_att)
   - Verify AttestationDocument with the AWS Nitro root certificate
   - Confirm PCR0/PCR1/PCR2/PCR3/PCR8 match the on-chain attestation_policy_hash
   - Confirm vault_signer_pubkey and tls_pubkey are included in the attestation
   - Confirm debug is disabled and the expected EIF signature is present
5. Client: trusts vault_signer_pubkey and uses it for subsequent communication
```

In implementation, the **attestation document for KMS bootstrap** is separate from the **runtime attestation document returned by `/v1/attestation`**. The former binds the KMS response to the bootstrap recipient key; the latter is regenerated at runtime and binds the current `snapshot_seqno` and ingress TLS public key.

**On-chain trust anchors:**
- Pin `VaultConfig.vault_signer_pubkey` and `VaultConfig.attestation_policy_hash`
- Clients/watchers independently verify through Remote Attestation that `vault_signer_pubkey` belongs to a legitimate Nitro Enclave
- The on-chain program verifies signatures from `vault_signer_pubkey`, and key updates are **not performed in place**
- If signer rotation is required, use `deploy a new Vault -> migrate during the exit window`

**Key bootstrap on Nitro:**

1. Generate an ephemeral key pair at enclave startup
2. Call KMS `GenerateDataKey` / `Decrypt` with a Nitro Attestation Document
3. KMS key policy is restricted by PCR conditions and returns decrypted DEKs only to attested enclaves
4. The enclave restores encrypted snapshots / encrypted seed material with the DEK

With this approach, the parent instance can hold snapshot files but cannot decrypt them without an attested enclave.

### 5.4 Participant Receipts (For Force-Settle)

Signed certificates issued by the enclave to participants (client / provider) at each balance update:

```rust
enum ParticipantKind {
    Client,
    Provider,
}

struct ParticipantReceipt {
    participant: Pubkey,
    participant_kind: ParticipantKind,
    recipient_ata: Pubkey,
    free_balance: u64,
    locked_balance: u64,
    max_lock_expires_at: i64, // Client: maximum expiry among locks in the receipt; Provider: 0
    nonce: u64,           // monotonic, only the latest is valid
    timestamp: i64,
    snapshot_seqno: u64,
    vault_config: Pubkey,
}
// Ed25519 signature by the enclave vault_signer
```

Normal withdraw uses a separate **replay-resistant signature message**:

```rust
struct WithdrawAuthorization {
    client: Pubkey,
    recipient_ata: Pubkey,
    amount: u64,
    withdraw_nonce: u64,
    expires_at: i64,
    vault_config: Pubkey,
}
// Signed by the enclave vault_signer. On-chain logic rejects nonce reuse.
```

During enclave failure:

- The client can recover `free_balance` after the dispute window
- If the client has `locked_balance > 0`, that portion can be recovered from the same force-settle request after `max_lock_expires_at`
- The provider can recover unbatched earned credit with a receipt where `locked_balance = 0`, `max_lock_expires_at = 0`

**Important**: to prevent stale receipts, **Receipt Watchtower is required** from Phase 4 onward.

- The enclave replicates the latest receipt to the watchtower whenever it issues a `ParticipantReceipt`
- `force_settle_challenge` can be submitted not only by the enclave itself, but also by **the participant or the watchtower**
- This enables challenges against stale receipts even when the enclave is stopped

### 5.5 Atomic Exchange Protocol

#### Phase 1-2: x402 HTTP envelope + Enclave Reservation Model

In Phase 1-2, the x402 HTTP envelope is preserved while the client locally generates a `subly402-svm-v1` payload and payment verification / reservation / settlement are handled by the Nitro Enclave facilitator. The Provider API itself is unchanged, but **existing generic facilitators are not used**. Atomicity still depends on trust in the Provider.

```
1. Client: computes `paymentDetailsHash` from `PAYMENT-REQUIRED` and locally generates a `subly402-svm-v1` payload containing the request hash
2. Client -> Provider: HTTP retry with `PAYMENT-SIGNATURE`
3. Provider -> Enclave facilitator `/verify`: payload verification
4. Enclave: locks δ from the client balance (free -> locked)
5. Provider: service execution
6. Provider -> Enclave facilitator `/settle`: reports execution completion
7. Enclave: locked -> provider_earned (payment finalized)
8. Enclave: adds δ to pending_settlements for later settlement with `settle_vault`

Timeout handling:
- If `/settle` does not arrive within Δ_lock: locked -> free (payment cancelled)
- If the Provider goes down after `/verify`: expire the reservation and make it non-reusable
```

**Constraint**: if the Provider only runs `/settle` and does not return the result, the client loses the payment. This constraint remains until Phase 3 introduces Provider TEE + adaptor signatures.

#### Phase 3: Ed25519 Adaptor Signatures (Fully Compliant with Paper Algorithm 2)

Introduce a TEE on the Provider side and cryptographically guarantee Exec-Pay-Deliver atomicity.

```
1. Request Submission & Asset Locking:
   - Enclave Vault(U): locks δ from the balance
   - Enclave Vault -> Provider TEE(S): transfers (cid, rid, req, δ)

2. TEE-assisted Execution & Adaptor-Signature Payment Commitment:
   - S TEE: res = Execute(req)
   - S TEE: secret value t <- Z_q, T = t·G (Ed25519 curve)
   - S TEE: h = H(res), EncRes = Enc_t(res)
   - S TEE: σ̂_S = pSign(sk_S, m, T)  // Ed25519 adaptor pre-signature
   - S → U: Π = (EncRes, T, σ̂_S)

3. Execution Verification & Conditional Payment:
   - U: verifies pVerify(pk_S, m, T, σ̂_S)
   - U: issues conditional payment signature σ_U = Sign(sk_U, m)
   - U → S: σ_U

4. Payment Finalization & Result Delivery:
   Off-chain path: S discloses t to U
     -> U: res = Dec_t(EncRes)
   On-chain path: S submits σ_S = AdaptSig(σ̂_S, t) to the chain
     -> U: recovers t with t = Extract(σ_S, σ̂_S, T) -> res = Dec_t(EncRes)
```

In implementation, Provider registration stores the ASC `participantPubkey` and `participantAttestation`, and `/channel/open` rejects providers whose key has not completed attested registration. `/channel/deliver` does not trust `provider_pubkey` in the request body; it accepts adaptor pre-signatures only when the key matches the `participantPubkey` bound to registration. `participantAttestation` contains the provider enclave's Nitro attestation document and expected policy, and the facilitator verifies the attestation certificate chain / COSE signature / PCR / user_data (`providerId`, `participantPubkey`, `attestationPolicyHash`).

**Ed25519 Adaptor Signature implementation notes:**
- Ed25519 adaptor signature schemes are academically defined (for example, [Aumayr et al., 2021])
- Production-quality libraries are limited. Phase 3 either implements it or waits for existing libraries to mature
- Alternative: consider verifying secp256k1 signatures with Solana's `Secp256k1SigVerify` precompile

### 5.6 Deposit Detection (Enclave-Side On-Chain Monitoring)

Because client deposits are executed directly on-chain, the enclave reflects balances by **monitoring on-chain events** rather than off-chain notifications. However, Nitro has no direct network access, so the enclave uses an **RPC connection with TLS established inside the enclave** through the parent's L4 egress relay. The parent can relay traffic, but cannot tamper with RPC contents.

```rust
/// Deposit detection loop inside the enclave
async fn monitor_deposits(rpc: &RpcClient, program_id: &Pubkey) {
    // Watch deposit instruction signatures with logsSubscribe
    let subscription = rpc.logs_subscribe(program_id).await;

    loop {
        let sig = subscription.next().await;
        // After finalization, fetch getTransaction(signature) and verify
        // deposit instruction, client signer, client ATA, and amount
        // -> client_balances[client].free += amount
        // -> Generate ParticipantReceipt and return it to the client
    }
}
```

**Commitment level**: do not tentatively apply `processed/confirmed`; wait for `finalized` before finalizing balances.

**Catch-up after WebSocket disconnect:**

WebSocket disconnects for `logsSubscribe` are inevitable. Run the following procedure so deposit events during disconnect/reconnect are not missed:

1. Attempt reconnect immediately after detecting disconnect
2. After reconnect succeeds, fetch deposit txs during the disconnect window with `getSignaturesForAddress(vault_token_account, { until: <last_processed_signature>, commitment: "finalized" })`
3. For each signature, parse instruction data with `getTransaction(sig, { commitment: "finalized" })` and verify deposit amount / client signer
4. Skip txs already recorded in WAL as `DepositApplied`
5. Apply unrecorded deposits with `client_balances[client].free += amount` and append `DepositApplied` to the WAL
6. Reject `/verify` with `503 syncing` until catch-up completes

The same logic is used for recovery after enclave restart (Nitro deployment spec §8.4).

### 5.7 Audit Record Generation (Inside TEE)

For each settlement, the TEE generates an encrypted audit record and writes it on-chain:

```rust
fn generate_audit_record(
    client: &Pubkey,
    provider: &Pubkey,
    amount: u64,
    auditor_epoch: u32,
    auditor_master_secret: &[u8; 32],
) -> AuditRecordData {
    // Derive the provider-specific audit key
    let provider_derived_secret = kdf(auditor_master_secret, provider.as_ref());
    let provider_derived_pubkey = derive_elgamal_pubkey(&provider_derived_secret);

    // ElGamal encryption, executed inside the TEE so plaintext is not externally exposed
    // ElGamal ciphertext is the point pair (C1, C2) = (r·G, r·P + m·G), 64 bytes
    let encrypted_sender = elgamal_encrypt(
        &provider_derived_pubkey, client.as_ref()
    );  // -> [u8; 64]
    let encrypted_amount = elgamal_encrypt(
        &provider_derived_pubkey, &amount.to_le_bytes()
    );  // -> [u8; 64]

    AuditRecordData {
        encrypted_sender,
        encrypted_amount,
        provider: *provider,
        timestamp: current_timestamp(),
        auditor_epoch,
    }
}
```

---

## 6. On-chain Program Design

Because this is TEE-first, the on-chain program stays focused on simple escrow + settlement + dispute resolution.
Individual client balances do not exist on-chain; they are managed inside the TEE.

### 6.1 Account Structures

```rust
pub enum VaultStatus {
    Active = 0,
    Paused = 1,
    Migrating = 2,
    Retired = 3,
}

#[account]
pub struct VaultConfig {
    pub bump: u8,                            // PDA bump
    pub vault_id: u64,                       // unique generation number under governance
    pub governance: Pubkey,                  // pause / migration / retire only
    pub status: u8,                          // VaultStatus
    pub vault_signer_pubkey: Pubkey,         // Enclave signing key
    pub usdc_mint: Pubkey,
    pub vault_token_account: Pubkey,
    pub auditor_master_pubkey: [u8; 32],
    pub auditor_epoch: u32,                  // current audit key epoch
    pub attestation_policy_hash: [u8; 32],   // PCR set + EIF signature + KMS key hash
    pub successor_vault: Pubkey,             // set only during migration, default when unset
    pub exit_deadline: i64,                  // migration/retire deadline
    pub lifetime_deposited: u64,             // lifetime counter
    pub lifetime_withdrawn: u64,             // lifetime counter
    pub lifetime_settled: u64,               // lifetime counter
}
/// The current escrow balance is read from `vault_token_account.amount`,
/// not derived backward from lifetime counters.

#[account]
pub struct AuditRecord {
    pub bump: u8,                          // 1
    pub vault: Pubkey,                     // 32
    pub batch_id: u64,                     // 8
    pub index: u8,                         // 1
    pub encrypted_sender: [u8; 64],        // 64 - ElGamal(C1‖C2) sender pubkey
    pub encrypted_amount: [u8; 64],        // 64 - ElGamal(C1‖C2) amount
    pub provider: Pubkey,                  // 32 - recipient is public
    pub timestamp: i64,                    // 8
    pub auditor_epoch: u32,                // 4 - audit key epoch used for encryption
}
// Size: 214 bytes + 8 discriminator = 222 bytes
// Note: ElGamal ciphertext is the point pair (C1, C2) = (r·G, r·P + m·G), 64 bytes each.
// Randomness r is embedded in C1, so a separate nonce field is unnecessary.

/// Balance certificate submitted by a participant (client/provider) for force-settle
#[account]
pub struct ForceSettleRequest {
    pub bump: u8,
    pub vault: Pubkey,
    pub participant: Pubkey,
    pub participant_kind: u8,              // 0=Client, 1=Provider
    pub recipient_ata: Pubkey,
    pub free_balance_due: u64,             // recoverable immediately after the dispute window
    pub locked_balance_due: u64,           // recoverable after max_lock_expires_at
    pub max_lock_expires_at: i64,          // 0 for provider claims
    pub receipt_nonce: u64,
    pub receipt_signature: [u8; 64],       // Ed25519 signature by the enclave
    pub initiated_at: i64,
    pub dispute_deadline: i64,
    pub is_resolved: bool,
}

#[account]
pub struct UsedWithdrawNonce {
    pub bump: u8,
    pub vault: Pubkey,
    pub client: Pubkey,
    pub withdraw_nonce: u64,
}
```

### 6.2 PDA Seeds

| PDA | Seeds |
|-----|-------|
| VaultConfig | `[b"vault_config", governance, vault_id.to_le_bytes()]` |
| VaultTokenAccount | `[b"vault_token", vault_config]` |
| AuditRecord | `[b"audit", vault_config, batch_id.to_le_bytes(), index]` |
| ForceSettleRequest | `[b"force_settle", vault_config, participant, participant_kind]` |
| UsedWithdrawNonce | `[b"withdraw_nonce", vault_config, client, withdraw_nonce.to_le_bytes()]` |

### 6.3 Instructions

**Vault Management:**

```
initialize_vault(vault_id, vault_signer_pubkey, auditor_master_pubkey, attestation_policy_hash)
  -> Create VaultConfig PDA + VaultTokenAccount PDA
  -> vault_id: new vault generation number under governance
  -> vault_signer_pubkey: Nitro Enclave signing key
  -> auditor_epoch = 0
  -> attestation_policy_hash: fixed value of PCR0/1/2/3/8 + EIF signature + KMS key hash
  -> status = Active

announce_migration(successor_vault, exit_deadline)
  -> governance only
  -> status = Migrating
  -> Announce migration to the new Vault without replacing the signer in-place

pause_vault()
  -> governance only
  -> status = Paused
  -> Stop new verify/settle and signer-authorized on-chain instructions during incidents

retire_vault()
  -> governance only
  -> status = Retired when now >= exit_deadline

rotate_auditor(new_auditor_master_pubkey)
  -> governance only
  -> Assumes the new auditor master secret has already been reflected into the enclave through an attested channel
  -> VaultConfig.auditor_master_pubkey = new_auditor_master_pubkey
  -> VaultConfig.auditor_epoch += 1
  -> Existing AuditRecords can be decrypted only with old-epoch keys. Rotation is future-only and does not perform retroactive re-encryption
```

**Client Operations (On-chain):**

```
deposit(amount: u64)
  -> require status == Active
  -> USDC CPI transfer: client ATA -> VaultTokenAccount
  -> VaultConfig.lifetime_deposited += amount
  -> Enclave reflects the balance:
    The enclave watches the deposit instruction signature and, after verifying the finalized tx,
    adds the amount to client_balances[client].free

withdraw(amount: u64, withdraw_nonce: u64, expires_at: i64, enclave_signature: [u8; 64])
  -> require status in {Active, Migrating} and now <= exit_deadline when Migrating
  -> Verify the enclave signature with vault_signer_pubkey
  -> Confirm `UsedWithdrawNonce` PDA is unused
  -> USDC CPI transfer: VaultTokenAccount -> client ATA
  -> VaultConfig.lifetime_withdrawn += amount
  -> Create `UsedWithdrawNonce` PDA to prevent replay
```

**Settlement (Executed by Enclave):**

```
settle_vault(batch_id: u64, batch_chunk_hash: [u8; 32], settlements: Vec<SettlementEntry>)
  -> require status in {Active, Migrating} and now <= exit_deadline when Migrating
  -> signer = vault_signer_pubkey (executable only by the enclave)
  -> Each entry is a (provider_token_account, amount) pair
  -> USDC CPI transfer: VaultTokenAccount -> each Provider TokenAccount
  -> Aggregate ASC settlements for multiple clients into one tx
  -> Include no individual client information
  -> VaultConfig.lifetime_settled += sum(amounts)
  -> After audit is enabled in Phase 2+, verify through `sysvar::instructions`
    that `record_audit(batch_id, batch_chunk_hash, records)` exists in the same tx

record_audit(batch_id: u64, batch_chunk_hash: [u8; 32], records: Vec<AuditRecordData>)
  -> require status in {Active, Migrating} and now <= exit_deadline when Migrating
  -> signer = vault_signer_pubkey
  -> Create encrypted AuditRecord PDAs
  -> Embed the current `auditor_epoch` in each record
  -> Use `sysvar::instructions` to verify that `settle_vault` in the same tx
    has matching `batch_id` / `batch_chunk_hash` / entry ordering
  -> Reject standalone execution
```

**Vault status guard matrix:**

- `Active`: allows `deposit`, `withdraw`, `settle_vault`, and `record_audit`. `force_settle_*` is always available as an emergency exit
- `Paused`: rejects `deposit`, `withdraw`, `settle_vault`, and `record_audit`. Allows only `force_settle_*`
- `Migrating`: rejects `deposit`. Allows `withdraw`, `settle_vault`, and `record_audit` until `exit_deadline`, then allows only `force_settle_*`
- `Retired`: allows only `force_settle_*` and audit reads

**Batch Limits from Solana Transaction Size Constraints:**

A Solana transaction is limited to 1232 bytes. Each CPI transfer consumes roughly 100 bytes plus 3,000-5,000 CU, so:

- **Phase 1 `settle_vault` alone**: up to **~24** provider transfers per tx (fixed overhead ~248 bytes + ~41 bytes per entry)
- **Phase 2+ `settle_vault + record_audit` atomic chunk**: up to **4-5** entries per tx, dominated by AuditRecord PDA creation

If the batch size is exceeded, split into multiple txs. This does not weaken privacy because every tx is only Vault-to-Provider and contains no client information.

```rust
// Batch splitting logic on the enclave side
const MAX_SETTLEMENTS_PER_TX_PHASE1: usize = 20;
const MAX_ATOMIC_SETTLEMENTS_PER_TX_WITH_AUDIT: usize = 4;

fn submit_batch(
    batch_id: u64,
    prepared: Vec<PreparedSettlement>,
) {
    let eligible = prepared
        .into_iter()
        .filter(|entry| {
            entry.provider_credit >= AUTO_BATCH_MIN_PROVIDER_PAYOUT
                || entry.oldest_credit_age >= MAX_SETTLEMENT_DELAY_SEC
        })
        .collect::<Vec<_>>();
    let interleaved = round_robin_by_provider(eligible, MAX_SETTLEMENTS_PER_TX_PHASE1);
    let chunks = split_evenly(interleaved, MAX_ATOMIC_SETTLEMENTS_PER_TX_WITH_AUDIT);

    for chunk in chunks {
        let settlement_chunk = aggregate_by_provider(&chunk);
        let audit_chunk = chunk
            .iter()
            .map(|entry| entry.audit.clone())
            .collect::<Vec<_>>();
        let batch_chunk_hash = hash_atomic_chunk(&settlement_chunk, &audit_chunk);
        submit_atomic_settle_and_audit_tx(
            batch_id,
            batch_chunk_hash,
            &settlement_chunk,
            &audit_chunk,
        );
    }
}
```

Here, `settlement_chunk` passed to `settle_vault` is an **aggregate per provider token account**, while `record_audit` stores encrypted records for each individual request included in the same chunk. Automatic batching holds small provider credits until they grow above the payout floor, and does not put provider aggregates on-chain until `MIN_BATCH_PROVIDERS` and `MIN_ANONYMITY_WINDOW_SEC` are satisfied. It prioritizes liveness and flushes only when `MAX_SETTLEMENT_DELAY_SEC` is reached. Atomic chunk sizes should be distributed as evenly as possible, and a trailing tiny chunk that would contain a single provider is held until the liveness deadline.

**Force Settlement (Exit Path During Enclave Failure, Aligned with A402 Algorithm 3):**

```
force_settle_init(
    free_balance,
    locked_balance,
    max_lock_expires_at,
    receipt_nonce,
    receipt_signature,
    receipt_message,
)
  -> participant (client/provider) submits an enclave-signed `ParticipantReceipt`
  -> Ed25519 signature verification (see below)
  -> Decode `receipt_message` and confirm participant / participant_kind / recipient_ata /
    vault / free_balance / locked_balance / max_lock_expires_at / receipt_nonce match
    instruction arguments and accounts
  -> Create ForceSettleRequest PDA
  -> dispute_deadline = current_time + DISPUTE_WINDOW (example: 24 hours)

force_settle_challenge(newer_receipt_nonce, newer_receipt_signature, newer_receipt_message)
  -> The participant, Receipt Watchtower, or an available enclave submits a newer-nonce certificate to challenge
  -> Update ForceSettleRequest recipient_ata / free_balance_due / locked_balance_due /
    max_lock_expires_at / receipt_nonce / receipt_signature with the newer receipt

force_settle_finalize()
  -> dispute_deadline has passed with no valid challenge
  -> let claimable_now = free_balance_due
      + (current_time >= max_lock_expires_at ? locked_balance_due : 0)
  -> require vault_token_account.amount >= claimable_now
      (if insufficient, fail with `vault_insolvent`; do not do partial payouts)
  -> USDC CPI transfer: VaultTokenAccount -> recipient_ata (claimable_now amount)
  -> free_balance_due = 0
  -> if current_time >= max_lock_expires_at { locked_balance_due = 0 }
  -> if both are 0, ForceSettleRequest.is_resolved = true
```

`force_settle_*` is designed as an **always-available emergency exit** independent of governance pause/migration operations. After `Paused` / `Retired` / expired `Migrating`, normal instructions stop, so `force_settle_*` becomes the only balance recovery path. Trust-minimized recovery is guaranteed only for a **solvent vault**. If funds are insufficient, the protocol stops as a protocol error and moves to incident response with governance/top-up.

**On-chain Ed25519 Signature Verification Method:**

To verify Ed25519 signatures on-chain in Solana, use the `Ed25519Program` precompile.
Unlike normal Signer verification, which checks transaction signers, this can **verify signatures over arbitrary messages**.

```
Transaction structure:
  Instruction 0: Ed25519Program.createInstructionWithPublicKey({
    publicKey: vault_signer_pubkey,
    message: receipt_message,    // serialized ParticipantReceipt
    signature: receipt_signature
  })
  Instruction 1: a402_vault::force_settle_init(...)
    -> Read sysvar::instructions inside the program and confirm
      that Ed25519 verification in Instruction 0 succeeded
```

This is a widely used pattern on Solana, for example in Serum and Wormhole, and can be verified at about ~2,000 CU/signature.

### 6.4 AuditRecord PDA Cost

Each AuditRecord PDA (222 bytes) requires about 0.00159 SOL for rent exemption.

| Scale | AuditRecord count | Required SOL | Notes |
|------|-------------|---------|------|
| Small test | 100 | ~0.156 SOL | Devnet airdrops are sufficient |
| Medium | 10,000 | ~15.6 SOL | |
| Large | 100,000 | ~156 SOL | |

**During Devnet development**: obtain Devnet SOL with `solana airdrop`.

**Considerations for Mainnet migration:**
- The Nitro Enclave signer pays AuditRecord rent as the payer for `settle_vault` / `record_audit` txs
- Add functionality to close old AuditRecords and recover rent after the audit retention period

---

## 7. Client SDK

### 7.1 API Design

Preserve the existing x402 user experience of `fetch -> 402 handling -> PAYMENT-SIGNATURE retry`, while internally generating a `subly402-svm-v1` payload for the Nitro Enclave.

```typescript
// @a402/client

// === Existing x402 (reference) ===
import { buildSolanaX402Client } from "@alchemy/x402";
const client = buildSolanaX402Client(privateKey);
const res = await client.fetch("https://x402.alchemy.com/solana-mainnet/v2", { body });

// === Privacy version (this protocol) ===
import { A402Client } from "@a402/client";

const client = new A402Client({
  walletKeypair,                              // Client's Solana Keypair
  vaultAddress: new PublicKey("..."),          // Vault address to join
  enclaveUrl: "https://vault.example.com",    // Nitro Enclave ingress endpoint
});

// First run: verify the TEE with Remote Attestation
await client.verifyAttestation();

// Usage is the same as existing x402: just fetch
const res = await client.fetch("https://x402.alchemy.com/solana-mainnet/v2", {
  method: "POST",
  body: JSON.stringify({
    jsonrpc: "2.0", method: "eth_blockNumber", params: [], id: 1
  }),
});
```

Internally, it automatically:
1. Receives `PAYMENT-REQUIRED` from the Provider
2. Verifies Nitro Enclave attestation
3. Locally generates the `subly402-svm-v1` payload
4. Puts the opaque payload in `PAYMENT-SIGNATURE` and resends to the Provider
5. The Provider verifies/settles through the custom facilitator and returns the response

### 7.2 Vault Operations

```typescript
// Deposit (direct on-chain)
await client.deposit(10_000_000);  // 10 USDC (6 decimals)

// Withdraw (enclave signature + nonce)
await client.withdraw(5_000_000);  // Signed by the enclave -> executed on-chain

// Force withdraw (during enclave failure)
const receipt = client.getLatestClientReceipt();
await client.forceSettle(receipt);  // Withdraw after the dispute window
```

### 7.3 Audit Tool

```typescript
import { AuditTool } from "@a402/client";

// Decrypt all transactions with the master key
const auditor = new AuditTool(auditorMasterSecret);
const allRecords = await auditor.decryptAll(vaultAddress);

// Decrypt only a specific provider
const providerRecords = await auditor.decryptForProvider(
  vaultAddress, providerAddress
);

// Give a derived key to a third party (partial disclosure)
const exportedKey = auditor.exportProviderKey(providerAddress);
// -> The holder of this key can decrypt only payments to Provider A
```

---

## 8. Development Phases

### Phase 1 — Nitro MVP: Vault + Custom Facilitator + Batch Settlement

**Goal**: Provide sender anonymity through Nitro Enclave and x402 HTTP envelope compatibility with the minimum viable configuration
**Environment**: Solana Devnet + Nitro Enclave-compatible EC2

- Anchor Program:
  - Account structs: deploy with fields for all phases (`VaultConfig`, `AuditRecord`, `ForceSettleRequest`, `UsedWithdrawNonce`). Changing account size later requires realloc + migration, so fix it from the first deployment
  - Instructions: `initialize_vault`, `deposit`, `withdraw`, `settle_vault`, `pause_vault` (emergency stop is required from day one)
  - Phase 2+ instructions (`record_audit`, `force_settle_*`, `announce_migration`, `retire_vault`) are added through program upgrades. This is safe because account structs do not change
- Nitro Enclave: client balance management, custom facilitator (`/verify`, `/settle`)
- Parent Instance: ingress relay / egress relay / KMS proxy / encrypted snapshot storage
- Deposit Detection: the enclave watches deposit instructions and reflects balances after `finalized`
- Remote Attestation: clients can verify the enclave
- Restart recovery through KMS-backed snapshot/WAL
- Basic Client SDK (deposit, withdraw, fetch, verifyAttestation)
- Test: Bankrun + local Nitro simulation + Dev Nitro environment

**Privacy**: sender anonymity from on-chain observers. The parent instance also cannot access plaintext payloads.
**Exec-Pay-Deliver**: not guaranteed (Provider trust model). The HTTP envelope is x402-compatible, but payment semantics are A402-specific.

### Phase 2 — Audit Records + Selective Disclosure

**Goal**: Generate encrypted audit trails per settlement, with provider-level disclosure
**Environment**: Solana Devnet

- `record_audit` instruction + AuditRecord PDA
- ElGamal encryption inside the enclave with provider-specific derived keys
- Hierarchical key derivation (KDF + ElGamal key pair)
- Batch splitting support for settle_vault (up to ~24 entries/tx, AuditRecord up to 4-5 entries/tx)
- `rotate_auditor` instruction (future-only; advances `auditor_epoch`, while the auditor stores old epoch keys)
- AuditTool (SDK)
- Test: encryption/decryption correctness + provider-specific disclosure verification

### Phase 3 — Atomic Service Channels + Provider TEE

**Goal**: A402 ASC-equivalent off-chain high-frequency micropayments + cryptographic atomicity

- ASC state management inside the enclave, aligned with A402 Algorithm 1
- **Provider-side TEE introduction**: Service Provider also executes requests inside a TEE
- **Ed25519 Adaptor Signatures**: cryptographically guarantees Exec-Pay-Deliver atomicity, fully aligned with A402 Algorithm 2
- **Provider key binding**: pin the provider TEE signing key in registration `participantPubkey`, and enforce that match during ASC deliver
- Batch Settlement: aggregate multiple ASCs into one tx with `settle_vault` (up to 20-30 entries)
- Participant Receipts: the enclave issues signed balance certificates for clients/providers
- Complete Client SDK `fetch` wrapper

**Exec-Pay-Deliver**: cryptographically guaranteed. The Provider cannot receive payment unless it returns the result.

### Phase 4 — Force Settlement + Dispute Resolution

**Goal**: On-chain exit path during enclave failure or migration (Trust-Minimized Asset Security)

- `force_settle_init` / `force_settle_challenge` / `force_settle_finalize`
- ForceSettleRequest PDA + dispute window, supporting both client and provider
- ParticipantReceipt signature verification: `Ed25519Program` precompile + `sysvar::instructions`
- `announce_migration` + exit window
- Receipt Watchtower (required): stores latest receipts and monitors/challenges force-settle requests

### Phase 5 — Arcium MXE Integration

**Goal**: Additional privacy layer through encrypted on-chain balances

- `encrypted-ixs/`: Arcis circuits (update_balance, settle_and_audit)
- Store encrypted balances in ClientDeposit PDA (`[u8; 32]` ciphertext)
- TEE + Arcium hybrid: state management in TEE, on-chain encryption verification in Arcium
- Balance privacy is possible with Arcium alone even without TEE, reducing TEE dependency
- Detailed design: [`docs/phase5-arcium-design.md`](./phase5-arcium-design.md)

### Phase 6 (Future) — Deposit Privacy

- Private deposits using Token-2022 Confidential Transfer
  - Note: as of 2026-04, Mainnet availability needs confirmation. It is available on ZK-Edge testnet
  - One Confidential Transfer requires seven transactions, making it unsuitable for high-frequency use
- Also hide Vault depositor addresses

---

## 9. Project Structure

```
a402-solana/
├── Anchor.toml
├── Cargo.toml
├── programs/
│   └── a402_vault/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs                 # Program entry
│           ├── constants.rs           # PDA seeds, dispute window duration
│           ├── error.rs               # Error codes
│           ├── state.rs               # VaultConfig, AuditRecord, ForceSettleRequest
│           └── instructions/
│               ├── mod.rs
│               ├── initialize_vault.rs
│               ├── announce_migration.rs
│               ├── pause_vault.rs
│               ├── retire_vault.rs
│               ├── deposit.rs
│               ├── withdraw.rs
│               ├── settle_vault.rs
│               ├── record_audit.rs
│               ├── force_settle_init.rs
│               ├── force_settle_challenge.rs
│               ├── force_settle_finalize.rs
│               └── rotate_auditor.rs
├── enclave/                           # Nitro Enclave service
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                    # Entrypoint (runs inside TEE)
│       ├── state.rs                   # VaultState, ClientBalance, ChannelState
│       ├── attestation.rs             # Remote Attestation
│       ├── facilitator.rs             # /verify /settle /attestation
│       ├── ingress_tls.rs             # TLS termination inside enclave
│       ├── egress_rpc.rs              # Solana RPC/WebSocket client
│       ├── asc_manager.rs             # ASC lifecycle (Phase 3)
│       ├── audit.rs                   # ElGamal encryption + key derivation
│       ├── receipt.rs                 # Participant receipt signing
│       ├── snapshot.rs                # Encrypted snapshot/WAL
│       └── kms_bootstrap.rs           # Attested KMS decrypt/data key bootstrap
├── watchtower/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                    # Receipt watchtower entrypoint
│       ├── receipt_store.rs           # Latest ParticipantReceipt per participant
│       └── challenger.rs              # force_settle_challenge submitter
├── parent/                            # Untrusted parent instance services
│   ├── Cargo.toml
│   └── src/
│       ├── ingress_relay.rs           # TCP -> vsock relay
│       ├── egress_relay.rs            # vsock -> TCP relay
│       ├── kms_proxy.rs               # Nitro KMS proxy supervisor
│       └── snapshot_store.rs          # EBS/S3 persistence for encrypted blobs
├── infra/
│   ├── terraform/
│   └── nitro/
│       ├── enclave.eif
│       └── attestation-policy.json
├── sdk/
│   ├── package.json
│   └── src/
│       ├── client.ts                  # A402Client
│       ├── attestation.ts             # Remote Attestation verification
│       ├── types.ts                   # Type definitions
│       └── audit.ts                   # AuditTool
├── encrypted-ixs/                     # Phase 5 (Arcium)
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs
└── tests/
    ├── a402-vault.ts                  # Anchor unit tests
    ├── a402-nitro-integration.ts      # Nitro integration tests
    ├── a402-parent-adversary.ts       # Parent relay compromise simulation
    └── a402-e2e.ts                    # Full E2E tests
```

---

## 10. Verification Plan

| Phase | Verification | Method |
|-------|---------|------|
| Phase 1 | Verify Nitro attestation, deposit -> Enclave balance update -> settle_vault -> withdraw. Confirm individual client payments do not appear on-chain | Bankrun + Nitro integration |
| Phase 1 | Confirm that compromising the Parent relay does not grant access to TLS termination, private keys, or plaintext state | Adversary simulation |
| Phase 1 | Confirm recovery from KMS bootstrap + encrypted snapshot/WAL after enclave restart | Fault injection |
| Phase 2 | Execute `settle_vault + record_audit` in the same tx and confirm the audit trail is not missing when payment succeeds | E2E |
| Phase 2 | Confirm that after `rotate_auditor`, new-epoch AuditRecords decrypt only with the new key, while old-epoch Records remain decryptable with the old key | E2E |
| Phase 3 | ASC open -> multiple requests (off-chain) -> batch settle. Confirm aggregation into one tx | E2E + Nitro + Provider TEE |
| Phase 4 | Enclave shutdown -> ParticipantReceipt submission -> dispute window -> recover `free_balance`, then recover `locked_balance` after `max_lock_expires_at` | Bankrun + fault injection |
| Phase 4 | Confirm Receipt Watchtower challenges stale receipts and prevents excessive withdrawal | Adversary simulation |
| Phase 4 | Confirm `force_settle_finalize` stops with `vault_insolvent` without partial payout when vault balance is insufficient | Insolvency simulation |
| Phase 4 | Confirm migration from old Vault to exit/new vault after `announce_migration` | Migration rehearsal |
| Phase 5 | Update Arcium encrypted_balance. Confirm balance privacy works with Arcium alone even without TEE | Arcium devnet |
