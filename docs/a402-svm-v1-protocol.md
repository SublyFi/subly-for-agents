# A402-SVM-V1 Protocol Specification

> Version: 0.1.0
> Date: 2026-04-12
> Status: Draft
> Companion: [a402-solana-design.md](./a402-solana-design.md)

---

## 1. Scope

`subly402-svm-v1` is a custom payment scheme that preserves the x402 HTTP envelope while replacing payment semantics from "the client directly submits an on-chain transfer" to "a vault balance inside a Nitro Enclave is conditionally reserved and later settled in batches."

This spec fixes:

- Payment details included in `accepts[]` in `PAYMENT-REQUIRED`
- Payment payload included in the `PAYMENT-SIGNATURE` header
- `/verify` `/settle` `/cancel` `/attestation` APIs between provider and facilitator
- State machines for payment idempotency / reservation / batch settlement

This spec does not yet fix:

- Phase 3 messages between provider TEEs
- Exact Ed25519 adaptor signature transcript
- Formal interoperability with x402 extensions such as signed offers / receipts

---

## 2. Compatibility Profile

`subly402-svm-v1` preserves the following:

- The client sends a normal HTTP request to the paid resource
- The server returns `402 Payment Required`
- The client resends the request with `PAYMENT-SIGNATURE`
- The server delegates verify / settle to the facilitator
- The server returns `PAYMENT-RESPONSE`

`subly402-svm-v1` changes the following:

- The contents of `PAYMENT-SIGNATURE` are not a raw Solana transfer transaction
- The verify / settle target is an A402-aware facilitator, not a generic x402 facilitator
- On-chain settlement is batched, not per-request

---

## 3. Roles

- `Client`: buyer-side agent that sends requests to the provider
- `Provider`: HTTP server that provides the paid resource
- `Facilitator`: A402-aware verifier / reserver / settler running inside the Nitro Enclave
- `ReceiptWatchtower`: stores the latest `ParticipantReceipt` and performs stale receipt challenges when the enclave is unavailable
- `Vault Program`: escrow / batch settlement / force-settle program on Solana
- `Governance`: operator key used only for vault pause / migration announcements

---

## 4. Seller Identity

The default seller flow does not require prior provider registration or API key issuance. Seller middleware includes `network`, `asset.mint`, and `payTo` when returning route-specific `PAYMENT-REQUIRED`. The facilitator automatically registers an open seller from this combination on the first valid `/verify`.

open seller identity:

```text
providerId = "payto_" || SHA-256(
  "SUBLY402-OPEN-PROVIDER-V1\n" ||
  network || "\n" ||
  assetMint || "\n" ||
  payTo || "\n"
)[0..32]
```

Constraints:

- `payTo` is the SPL token account where the seller ultimately receives funds
- If `sellerWallet` is provided, Solana middleware may automatically derive that wallet owner's USDC ATA as `payTo`
- An open seller is bound to `network`, `assetMint`, `payTo`, and `vault`
- If `providerId` is not specified, middleware / facilitator use the deterministic id above
- Sellers requiring explicit `providerId`, mTLS, bearer/API-key auth, or ASC provider participant attestation use the advanced registration flow

advanced `ProviderRegistration`:

```json
{
  "providerId": "prov_01JQ8V8T3V9Q8T8M8G9K0J4W7A",
  "displayName": "alchemy-solana-rpc",
  "participantPubkey": "9xQeWvG816bUx9EPfEZmP4nTqYhA6s1xY9q6m7V4sQ9N",
  "participantAttestation": {
    "document": "base64(...)",
    "policy": {
      "version": 1,
      "pcrs": {
        "0": "...",
        "1": "...",
        "2": "...",
        "3": "...",
        "8": "..."
      },
      "eifSigningCertSha256": "...",
      "kmsKeyArnSha256": "...",
      "protocol": "a402-provider-v1"
    },
    "maxAgeMs": 600000
  },
  "settlementTokenAccount": "7xKXtg2CW...",
  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
  "assetMint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
  "allowedOrigins": ["https://x402.alchemy.example"],
  "authMode": "bearer",
  "authMaterial": {
    "apiKeyId": "pk_live_provider_123"
  }
}
```

Constraints:

- `providerId` is unique within the facilitator
- `settlementTokenAccount` is the SPL token account where the provider ultimately receives funds
- `authMode` supports `bearer` / `api-key` / `mtls`
- Both `bearer` and `api-key` register a SHA-256 hash of the provider secret with the facilitator and present it via `Authorization: Bearer ...` or `x-a402-provider-auth`
- `allowedOrigins` is checked against the request origin during `/verify`
- Phase 3 ASC providers must have `participantPubkey` and must present the corresponding `participantAttestation` to the facilitator to complete attested registration
- `participantAttestation.document` is either a Nitro attestation document or a local-dev provider attestation document, and must bind `providerId`, `participantPubkey`, and `attestationPolicyHash` in signed user_data
- The facilitator must compare `participantAttestation.policy.pcrs` with the attestation document and confirm that the policy hash computed from `participantAttestation.policy` matches `attestationPolicyHash` in user_data

---

## 5. PAYMENT-REQUIRED Schema

The provider returns the following as each element of `accepts[]`.

For x402 v2 compatibility, the `402 Payment Required` response:

- Puts `{"accepts":[...]}` as Base64-encoded JSON in the `PAYMENT-REQUIRED` response header
- May mirror the same `accepts[]` in the response body

```json
{
  "scheme": "subly402-svm-v1",
  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
  "amount": "1000000",
  "asset": {
    "kind": "spl-token",
    "mint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    "decimals": 6,
    "symbol": "USDC"
  },
  "payTo": "7xKXtg2CW...",
  "providerId": "prov_01JQ8V8T3V9Q8T8M8G9K0J4W7A",
  "facilitatorUrl": "https://vault.example.com/v1",
  "vault": {
    "config": "9oX9G2xD...",
    "signer": "6MS8C3c4...",
    "attestationPolicyHash": "1a6c2f1f4f8f2a0f7a0e8d5b5a1a6d2d53b49939f4c7d9626abfce2033d5d2fe"
  },
  "paymentDetailsId": "paydet_01JQ8VB4E4X7M1K5Q7SY4P1Y7H",
  "verifyWindowSec": 60,
  "maxSettlementDelaySec": 900,
  "privacyMode": "vault-batched-v1"
}
```

Required fields:

| Field                         | Type    | Meaning                                                     |
| ----------------------------- | ------- | ----------------------------------------------------------- |
| `scheme`                      | string  | Fixed value `subly402-svm-v1`                               |
| `network`                     | string  | Solana network id in CAIP-2 format                          |
| `amount`                      | string  | Decimal string in atomic units                              |
| `asset.mint`                  | string  | SPL token mint                                              |
| `payTo`                       | string  | provider settlement token account                           |
| `providerId`                  | string  | Open seller deterministic id or registered provider id      |
| `facilitatorUrl`              | string  | Base URL providing `/verify` `/settle` `/attestation`       |
| `vault.config`                | string  | VaultConfig PDA                                             |
| `vault.signer`                | string  | Enclave signer pubkey                                       |
| `vault.attestationPolicyHash` | string  | attestation policy hash                                     |
| `paymentDetailsId`            | string  | Unique id issued by the provider                            |
| `verifyWindowSec`             | integer | Seconds to wait for `/settle` after verify                  |
| `maxSettlementDelaySec`       | integer | Maximum delay before provider credit is batched on-chain    |

`paymentDetailsHash` is computed consistently by client / provider / facilitator as:

```text
paymentDetailsHash = SHA-256(canonical_json(selected_accept_object))
```

Here, `canonical_json` is:

- UTF-8
- Keys sorted lexicographically
- No extra whitespace
- Integers in decimal notation
- No string normalization

---

## 6. PAYMENT-SIGNATURE Payload

The `PAYMENT-SIGNATURE` header value is the following JSON encoded as UTF-8 and sent as Base64-encoded data. Implementations may also accept Base64URL for backward compatibility.

```json
{
  "version": 1,
  "scheme": "subly402-svm-v1",
  "paymentId": "pay_01JQ8VKGW2P4M0C31Q1QKQQR4M",
  "client": "4xzJcN4h...",
  "vault": "9oX9G2xD...",
  "providerId": "prov_01JQ8V8T3V9Q8T8M8G9K0J4W7A",
  "payTo": "7xKXtg2CW...",
  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
  "assetMint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
  "amount": "1000000",
  "requestHash": "4b6ee3b1ff5a4f4f923ce2d2d7a6cda3dd44f5d466fb40f11bf3f5e7c4d84c22",
  "paymentDetailsHash": "0f3073c55f5016b4310f6123f2142d0f2ef758f2f2efb7e88a2f8d2a5ec7f182",
  "expiresAt": "2026-04-12T00:30:00Z",
  "nonce": "1844674407370955161",
  "clientSig": "base64(ed25519(signature))"
}
```

Required constraints:

- `paymentId` is generated uniquely by the client
- `vault` must match `vault.config`
- `payTo` must match `payment details.payTo`
- `expiresAt` must be in the future when the provider accepts it
- `nonce` must not be reused locally by the client

### 6.1 Client Signature Message

The client signs the following message with Ed25519.

```text
A402-SVM-V1-AUTH
version
scheme
paymentId
client
vault
providerId
payTo
network
assetMint
amount
requestHash
paymentDetailsHash
expiresAt
nonce
```

Each line is a UTF-8 string ending with `\n`. Integers are converted to decimal strings.

---

## 7. Request Hash

`requestHash` binds the paid request to the payment authorization.

```text
requestHash = SHA-256(
  "A402-SVM-V1-REQ\n" ||
  METHOD || "\n" ||
  ORIGIN || "\n" ||
  PATH_AND_QUERY || "\n" ||
  BODY_SHA256_HEX || "\n" ||
  PAYMENT_DETAILS_HASH_HEX || "\n"
)
```

Rules:

- `METHOD` is the uppercase HTTP method
- `ORIGIN` is `scheme://host[:port]`
- `PATH_AND_QUERY` is raw path + raw query
- `BODY_SHA256_HEX` is the SHA-256 of the request body bytes
- If the body is empty, use the SHA-256 of the empty byte string

The provider recomputes the received request using these rules during `/verify` and passes it to the facilitator.

---

## 8. Facilitator API

The base URL is `facilitatorUrl` and provides the following.

### 8.0 Vault Status Semantics

The facilitator behaves consistently with the on-chain vault status.

- `Active`: allows `/verify`, `/settle`, `/cancel`
- `Paused`: rejects `/verify`, `/settle`, `/cancel` with `503 vault_paused`
- `Migrating`: rejects new `/verify` with `503 vault_migrating`, and allows only `/settle` and `/cancel` for existing reservations until `exit_deadline`
- `Retired`: rejects `/verify`, `/settle`, `/cancel`

The provider must not continue the resource handler after receiving `503 vault_paused` / `503 vault_migrating`.

### 8.1 `GET /v1/attestation`

Uses:

- Client verifies Nitro Attestation
- Provider audits the facilitator runtime policy

response:

```json
{
  "vaultConfig": "9oX9G2xD...",
  "vaultSigner": "6MS8C3c4...",
  "attestationPolicyHash": "1a6c2f1f4f8f2a0f7a0e8d5b5a1a6d2d53b49939f4c7d9626abfce2033d5d2fe",
  "attestationDocument": "base64(...)",
  "issuedAt": "2026-04-12T00:00:00Z",
  "expiresAt": "2026-04-12T00:10:00Z"
}
```

### 8.2 `POST /v1/verify`

Authentication:

- The default open seller flow does not require a provider API key
- Advanced registered providers may use `Authorization: Bearer <provider-api-key>` / API key header / mTLS
- In bearer mode, `x-subly402-provider-id` or `X-A402-Provider-Id` indicates provider identity

request:

```json
{
  "paymentPayload": { "...": "..." },
  "paymentDetails": { "...": "..." },
  "requestContext": {
    "method": "POST",
    "origin": "https://x402.alchemy.example",
    "pathAndQuery": "/solana-mainnet/v2",
    "bodySha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
  }
}
```

response:

```json
{
  "ok": true,
  "verificationId": "ver_01JQ8VQ6M1MS4KTW46ZF4GJKF3",
  "reservationId": "res_01JQ8VQ6P4MYCNZJ5J8CMWQ66E",
  "reservationExpiresAt": "2026-04-12T00:01:00Z",
  "providerId": "prov_01JQ8V8T3V9Q8T8M8G9K0J4W7A",
  "amount": "1000000",
  "verificationReceipt": "base64(enclave-signed-verification-receipt)"
}
```

Validations the facilitator must perform in `/verify`:

1. The open seller identity matches `paymentDetails` / payload, or provider auth matches advanced registration
2. `paymentDetails.scheme == "subly402-svm-v1"`
3. `paymentDetails.verifyWindowSec` is a positive integer
4. `paymentDetailsHash` matches
5. `requestHash` matches the value recomputed from `requestContext`
6. `clientSig` is valid
7. `expiresAt` is in the future
8. `providerId`, `payTo`, `assetMint`, `network`, and `vault` match the open seller identity or advanced registration / vault config
9. The client's `free_balance >= amount`
10. `paymentId` is unused, or this is an idempotent replay for the same request
11. Vault status is `Active`

Side effects on successful `/verify`:

- `free_balance -= amount`
- `locked_balance += amount`
- `reservationExpiresAt = verified_at + verifyWindowSec`
- Set reservation state to `RESERVED`
- Append `ReservationCreated` to the encrypted WAL and return the response only after it is durable

### 8.3 `POST /v1/settle`

Authentication:

- Same as `/verify`. In the default open seller flow, settlement requests are handled with the seller identity bound to the verification.

request:

```json
{
  "verificationId": "ver_01JQ8VQ6M1MS4KTW46ZF4GJKF3",
  "resultHash": "a9cd98f7b4c3c59e4d5f6f0d215b0bb7f08933f5d6b8e0c5f9893f6ce6d033bd",
  "statusCode": 200
}
```

response:

```json
{
  "ok": true,
  "settlementId": "set_01JQ8VV2SEQQFG28M0WSTC3Q59",
  "offchainSettledAt": "2026-04-12T00:00:22Z",
  "providerCreditAmount": "1000000",
  "batchId": null,
  "participantReceipt": "base64(enclave-signed-provider-participant-receipt)"
}
```

Side effects on successful `/settle`:

- Set reservation state to `SETTLED_OFFCHAIN`
- `locked_balance -= amount`
- Add `amount` to the provider credit ledger
- Issue a `ParticipantReceipt` for the provider
- Append `SettlementCommitted` to the encrypted WAL and return the response only after it is durable

`/settle` must succeed only when the reservation is still `RESERVED` and `now <= reservationExpiresAt`. Reservations past `verifyWindowSec` do not wait for a background sweeper; the request itself immediately transitions them to `EXPIRED`, returns locked balance to client free balance, and then returns `reservation_expired`.

### 8.4 Provider Single-Execution Rule

The provider must treat `verificationId` as a **single-execution capability**.

Recommended provider-side middleware / server states:

- `VERIFIED_UNSERVED`
- `EXECUTING`
- `SERVED_SUCCESS`
- `SERVED_ERROR`

Rules:

1. A handler may be started only once for the same `verificationId`
2. If a duplicate request arrives while `EXECUTING`, return `409 duplicate_execution_in_flight` or wait for the same in-flight result
3. If a duplicate request arrives after `SERVED_SUCCESS` / `SERVED_ERROR`, return the original HTTP status / body / `PAYMENT-RESPONSE` unchanged
4. Clustered deployments must place the execution cache in shared storage or use sticky routing by `verificationId`

These rules prevent multiple executions of the resource handler even if the same signed authorization is replayed multiple times.

### 8.5 `POST /v1/cancel`

Use:

- Provider explicitly releases a reservation before executing the service

Authentication:

- Same as `/verify` (`Authorization: Bearer <provider-api-key>` or mTLS)
- The facilitator records the association between `verificationId` and `providerId` when returning the `/verify` response
- If the `providerId` obtained from `/cancel` request authentication does not match the issuer of that `verificationId`, return `403 provider_mismatch`
- This prevents unauthorized third-party reservation cancellation

request:

```json
{
  "verificationId": "ver_01JQ8VQ6M1MS4KTW46ZF4GJKF3",
  "reason": "upstream_unavailable"
}
```

response:

```json
{
  "ok": true,
  "cancelledAt": "2026-04-12T00:00:05Z"
}
```

### 8.6 PAYMENT-RESPONSE Schema

The provider puts at least the following in the `PAYMENT-RESPONSE` response header.

The header value is Base64-encoded JSON.

```json
{
  "scheme": "subly402-svm-v1",
  "paymentId": "pay_01JQ8VKGW2P4M0C31Q1QKQQR4M",
  "verificationId": "ver_01JQ8VQ6M1MS4KTW46ZF4GJKF3",
  "settlementId": "set_01JQ8VV2SEQQFG28M0WSTC3Q59",
  "batchId": null,
  "txSignature": null,
  "participantReceipt": "base64(enclave-signed-provider-participant-receipt)"
}
```

Meaning:

- `batchId == null` and `txSignature == null`: settled off-chain, not yet batched on-chain
- If the provider queries after batch completion, it can retrieve `batchId` and `txSignature`
- `participantReceipt` is the basis for provider force-settle

---

## 9. State Machine and Idempotency

States per `paymentId`:

- `UNSEEN`
- `RESERVED`
- `CANCELLED`
- `EXPIRED`
- `SETTLED_OFFCHAIN`
- `BATCHED_ONCHAIN`

Transitions:

```text
UNSEEN --verify--> RESERVED
RESERVED --cancel--> CANCELLED
RESERVED --timeout--> EXPIRED
RESERVED --settle--> SETTLED_OFFCHAIN
SETTLED_OFFCHAIN --batch confirmed--> BATCHED_ONCHAIN
```

idempotency rules:

- `/verify` retries with the same `paymentId` + same `requestHash` + same `paymentDetailsHash` return the same `verificationId`
- If request binding differs for the same `paymentId`, return `409 payment_id_reused`
- `/settle` retries against `SETTLED_OFFCHAIN` return the same `settlementId`
- Reject `/settle` for payments already `CANCELLED` / `EXPIRED`

Provider-side execution cache rules:

- Duplicate requests for the same `verificationId` must not trigger a new execution
- If the provider uses a clustered deployment, the execution cache must be made consistent through shared storage or sticky routing

---

## 10. Batch Settlement

The facilitator keeps off-chain credit per provider and pays it on-chain in aggregate with `settle_vault`.

### 10.1 Batch Trigger

Phase 1 recommended values:

- `BATCH_WINDOW_SEC = 120` (env `SUBLY402_BATCH_WINDOW_SEC`)
- `MAX_SETTLEMENT_DELAY_SEC = 900`
- `MAX_SETTLEMENTS_PER_TX = 20`
- `JITTER_SEC = 0..30`

Batches are triggered by any of the following:

1. Batch window elapsed
2. Pending provider count reached `MAX_SETTLEMENTS_PER_TX`
3. Oldest batch-eligible settlement reached `MAX_SETTLEMENT_DELAY_SEC`

### 10.2 Privacy Rules

- Do not settle on-chain per individual request
- Mix multiple providers into the same batch whenever possible
- Select pending credit round-robin across providers so a batch does not become single-provider through consecutive selection of one provider
- The facilitator SHOULD defer automatic batch inclusion for provider credits smaller than a configured payout floor (Phase 1 recommendation: `AUTO_BATCH_MIN_PROVIDER_PAYOUT = 1_000_000` atomic units = 1 USDC) and wait for aggregation, unless `MAX_SETTLEMENT_DELAY_SEC` has been reached
- Add jitter to batch submit time
- Return an off-chain receipt to the provider when `/settle` succeeds, and finalize credit before on-chain arrival
- `MIN_ANONYMITY_WINDOW_SEC = 300` (Phase 1 public default, env `SUBLY402_MIN_ANONYMITY_WINDOW_SEC`): each settlement is excluded from automatic batching until its age reaches this value. Even if an older sibling is paid first, a fresh sibling continues aging in the vault until it satisfies the window. This is a time-based anonymity gate that gives each settlement a minimum waiting period independent of batch cadence.
- `MIN_BATCH_PROVIDERS = 2` (Phase 1 public default, env `SUBLY402_MIN_BATCH_PROVIDERS`): if the number of providers in a batch is below this value, wait until `MAX_SETTLEMENT_DELAY_SEC` so the credit can join credit from other providers. If the trailing atomic chunk would be single-provider, hold it until the liveness deadline as well. In all cases, `settle_vault` txs contain only Vault-to-Provider transfers and no client information, so linkability remains at the level of "someone used this provider set during this period."

### 10.3 Batch Receipts

After batch confirmation, the facilitator records `settlementId -> batchId -> txSignature` for later audit and dispute use.

---

## 11. Failure Semantics

- Participant receipt semantics:

  - Client receipts have `freeBalance`, `lockedBalance`, and `maxLockExpiresAt`
  - Provider receipts have `lockedBalance = 0`, `maxLockExpiresAt = 0`

- If the provider fails after successful `/verify`:

  - The reservation becomes `EXPIRED` after `verifyWindowSec`
  - Locked balance returns to client free balance

- If the HTTP response to the provider is lost after successful `/settle`:

  - The provider retries `/settle` with the same `verificationId`
  - The facilitator returns the same `settlementId`

- Restart after enclave crash:

  - Recover from encrypted snapshot + WAL
  - Unbatched provider credit can be force-settled with the provider receipt
  - The client can use a participant receipt to recover `freeBalance` after the dispute window
  - If the latest receipt still has `lockedBalance > 0`, that portion can be recovered from the same force-settle request after `maxLockExpiresAt`
  - ReceiptWatchtower must store the latest receipt for stale receipt challenges

- If the paired audit chunk fails during on-chain batch submission:
  - The entire Solana transaction rolls back
  - Provider credit remains `SETTLED_OFFCHAIN` and is resent in a later batch window

---

## 12. Security Invariants

- On-chain observers cannot see direct `client -> provider` correspondence
- The parent instance cannot read payment payloads, request bodies, secret keys, or vault balances
- Providers cannot obtain credit without facilitator verify
- The same `paymentId` cannot be reused for a different request
- The facilitator must not return verify / settle success before writing to durable WAL
- When audit mode is enabled, on-chain settlement chunks must be in the same transaction as their matching audit chunk
- Client / provider balances must remain recoverable by participant receipt even when the vault is unavailable
- The client's locked portion must be recoverable after `maxLockExpiresAt` bound to that receipt
- Recoverability through participant receipts assumes at least one honest available ReceiptWatchtower and a solvent vault
- In Phase 3 ASC, the `providerPubkey` presented by the provider in `/channel/deliver` must match the registration `participantPubkey`, and providers without a registered `participantPubkey` cannot start `/channel/open`

---

## 13. Open Items

- Whether provider auth should standardize on `bearer` or `mtls`
- Whether `requestHash` should require signed offers / payment identifier extensions
- How Phase 3 should map `verificationId` to ASC `rid`
