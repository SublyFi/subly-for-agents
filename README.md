# Subly402

Privacy-first x402 payments for Solana agents.

Subly402 lets an AI agent call a paid HTTP API, receive a normal `402 Payment Required` response, and pay with USDC on Solana without creating a direct public buyer-to-provider payment edge. The core product is a vault-backed facilitator: buyers deposit into a shared Solana vault, the facilitator verifies x402-style payment payloads inside an AWS Nitro Enclave, and providers receive batched vault payouts instead of direct transfers from each buyer.

The next release track turns that vault into an Arcium-backed yield vault: client balances, yield, and authorization state move toward encrypted MPC accounting while the Nitro facilitator keeps the real-time x402 request path fast. That work lives on `feature/arcium` so reviewers can inspect it without losing the stable Devnet/Nitro payment flow on `main`.

## Status

| Area                  | Current state                                                        |
| --------------------- | -------------------------------------------------------------------- |
| Public demo site      | https://www.sublyfi.com/                                             |
| Public facilitator    | `https://api.demo.sublyfi.com`                                       |
| Pitch video           | https://www.loom.com/share/f2d2482a73824ff9abe1de0186a355f7          |
| Demo video            | https://www.loom.com/share/8ae7523608b34d88abc2aae3a5b5b031          |
| Project X             | https://x.com/subly_fi                                               |
| Buyer SDK             | [`subly402-sdk`](https://www.npmjs.com/package/subly402-sdk)         |
| Seller middleware     | [`subly402-express`](https://www.npmjs.com/package/subly402-express) |
| Active release branch | `feature/arcium`                                                     |

**Branch note:** Arcium integration and mainnet release preparation are being developed on `feature/arcium`. That branch keeps the current Devnet/Nitro flow working while adding encrypted accounting, budget grants, withdrawal grants, and release hardening for a mainnet path.
The currently published `0.1.1` NPM packages cover the Devnet/Nitro x402 flow; Arcium SDK helpers are branch work for the next package release.

Some internal file names and environment variables still use the historical `A402_` prefix. The public project, NPM packages, and integration surface are Subly402.

## Why Subly Exists

Direct x402 payments are simple for developers, but every Solana token transfer is public. If an agent pays APIs directly from its wallet, observers can infer which providers it uses, how often it calls them, and roughly what its workflow costs. For autonomous agents and businesses, that payment graph can leak strategy, vendors, usage patterns, and budget.

Subly keeps the x402 developer experience and changes the settlement shape:

```text
Direct x402:
  buyer token account -> provider token account

Subly402:
  buyer token account -> Subly vault
  Subly vault -> provider token account, batched with other activity
```

The first deposit remains public, but individual paid API requests no longer create direct on-chain buyer-to-provider edges.

## What Is Implemented

- `programs/subly402_vault`: Anchor program for USDC escrow, deposits, withdrawals, provider settlement, receipt recovery, and encrypted audit records.
- `enclave`: Nitro Enclave facilitator that verifies payment payloads, manages private balances, forwards paid requests, signs receipts, encrypts audit data, and builds batched settlement.
- `parent`: untrusted EC2-side relay, KMS proxy, and encrypted snapshot/WAL storage. It forwards traffic but must not terminate TLS.
- `watchtower`: stale receipt and force-settlement support for enclave outage recovery.
- `sdk`: buyer SDK published as `subly402-sdk`; wraps `fetch`, verifies facilitator attestation, signs payment payloads, and supports on-demand vault deposits.
- `middleware`: seller middleware published as `subly402-express`; Express middleware for paid routes with automatic Solana `payTo` derivation.
- `scripts/demo`: side-by-side demos comparing direct x402 settlement with Subly vault settlement.
- On `feature/arcium`: `encrypted-ixs` and `sdk/src/arcium.ts` implement the Arcium yield-vault track for encrypted per-client accounting and grant authorization.

## Technical Architecture

```text
Buyer / agent
  -> paid API request
  -> provider returns HTTP 402
  -> subly402-sdk verifies facilitator attestation
  -> buyer signs payment payload
  -> provider settles through subly402-express
  -> Nitro Enclave reserves balance and forwards the paid request
  -> vault batches provider payouts on Solana
```

The public deployment topology is:

```text
Internet
  -> NLB TCP/443
  -> parent EC2 with Nitro Enclaves enabled
  -> ingress relay
  -> vsock
  -> Subly402 Nitro Enclave

parent EC2
  - parent relay
  - watchtower
  - nitro-cli
  - encrypted snapshot/WAL storage
```

The most important security assumptions are:

- TLS terminates inside the Nitro Enclave.
- The parent instance, NLB, nginx, or ALB must not see plaintext request or payment data.
- KMS access is conditioned on Nitro attestation measurements.
- Buyers should pin the facilitator's attestation policy before paying.

## Payment Flow

1. A seller protects a route with `subly402-express` and chooses a price, network, and receiving wallet.
2. A buyer wraps `fetch` with `subly402-sdk`.
3. The seller returns a standard `402 Payment Required` envelope for the paid route.
4. The buyer SDK fetches `/v1/attestation`, verifies the Nitro policy, signs the payment payload, and retries.
5. If the buyer has insufficient vault balance, the SDK can call an `autoDeposit` hook, deposit USDC into the vault, and retry with a fresh signature.
6. The provider asks the facilitator to verify and settle.
7. The enclave reserves internal balance, forwards the paid request, persists receipts/WAL, and later submits aggregate provider payouts from the vault.
8. On-chain observers see deposits and aggregate provider payouts, not per-request buyer-to-provider transfers.

## Privacy Boundaries

| Data                                      | Public on-chain observer     | Parent EC2 / relay        | Nitro Enclave                                                     | Provider                                        |
| ----------------------------------------- | ---------------------------- | ------------------------- | ----------------------------------------------------------------- | ----------------------------------------------- |
| Buyer deposit into vault                  | Visible                      | Visible                   | Visible                                                           | Not needed                                      |
| Individual buyer-to-provider payment edge | Hidden                       | Hidden from plaintext TLS | Known                                                             | Sees own request                                |
| Per-request amount                        | Hidden in batched settlement | Hidden from plaintext TLS | Known                                                             | Sees own price                                  |
| Provider aggregate payout                 | Visible                      | Visible                   | Visible                                                           | Visible                                         |
| Buyer private balance                     | Hidden on-chain              | Hidden                    | Known today; moving to Arcium encrypted state on `feature/arcium` | Hidden                                          |
| Audit trail                               | Encrypted records            | Encrypted records         | Encrypts records                                                  | Decryptable only with authorized disclosure key |

## Arcium And Mainnet Preparation

`feature/arcium` is the active branch for the next release track. The goal is to reduce how much long-lived accounting state the TEE must hold by moving per-client balances and authorization state into Arcium MPC.

Switch to `feature/arcium` to inspect the Arcium-specific files. The main branch intentionally keeps the stable Devnet/Nitro payment path as the default entry point while documenting the active Arcium and mainnet-readiness work.

The branch includes:

- Arcium circuits under `encrypted-ixs`.
- `ClientVaultState`, `DepositCredit`, `BudgetGrant`, and `WithdrawalGrant` flows.
- `Enc<Mxe>` state for balances, yield, and grant state.
- `Enc<Shared>` grant outputs for the attested enclave key.
- SDK helpers for Arcium encryption/decryption, staged for a future `subly402-sdk/arcium` package subpath.
- Devnet scripts for Arcium config, computation definition initialization, smoke tests, and state sync.
- Mainnet release hardening around attestation pinning, recovery paths, batch policy, NPM package UX, and deployment repeatability.

The Nitro Enclave still handles real-time HTTP request forwarding in this phase. Arcium is used for encrypted money-at-rest accounting and budget authorization, while Subly's existing vault path remains the baseline payment flow.

## Devnet Deployment Addresses

Current public Devnet deployment:

| Item                | Address                                        |
| ------------------- | ---------------------------------------------- |
| Program ID          | `3iusaL6ys79DsbpweDwGhHvtjdnhAhtpyczPtMbu5Mbe` |
| VaultConfig         | `EGJVg1tw3NJQj34Wk1vqSSbXEPd3CaYzmrAzWLwrcm3A` |
| Vault token account | `41E84Z5PVYCWvZKLcN3vWn7fDku793aTB7pfpyrhCg98` |
| Vault signer        | `4YDcz8mRMGPhZbFiL1RTmXhYNUx7jDsYcU9y5oB9bE2N` |
| Devnet USDC mint    | `3sJgMz6NUf7zmsNfsgnJH6KKWxQaVkz8frAyKnEMAHy2` |
| Public facilitator  | `https://api.demo.sublyfi.com`                 |

Explorer links:

- Program: https://explorer.solana.com/address/3iusaL6ys79DsbpweDwGhHvtjdnhAhtpyczPtMbu5Mbe?cluster=devnet
- VaultConfig: https://explorer.solana.com/address/EGJVg1tw3NJQj34Wk1vqSSbXEPd3CaYzmrAzWLwrcm3A?cluster=devnet
- Vault token account: https://explorer.solana.com/address/41E84Z5PVYCWvZKLcN3vWn7fDku793aTB7pfpyrhCg98?cluster=devnet
- Devnet USDC mint: https://explorer.solana.com/address/3sJgMz6NUf7zmsNfsgnJH6KKWxQaVkz8frAyKnEMAHy2?cluster=devnet

Previous Devnet vault, kept here so old explorer links and recordings are not confused with the current demo state:

| Item                          | Address                                        |
| ----------------------------- | ---------------------------------------------- |
| Old VaultConfig               | `6i5SyF8Hx2u5MZW2JgWGhdg5CJsAKeF7UaRAd9bERDDL` |
| Old Vault token account / ATA | `76YBLxs4EBrvbiP9RT6vH66i6qZb9b67hUdoajjqz5u`  |

Verify the deployed program:

```bash
solana program show 3iusaL6ys79DsbpweDwGhHvtjdnhAhtpyczPtMbu5Mbe --url devnet
curl -s https://api.demo.sublyfi.com/v1/attestation | jq .
```

## Developer Quickstart

Install the released packages:

```bash
yarn add subly402-sdk subly402-express express
```

The snippets below show the integration surface. For a complete runnable Devnet flow, use the demo commands in [Running The Demo Locally](#running-the-demo-locally).

Seller side:

```ts
import express from "express";
import {
  Subly402FacilitatorClient,
  Subly402ResourceServer,
  Subly402ExactScheme,
  paymentMiddleware,
  captureSubly402RawBody,
} from "subly402-express";

const app = express();
app.use(express.json({ verify: captureSubly402RawBody }));

const facilitator = new Subly402FacilitatorClient({
  url: "https://api.demo.sublyfi.com",
  assetMint: process.env.SUBLY402_USDC_MINT!,
});

const resourceServer = new Subly402ResourceServer(facilitator).register(
  "solana:devnet",
  new Subly402ExactScheme()
);

app.use(
  paymentMiddleware(
    {
      "GET /weather": {
        accepts: [
          {
            scheme: "exact",
            price: "$0.001",
            network: "solana:devnet",
            sellerWallet: process.env.SELLER_WALLET!,
          },
        ],
      },
    },
    resourceServer
  )
);

app.get("/weather", (_req, res) => {
  res.json({ temperature: 72, conditions: "clear" });
});

app.listen(3000);
```

Buyer side:

```ts
import { Subly402Client, wrapFetchWithPayment } from "subly402-sdk";

// App-provided values:
// - signer: a funded Solana signer
// - policy: Nitro attestation policy for the facilitator
// - depositIntoSublyVault: transaction helper that deposits USDC into the vault
// See scripts/demo/subly402-buyer.js and scripts/demo/four-way-common.js for
// the complete Devnet implementation used by the public demo scripts.
const client = new Subly402Client({
  signer,
  network: "solana:devnet",
  trustedFacilitators: ["https://api.demo.sublyfi.com"],
  autoDeposit: {
    maxDepositPerRequest: "$0.05",
    deposit: async ({ amountAtomic, details, facilitatorUrl }) => {
      await depositIntoSublyVault({
        amountAtomic,
        mint: details.asset.mint,
        vaultConfig: details.vault.config,
        facilitatorUrl,
      });
    },
  },
  nitroAttestation: { policy },
});

const fetchWithPayment = wrapFetchWithPayment(fetch, client);
const res = await fetchWithPayment("https://api.example.com/weather");
```

No Subly API key or provider registration is required for the default flow. Sellers provide a wallet owner; the middleware derives the USDC associated token account and uses `network + assetMint + payTo` as the open seller identity.

## Running The Demo Locally

For the side-by-side demo that compares direct x402 with Subly vault settlement:

1. Create `.env.devnet.local` with a funded Devnet wallet and RPC endpoint:

```bash
export SUBLY402_SOLANA_RPC_URL="https://<your-devnet-rpc>"
export SUBLY402_SOLANA_WS_URL="wss://<your-devnet-ws>"
export ANCHOR_PROVIDER_URL="$SUBLY402_SOLANA_RPC_URL"
export ANCHOR_WALLET="$HOME/.config/solana/<wallet>.json"
```

2. Build, deploy, bootstrap, and start the local facilitator/watchtower:

```bash
yarn install --frozen-lockfile
npm --prefix middleware run build
npm --prefix sdk run build

NO_DNA=1 anchor build
NO_DNA=1 anchor deploy \
  --provider.cluster "$ANCHOR_PROVIDER_URL" \
  --provider.wallet "$ANCHOR_WALLET"

yarn devnet:bootstrap
yarn devnet:start
```

`yarn devnet:bootstrap` creates `data/devnet-state.json` and `.env.devnet.generated`. `yarn devnet:start` starts the local watchtower and enclave process against Solana Devnet.

3. Run the official x402 direct-payment demo in two terminals:

```bash
yarn demo:x402-seller
yarn demo:x402-buyer
```

4. Run the Subly private-vault demo in two terminals:

```bash
yarn demo:subly-seller
yarn demo:subly-buyer
```

Expected public chain difference:

- Direct x402: buyer token account pays the seller token account directly.
- Subly402: buyer token account deposits into the Subly vault; the seller receives a later vault payout after batching.

More detail is in [docs/demo-side-by-side.md](./docs/demo-side-by-side.md), [docs/quickstart.md](./docs/quickstart.md), and [docs/devnet-setup.md](./docs/devnet-setup.md).

## Repository Map

| Path                      | Purpose                                                      |
| ------------------------- | ------------------------------------------------------------ |
| `programs/subly402_vault` | Anchor vault program                                         |
| `enclave`                 | Nitro Enclave facilitator                                    |
| `parent`                  | Parent EC2 relay / KMS proxy / snapshot bridge               |
| `watchtower`              | Receipt recovery and force-settlement support                |
| `sdk`                     | Buyer SDK package                                            |
| `middleware`              | Express seller middleware package                            |
| `encrypted-ixs`           | Arcium circuits on `feature/arcium`                          |
| `scripts/demo`            | Public demo scripts                                          |
| `scripts/devnet`          | Local Devnet helpers; Arcium scripts are on `feature/arcium` |
| `scripts/nitro`           | Nitro build/provision/deployment helpers                     |
| `infra/nitro`             | Terraform, systemd, and Nitro deployment assets              |
| `docs`                    | Architecture, protocol, demo, and deployment references      |

## Deployment Runbook

The sections below are the operational deployment guide for maintaining the public Devnet facilitator or running your own Nitro-backed facilitator.
This section still uses several historical `A402_` variable names because those names exist in the current deployment scripts.

## Shortest Path

For routine updates like code changes to the existing `api.demo.sublyfi.com` environment, use [docs/redeploy-devnet.md](./docs/redeploy-devnet.md) every time.
The flow is to place the runtime archive generated on the Build EC2 in S3, then have the Parent EC2 fetch it and update `/opt/subly402` and `/etc/subly402`.

The shortest path to a public Devnet deployment is:

1. Decide the AWS Region / VPC / KMS key first
2. Fill in `.env.devnet.local` locally
3. Deploy the Solana program to Devnet
4. Generate the Nitro runtime env
5. Build the EIF and capture measurements
6. Finalize `attestation_policy_hash` from the measurements and initialize the on-chain vault
7. Use Terraform to create parent EC2 / NLB / S3, and apply an attestation-conditioned policy to the same KMS key
8. Place the binary / env / EIF on the parent EC2 and start it
9. Check `https://<NLB>/v1/attestation`

## Prerequisite Tools

Required on the local work machine:

- Node.js 18+
- Yarn 1.x
- Rust / Cargo
- Solana CLI
- Anchor CLI
- AWS CLI
- Docker
- Terraform
- `nitro-cli`

Local build versions verified for this repo:

- `anchor-cli 0.32.1`
- `solana-cli 3.1.12`
- `rustc 1.89.0`
- `node v24`

## 1. Local Preparation

### 1-0. Prepare one KMS key first

`yarn nitro:prepare` immediately converts the vault signer seed into KMS ciphertext.
Therefore, `A402_KMS_KEY_ARN` is required at this point.

If you have not created a KMS key yet, complete [2-4. Create the KMS key](#2-4-create-the-kms-key) first.

### 1-1. Create `.env.devnet.local`

Create `.env.devnet.local` at the repo root and include at least:

```bash
export A402_SOLANA_RPC_URL='https://<your-devnet-rpc>'
export A402_SOLANA_WS_URL='wss://<your-devnet-ws>'
export ANCHOR_PROVIDER_URL="$A402_SOLANA_RPC_URL"
export ANCHOR_WALLET="$HOME/.config/solana/<wallet>.json"

export AWS_REGION='us-east-1'
export A402_KMS_KEY_ARN='arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
export A402_KMS_KEY_ID="$A402_KMS_KEY_ARN"
export A402_SNAPSHOT_DATA_KEY_ID="$A402_KMS_KEY_ARN"

export A402_EIF_SIGNING_CERT_PATH="$PWD/infra/nitro/certs/eif-signing-cert.pem"
export A402_NITRO_SIGNING_PRIVATE_KEY="$PWD/infra/nitro/certs/eif-signing-key.pem"
```

Add these later if needed:

- `A402_PUBLIC_ENCLAVE_URL`
- `A402_KMS_PROVISIONER_PRINCIPAL_ARN`
- `A402_ENCLAVE_TLS_CA_SOURCE`

Notes:

- `A402_KMS_KEY_ARN` is the KMS key actually used by the Nitro runtime
- Pass the same key to Terraform later as `existing_runtime_kms_key_arn`
- You do not need to create a separate KMS key

### 1-2. Align the Solana CLI endpoint

```bash
source ./.env.devnet.local
solana config set \
  --url "$A402_SOLANA_RPC_URL" \
  --ws "$A402_SOLANA_WS_URL" \
  --keypair "$ANCHOR_WALLET"
```

### 1-3. Build / deploy the program

```bash
NO_DNA=1 anchor build
NO_DNA=1 anchor deploy \
  --provider.cluster "$A402_SOLANA_RPC_URL" \
  --provider.wallet "$ANCHOR_WALLET"
```

### 1-4. Generate initial information for the Nitro runtime

This command performs the following:

- Generates the vault signer seed
- Converts the signer seed to KMS ciphertext
- Generates the watchtower keypair
- Funds the signer / watchtower with Devnet lamports
- Generates `parent.env`, `watchtower.env`, `enclave.env`, and `run-enclave.json`

```bash
yarn nitro:prepare
```

Generated files:

- `infra/nitro/generated/nitro-plan.json`
- `infra/nitro/generated/parent.env`
- `infra/nitro/generated/watchtower.env`
- `infra/nitro/generated/enclave.env`
- `infra/nitro/generated/run-enclave.json`

### 1-5. Specify source paths for TLS certificates used inside the enclave

For Devnet agent-client-focused usage, self-signed certificates are acceptable.
This implementation allows the client to verify `tlsPublicKeySha256` from `/v1/attestation`.

```bash
export A402_ENCLAVE_TLS_CERT_SOURCE="$PWD/infra/nitro/certs/server.crt"
export A402_ENCLAVE_TLS_KEY_SOURCE="$PWD/infra/nitro/certs/server.key"
```

If optionally using mTLS:

```bash
export A402_ENCLAVE_TLS_CA_SOURCE="$PWD/infra/nitro/certs/client-ca.crt"
```

### 1-6. Build the EIF

```bash
yarn nitro:build-eif
```

Generated files:

- `infra/nitro/generated/a402-enclave.eif`
- `infra/nitro/generated/eif-measurements.json`

### 1-7. Finalize the policy hash from PCRs and initialize the vault

```bash
yarn nitro:provision
```

This step performs the following:

- Computes `attestation_policy_hash` from the measured EIF values
- Derives `PCR3` from the IAM role ARN for the parent EC2
- Runs `initialize_vault` if needed
- Generates `terraform.attestation.auto.tfvars.json`
- Generates the client reference env

Note:

- If you change `project_name` from the Terraform default (`a402-devnet`), set `A402_NITRO_PROJECT_NAME` to the same value before `yarn nitro:prepare` and `yarn nitro:provision`

Generated files:

- `infra/nitro/generated/attestation-policy.json`
- `infra/nitro/generated/attestation-policy.hash`
- `infra/nitro/generated/nitro-state.json`
- `infra/nitro/generated/terraform.attestation.auto.tfvars.json`
- `infra/nitro/generated/client.env`

### 1-8. Build the parent / watchtower release binaries

Build the binaries that will be copied to EC2 separately.

```bash
NO_DNA=1 cargo build --release -p a402-parent -p a402-watchtower
```

## 2. AWS Environment Setup

Here, avoiding configuration mistakes matters more than the commands themselves.

### 2-1. Choose a Region

First choose one Region and keep it fixed.

Recommended:

- `us-east-1`

Reasons:

- Nitro / KMS / NLB / EC2 documentation examples are common
- Devnet RPC endpoints are easy to place near us-east

### 2-2. Prepare the VPC / subnets

Required layout:

- At least two public subnets
- Place the parent EC2 in one of them
- Place the NLB across at least two public subnets

Guidance:

- `NLB` is public
- `watchtower` is not public
- Parent EC2 inbound allows only `443` and, if needed, `22`

### 2-3. Define the Security Group

Configure the parent EC2 with the following approach.

Allow:

- `443/tcp` from `0.0.0.0/0`
- `22/tcp` only from your fixed IP

Do not allow:

- Do not expose `3200/tcp` publicly
- Do not expose the enclave vsock port publicly

egress:

- `0.0.0.0/0` is acceptable initially
- If tightening later, restrict it to Solana RPC, AWS KMS/STS, and provider domains

### 2-4. Create the KMS key

Starting with one KMS key is fine.

Uses:

- Decrypting the vault signer seed
- Generating the snapshot data key

Settings to check when creating it:

- `Symmetric`
- `Encrypt and decrypt`
- Turn key rotation `ON`

Recommended AWS Console steps:

1. Open `KMS`
2. Open `Customer managed keys`
3. `Create key`
4. Select `Symmetric`
5. Select `Encrypt and decrypt`
6. Choose a key alias
   Example: `alias/a402-devnet-runtime`
7. Select your admin role as the key administrator
8. For key usage permissions, initially add only your working principal and create the key
9. Copy the key ARN after creation
10. Put that ARN in `A402_KMS_KEY_ARN` in `.env.devnet.local`

This repo's Terraform can later apply a policy conditioned on the `attested enclave PCRs` to the same KMS key.

### 2-5. Prepare the EIF signing certificate

This certificate is needed to sign the EIF with `nitro-cli build-enclave`.

Minimum required files:

- signing certificate
- private key

This certificate is separate from the TLS certificate.

Distinction:

- `EIF signing cert`: signs the enclave image
- `TLS cert`: used for HTTPS between client/provider and enclave

### 2-6. Choose the parent EC2

Recommended:

- Nitro Enclaves-compatible instance type
- Linux
- At least `c6a.xlarge` or equivalent
- Root volume of at least 30GB

Reason:

- CPU / memory are split out to the enclave, so the parent also needs headroom

How to think about Terraform values:

- `vpc_id`: target VPC
- `nlb_subnet_ids`: at least two public subnets
- `instance_subnet_id`: subnet where the parent EC2 is placed
- `ami_id`: Linux AMI
- `snapshot_bucket_name`: unique S3 bucket name

### 2-7. Use an NLB

This is important.

Use:

- `NLB`
- `TCP/443`

Do not use:

- `ALB`
- TLS termination in parent nginx
- Any setup that terminates ACM on the parent

Reason:

- The parent must not see TLS plaintext

### 2-8. Terraform apply

Use the file generated after `yarn nitro:provision`:
`infra/nitro/generated/terraform.attestation.auto.tfvars.json`

```bash
cd infra/nitro/terraform
terraform init
terraform apply \
  -var-file=../generated/terraform.attestation.auto.tfvars.json \
  -var="existing_runtime_kms_key_arn=$A402_KMS_KEY_ARN" \
  -var='aws_region=us-east-1' \
  -var='vpc_id=vpc-xxxxxxxx' \
  -var='nlb_subnet_ids=["subnet-aaaa","subnet-bbbb"]' \
  -var='instance_subnet_id=subnet-aaaa' \
  -var='ami_id=ami-xxxxxxxx' \
  -var='snapshot_bucket_name=a402-devnet-snapshots-xxxxxxxx'
```

Add if needed:

- `kms_provisioner_principal_arns`

Use this when the IAM principal running `nitro:prepare` needs KMS `Encrypt` permissions.

When `existing_runtime_kms_key_arn` is specified:

- Terraform uses the same KMS key used by `nitro:prepare`
- Terraform does not create a new runtime KMS key
- Terraform applies an attestation-aware policy to that key

## 3. Deploy to the Parent EC2

After `terraform apply`, place the following on the parent EC2.

binary:

- `target/release/a402-parent`
- `target/release/a402-watchtower`

generated files:

- `infra/nitro/generated/a402-enclave.eif`
- `infra/nitro/generated/parent.env`
- `infra/nitro/generated/watchtower.env`
- `infra/nitro/generated/run-enclave.json`

helper scripts:

- `scripts/nitro/start-parent.sh`
- `scripts/nitro/start-watchtower.sh`
- `infra/nitro/systemd/a402-parent.service`
- `infra/nitro/systemd/a402-watchtower.service`

Recommended layout:

- `/opt/a402/bin/a402-parent`
- `/opt/a402/bin/a402-watchtower`
- `/opt/a402/bin/start-parent.sh`
- `/opt/a402/bin/start-watchtower.sh`
- `/opt/a402/enclave/a402-enclave.eif`
- `/etc/a402/parent.env`
- `/etc/a402/watchtower.env`
- `/etc/a402/run-enclave.json`

Notes:

- `enclave.env` is embedded into the image during the EIF build
- Do not put `A402_VAULT_SIGNER_SECRET_KEY_B64` on the parent
- The parent only holds ciphertext and relay functionality

## 4. Software Required on the Parent EC2

Required on the parent EC2:

- `nitro-cli`
- `a402-parent`
- `a402-watchtower`

As needed:

- `jq`
- `curl`
- `systemd`

Notes:

- Docker is required on the `machine that builds the EIF`
- It is usually unnecessary on a `parent EC2 that only runs the EIF`

## 5. Startup Order

Start components in this order.

1. watchtower
2. parent
3. enclave

### 5-1. Recommended: start with systemd

systemd units are already in the repo.

```bash
sudo cp infra/nitro/systemd/a402-parent.service /etc/systemd/system/
sudo cp infra/nitro/systemd/a402-watchtower.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now a402-watchtower
sudo systemctl enable --now a402-parent
```

### 5-2. Starting directly

Use wrappers that read env files instead of invoking the raw binaries directly.

```bash
bash /opt/a402/bin/start-watchtower.sh /etc/a402/watchtower.env
```

```bash
bash /opt/a402/bin/start-parent.sh /etc/a402/parent.env
```

### 5-3. Start the enclave

```bash
NO_DNA=1 nitro-cli run-enclave --config /etc/a402/run-enclave.json
```

From the repo:

```bash
yarn nitro:run /etc/a402/run-enclave.json
```

Check status:

```bash
yarn nitro:describe
curl -sk https://<your-nlb-dns>/v1/attestation | jq .
```

## 6. Initial Public Smoke Test

If you want to use the admin APIs only for the initial run, put the following in `enclave.env` before building the EIF.

```bash
export SUBLY402_ENABLE_PROVIDER_REGISTRATION_API='1'
export SUBLY402_ENABLE_ADMIN_API='1'
export SUBLY402_ADMIN_AUTH_TOKEN='<operator-only-random-token>'
```

With that state:

1. `yarn nitro:build-eif`
2. `yarn nitro:provision`
3. Redeploy to the parent
4. Restart the enclave

After the smoke test, set both back to `0` and rebuild the EIF.
`prepare` writes only `SUBLY402_ADMIN_AUTH_TOKEN_SHA256` to the enclave side.
Use `SUBLY402_ALLOW_ADMIN_PRIVACY_BYPASS_BATCH=1` only when a single-provider smoke test requires immediate batching, and keep it at `0` in the public runtime.

## 7. Daily Commands

```bash
source ./.env.devnet.local
```

```bash
NO_DNA=1 anchor build
```

```bash
NO_DNA=1 anchor deploy \
  --provider.cluster "$A402_SOLANA_RPC_URL" \
  --provider.wallet "$ANCHOR_WALLET"
```

```bash
yarn nitro:prepare
```

```bash
yarn nitro:build-eif
```

```bash
yarn nitro:provision
```

```bash
yarn nitro:describe
```

```bash
yarn nitro:terminate
```

## 8. Meaning of Generated Files

`infra/nitro/generated/nitro-plan.json`

- Nitro plan
- Intermediate information around vault / signer / watchtower / KMS

`infra/nitro/generated/enclave.env`

- Runtime env embedded into the enclave image during the EIF build

`infra/nitro/generated/run-enclave.json`

- Configuration passed to `nitro-cli run-enclave --config ...`

`infra/nitro/generated/eif-measurements.json`

- Measured PCR values for the EIF

`infra/nitro/generated/terraform.attestation.auto.tfvars.json`

- Attestation condition values passed to Terraform

`infra/nitro/generated/client.env`

- Public information referenced by clients

## 9. Common Failure Points

### `nitro:prepare` fails with KMS

Check:

- `AWS_REGION`
- `A402_KMS_KEY_ARN`
- Whether the executing IAM principal has `kms:Encrypt`

### `nitro:build-eif` fails

Check:

- `A402_ENCLAVE_TLS_CERT_SOURCE`
- `A402_ENCLAVE_TLS_KEY_SOURCE`
- `A402_EIF_SIGNING_CERT_PATH`
- `A402_NITRO_SIGNING_PRIVATE_KEY`

### `nitro:provision` fails

Check:

- Whether `anchor deploy` has completed
- Whether `infra/nitro/generated/eif-measurements.json` exists
- Whether `ANCHOR_WALLET` is funded

### `curl https://<nlb>/v1/attestation` fails

Check:

- Whether the NLB is `TCP/443`
- Whether parent `443` is open
- Whether parent / watchtower / enclave were started in the correct order
- Whether `A402_WATCHTOWER_URL` points to `127.0.0.1:3200`

## 10. Reference Documents

- Existing Devnet repeat deployment runbook: [docs/redeploy-devnet.md](./docs/redeploy-devnet.md)
- Detailed Nitro procedure: [docs/nitro-devnet-deploy.md](./docs/nitro-devnet-deploy.md)
- Nitro template: [infra/nitro/README.md](./infra/nitro/README.md)
- Local Devnet procedure: [docs/devnet-setup.md](./docs/devnet-setup.md)
