```
Old VaultConfig: 6i5SyF8Hx2u5MZW2JgWGhdg5CJsAKeF7UaRAd9bERDDL
Old Vault ATA:   76YBLxs4EBrvbiP9RT6vH66i6qZb9b67hUdoajjqz5u

```

# A402 / Privacy First x402 on Solana

This repository implements `Privacy First x402` for public Solana Devnet deployment with AWS Nitro Enclaves.

The most important assumptions:

- `TEE is required`
- `TLS terminates inside the enclave`
- `parent instance / NLB / nginx / ALB must not see plaintext`

This README has two goals.

1. Make local preparation mostly copy-and-run commands
2. Spell out what to configure on the AWS side, down to the relevant screens

## Architecture Overview

The public topology is:

```text
Internet
  -> NLB TCP/443
  -> parent EC2 (Nitro Enclaves enabled)
  -> ingress_relay
  -> vsock
  -> a402-enclave

parent EC2
  - a402-parent
  - a402-watchtower
  - nitro-cli
  - encrypted snapshot/WAL storage
```

Responsibilities:

- `programs/a402_vault`: Solana program deployed to Devnet
- `enclave`: facilitator running inside the Nitro enclave
- `parent`: relay / KMS proxy / snapshot store on the parent instance
- `watchtower`: long-running process for stale receipt challenges

## x402-Compatible Integration Shape

After deploying the facilitator, Buyer / Seller integration can start like a normal x402 quickstart, without issuing API keys or registering providers.

The Seller only provides the protected route, price, network, and receiving wallet. On Solana, the middleware automatically derives the USDC ATA as `payTo`. `providerId` is derived from `network + assetMint + payTo`, and the enclave automatically registers it as an open seller during the first valid payment verification.

```ts
const facilitator = new Subly402FacilitatorClient({
  url: "https://<your-subly-facilitator>",
  assetMint: process.env.USDC_MINT!,
});

const resourceServer = new Subly402ResourceServer(facilitator).register(
  "solana:*",
  new Subly402ExactScheme(),
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
    resourceServer,
  ),
);
```

Buyers also do not need a Subly API key or account registration. Pass a funded signer and the Nitro attestation policy for the trusted facilitator, then wrap `fetch`.

```ts
const client = new Subly402Client({
  signer,
  network: "solana:devnet",
  trustedFacilitators: ["https://<your-subly-facilitator>"],
  autoDeposit: {
    maxDepositPerRequest: "$0.05",
    deposit: async ({ amount, details }) => {
      await depositIntoSublyVault({ amount, mint: details.asset.mint });
    },
  },
  nitroAttestation: { policy },
});

const fetchWithPayment = wrapFetchWithPayment(fetch, client);
const res = await fetchWithPayment("https://api.example.com/weather");
```

If the balance is insufficient, the Buyer SDK's `autoDeposit` hook can deposit the required amount on demand before re-signing and retrying. This preserves the same x402 experience of receiving a 402, paying, and retrying, while vault batching hides correlation with Seller payouts.

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
