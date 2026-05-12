# Devnet Redeploy Runbook

This is the repeatable deployment procedure for rolling a new Subly402 runtime into the existing `api.demo.sublyfi.com` environment.

Use this for routine code updates, not for first-time provisioning.

## Current Infrastructure

```text
Build EC2
  InstanceId: i-0b7643499a0878779
  Name: Subly402
  Repo: /root/privacy-x402

Parent EC2
  InstanceId: i-08667fcbce5825d7d
  Name: subly402-devnet-parent

Public endpoint
  https://api.demo.sublyfi.com

NLB
  subly402-devnet-nlb-a308ae25ce97c60b.elb.us-east-1.amazonaws.com

S3 release bucket
  subly402-devnet-snapshots-01
```

## 1. Enter Build EC2

From your local machine:

```bash
aws ssm start-session \
  --region us-east-1 \
  --target i-0b7643499a0878779
```

On the Build EC2:

```bash
sudo -i
export HOME=/root

source /root/.cargo/env

export NVM_DIR=/root/.nvm
source /root/.nvm/nvm.sh
nvm use 24.10.0

export PATH="/root/.local/share/solana/install/active_release/bin:$PATH"

cd /root/privacy-x402
```

Check the toolchain:

```bash
git log -1 --oneline
node --version
yarn --version
cargo --version
nitro-cli --version
docker --version
```

## 2. Update Code

```bash
git fetch origin
git checkout main
git pull --ff-only
git log -1 --oneline
```

## 3. Load Deploy Environment

```bash
source ./.env.devnet.local

export SUBLY402_PUBLIC_ENCLAVE_URL="https://api.demo.sublyfi.com"
export SUBLY402_REQUEST_ORIGIN="https://demo.sublyfi.com"
export SUBLY402_NITRO_PROJECT_NAME="subly402-devnet"

export SUBLY402_ENABLE_PROVIDER_REGISTRATION_API="0"
export SUBLY402_ENABLE_ADMIN_API="0"
export SUBLY402_ALLOW_ADMIN_PRIVACY_BYPASS_BATCH="0"

export DEPLOY_BUCKET="subly402-devnet-snapshots-01"
```

Use the next vault id for a new EIF/policy. The current public deployment uses vault id `6`, so this command selects the next id from the previous build state and falls back to `7` for this devnet environment.

```bash
export SUBLY402_VAULT_ID="$(node -e 'const fs=require("fs"); const p="infra/nitro/generated/nitro-state.json"; const id=fs.existsSync(p)?BigInt(JSON.parse(fs.readFileSync(p,"utf8")).vaultId)+1n:7n; console.log(id.toString())')"
echo "SUBLY402_VAULT_ID=${SUBLY402_VAULT_ID}"
```

## 4. Build and Test

```bash
yarn install --frozen-lockfile

npm --prefix middleware run build
npm --prefix sdk run build

npx ts-mocha --exit tests/middleware_raw_body.ts tests/subly402_interface.ts

cargo test -p subly402-enclave verify_and_settle_auto_register_open_provider_without_auth_headers
```

Build parent and watchtower release binaries:

```bash
NO_DNA=1 cargo build --release \
  -p subly402-parent \
  -p subly402-watchtower
```

## 5. Generate Nitro Artifacts

Run these in order. If `nitro:prepare` fails, stop and fix it before continuing. Do not run `nitro:build-eif` after a failed prepare because it can reuse stale generated env files.

```bash
yarn nitro:prepare
yarn nitro:build-eif
yarn nitro:provision
```

Check the generated public values:

```bash
cat infra/nitro/generated/client.env
cat infra/nitro/generated/attestation-policy.hash
ls -lh infra/nitro/generated/subly402-enclave.eif
```

If `nitro:provision` fails with `on-chain attestation policy hash mismatch`, choose a new unused vault id and repeat from `nitro:prepare`:

```bash
export SUBLY402_VAULT_ID="$((SUBLY402_VAULT_ID + 1))"
echo "SUBLY402_VAULT_ID=${SUBLY402_VAULT_ID}"
yarn nitro:prepare
yarn nitro:build-eif
yarn nitro:provision
```

## 6. Apply Terraform

This updates KMS attestation policy for the newly built EIF PCRs.

```bash
cd /root/privacy-x402/infra/nitro/terraform

terraform init

terraform apply \
  -var-file=../generated/terraform.attestation.auto.tfvars.json \
  -var="existing_runtime_kms_key_arn=$SUBLY402_KMS_KEY_ARN" \
  -var='aws_region=us-east-1' \
  -var='vpc_id=vpc-0660d9d5956dd5153' \
  -var='nlb_subnet_ids=["subnet-04520a16ec89ae9b4","subnet-0ca4d90d94eaac91d"]' \
  -var='instance_subnet_id=subnet-04520a16ec89ae9b4' \
  -var='ami_id=ami-098e39bafa7e7303d' \
  -var='snapshot_bucket_name=subly402-devnet-snapshots-01'

cd /root/privacy-x402
```

## 7. Package Runtime on Build EC2

```bash
export RELEASE_ID="$(git rev-parse --short HEAD)-$(date -u +%Y%m%dT%H%M%SZ)"
export S3_PREFIX="releases/subly402/${RELEASE_ID}"

rm -rf .deploy/subly402-runtime
mkdir -p \
  .deploy/subly402-runtime/bin \
  .deploy/subly402-runtime/enclave \
  .deploy/subly402-runtime/etc \
  .deploy/subly402-runtime/scripts

cp target/release/subly402-parent .deploy/subly402-runtime/bin/
cp target/release/subly402-watchtower .deploy/subly402-runtime/bin/
cp infra/nitro/generated/subly402-enclave.eif .deploy/subly402-runtime/enclave/
cp infra/nitro/generated/parent.env .deploy/subly402-runtime/etc/
cp infra/nitro/generated/watchtower.env .deploy/subly402-runtime/etc/
cp infra/nitro/generated/run-enclave.json .deploy/subly402-runtime/etc/
cp infra/nitro/generated/client.env .deploy/subly402-runtime/etc/
cp scripts/nitro/start-parent.sh .deploy/subly402-runtime/scripts/
cp scripts/nitro/start-watchtower.sh .deploy/subly402-runtime/scripts/
cp scripts/nitro/run-enclave.sh .deploy/subly402-runtime/scripts/

tar -C .deploy/subly402-runtime -czf ".deploy/subly402-runtime.tgz" .
(cd .deploy && sha256sum "subly402-runtime.tgz" > "subly402-runtime.tgz.sha256")
printf '%s\n' "${RELEASE_ID}" > .deploy/latest-release.txt
```

Upload the release to S3:

```bash
aws s3 cp ".deploy/subly402-runtime.tgz" \
  "s3://${DEPLOY_BUCKET}/${S3_PREFIX}/subly402-runtime.tgz" \
  --sse aws:kms \
  --sse-kms-key-id "$SUBLY402_KMS_KEY_ARN"

aws s3 cp ".deploy/subly402-runtime.tgz.sha256" \
  "s3://${DEPLOY_BUCKET}/${S3_PREFIX}/subly402-runtime.tgz.sha256" \
  --sse aws:kms \
  --sse-kms-key-id "$SUBLY402_KMS_KEY_ARN"

aws s3 cp infra/nitro/generated/client.env \
  "s3://${DEPLOY_BUCKET}/${S3_PREFIX}/client.env" \
  --sse aws:kms \
  --sse-kms-key-id "$SUBLY402_KMS_KEY_ARN"

aws s3 cp .deploy/latest-release.txt \
  "s3://${DEPLOY_BUCKET}/releases/subly402/latest-release.txt" \
  --sse aws:kms \
  --sse-kms-key-id "$SUBLY402_KMS_KEY_ARN"

echo "RELEASE_ID=${RELEASE_ID}"
echo "s3://${DEPLOY_BUCKET}/${S3_PREFIX}/subly402-runtime.tgz"
aws s3 ls "s3://${DEPLOY_BUCKET}/${S3_PREFIX}/"
```

The upload also updates `s3://${DEPLOY_BUCKET}/releases/subly402/latest-release.txt`, which the Parent EC2 step reads.

## 8. Enter Parent EC2

From your local machine:

```bash
aws ssm start-session \
  --region us-east-1 \
  --target i-08667fcbce5825d7d
```

On the Parent EC2:

```bash
sudo -i
```

## 9. Download Release on Parent EC2

```bash
export DEPLOY_BUCKET="subly402-devnet-snapshots-01"
export RELEASE_ID="$(aws s3 cp "s3://${DEPLOY_BUCKET}/releases/subly402/latest-release.txt" - | tr -d '[:space:]')"
export S3_PREFIX="releases/subly402/${RELEASE_ID}"
echo "RELEASE_ID=${RELEASE_ID}"

mkdir -p /tmp/subly402-deploy
cd /tmp/subly402-deploy

aws s3 cp "s3://${DEPLOY_BUCKET}/${S3_PREFIX}/subly402-runtime.tgz" .
aws s3 cp "s3://${DEPLOY_BUCKET}/${S3_PREFIX}/subly402-runtime.tgz.sha256" .

sha256sum -c subly402-runtime.tgz.sha256
```

Extract:

```bash
rm -rf runtime
mkdir runtime
tar -C runtime -xzf subly402-runtime.tgz
```

Confirm the release values before installing:

```bash
grep -E 'VAULT_CONFIG|USDC_MINT|ATTESTATION_POLICY_HASH|PUBLIC_ENCLAVE_URL' runtime/etc/client.env
ls -lh runtime/enclave/subly402-enclave.eif
```

## 10. Stop, Install, and Start Runtime

Run this as root on the Parent EC2.

```bash
systemctl stop subly402-parent subly402-watchtower || true
nitro-cli terminate-enclave --all || true

mkdir -p /opt/subly402/bin /opt/subly402/enclave /etc/subly402

install -m 0755 runtime/bin/subly402-parent /opt/subly402/bin/subly402-parent
install -m 0755 runtime/bin/subly402-watchtower /opt/subly402/bin/subly402-watchtower
install -m 0755 runtime/scripts/start-parent.sh /opt/subly402/bin/start-parent.sh
install -m 0755 runtime/scripts/start-watchtower.sh /opt/subly402/bin/start-watchtower.sh
install -m 0755 runtime/scripts/run-enclave.sh /opt/subly402/bin/run-enclave.sh

install -m 0644 runtime/enclave/subly402-enclave.eif /opt/subly402/enclave/subly402-enclave.eif

install -o subly402 -g subly402 -m 0600 runtime/etc/parent.env /etc/subly402/parent.env
install -o subly402 -g subly402 -m 0600 runtime/etc/watchtower.env /etc/subly402/watchtower.env
install -m 0644 runtime/etc/run-enclave.json /etc/subly402/run-enclave.json
install -m 0644 runtime/etc/client.env /etc/subly402/client.env

NO_DNA=1 nitro-cli describe-eif \
  --eif-path /opt/subly402/enclave/subly402-enclave.eif | grep -E 'PCR0|PCR1|PCR2|PCR8'

systemctl start subly402-watchtower
systemctl start subly402-parent

NO_DNA=1 nitro-cli run-enclave --config /etc/subly402/run-enclave.json
```

Check service state:

```bash
systemctl status subly402-watchtower --no-pager
systemctl status subly402-parent --no-pager
NO_DNA=1 nitro-cli describe-enclaves
```

## 11. Verify Public Endpoint

From your local machine:

```bash
curl -sS https://api.demo.sublyfi.com/v1/attestation | jq '{
  vaultConfig,
  vaultSigner,
  attestationPolicyHash,
  snapshotSeqno,
  issuedAt,
  expiresAt
}'
```

The returned `vaultConfig` and `attestationPolicyHash` must match `/etc/subly402/client.env` on the Parent EC2 and `infra/nitro/generated/client.env` from the Build EC2.

On Parent EC2:

```bash
grep ATTESTATION_POLICY_HASH /etc/subly402/client.env
curl -sS https://api.demo.sublyfi.com/v1/attestation | jq -r .attestationPolicyHash
```

## Common Failures

### `nitro:prepare` asks for `SUBLY402_ADMIN_AUTH_TOKEN`

Control-plane APIs are enabled. For public registrationless runtime, set these to `0` in `.env.devnet.local` or export them before running prepare:

```bash
export SUBLY402_ENABLE_PROVIDER_REGISTRATION_API="0"
export SUBLY402_ENABLE_ADMIN_API="0"
export SUBLY402_ALLOW_ADMIN_PRIVACY_BYPASS_BATCH="0"
```

Then rerun from `yarn nitro:prepare`.

### `on-chain attestation policy hash mismatch`

The selected `SUBLY402_VAULT_ID` already exists with a different policy hash. Pick a new vault id and rerun from prepare:

```bash
export SUBLY402_VAULT_ID="$((SUBLY402_VAULT_ID + 1))"
echo "SUBLY402_VAULT_ID=${SUBLY402_VAULT_ID}"
yarn nitro:prepare
yarn nitro:build-eif
yarn nitro:provision
```

### `systemctl ... Access denied` or `/dev/nitro_enclaves` open failure

You are not root on the Parent EC2. Run:

```bash
sudo -i
```

Then retry the stop/install/start commands.

### Public endpoint still returns the old vault

Check that the Parent EC2 actually received the new runtime:

```bash
grep -E 'VAULT_CONFIG|ATTESTATION_POLICY_HASH' /etc/subly402/client.env
ls -lh /opt/subly402/enclave/subly402-enclave.eif
cat /etc/subly402/run-enclave.json
```

If `/etc/subly402/client.env` is missing or stale, repeat the install step from `/tmp/subly402-deploy/runtime`.
