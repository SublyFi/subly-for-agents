# Nitro Rollout

This directory is the template for deploying A402 to a public Devnet environment on AWS Nitro Enclaves.

For the shortest path, see [`docs/nitro-devnet-deploy.md`](../../docs/nitro-devnet-deploy.md).

Included components:

- `terraform/`: skeleton for parent EC2 / NLB / IAM / KMS / snapshot bucket
- `env/`: env templates for `parent` and `watchtower`
- `systemd/`: long-running parent / watchtower units
- `enclave/`: Dockerfile and entrypoint for EIF builds

Added automation:

- `yarn nitro:prepare`: generates the vault signer ciphertext and runtime env
- `yarn nitro:build-eif`: builds the EIF and outputs measurements
- `yarn nitro:provision`: materializes the policy hash from PCRs and runs on-chain initialization

Prerequisites:

- The Solana program is already deployed to Devnet
- `a402-parent`, `a402-watchtower`, and `a402-enclave` can be built
- The enclave EIF is built separately
- AWS-side VPC / subnet / AMI values are filled in for your environment

Procedure:

1. Create `terraform.tfvars` in `infra/nitro/terraform`
2. Run `terraform init && terraform apply` to create EC2 / NLB / KMS / S3
3. Place `a402-parent`, `a402-watchtower`, and the EIF on the generated parent EC2
4. Copy `env/*.example` to `/etc/a402/*.env` and fill in the values
5. Place `systemd/*.service` in `/etc/systemd/system/` and run `systemctl enable --now`
6. Start the EIF with Nitro and connect with `A402_PARENT_INTERCONNECT_MODE=vsock` / `A402_ENCLAVE_INTERCONNECT_MODE=vsock`

Important:

- In this turn, `ingress`, `KMS`, and `snapshot_store` were made compatible with both `tcp(dev)` and `vsock(prod)`
- Enclave outbound HTTP / HTTPS / Solana RPC traffic exits through `parent egress_relay`
- The Nitro attestation document for bootstrap is generated from NSM inside the enclave and used for KMS decrypt / data key retrieval
- `deposit_detector` monitors the vault token account with `logsSubscribe(finalized)` and catches up after disconnects
- In production, set `A402_EGRESS_ALLOWLIST` to restrict the parent relay destinations

Remaining tasks before the public URL is live:

1. Pin `A402_EGRESS_ALLOWLIST` and AWS-side egress controls to production values
2. Move EIF build and PCR measurement into CI or a build script
3. Bind the KMS key policy to the actual PCRs
