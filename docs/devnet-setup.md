# Devnet Setup

Local Devnet settings live in `.env.devnet.local`, which is ignored by git.

## One-time RPC setup

```bash
source ./.env.devnet.local
solana config set --url "$A402_SOLANA_RPC_URL" --ws "$A402_SOLANA_WS_URL" --keypair "$ANCHOR_WALLET"
```

## Deploy the program

```bash
NO_DNA=1 anchor build
NO_DNA=1 anchor deploy \
  --provider.cluster "$A402_SOLANA_RPC_URL" \
  --provider.wallet "$ANCHOR_WALLET"
```

## Bootstrap the vault

This creates a Devnet USDC mint if needed, derives the vault PDAs, initializes
the on-chain vault, and writes reusable runtime values to:

- `data/devnet-state.json`
- `.env.devnet.generated`

```bash
yarn devnet:bootstrap
```

## Start local watchtower + enclave against Devnet

```bash
yarn devnet:start
```

## Configure Arcium and pin MXE key

After deploying the MXE with `arcium deploy`, set the Arcium deployment env in
`.env.devnet.local`, initialize the Subly computation definitions, and pin the
Arcium config:

```bash
yarn devnet:arcium-init-comp-defs
```

The comp definition script distinguishes `completed` from `pending_upload`.
Arcium computations can only be queued after the raw circuit is uploaded and the
definition is finalized. Upload one or more circuits explicitly:

```bash
SUBLY402_ARCIUM_COMP_DEF_NAMES=init_agent_vault \
SUBLY402_ARCIUM_UPLOAD_CIRCUITS=1 \
SUBLY402_ARCIUM_UPLOAD_CHUNK_SIZE=1 \
SUBLY402_ARCIUM_UPLOAD_DELAY_MS=100 \
yarn devnet:arcium-init-comp-defs
```

Large circuits are expensive on devnet because raw circuit accounts are rent
exempt and uploads are split into 814-byte transactions. Check rent before
uploading:

```bash
solana rent $(( $(wc -c < build/authorize_budget.arcis) + 9 ))
```

```bash
yarn devnet:arcium-config
```

This initializes or checks `ArciumConfig`, stores the decoded Arcium state in
`data/devnet-state.json`, and writes `SUBLY402_ARCIUM_MXE_PUBLIC_KEY_HEX` to
`.env.devnet.generated` so the enclave can reject grant ciphertexts that were
not encrypted by the expected MXE key. It also pins the expected
`authorize_budget` / `authorize_withdrawal` domain hash parts in
`.env.devnet.generated`, so the enclave validates encrypted grants against the
current Arcium deployment instead of trusting request-supplied hashes. Restart
the enclave after changing these values.

If this change is deployed onto an existing devnet vault, close/recreate pending
`WithdrawalGrant` accounts first because the account layout now includes
`stateVersionAtAuthorization`.

If an existing `ArciumConfig` points to old MXE/cluster/mempool values, redeploy
the program with `update_arcium_deployment`, update `.env.devnet.local`, then
run:

```bash
SUBLY402_ARCIUM_ALLOW_CONFIG_ROTATION=1 yarn devnet:arcium-config
```

To load ready Arcium grant ciphertexts into the enclave cache:

```bash
yarn devnet:arcium-sync
```

To run the Arcium on-chain smoke path:

```bash
yarn devnet:arcium-smoke
```

For partial verification while only some circuits are uploaded:

```bash
SUBLY402_ARCIUM_SMOKE_UNTIL=init_agent_vault yarn devnet:arcium-smoke
```

## Check status

```bash
yarn devnet:status
```

## Run an end-to-end smoke test

This executes:

- client funding
- mint to client ATA
- on-chain `deposit`
- authenticated `provider/register`
- `verify`
- `settle`
- authenticated `fire-batch`

Set `SUBLY402_ADMIN_AUTH_TOKEN` in `.env.devnet.local` when
`SUBLY402_ENABLE_PROVIDER_REGISTRATION_API=1` or `SUBLY402_ENABLE_ADMIN_API=1`.
Single-provider smoke tests that need immediate on-chain payout must also set
`SUBLY402_ALLOW_ADMIN_PRIVACY_BYPASS_BATCH=1`; keep it unset or `0` for public
runtime.

```bash
yarn devnet:smoke
```

## Stop local processes

```bash
yarn devnet:stop
```
