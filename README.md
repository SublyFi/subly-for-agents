# Subly update video since our hackathon submission
https://www.loom.com/share/34b86a80e1344d898805f5e09a0c5f0b

# New Repo
https://github.com/SublyFi/subly-payment-protocol

# Subly402

Privacy-first x402 payments for Solana agents.

Subly402 lets an agent call a paid HTTP API, receive a normal `402 Payment Required` response, and pay with USDC on Solana without creating a direct public buyer-to-provider payment edge. Buyers deposit into a shared Solana vault, a Nitro Enclave facilitator verifies x402-style payment payloads, and providers receive batched vault payouts instead of direct transfers from each buyer.

The next release track turns the vault into an Arcium-backed yield vault. Client balances, yield, and authorization state move toward encrypted MPC accounting while the Nitro facilitator keeps the real-time x402 request path fast. That work lives on `feature/arcium`; `main` stays the stable Devnet/Nitro payment entry point.

What to evaluate:

- Working Devnet x402 flow with published buyer SDK and seller middleware.
- Privacy improvement: no direct buyer-to-provider token transfer for paid API calls.
- Next track: Arcium-backed yield vault for encrypted accounting and mainnet readiness.

## Links

| Item                  | Link                                                                 |
| --------------------- | -------------------------------------------------------------------- |
| Demo site             | https://www.sublyfi.com/                                             |
| Public facilitator    | `https://api.demo.sublyfi.com`                                       |
| Pitch video           | [Loom](https://www.loom.com/share/f2d2482a73824ff9abe1de0186a355f7)  |
| Demo video            | [Loom](https://www.loom.com/share/8ae7523608b34d88abc2aae3a5b5b031)  |
| Project X             | https://x.com/subly_fi                                               |
| Buyer SDK             | [`subly402-sdk`](https://www.npmjs.com/package/subly402-sdk)         |
| Seller middleware     | [`subly402-express`](https://www.npmjs.com/package/subly402-express) |
| Arcium/mainnet branch | `feature/arcium`                                                     |

Published NPM packages currently cover the Devnet/Nitro x402 flow. Arcium SDK helpers are implemented on `feature/arcium` for the next package release.

## Why It Exists

Direct x402 payments are simple, but Solana token transfers are public. If an agent pays APIs directly from its wallet, observers can infer which providers it uses, how often it calls them, and what its workflow costs. That can leak strategy, vendors, usage patterns, and budget.

Subly keeps the x402 developer experience and changes the settlement graph:

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
- `enclave`: Nitro Enclave facilitator that verifies payment payloads, manages balances, forwards paid requests, signs receipts, encrypts audit data, and builds batched settlement.
- `parent`: untrusted EC2-side relay, KMS proxy, and encrypted snapshot/WAL storage. It forwards traffic but must not terminate TLS.
- `watchtower`: receipt recovery and force-settlement support for enclave outage scenarios.
- `sdk`: buyer SDK published as `subly402-sdk`.
- `middleware`: Express seller middleware published as `subly402-express`.
- `scripts/demo`: side-by-side demos comparing direct x402 settlement with Subly vault settlement.
- On `feature/arcium`: Arcium circuits and SDK helpers for encrypted per-client accounting, yield state, and budget grants.

## Architecture

```text
Buyer / agent
  -> paid API request
  -> provider returns HTTP 402
  -> subly402-sdk verifies facilitator attestation
  -> buyer signs payment payload
  -> provider settles through subly402-express
  -> Nitro Enclave reserves balance and forwards the request
  -> vault batches provider payouts on Solana
```

Public Devnet topology:

```text
Internet
  -> NLB TCP/443
  -> parent EC2 with Nitro Enclaves enabled
  -> ingress relay
  -> vsock
  -> Subly402 Nitro Enclave
```

Security assumptions:

- TLS terminates inside the Nitro Enclave.
- The parent instance, NLB, nginx, or ALB must not see plaintext request or payment data.
- KMS access is conditioned on Nitro attestation measurements.
- Buyers should pin the facilitator's attestation policy before paying.

## Privacy Model

| Data                              | On-chain visibility                                                         | Trusted component              |
| --------------------------------- | --------------------------------------------------------------------------- | ------------------------------ |
| Buyer deposit into vault          | Visible                                                                     | Solana vault                   |
| Individual buyer-to-provider edge | Hidden                                                                      | Nitro Enclave                  |
| Per-request amount                | Hidden in batched settlement                                                | Nitro Enclave                  |
| Provider aggregate payout         | Visible                                                                     | Solana vault                   |
| Buyer private balance             | Hidden on-chain today; moving to Arcium encrypted state on `feature/arcium` | Nitro today, Arcium track next |
| Audit trail                       | Encrypted records                                                           | Authorized disclosure keys     |

This is not deposit privacy. The anonymity set starts with the vault depositors, and provider payouts remain public at aggregate granularity.

## Arcium And Mainnet Track

`feature/arcium` is the active branch for Arcium integration and mainnet release preparation. It keeps the Devnet/Nitro payment path working while adding:

- `ClientVaultState`, `DepositCredit`, `BudgetGrant`, and `WithdrawalGrant` flows.
- `Enc<Mxe>` state for balances, yield, and grant state.
- `Enc<Shared>` grant outputs for the attested enclave key.
- Arcium computation definition initialization, smoke tests, and state sync scripts.
- Mainnet hardening around attestation pinning, recovery paths, batch policy, NPM package UX, and deployment repeatability.

The Nitro Enclave still handles real-time HTTP request forwarding in this phase. Arcium is used for encrypted money-at-rest accounting and budget authorization.

## Devnet Addresses

Current public Devnet deployment:

| Item                | Address                                                                                                                                           |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Program ID          | [`3iusaL6ys79DsbpweDwGhHvtjdnhAhtpyczPtMbu5Mbe`](https://explorer.solana.com/address/3iusaL6ys79DsbpweDwGhHvtjdnhAhtpyczPtMbu5Mbe?cluster=devnet) |
| VaultConfig         | [`EGJVg1tw3NJQj34Wk1vqSSbXEPd3CaYzmrAzWLwrcm3A`](https://explorer.solana.com/address/EGJVg1tw3NJQj34Wk1vqSSbXEPd3CaYzmrAzWLwrcm3A?cluster=devnet) |
| Vault token account | [`41E84Z5PVYCWvZKLcN3vWn7fDku793aTB7pfpyrhCg98`](https://explorer.solana.com/address/41E84Z5PVYCWvZKLcN3vWn7fDku793aTB7pfpyrhCg98?cluster=devnet) |
| Vault signer        | `4YDcz8mRMGPhZbFiL1RTmXhYNUx7jDsYcU9y5oB9bE2N`                                                                                                    |
| Devnet USDC mint    | [`3sJgMz6NUf7zmsNfsgnJH6KKWxQaVkz8frAyKnEMAHy2`](https://explorer.solana.com/address/3sJgMz6NUf7zmsNfsgnJH6KKWxQaVkz8frAyKnEMAHy2?cluster=devnet) |
| Public facilitator  | `https://api.demo.sublyfi.com`                                                                                                                    |

Previous Devnet vault:

| Item                          | Address                                        |
| ----------------------------- | ---------------------------------------------- |
| Old VaultConfig               | `6i5SyF8Hx2u5MZW2JgWGhdg5CJsAKeF7UaRAd9bERDDL` |
| Old Vault token account / ATA | `76YBLxs4EBrvbiP9RT6vH66i6qZb9b67hUdoajjqz5u`  |

Verify the current deployment:

```bash
solana program show 3iusaL6ys79DsbpweDwGhHvtjdnhAhtpyczPtMbu5Mbe --url devnet
curl -s https://api.demo.sublyfi.com/v1/attestation | jq .
```

## Try The Demo

Create `.env.devnet.local` with a funded Devnet wallet and RPC endpoint:

```bash
export SUBLY402_SOLANA_RPC_URL="https://<your-devnet-rpc>"
export SUBLY402_SOLANA_WS_URL="wss://<your-devnet-ws>"
export ANCHOR_PROVIDER_URL="$SUBLY402_SOLANA_RPC_URL"
export ANCHOR_WALLET="$HOME/.config/solana/<wallet>.json"
```

Build, deploy, bootstrap, and start the local facilitator/watchtower:

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

Run direct x402 in two terminals:

```bash
yarn demo:x402-seller
yarn demo:x402-buyer
```

Run Subly private-vault settlement in two terminals:

```bash
yarn demo:subly-seller
yarn demo:subly-buyer
```

Expected public chain difference:

- Direct x402: buyer token account pays the seller token account directly.
- Subly402: buyer token account deposits into the Subly vault; the seller receives a later vault payout after batching.

See [docs/demo-side-by-side.md](./docs/demo-side-by-side.md) and [docs/devnet-setup.md](./docs/devnet-setup.md) for the full local Devnet flow.

## SDK And Middleware

Install the released packages:

```bash
yarn add subly402-sdk subly402-express express
```

Seller shape:

```ts
const facilitator = new Subly402FacilitatorClient({
  url: "https://api.demo.sublyfi.com",
  assetMint: process.env.SUBLY402_USDC_MINT!,
});

const resourceServer = new Subly402ResourceServer(facilitator).register(
  "solana:devnet",
  new Subly402ExactScheme()
);

app.use(paymentMiddleware(routes, resourceServer));
```

Buyer shape:

```ts
const client = new Subly402Client({
  signer,
  network: "solana:devnet",
  trustedFacilitators: ["https://api.demo.sublyfi.com"],
  autoDeposit,
  nitroAttestation: { policy },
});

const fetchWithPayment = wrapFetchWithPayment(fetch, client);
const res = await fetchWithPayment("https://api.example.com/weather");
```

No Subly API key or provider pre-registration is required for the default flow. Sellers provide a wallet owner; the middleware derives the USDC associated token account and uses `network + assetMint + payTo` as the open seller identity.

For complete code, see [docs/quickstart.md](./docs/quickstart.md), [middleware/README.md](./middleware/README.md), and [sdk/README.md](./sdk/README.md).

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

## Operations Docs

README stays short; operational runbooks live in docs:

Some operational files still use historical `A402_` names, but the public project, NPM packages, and integration surface are Subly402.

- First Nitro Devnet deployment: [docs/nitro-devnet-deploy.md](./docs/nitro-devnet-deploy.md)
- Routine redeploys to `api.demo.sublyfi.com`: [docs/redeploy-devnet.md](./docs/redeploy-devnet.md)
- Local Devnet setup: [docs/devnet-setup.md](./docs/devnet-setup.md)
- Public architecture diagrams: [docs/architecture-public.md](./docs/architecture-public.md)
- Protocol details: [docs/a402-svm-v1-protocol.md](./docs/a402-svm-v1-protocol.md)
- Nitro infrastructure template: [infra/nitro/README.md](./infra/nitro/README.md)
