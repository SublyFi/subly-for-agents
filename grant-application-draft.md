# Agentic Engineering Grant Application Draft

Submit here: https://superteam.fun/earn/grants/agentic-engineering

## Step 1: Basics

**Project Title**
> Subly402: Privacy-First x402 on Solana

**One Line Description**
> Subly402 lets AI agents pay x402 APIs on Solana through a Nitro-backed private vault, hiding direct buyer-to-provider payment links while keeping the standard HTTP 402 developer flow.

**TG username**
> TODO: t.me/<your_username>

**Wallet Address**
> TODO: <your Solana wallet address>

## Step 2: Details

**Project Details**
> Subly402 is a privacy-first x402 payment layer for AI agents on Solana. Standard x402 payments expose a direct on-chain buyer-to-provider payment edge, which leaks which agent paid which API, how much they paid, and how frequently they use each service. That is a bad default for agent commerce because payment history can reveal workflows, vendors, strategy, and business intelligence.
>
> The project solves this by routing x402-compatible payments through a Solana vault and an AWS Nitro Enclave facilitator. Buyers and sellers keep the familiar x402 flow: sellers protect routes with Express middleware and buyers use a fetch wrapper. Under the hood, buyers deposit into the Subly vault, the enclave verifies and reserves signed payment payloads, forwards paid requests, and settles payouts from the vault in batches so public settlement shows aggregate provider payouts instead of direct buyer-to-seller edges.
>
> The repo includes an Anchor `subly402_vault` program on Devnet, Nitro enclave and parent/watchtower services, TypeScript SDK and Express middleware packages, demo scripts comparing official x402 direct settlement against Subly402 private vault settlement, and documentation for devnet, Nitro deployment, and public architecture. Recent work adds Phase 5 Arcium accounting so per-client balances, yield, budget authorization, and owner views can move into encrypted MPC state while the TEE continues handling real-time x402 request forwarding.
>
> The end goal for this grant is to polish the public demo and developer experience: make the Subly402 seller/buyer flow repeatable, publish clear docs around attestation and privacy assumptions, stabilize Arcium budget authorization in mirror mode, and produce evidence that an agent can consume paid APIs without creating a direct public payment graph.

**Deadline**
> TODO: <target shipping deadline in Asia/Calcutta timezone>

**Proof of Work**
> GitHub repo: https://github.com/SublyFi/privacy-x402
>
> Public demo facilitator referenced in docs: https://api.demo.sublyfi.com
>
> Implemented artifacts include: Anchor vault program at `programs/subly402_vault`, Nitro enclave services in `enclave`, parent relay in `parent`, watchtower in `watchtower`, TypeScript buyer SDK in `sdk`, seller middleware in `middleware`, Subly402 and official x402 side-by-side demo scripts in `scripts/demo`, Devnet/Nitro deployment scripts in `scripts/devnet` and `scripts/nitro`, and Arcium circuit/build artifacts under `build`.
>
> Recent git history shows active implementation work: Phase 5 Arcium accounting, configurable Subly402 batch windows, package version bumps for publishing, x402-compatible Subly402 demo flows, buyer auto-deposit retry fixes, repeatable Devnet redeploy documentation, x402-compatible defaults, hardened privacy controls and attested TLS, program ID alignment, Subly402 SDK/middleware/demos, per-settlement batch privacy windows, and hardened MVP demo scripts.
>
> Documentation includes `README.md`, `docs/architecture-public.md`, `docs/demo-side-by-side.md`, `docs/quickstart.md`, `docs/devnet-setup.md`, `docs/nitro-devnet-deploy.md`, `docs/redeploy-devnet.md`, and `docs/phase5-arcium-design.md`.
>
> AI-assisted development transcript files exported to the project root: `./claude-session.jsonl` and `./codex-session.jsonl`. Attach one or both to the grant form as proof of agentic engineering work.

**Personal X Profile**
> TODO: x.com/<your_handle>

**Personal GitHub Profile**
> github.com/yukikm

**Colosseum Crowdedness Score**
> TODO: Visit https://colosseum.com/copilot, get the Crowdedness Score for Subly402 / privacy-first x402 on Solana, take a screenshot, upload it to a publicly accessible Google Drive link, and paste that link here.

**AI Session Transcript**
> Attach `./claude-session.jsonl` and/or `./codex-session.jsonl` from this project root.

## Step 3: Milestones

**Goals and Milestones**
> 1. Milestone 1: Stabilize public Subly402 demo flow. Complete the seller-host, buyer, facilitator, and Devnet setup path so a reviewer can compare official x402 direct settlement with Subly402 vault settlement end to end. Target: TODO date.
>
> 2. Milestone 2: Harden developer SDK and middleware ergonomics. Finalize buyer auto-deposit retry behavior, seller auto-registration, x402-compatible response headers, and attestation failure handling. Target: TODO date.
>
> 3. Milestone 3: Document privacy and attestation clearly. Publish concise docs explaining what is hidden, what remains public, how Nitro PCR pinning works, and how sellers can integrate without provider registration or API keys. Target: TODO date.
>
> 4. Milestone 4: Complete Phase 5 Arcium mirror-mode integration. Validate encrypted budget authorization, owner-view helpers, withdrawal/reconciliation circuit flows, and Devnet configuration scripts without making Arcium mandatory for the baseline x402 path. Target: TODO date.
>
> 5. Milestone 5: Package grant deliverables. Submit Colosseum project link, GitHub repo, AI session transcript, and a short demo recording or public instructions showing private vault settlement versus direct x402 settlement. Target: TODO final deadline.

**Primary KPI**
> One successful public Devnet demo where at least 3 paid API calls are completed through Subly402 and the public chain view shows vault-mediated settlement instead of direct buyer-to-seller settlement.

**Final tranche checkbox**
> Confirmed: to receive the final tranche, I will submit the Colosseum project link, GitHub repo, and AI subscription receipt.

## Submission Checklist

- `./claude-session.jsonl`
- `./codex-session.jsonl`
- Colosseum Crowdedness Score screenshot link
- Telegram username
- Solana wallet address
- X profile
- Target deadline in Asia/Calcutta timezone
- Copy-paste application text above

Submit here: https://superteam.fun/earn/grants/agentic-engineering
