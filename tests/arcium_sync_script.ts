import { expect } from "chai";
import { createRequire } from "module";

import BN from "bn.js";
import { Keypair, PublicKey } from "@solana/web3.js";

const requireFromTest = createRequire(
  `${process.cwd()}/tests/arcium_sync_script.ts`
);
const {
  budgetGrantLoadRequestFromAccount,
  computeArciumDomainHashParts,
  stringifyJsonExact,
  withdrawalGrantLoadRequestFromAccount,
} = requireFromTest("../scripts/devnet/arcium-sync");

const VAULT_CONFIG = new PublicKey("11111111111111111111111111111112");
const PROGRAM_ID = new PublicKey(
  "Arcj82pX7HxYKLR92qvgZUAd7vGS1k4hQvAFcPATFdEQ"
);
const ARCIUM_PROGRAM_ID = new PublicKey("11111111111111111111111111111115");
const MXE_ACCOUNT = new PublicKey("11111111111111111111111111111116");
const USDC_MINT = new PublicKey("11111111111111111111111111111117");
const TEE_PUBLIC_KEY = new Array(32).fill(7);
const MXE_PUBLIC_KEY = new Array(32).fill(8);

function fakeCiphertexts(count: number): number[][] {
  return Array.from({ length: count }, (_item, index) =>
    new Array(32).fill(index)
  );
}

function publicKeyLike(pubkey: PublicKey): { toBase58: () => string } {
  return { toBase58: () => pubkey.toBase58() };
}

describe("arcium devnet sync script", () => {
  it("builds encrypted enclave budget grant load requests from Arcium accounts", () => {
    const budgetGrant = Keypair.generate().publicKey;
    const client = Keypair.generate().publicKey;
    const request = budgetGrantLoadRequestFromAccount(
      {
        publicKey: budgetGrant,
        account: {
          vaultConfig: VAULT_CONFIG,
          clientVaultState: Keypair.generate().publicKey,
          client,
          budgetId: new BN(7),
          requestNonce: new BN(8),
          status: 1,
          expiresAt: new BN(1_800_000_000),
          stateVersionAtAuthorization: new BN(2),
          grantCiphertexts: fakeCiphertexts(15),
          grantNonce: new Array(16).fill(4),
        },
      },
      {
        expectedDomainHash: { lo: 11n, hi: 12n },
        teeX25519Pubkey: TEE_PUBLIC_KEY,
        mxePublicKey: MXE_PUBLIC_KEY,
      }
    );

    expect(request).to.deep.equal({
      grantId: budgetGrant.toBase58(),
      vaultConfig: VAULT_CONFIG.toBase58(),
      client: client.toBase58(),
      budgetId: 7n,
      requestNonce: 8n,
      expiresAt: 1_800_000_000n,
      stateVersionAtAuthorization: 2n,
      domainHashLo: 11n,
      domainHashHi: 12n,
      teeX25519Pubkey: TEE_PUBLIC_KEY,
      mxePublicKey: MXE_PUBLIC_KEY,
      grantCiphertexts: fakeCiphertexts(15),
      grantNonce: new Array(16).fill(4),
    });
  });

  it("builds encrypted enclave withdrawal grant load requests from Arcium accounts", () => {
    const withdrawalGrant = Keypair.generate().publicKey;
    const client = Keypair.generate().publicKey;
    const recipientAta = Keypair.generate().publicKey;
    const request = withdrawalGrantLoadRequestFromAccount(
      {
        publicKey: withdrawalGrant,
        account: {
          vaultConfig: VAULT_CONFIG,
          clientVaultState: Keypair.generate().publicKey,
          client,
          withdrawalId: new BN(10),
          status: 1,
          recipientAta,
          expiresAt: new BN(1_800_000_100),
          stateVersionAtAuthorization: new BN(3),
          grantCiphertexts: fakeCiphertexts(15),
          grantNonce: new Array(16).fill(5),
        },
      },
      {
        expectedDomainHash: { lo: 21n, hi: 22n },
        teeX25519Pubkey: TEE_PUBLIC_KEY,
        mxePublicKey: MXE_PUBLIC_KEY,
      }
    );

    expect(request).to.deep.equal({
      grantId: withdrawalGrant.toBase58(),
      vaultConfig: VAULT_CONFIG.toBase58(),
      client: client.toBase58(),
      withdrawalId: 10n,
      recipientAta: recipientAta.toBase58(),
      expiresAt: 1_800_000_100n,
      stateVersionAtAuthorization: 3n,
      domainHashLo: 21n,
      domainHashHi: 22n,
      teeX25519Pubkey: TEE_PUBLIC_KEY,
      mxePublicKey: MXE_PUBLIC_KEY,
      grantCiphertexts: fakeCiphertexts(15),
      grantNonce: new Array(16).fill(5),
      consumed: false,
    });
  });

  it("serializes u64 BigInt fields as exact JSON numbers for enclave admin APIs", () => {
    expect(
      stringifyJsonExact({
        amount: 18_446_744_073_709_551_615n,
        nested: [1n, "ok"],
      })
    ).to.equal('{"amount":18446744073709551615,"nested":[1,"ok"]}');
  });

  it("matches the on-chain Arcium domain hash preimage", () => {
    const common = {
      programId: PROGRAM_ID,
      vaultConfig: VAULT_CONFIG,
      vaultConfigAccount: { usdcMint: USDC_MINT },
      arciumConfigAccount: {
        arciumProgramId: ARCIUM_PROGRAM_ID,
        mxeAccount: MXE_ACCOUNT,
        teeX25519Pubkey: TEE_PUBLIC_KEY,
        attestationPolicyHash: new Array(32).fill(8),
        compDefVersion: 3,
      },
    };

    const first = computeArciumDomainHashParts({
      ...common,
      instructionKind: "authorize_budget",
    });
    const fromPublicKeyLikes = computeArciumDomainHashParts({
      instructionKind: "authorize_budget",
      programId: publicKeyLike(PROGRAM_ID),
      vaultConfig: publicKeyLike(VAULT_CONFIG),
      vaultConfigAccount: { usdcMint: publicKeyLike(USDC_MINT) },
      arciumConfigAccount: {
        arciumProgramId: publicKeyLike(ARCIUM_PROGRAM_ID),
        mxeAccount: publicKeyLike(MXE_ACCOUNT),
        teeX25519Pubkey: TEE_PUBLIC_KEY,
        attestationPolicyHash: new Array(32).fill(8),
        compDefVersion: 3,
      },
    });
    const second = computeArciumDomainHashParts({
      ...common,
      instructionKind: "authorize_budget",
    });
    const different = computeArciumDomainHashParts({
      ...common,
      instructionKind: "authorize_withdrawal",
    });

    expect(second).to.deep.equal(first);
    expect(fromPublicKeyLikes).to.deep.equal(first);
    expect(different).not.to.deep.equal(first);
  });
});
