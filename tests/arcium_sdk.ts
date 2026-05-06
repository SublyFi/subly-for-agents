import { expect } from "chai";
import { createHash } from "crypto";

import { x25519 } from "@arcium-hq/client";

import {
  assertArciumNodeRuntime,
  createArciumSharedCipher,
  decryptArciumAgentVaultView,
  decryptArciumBudgetGrantView,
  decryptArciumWithdrawalGrantView,
  decryptArciumScalars,
  deriveArciumX25519Keypair,
  encryptArciumBudgetRequest,
  encryptArciumReconcileReport,
  encryptArciumWithdrawalReport,
  encryptArciumWithdrawalRequest,
  splitU256Le,
} from "../sdk/src/arcium";

function fakeSignature(message: Uint8Array): Uint8Array {
  return createHash("sha256")
    .update("test-wallet-signature")
    .update(Buffer.from(message))
    .digest();
}

const PROGRAM_ID = "3iusaL6ys79DsbpweDwGhHvtjdnhAhtpyczPtMbu5Mbe";
const VAULT_CONFIG = "11111111111111111111111111111112";
const DERIVATION_SCOPE = "subly402:test:owner-view:v1";
const CLIENT_ADDRESS = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWkYkF8nzWFSS1t";

describe("arcium sdk helpers", () => {
  it("rejects unsupported Node runtimes for the Arcium subpath", () => {
    expect(() => assertArciumNodeRuntime("20.18.0")).not.to.throw();
    expect(() => assertArciumNodeRuntime("21.0.0")).not.to.throw();
    expect(() => assertArciumNodeRuntime("20.17.9")).to.throw(
      "requires Node.js >=20.18.0"
    );
    expect(() => assertArciumNodeRuntime("not-a-version")).to.throw(
      "requires Node.js >=20.18.0"
    );
  });

  it("derives stable recoverable x25519 keys from a wallet signature", async () => {
    const signer = {
      publicKey: CLIENT_ADDRESS,
      signMessage: fakeSignature,
    };

    const first = await deriveArciumX25519Keypair(signer, {
      programId: PROGRAM_ID,
      vaultConfig: VAULT_CONFIG,
      derivationScope: DERIVATION_SCOPE,
    });
    const second = await deriveArciumX25519Keypair(signer, {
      programId: PROGRAM_ID,
      vaultConfig: VAULT_CONFIG,
      derivationScope: DERIVATION_SCOPE,
    });
    const differentLabel = await deriveArciumX25519Keypair(signer, {
      programId: PROGRAM_ID,
      vaultConfig: VAULT_CONFIG,
      derivationScope: DERIVATION_SCOPE,
      label: "owner-view",
    });
    const differentScope = await deriveArciumX25519Keypair(signer, {
      programId: PROGRAM_ID,
      vaultConfig: VAULT_CONFIG,
      derivationScope: "subly402:test:budget:v1",
    });

    expect(Array.from(second.privateKey)).to.deep.equal(
      Array.from(first.privateKey)
    );
    expect(Array.from(second.publicKey)).to.deep.equal(
      Array.from(first.publicKey)
    );
    expect(Array.from(differentLabel.publicKey)).not.to.deep.equal(
      Array.from(first.publicKey)
    );
    expect(Array.from(differentScope.publicKey)).not.to.deep.equal(
      Array.from(first.publicKey)
    );
    expect(Buffer.from(first.derivationMessage).toString("utf8")).to.contain(
      `vault:${VAULT_CONFIG}`
    );
    expect(Buffer.from(first.derivationMessage).toString("utf8")).to.contain(
      `scope:${DERIVATION_SCOPE}`
    );
  });

  it("derives x25519 keys from signMessages and secretKey signers", async () => {
    const signMessageSigner = {
      publicKey: CLIENT_ADDRESS,
      signMessage: fakeSignature,
    };
    const signMessagesSigner = {
      address: CLIENT_ADDRESS,
      signMessages: async (messages: Array<{ content: Uint8Array }>) => [
        {
          [CLIENT_ADDRESS]: fakeSignature(messages[0].content),
        },
      ],
    } as any;
    const secretKeySigner = {
      publicKey: CLIENT_ADDRESS,
      secretKey: new Uint8Array(64).fill(8),
    };

    const args = {
      programId: PROGRAM_ID,
      vaultConfig: VAULT_CONFIG,
      derivationScope: DERIVATION_SCOPE,
    };
    const signMessageKeypair = await deriveArciumX25519Keypair(
      signMessageSigner,
      args
    );
    const signMessagesKeypair = await deriveArciumX25519Keypair(
      signMessagesSigner,
      args
    );
    const secretKeyKeypair = await deriveArciumX25519Keypair(
      secretKeySigner,
      args
    );

    expect(Array.from(signMessagesKeypair.publicKey)).to.deep.equal(
      Array.from(signMessageKeypair.publicKey)
    );
    expect(secretKeyKeypair.publicKey).to.have.length(32);
  });

  it("requires a non-empty Arcium derivation scope", async () => {
    const signer = {
      publicKey: CLIENT_ADDRESS,
      signMessage: fakeSignature,
    };

    let error: unknown;
    try {
      await deriveArciumX25519Keypair(signer, {
        programId: PROGRAM_ID,
        vaultConfig: VAULT_CONFIG,
        derivationScope: " ",
      });
    } catch (caught) {
      error = caught;
    }

    expect(error).to.be.instanceOf(Error);
    expect((error as Error).message).to.contain(
      "derivationScope must be a non-empty string"
    );
  });

  it("encrypts budget requests and reconcile reports in circuit argument order", async () => {
    const signer = {
      publicKey: CLIENT_ADDRESS,
      signMessage: fakeSignature,
    };
    const clientKeys = await deriveArciumX25519Keypair(signer, {
      programId: PROGRAM_ID,
      vaultConfig: VAULT_CONFIG,
      derivationScope: DERIVATION_SCOPE,
    });
    const mxePrivateKey = x25519.utils.randomSecretKey();
    const mxePublicKey = x25519.getPublicKey(mxePrivateKey);
    const clientCipher = createArciumSharedCipher(
      clientKeys.privateKey,
      mxePublicKey
    );
    const mxeCipher = createArciumSharedCipher(
      mxePrivateKey,
      clientKeys.publicKey
    );
    const nonce = Uint8Array.from(Array.from({ length: 16 }, (_, i) => i));

    const budget = encryptArciumBudgetRequest(
      clientCipher,
      clientKeys.publicKey,
      {
        domainHashLo: 11n,
        domainHashHi: 12n,
        budgetId: 7,
        requestNonce: "8",
        amount: 1_000_000n,
        expiresAt: 1_800_000_000n,
      },
      { nonce }
    );

    expect(budget.ciphertexts).to.have.length(6);
    expect(Array.from(budget.x25519PublicKey)).to.deep.equal(
      Array.from(clientKeys.publicKey)
    );
    expect(budget.nonceU128).to.equal(20011376718272490338853433276725592320n);
    expect(
      decryptArciumScalars(mxeCipher, budget.ciphertexts, budget.nonce)
    ).to.deep.equal([11n, 12n, 7n, 8n, 1_000_000n, 1_800_000_000n]);

    const report = encryptArciumReconcileReport(
      clientCipher,
      clientKeys.publicKey,
      {
        domainHashLo: 21n,
        domainHashHi: 22n,
        budgetId: 7n,
        requestNonce: 8n,
        reportNonce: 9n,
        consumedDelta: 123n,
        refundRemaining: true,
      },
      { nonce: Uint8Array.from(Array.from({ length: 16 }, (_, i) => 16 - i)) }
    );

    expect(report.ciphertexts).to.have.length(7);
    expect(
      decryptArciumScalars(mxeCipher, report.ciphertexts, report.nonce)
    ).to.deep.equal([21n, 22n, 7n, 8n, 9n, 123n, 1n]);

    const withdrawal = encryptArciumWithdrawalRequest(
      clientCipher,
      clientKeys.publicKey,
      {
        domainHashLo: 31n,
        domainHashHi: 32n,
        withdrawalId: 10n,
        amount: 456n,
        expiresAt: 1_800_000_100n,
      },
      { nonce: Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 1)) }
    );
    expect(withdrawal.ciphertexts).to.have.length(5);
    expect(
      decryptArciumScalars(mxeCipher, withdrawal.ciphertexts, withdrawal.nonce)
    ).to.deep.equal([31n, 32n, 10n, 456n, 1_800_000_100n]);

    const withdrawalReport = encryptArciumWithdrawalReport(
      clientCipher,
      clientKeys.publicKey,
      {
        domainHashLo: 41n,
        domainHashHi: 42n,
        withdrawalId: 10n,
        withdrawnAmount: 400n,
        refundRemaining: false,
      },
      { nonce: Uint8Array.from(Array.from({ length: 16 }, (_, i) => i + 2)) }
    );
    expect(withdrawalReport.ciphertexts).to.have.length(5);
    expect(
      decryptArciumScalars(
        mxeCipher,
        withdrawalReport.ciphertexts,
        withdrawalReport.nonce
      )
    ).to.deep.equal([41n, 42n, 10n, 400n, 0n]);
  });

  it("splits hashes and decodes encrypted Arcium views", async () => {
    const clientPrivateKey = x25519.utils.randomSecretKey();
    const clientPublicKey = x25519.getPublicKey(clientPrivateKey);
    const mxePrivateKey = x25519.utils.randomSecretKey();
    const mxePublicKey = x25519.getPublicKey(mxePrivateKey);
    const clientCipher = createArciumSharedCipher(
      clientPrivateKey,
      mxePublicKey
    );
    const mxeCipher = createArciumSharedCipher(mxePrivateKey, clientPublicKey);
    const nonce = new Uint8Array(16).fill(3);

    const split = splitU256Le(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    expect(split.lo).to.equal(20011376718272490338853433276725592320n);
    expect(split.hi).to.equal(41362427191743139026751447860679676176n);

    const ownerViewCiphertexts = mxeCipher.encrypt(
      [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n],
      nonce
    );
    expect(
      decryptArciumAgentVaultView(clientCipher, ownerViewCiphertexts, nonce)
    ).to.deep.equal({
      free: 1n,
      locked: 2n,
      yieldEarned: 3n,
      spent: 4n,
      withdrawn: 5n,
      strategyShares: 6n,
      maxLockExpiresAt: 7n,
      yieldIndexCheckpointQ64: 8n,
    });

    const grantCiphertexts = mxeCipher.encrypt(
      [
        1n,
        7n,
        8n,
        100n,
        90n,
        1_800_000_000n,
        2n,
        11n,
        12n,
        13n,
        14n,
        15n,
        16n,
        17n,
        18n,
      ],
      nonce
    );
    expect(
      decryptArciumBudgetGrantView(clientCipher, grantCiphertexts, nonce)
    ).to.deep.equal({
      approved: true,
      budgetId: 7n,
      requestNonce: 8n,
      amount: 100n,
      remaining: 90n,
      expiresAt: 1_800_000_000n,
      stateVersion: 2n,
      domainHashLo: 11n,
      domainHashHi: 12n,
      vaultConfigLo: 13n,
      vaultConfigHi: 14n,
      clientLo: 15n,
      clientHi: 16n,
      budgetGrantLo: 17n,
      budgetGrantHi: 18n,
    });

    const withdrawalGrantCiphertexts = mxeCipher.encrypt(
      [
        1n,
        10n,
        456n,
        1_800_000_100n,
        2n,
        21n,
        22n,
        23n,
        24n,
        25n,
        26n,
        27n,
        28n,
        19n,
        20n,
      ],
      nonce
    );
    expect(
      decryptArciumWithdrawalGrantView(
        clientCipher,
        withdrawalGrantCiphertexts,
        nonce
      )
    ).to.deep.equal({
      approved: true,
      withdrawalId: 10n,
      amount: 456n,
      expiresAt: 1_800_000_100n,
      stateVersion: 2n,
      domainHashLo: 21n,
      domainHashHi: 22n,
      vaultConfigLo: 23n,
      vaultConfigHi: 24n,
      clientLo: 25n,
      clientHi: 26n,
      withdrawalGrantLo: 27n,
      withdrawalGrantHi: 28n,
      recipientLo: 19n,
      recipientHi: 20n,
    });
  });
});
