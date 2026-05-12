#!/usr/bin/env node

require("ts-node/register/transpile-only");

const { createHash, hkdfSync } = require("crypto");
const { RistrettoPoint } = require("@noble/curves/ed25519");
const { Keypair, PublicKey } = require("@solana/web3.js");
const { AuditTool } = require("../../sdk/src/audit");

const SCALAR_ORDER = BigInt(
  "7237005577332262213973186563042994240857116359379907606001950938285454250989"
);

function seed(label) {
  return createHash("sha256").update(label).digest();
}

function keypair(label) {
  return Keypair.fromSeed(seed(label));
}

function bytesToScalar(bytes) {
  let n = 0n;
  const len = Math.min(bytes.length, 64);
  for (let i = len - 1; i >= 0; i -= 1) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  return n % SCALAR_ORDER;
}

function kdfMask(sharedSecretBytes) {
  const hash = createHash("sha256");
  hash.update("subly402-elgamal-mask-v1");
  hash.update(sharedSecretBytes);
  return new Uint8Array(hash.digest());
}

function deriveProviderKeyMaterial(masterSecret, provider) {
  return new Uint8Array(
    hkdfSync(
      "sha256",
      masterSecret,
      Buffer.from("subly402-audit-v1"),
      provider.toBuffer(),
      64
    )
  );
}

function encryptWithProvider(masterSecret, provider, plaintext, nonceLabel) {
  const providerSecret = bytesToScalar(
    deriveProviderKeyMaterial(masterSecret, provider)
  );
  const r = bytesToScalar(seed(nonceLabel));
  const providerPublic = RistrettoPoint.BASE.multiply(providerSecret);
  const c1 = RistrettoPoint.BASE.multiply(r);
  const shared = providerPublic.multiply(r);
  const mask = kdfMask(shared.toRawBytes());

  const ciphertext = new Uint8Array(64);
  ciphertext.set(c1.toRawBytes(), 0);
  for (let i = 0; i < 32; i += 1) {
    ciphertext[32 + i] = plaintext[i] ^ mask[i];
  }
  return ciphertext;
}

function encodeAmount(amount) {
  const out = new Uint8Array(32);
  Buffer.from(out.buffer, out.byteOffset, out.byteLength).writeBigUInt64LE(
    BigInt(amount),
    0
  );
  return out;
}

function buildRawRecord({
  masterSecret,
  vault,
  batchId,
  index,
  sender,
  provider,
  amount,
  timestamp,
  auditorEpoch,
}) {
  const recordLabel = `${batchId}:${index}`;
  return {
    address: keypair(`audit-pda-${recordLabel}`).publicKey,
    vault,
    batchId,
    index,
    encryptedSender: encryptWithProvider(
      masterSecret,
      provider,
      sender.toBytes(),
      `sender-${recordLabel}`
    ),
    encryptedAmount: encryptWithProvider(
      masterSecret,
      provider,
      encodeAmount(amount),
      `amount-${recordLabel}`
    ),
    provider,
    timestamp,
    auditorEpoch,
  };
}

function shortHex(bytes) {
  return Buffer.from(bytes).toString("hex").slice(0, 24) + "...";
}

function publicView(raw) {
  return {
    address: raw.address.toBase58(),
    provider: raw.provider.toBase58(),
    batchId: raw.batchId,
    index: raw.index,
    encryptedSender: shortHex(raw.encryptedSender),
    encryptedAmount: shortHex(raw.encryptedAmount),
    timestamp: raw.timestamp,
    auditorEpoch: raw.auditorEpoch,
  };
}

function decryptedView(record) {
  return {
    sender: record.sender.toBase58(),
    amountAtomic: record.amount,
    provider: record.provider.toBase58(),
    batchId: record.batchId,
    index: record.index,
  };
}

async function main() {
  const masterSecret = seed("subly402-demo-auditor-master-secret");
  const vault = keypair("vault-config").publicKey;
  const providerA = keypair("provider-a").publicKey;
  const providerB = keypair("provider-b").publicKey;
  const alice = keypair("buyer-alice").publicKey;
  const bob = keypair("buyer-bob").publicKey;
  const carol = keypair("buyer-carol").publicKey;

  const rawRecords = [
    buildRawRecord({
      masterSecret,
      vault,
      batchId: 42,
      index: 0,
      sender: alice,
      provider: providerA,
      amount: 1_250_000,
      timestamp: 1_762_540_800,
      auditorEpoch: 7,
    }),
    buildRawRecord({
      masterSecret,
      vault,
      batchId: 42,
      index: 1,
      sender: bob,
      provider: providerB,
      amount: 2_400_000,
      timestamp: 1_762_540_800,
      auditorEpoch: 7,
    }),
    buildRawRecord({
      masterSecret,
      vault,
      batchId: 43,
      index: 0,
      sender: carol,
      provider: providerA,
      amount: 500_000,
      timestamp: 1_762_541_100,
      auditorEpoch: 7,
    }),
  ];

  const auditTool = new AuditTool(masterSecret);
  const providerAKey = await auditTool.exportProviderKey(providerA);
  const providerBKey = await auditTool.exportProviderKey(providerB);

  const providerARecords = rawRecords.filter((record) =>
    record.provider.equals(providerA)
  );
  const providerBRecords = rawRecords.filter((record) =>
    record.provider.equals(providerB)
  );

  const authorizedA = await AuditTool.decryptWithKey(
    providerAKey,
    providerARecords
  );
  const unauthorizedAKeyOnB = await AuditTool.decryptWithKey(
    providerAKey,
    providerBRecords
  );
  const authorizedB = await AuditTool.decryptWithKey(providerBKey, rawRecords);

  const output = {
    demo: "subly402 selective audit disclosure",
    publicLedger: rawRecords.map(publicView),
    auditorGrantedProviderAKey: {
      provider: providerA.toBase58(),
      keyFingerprintSha256: createHash("sha256")
        .update(providerAKey)
        .digest("hex"),
      decryptedRecords: authorizedA.map(decryptedView),
    },
    sameAuditorTryingProviderBRecords: {
      targetProvider: providerB.toBase58(),
      decryptedRecordCount: unauthorizedAKeyOnB.length,
    },
    auditorGrantedProviderBKey: {
      provider: providerB.toBase58(),
      decryptedRecords: authorizedB.map(decryptedView),
    },
    checks: {
      publicLedgerContainsOnlyCiphertexts: rawRecords.every(
        (record) =>
          record.encryptedSender.length === 64 &&
          record.encryptedAmount.length === 64
      ),
      providerAKeyDecryptsOnlyProviderA:
        authorizedA.length === 2 && unauthorizedAKeyOnB.length === 0,
      providerBKeyDecryptsOnlyProviderB:
        authorizedB.length === 1 && authorizedB[0].provider.equals(providerB),
    },
  };

  console.log(JSON.stringify(output, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
