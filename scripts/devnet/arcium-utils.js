const crypto = require("crypto");

const { requireSdkArcium } = require("./common");

function numberValue(value) {
  if (typeof value === "number") {
    return value;
  }
  if (value && typeof value.toNumber === "function") {
    return value.toNumber();
  }
  return Number(value);
}

function publicKeyFrom(value, field) {
  const anchor = require("@coral-xyz/anchor");
  if (value instanceof anchor.web3.PublicKey) {
    return value;
  }
  if (value && typeof value.toBase58 === "function") {
    return new anchor.web3.PublicKey(value.toBase58());
  }
  try {
    return new anchor.web3.PublicKey(value);
  } catch (error) {
    throw new Error(`${field} must be a valid public key`);
  }
}

function u32Le(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(numberValue(value));
  return out;
}

function leBytesToBigInt(bytes) {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) + BigInt(bytes[index]);
  }
  return value;
}

function bytesFromU256(value) {
  if (typeof value === "string") {
    const normalized = value.startsWith("0x") ? value.slice(2) : value;
    return Buffer.from(normalized, "hex");
  }
  return Buffer.from(value);
}

function splitU256Le(value) {
  const bytes = bytesFromU256(value);
  if (bytes.length !== 32) {
    throw new Error(`u256 value must be 32 bytes, got ${bytes.length}`);
  }
  return {
    lo: leBytesToBigInt(bytes.subarray(0, 16)),
    hi: leBytesToBigInt(bytes.subarray(16, 32)),
  };
}

function computeArciumDomainHashParts({
  instructionKind,
  programId,
  vaultConfig,
  vaultConfigAccount,
  arciumConfigAccount,
}) {
  const hash = crypto.createHash("sha256");
  hash.update(Buffer.from("subly402:arcium-domain:v1"));
  hash.update(Buffer.from(instructionKind));
  hash.update(publicKeyFrom(programId, "programId").toBuffer());
  hash.update(publicKeyFrom(vaultConfig, "vaultConfig").toBuffer());
  hash.update(
    publicKeyFrom(vaultConfigAccount.usdcMint, "usdcMint").toBuffer()
  );
  hash.update(
    publicKeyFrom(
      arciumConfigAccount.arciumProgramId,
      "arciumProgramId"
    ).toBuffer()
  );
  hash.update(
    publicKeyFrom(arciumConfigAccount.mxeAccount, "mxeAccount").toBuffer()
  );
  hash.update(Buffer.from(arciumConfigAccount.teeX25519Pubkey));
  hash.update(Buffer.from(arciumConfigAccount.attestationPolicyHash));
  hash.update(u32Le(arciumConfigAccount.compDefVersion));
  return splitU256Le(hash.digest());
}

async function fetchArciumMxePublicKeyWithRetry(provider, programId, options) {
  return requireSdkArcium().fetchArciumMxePublicKeyWithRetry(
    provider,
    programId,
    options
  );
}

module.exports = {
  computeArciumDomainHashParts,
  fetchArciumMxePublicKeyWithRetry,
  splitU256Le,
};
