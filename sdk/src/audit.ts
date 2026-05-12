/**
 * AuditTool — Decrypt ElGamal-encrypted audit records with selective disclosure.
 *
 * Per design doc §7.3:
 *   - Master key: decrypt ALL audit records across all providers
 *   - Provider-derived key: decrypt only records for that specific provider
 *   - Export provider key: give to a third-party auditor for scoped access
 *
 * ElGamal ciphertext format (64 bytes):
 *   C1 = r * G           (32 bytes, compressed Ristretto255 point)
 *   C2 = data XOR SHA256("subly402-elgamal-mask-v1" || r * P)  (32 bytes)
 *
 * Key derivation (HKDF-SHA256):
 *   provider_secret = HKDF(master_secret, salt="subly402-audit-v1", info=provider_address)
 *   provider_key = provider_secret mod l (reduced to Ristretto scalar)
 */

import { createHash, hkdf as nodeHkdf } from "crypto";
import { PublicKey, Connection } from "@solana/web3.js";

/** Decrypted audit record */
export interface DecryptedAuditRecord {
  sender: PublicKey;
  amount: number;
  provider: PublicKey;
  timestamp: number;
  auditorEpoch: number;
  /** On-chain account address of the AuditRecord PDA */
  address: PublicKey;
  batchId: number;
  index: number;
}

/** Raw on-chain audit record data */
export interface RawAuditRecord {
  address: PublicKey;
  vault: PublicKey;
  batchId: number;
  index: number;
  encryptedSender: Uint8Array; // 64 bytes
  encryptedAmount: Uint8Array; // 64 bytes
  provider: PublicKey;
  timestamp: number;
  auditorEpoch: number;
}

/**
 * AuditTool for decrypting Subly402 audit records.
 *
 * Usage:
 *   // Full audit (master key)
 *   const tool = new AuditTool(masterSecret);
 *   const all = await tool.decryptAll(vaultAddress, connection, programId);
 *
 *   // Provider-scoped audit (derived key)
 *   const records = await tool.decryptForProvider(vaultAddress, providerAddress, connection, programId);
 *
 *   // Export key for third-party auditor
 *   const exportedKey = tool.exportProviderKey(providerAddress);
 */
export class AuditTool {
  private masterSecret: Uint8Array;

  constructor(masterSecret: Uint8Array | Buffer) {
    if (masterSecret.length !== 32) {
      throw new Error("Master secret must be 32 bytes");
    }
    this.masterSecret = new Uint8Array(masterSecret);
  }

  /**
   * Decrypt all audit records for a vault using the master secret.
   * Iterates through providers and derives appropriate keys.
   */
  async decryptAll(
    vaultAddress: PublicKey,
    connection: Connection,
    programId: PublicKey
  ): Promise<DecryptedAuditRecord[]> {
    const rawRecords = await this.fetchAuditRecords(
      vaultAddress,
      connection,
      programId
    );

    const results: DecryptedAuditRecord[] = [];

    for (const raw of rawRecords) {
      // Derive provider-specific key for each record
      const providerSecret = await this.deriveProviderSecret(raw.provider);
      const decrypted = this.decryptRecord(raw, providerSecret);
      if (decrypted) {
        results.push(decrypted);
      }
    }

    return results;
  }

  /**
   * Decrypt only audit records for a specific provider.
   */
  async decryptForProvider(
    vaultAddress: PublicKey,
    providerAddress: PublicKey,
    connection: Connection,
    programId: PublicKey
  ): Promise<DecryptedAuditRecord[]> {
    const rawRecords = await this.fetchAuditRecords(
      vaultAddress,
      connection,
      programId
    );

    const providerSecret = await this.deriveProviderSecret(providerAddress);
    const results: DecryptedAuditRecord[] = [];

    for (const raw of rawRecords) {
      if (!raw.provider.equals(providerAddress)) {
        continue;
      }
      const decrypted = this.decryptRecord(raw, providerSecret);
      if (decrypted) {
        results.push(decrypted);
      }
    }

    return results;
  }

  /**
   * Decrypt audit records using an externally-provided derived key.
   * Used when a third party has received an exported provider key.
   */
  static async decryptWithKey(
    derivedSecret: Uint8Array,
    rawRecords: RawAuditRecord[]
  ): Promise<DecryptedAuditRecord[]> {
    const results: DecryptedAuditRecord[] = [];
    for (const raw of rawRecords) {
      const decrypted = decryptRecordWithSecret(raw, derivedSecret);
      if (decrypted) {
        results.push(decrypted);
      }
    }
    return results;
  }

  /**
   * Export a provider-derived secret key for selective disclosure.
   * The exported key can decrypt only that provider's audit records.
   */
  async exportProviderKey(providerAddress: PublicKey): Promise<Uint8Array> {
    const keyMaterial = await this.deriveProviderSecret(providerAddress);
    return scalarToBytes(bytesToScalar(keyMaterial));
  }

  /**
   * Derive provider-specific secret from master secret via HKDF.
   * Matches enclave audit.rs derive_provider_key().
   */
  private async deriveProviderSecret(provider: PublicKey): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      nodeHkdf(
        "sha256",
        this.masterSecret,
        Buffer.from("subly402-audit-v1"),
        provider.toBuffer(),
        64,
        (err, derivedKey) => {
          if (err) {
            reject(err);
            return;
          }
          // Return the raw 64-byte derived key material
          // The Rust side reduces this mod l for Ristretto scalar
          resolve(new Uint8Array(derivedKey));
        }
      );
    });
  }

  /**
   * Decrypt a single audit record with a derived secret.
   */
  private decryptRecord(
    raw: RawAuditRecord,
    derivedSecret: Uint8Array
  ): DecryptedAuditRecord | null {
    return decryptRecordWithSecret(raw, derivedSecret);
  }

  /**
   * Fetch all AuditRecord PDAs for a vault from on-chain.
   */
  private async fetchAuditRecords(
    vaultAddress: PublicKey,
    connection: Connection,
    programId: PublicKey
  ): Promise<RawAuditRecord[]> {
    // Use getProgramAccounts with memcmp filter on vault field
    // AuditRecord layout after 8-byte discriminator:
    //   bump (1) + vault (32) = vault starts at offset 9
    const accounts = await connection.getProgramAccounts(programId, {
      filters: [
        { dataSize: 222 }, // AuditRecord::LEN
        {
          memcmp: {
            offset: 9, // 8 discriminator + 1 bump
            bytes: vaultAddress.toBase58(),
          },
        },
      ],
    });

    return accounts.map((acc) =>
      parseAuditRecord(acc.pubkey, acc.account.data)
    );
  }
}

/**
 * Parse an AuditRecord from raw account data.
 */
function parseAuditRecord(address: PublicKey, data: Buffer): RawAuditRecord {
  // Skip 8-byte discriminator
  let offset = 8;

  const bump = data[offset];
  offset += 1;
  const vault = new PublicKey(data.subarray(offset, offset + 32));
  offset += 32;
  const batchId = Number(data.readBigUInt64LE(offset));
  offset += 8;
  const index = data[offset];
  offset += 1;
  const encryptedSender = new Uint8Array(data.subarray(offset, offset + 64));
  offset += 64;
  const encryptedAmount = new Uint8Array(data.subarray(offset, offset + 64));
  offset += 64;
  const provider = new PublicKey(data.subarray(offset, offset + 32));
  offset += 32;
  const timestamp = Number(data.readBigInt64LE(offset));
  offset += 8;
  const auditorEpoch = data.readUInt32LE(offset);

  return {
    address,
    vault,
    batchId,
    index,
    encryptedSender,
    encryptedAmount,
    provider,
    timestamp,
    auditorEpoch,
  };
}

/**
 * Decrypt a single audit record using a derived secret.
 *
 * This performs the ECIES-like ElGamal decryption:
 *   shared_secret = secret_scalar * C1
 *   mask = SHA256("subly402-elgamal-mask-v1" || shared_secret)
 *   plaintext = C2 XOR mask
 *
 * Uses Ristretto255 point multiplication.
 * NOTE: Full implementation requires @noble/curves for Ristretto255.
 * This implementation uses a compatible scalar-mult approach.
 */
function decryptRecordWithSecret(
  raw: RawAuditRecord,
  derivedSecret: Uint8Array
): DecryptedAuditRecord | null {
  try {
    const senderBytes = elgamalDecrypt(derivedSecret, raw.encryptedSender);
    const amountBytes = elgamalDecrypt(derivedSecret, raw.encryptedAmount);

    if (!senderBytes || !amountBytes) return null;

    const sender = new PublicKey(senderBytes);

    // Amount is LE u64 in first 8 bytes, rest is zero padding
    for (let i = 8; i < amountBytes.length; i++) {
      if (amountBytes[i] !== 0) {
        return null;
      }
    }
    const amount = Number(Buffer.from(amountBytes).readBigUInt64LE(0));

    return {
      sender,
      amount,
      provider: raw.provider,
      timestamp: raw.timestamp,
      auditorEpoch: raw.auditorEpoch,
      address: raw.address,
      batchId: raw.batchId,
      index: raw.index,
    };
  } catch {
    return null;
  }
}

// Lazily resolved Ristretto255 dependency
let _RistrettoPoint: any = null;
let _ristrettoChecked = false;

function getRistrettoPoint(): any {
  if (!_ristrettoChecked) {
    _ristrettoChecked = true;
    try {
      _RistrettoPoint = require("@noble/curves/ed25519").RistrettoPoint;
    } catch {
      // not installed
    }
  }
  if (!_RistrettoPoint) {
    throw new Error(
      "@noble/curves is required for audit record decryption. Install it with: npm install @noble/curves"
    );
  }
  return _RistrettoPoint;
}

/**
 * ElGamal decryption (ECIES variant on Ristretto255).
 *
 * Ciphertext: C1 (32 bytes) || C2 (32 bytes)
 * Returns 32-byte plaintext.
 *
 * Requires @noble/curves to be installed.
 */
function elgamalDecrypt(
  secretKey: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array | null {
  if (ciphertext.length !== 64) return null;

  const RistrettoPoint = getRistrettoPoint();

  const c1Bytes = ciphertext.slice(0, 32);
  const c2 = ciphertext.slice(32, 64);

  // Decompress C1 point
  const c1Point = RistrettoPoint.fromHex(Buffer.from(c1Bytes).toString("hex"));

  // Compute shared_secret = secret * C1
  // The secret is 64 bytes from HKDF, needs to be reduced mod l
  const sharedPoint = c1Point.multiply(bytesToScalar(secretKey));
  const sharedBytes = Buffer.from(sharedPoint.toRawBytes());

  // Derive mask
  const mask = kdfMask(sharedBytes);

  // XOR to recover plaintext
  const plaintext = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    plaintext[i] = c2[i] ^ mask[i];
  }

  return plaintext;
}

/**
 * Convert variable-length bytes to a Ristretto255 scalar (mod l).
 * Matches curve25519-dalek's Scalar::from_bytes_mod_order_wide for 64-byte input.
 */
function bytesToScalar(bytes: Uint8Array): bigint {
  // Ristretto255 scalar order l
  const l = BigInt(
    "7237005577332262213973186563042994240857116359379907606001950938285454250989"
  );

  // Convert LE bytes to bigint, then mod l
  let n = BigInt(0);
  const len = Math.min(bytes.length, 64);
  for (let i = len - 1; i >= 0; i--) {
    n = (n << BigInt(8)) | BigInt(bytes[i]);
  }

  return n % l;
}

function scalarToBytes(scalar: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let value = scalar;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(value & BigInt(0xff));
    value >>= BigInt(8);
  }
  return out;
}

/**
 * Compute KDF mask from shared secret bytes.
 * Matches enclave audit.rs kdf_mask().
 */
function kdfMask(sharedSecretBytes: Buffer): Uint8Array {
  const hash = createHash("sha256");
  hash.update("subly402-elgamal-mask-v1");
  hash.update(sharedSecretBytes);
  return new Uint8Array(hash.digest());
}
