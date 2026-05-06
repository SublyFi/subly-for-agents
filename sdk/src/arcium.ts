import { createHash, randomBytes } from "crypto";
import { createSignableMessage } from "@solana/kit";

import { ed25519Sign } from "./crypto";
import type { Subly402PublicKeyLike, Subly402Signer } from "./types";

const bs58Encode = require("bs58").encode as (source: Uint8Array) => string;

type ArciumClientModule = typeof import("@arcium-hq/client");
type RescueCipherInstance = InstanceType<ArciumClientModule["RescueCipher"]>;

export const MIN_ARCIUM_NODE_VERSION = "20.18.0";
export const ARCIUM_AGENT_VAULT_SCALARS = 8;
export const ARCIUM_BUDGET_GRANT_SCALARS = 15;
export const ARCIUM_BUDGET_REQUEST_SCALARS = 6;
export const ARCIUM_RECONCILE_REPORT_SCALARS = 7;
export const ARCIUM_WITHDRAWAL_GRANT_SCALARS = 15;
export const ARCIUM_WITHDRAWAL_REQUEST_SCALARS = 5;
export const ARCIUM_WITHDRAWAL_REPORT_SCALARS = 5;

function parseNodeVersion(
  version: string | undefined
): [number, number, number] | null {
  const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version ?? "");
  if (!match) {
    return null;
  }
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

export function assertArciumNodeRuntime(
  version: string | undefined = typeof process !== "undefined"
    ? process.versions.node
    : undefined
): void {
  const parsed = parseNodeVersion(version);
  const minimum = parseNodeVersion(MIN_ARCIUM_NODE_VERSION);
  if (
    !parsed ||
    !minimum ||
    parsed[0] < minimum[0] ||
    (parsed[0] === minimum[0] && parsed[1] < minimum[1]) ||
    (parsed[0] === minimum[0] &&
      parsed[1] === minimum[1] &&
      parsed[2] < minimum[2])
  ) {
    throw new Error(
      `subly402-sdk/arcium requires Node.js >=${MIN_ARCIUM_NODE_VERSION} because @arcium-hq/client@0.9.7 requires it; current runtime is ${
        version ?? "unknown"
      }`
    );
  }
}

assertArciumNodeRuntime();

const { deserializeLE, getMXEPublicKey, RescueCipher, x25519 } =
  require("@arcium-hq/client") as ArciumClientModule;

export type ArciumScalarLike = bigint | number | string;
export type ArciumCiphertext = ArrayLike<number>;

export interface ArciumX25519Keypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  derivationMessage: Uint8Array;
}

export interface ArciumX25519DerivationArgs {
  programId: Subly402PublicKeyLike | string;
  vaultConfig: Subly402PublicKeyLike | string;
  derivationScope: string;
  label?: string;
}

export interface ArciumEncryptedSharedInput {
  x25519PublicKey: Uint8Array;
  nonce: Uint8Array;
  nonceU128: bigint;
  ciphertexts: number[][];
}

export interface ArciumU128Pair {
  lo: bigint;
  hi: bigint;
}

export interface ArciumBudgetRequestPlaintext {
  domainHashLo: ArciumScalarLike;
  domainHashHi: ArciumScalarLike;
  budgetId: ArciumScalarLike;
  requestNonce: ArciumScalarLike;
  amount: ArciumScalarLike;
  expiresAt: ArciumScalarLike;
}

export interface ArciumReconcileReportPlaintext {
  domainHashLo: ArciumScalarLike;
  domainHashHi: ArciumScalarLike;
  budgetId: ArciumScalarLike;
  requestNonce: ArciumScalarLike;
  reportNonce: ArciumScalarLike;
  consumedDelta: ArciumScalarLike;
  refundRemaining: boolean | 0 | 1;
}

export interface ArciumWithdrawalRequestPlaintext {
  domainHashLo: ArciumScalarLike;
  domainHashHi: ArciumScalarLike;
  withdrawalId: ArciumScalarLike;
  amount: ArciumScalarLike;
  expiresAt: ArciumScalarLike;
}

export interface ArciumWithdrawalReportPlaintext {
  domainHashLo: ArciumScalarLike;
  domainHashHi: ArciumScalarLike;
  withdrawalId: ArciumScalarLike;
  withdrawnAmount: ArciumScalarLike;
  refundRemaining: boolean | 0 | 1;
}

export interface ArciumAgentVaultView {
  free: bigint;
  locked: bigint;
  yieldEarned: bigint;
  spent: bigint;
  withdrawn: bigint;
  strategyShares: bigint;
  maxLockExpiresAt: bigint;
  yieldIndexCheckpointQ64: bigint;
}

export interface ArciumBudgetGrantView {
  approved: boolean;
  budgetId: bigint;
  requestNonce: bigint;
  amount: bigint;
  remaining: bigint;
  expiresAt: bigint;
  stateVersion: bigint;
  domainHashLo: bigint;
  domainHashHi: bigint;
  vaultConfigLo: bigint;
  vaultConfigHi: bigint;
  clientLo: bigint;
  clientHi: bigint;
  budgetGrantLo: bigint;
  budgetGrantHi: bigint;
}

export interface ArciumWithdrawalGrantView {
  approved: boolean;
  withdrawalId: bigint;
  amount: bigint;
  expiresAt: bigint;
  stateVersion: bigint;
  domainHashLo: bigint;
  domainHashHi: bigint;
  vaultConfigLo: bigint;
  vaultConfigHi: bigint;
  clientLo: bigint;
  clientHi: bigint;
  withdrawalGrantLo: bigint;
  withdrawalGrantHi: bigint;
  recipientLo: bigint;
  recipientHi: bigint;
}

export interface FetchMxePublicKeyOptions {
  attempts?: number;
  delayMs?: number;
}

const TEXT_ENCODER = new TextEncoder();
const MAX_U8 = (1n << 8n) - 1n;
const MAX_U64 = (1n << 64n) - 1n;
const MAX_U128 = (1n << 128n) - 1n;

function toBase58(value: Subly402PublicKeyLike | string): string {
  if (typeof value === "string") {
    return value;
  }
  if (value instanceof Uint8Array) {
    return bs58Encode(value);
  }
  return value.toBase58();
}

function requireNonEmptyString(
  value: string | undefined,
  field: string
): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new Error(`${field} must be a non-empty string`);
  }
  return normalized;
}

function signerAddress(
  signer: Pick<Subly402Signer, "publicKey" | "address">
): string {
  if (signer.address) {
    return signer.address;
  }
  const publicKey = signer.publicKey;
  if (typeof publicKey === "string") {
    return publicKey;
  }
  if (publicKey && typeof publicKey.toBase58 === "function") {
    return publicKey.toBase58();
  }
  throw new Error("Arcium x25519 key derivation requires a signer address");
}

async function signArciumDerivationMessage(
  signer: Pick<
    Subly402Signer,
    "publicKey" | "address" | "secretKey" | "signMessage" | "signMessages"
  >,
  message: Uint8Array
): Promise<Uint8Array> {
  if (signer.signMessages) {
    const address = signerAddress(signer);
    const [signatures] = await signer.signMessages([
      createSignableMessage(message),
    ]);
    const signature =
      (signatures as Record<string, Uint8Array>)[address] ??
      Object.values(signatures as Record<string, Uint8Array>)[0];
    if (!signature) {
      throw new Error("Arcium signer did not return a message signature");
    }
    return signature;
  }
  if (signer.signMessage) {
    return signer.signMessage(message);
  }
  if (signer.secretKey) {
    return ed25519Sign(message, signer.secretKey);
  }
  throw new Error(
    "Arcium x25519 key derivation requires signMessages, signMessage, or secretKey"
  );
}

function toUnsignedBigInt(
  value: ArciumScalarLike,
  max: bigint,
  field: string
): bigint {
  let parsed: bigint;
  if (typeof value === "bigint") {
    parsed = value;
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error(`${field} must be a safe integer`);
    }
    parsed = BigInt(value);
  } else if (/^0x[0-9a-fA-F]+$/.test(value)) {
    parsed = BigInt(value);
  } else if (/^[0-9]+$/.test(value)) {
    parsed = BigInt(value);
  } else {
    throw new Error(`${field} must be an unsigned integer`);
  }

  if (parsed < 0n || parsed > max) {
    throw new Error(`${field} is out of range`);
  }
  return parsed;
}

function copyBytes(
  value: ArrayLike<number>,
  length: number,
  field: string
): Uint8Array {
  if (value.length !== length) {
    throw new Error(`${field} must be ${length} bytes`);
  }
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    const byte = value[i];
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`${field} contains an invalid byte`);
    }
    out[i] = byte;
  }
  return out;
}

function normalizeCiphertexts(
  ciphertexts: readonly ArciumCiphertext[],
  expectedLength: number,
  field: string
): number[][] {
  if (ciphertexts.length !== expectedLength) {
    throw new Error(`${field} must contain ${expectedLength} ciphertexts`);
  }
  return ciphertexts.map((ciphertext, index) =>
    Array.from(copyBytes(ciphertext, 32, `${field}[${index}]`))
  );
}

function randomNonce(): Uint8Array {
  return new Uint8Array(randomBytes(16));
}

function buildDerivationMessage(args: {
  programId: Subly402PublicKeyLike | string;
  vaultConfig: Subly402PublicKeyLike | string;
  derivationScope: string;
  walletAddress?: Subly402PublicKeyLike | string;
  label?: string;
}): Uint8Array {
  const derivationScope = requireNonEmptyString(
    args.derivationScope,
    "derivationScope"
  );
  const label = args.label
    ? requireNonEmptyString(args.label, "label")
    : "default";
  const message =
    "SUBLY402-ARCIUM-X25519-V1\n" +
    `program:${toBase58(args.programId)}\n` +
    `vault:${toBase58(args.vaultConfig)}\n` +
    `wallet:${args.walletAddress ? toBase58(args.walletAddress) : ""}\n` +
    `scope:${derivationScope}\n` +
    `label:${label}\n`;
  return TEXT_ENCODER.encode(message);
}

export async function deriveArciumX25519Keypair(
  signer: Pick<
    Subly402Signer,
    "publicKey" | "address" | "secretKey" | "signMessage" | "signMessages"
  >,
  args: ArciumX25519DerivationArgs
): Promise<ArciumX25519Keypair> {
  const walletAddress =
    typeof signer.address === "string"
      ? signer.address
      : signer.publicKey && typeof signer.publicKey !== "string"
      ? signer.publicKey
      : signer.publicKey;
  const derivationMessage = buildDerivationMessage({
    programId: args.programId,
    vaultConfig: args.vaultConfig,
    derivationScope: args.derivationScope,
    walletAddress,
    label: args.label,
  });
  const signature = await signArciumDerivationMessage(
    signer,
    derivationMessage
  );
  const privateKey = createHash("sha256")
    .update("SUBLY402-ARCIUM-X25519-PRIVATE-V1")
    .update(Buffer.from(signature))
    .digest();
  const publicKey = x25519.getPublicKey(privateKey);

  return {
    privateKey: new Uint8Array(privateKey),
    publicKey: new Uint8Array(publicKey),
    derivationMessage,
  };
}

export function createArciumSharedCipher(
  privateKey: ArrayLike<number>,
  peerX25519PublicKey: ArrayLike<number>
): RescueCipherInstance {
  const sharedSecret = x25519.getSharedSecret(
    copyBytes(privateKey, 32, "privateKey"),
    copyBytes(peerX25519PublicKey, 32, "peerX25519PublicKey")
  );
  return new RescueCipher(sharedSecret);
}

export function encryptArciumSharedScalars(
  cipher: RescueCipherInstance,
  x25519PublicKey: ArrayLike<number>,
  plaintexts: readonly ArciumScalarLike[],
  options: {
    nonce?: ArrayLike<number>;
  } = {}
): ArciumEncryptedSharedInput {
  const nonce = options.nonce
    ? copyBytes(options.nonce, 16, "nonce")
    : randomNonce();
  const ciphertexts = cipher.encrypt(
    plaintexts.map((value, index) =>
      toUnsignedBigInt(value, MAX_U128, `plaintexts[${index}]`)
    ),
    nonce
  );

  return {
    x25519PublicKey: copyBytes(x25519PublicKey, 32, "x25519PublicKey"),
    nonce,
    nonceU128: deserializeLE(nonce),
    ciphertexts,
  };
}

export function encryptArciumBudgetRequest(
  cipher: RescueCipherInstance,
  x25519PublicKey: ArrayLike<number>,
  request: ArciumBudgetRequestPlaintext,
  options: {
    nonce?: ArrayLike<number>;
  } = {}
): ArciumEncryptedSharedInput {
  return encryptArciumSharedScalars(
    cipher,
    x25519PublicKey,
    [
      toUnsignedBigInt(request.domainHashLo, MAX_U128, "domainHashLo"),
      toUnsignedBigInt(request.domainHashHi, MAX_U128, "domainHashHi"),
      toUnsignedBigInt(request.budgetId, MAX_U64, "budgetId"),
      toUnsignedBigInt(request.requestNonce, MAX_U64, "requestNonce"),
      toUnsignedBigInt(request.amount, MAX_U64, "amount"),
      toUnsignedBigInt(request.expiresAt, MAX_U64, "expiresAt"),
    ],
    options
  );
}

export function encryptArciumReconcileReport(
  cipher: RescueCipherInstance,
  x25519PublicKey: ArrayLike<number>,
  report: ArciumReconcileReportPlaintext,
  options: {
    nonce?: ArrayLike<number>;
  } = {}
): ArciumEncryptedSharedInput {
  return encryptArciumSharedScalars(
    cipher,
    x25519PublicKey,
    [
      toUnsignedBigInt(report.domainHashLo, MAX_U128, "domainHashLo"),
      toUnsignedBigInt(report.domainHashHi, MAX_U128, "domainHashHi"),
      toUnsignedBigInt(report.budgetId, MAX_U64, "budgetId"),
      toUnsignedBigInt(report.requestNonce, MAX_U64, "requestNonce"),
      toUnsignedBigInt(report.reportNonce, MAX_U64, "reportNonce"),
      toUnsignedBigInt(report.consumedDelta, MAX_U64, "consumedDelta"),
      report.refundRemaining === true
        ? 1n
        : report.refundRemaining === false
        ? 0n
        : toUnsignedBigInt(report.refundRemaining, MAX_U8, "refundRemaining"),
    ],
    options
  );
}

export function encryptArciumWithdrawalRequest(
  cipher: RescueCipherInstance,
  x25519PublicKey: ArrayLike<number>,
  request: ArciumWithdrawalRequestPlaintext,
  options: {
    nonce?: ArrayLike<number>;
  } = {}
): ArciumEncryptedSharedInput {
  return encryptArciumSharedScalars(
    cipher,
    x25519PublicKey,
    [
      toUnsignedBigInt(request.domainHashLo, MAX_U128, "domainHashLo"),
      toUnsignedBigInt(request.domainHashHi, MAX_U128, "domainHashHi"),
      toUnsignedBigInt(request.withdrawalId, MAX_U64, "withdrawalId"),
      toUnsignedBigInt(request.amount, MAX_U64, "amount"),
      toUnsignedBigInt(request.expiresAt, MAX_U64, "expiresAt"),
    ],
    options
  );
}

export function encryptArciumWithdrawalReport(
  cipher: RescueCipherInstance,
  x25519PublicKey: ArrayLike<number>,
  report: ArciumWithdrawalReportPlaintext,
  options: {
    nonce?: ArrayLike<number>;
  } = {}
): ArciumEncryptedSharedInput {
  return encryptArciumSharedScalars(
    cipher,
    x25519PublicKey,
    [
      toUnsignedBigInt(report.domainHashLo, MAX_U128, "domainHashLo"),
      toUnsignedBigInt(report.domainHashHi, MAX_U128, "domainHashHi"),
      toUnsignedBigInt(report.withdrawalId, MAX_U64, "withdrawalId"),
      toUnsignedBigInt(report.withdrawnAmount, MAX_U64, "withdrawnAmount"),
      report.refundRemaining === true
        ? 1n
        : report.refundRemaining === false
        ? 0n
        : toUnsignedBigInt(report.refundRemaining, MAX_U8, "refundRemaining"),
    ],
    options
  );
}

export function splitU256Le(value: ArrayLike<number> | string): ArciumU128Pair {
  let bytes: Uint8Array;
  if (typeof value === "string") {
    const hex = value.startsWith("0x") ? value.slice(2) : value;
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
      throw new Error("u256 hex value must contain exactly 32 bytes");
    }
    bytes = new Uint8Array(Buffer.from(hex, "hex"));
  } else {
    bytes = copyBytes(value, 32, "u256");
  }

  return {
    lo: deserializeLE(bytes.slice(0, 16)),
    hi: deserializeLE(bytes.slice(16, 32)),
  };
}

export function decryptArciumScalars(
  cipher: RescueCipherInstance,
  ciphertexts: readonly ArciumCiphertext[],
  nonce: ArrayLike<number>,
  expectedLength = ciphertexts.length
): bigint[] {
  return cipher.decrypt(
    normalizeCiphertexts(ciphertexts, expectedLength, "ciphertexts"),
    copyBytes(nonce, 16, "nonce")
  );
}

export function decryptArciumAgentVaultView(
  cipher: RescueCipherInstance,
  ciphertexts: readonly ArciumCiphertext[],
  nonce: ArrayLike<number>
): ArciumAgentVaultView {
  const values = decryptArciumScalars(
    cipher,
    ciphertexts,
    nonce,
    ARCIUM_AGENT_VAULT_SCALARS
  );
  return {
    free: values[0],
    locked: values[1],
    yieldEarned: values[2],
    spent: values[3],
    withdrawn: values[4],
    strategyShares: values[5],
    maxLockExpiresAt: values[6],
    yieldIndexCheckpointQ64: values[7],
  };
}

export function decryptArciumBudgetGrantView(
  cipher: RescueCipherInstance,
  ciphertexts: readonly ArciumCiphertext[],
  nonce: ArrayLike<number>
): ArciumBudgetGrantView {
  const values = decryptArciumScalars(
    cipher,
    ciphertexts,
    nonce,
    ARCIUM_BUDGET_GRANT_SCALARS
  );
  return {
    approved: values[0] === 1n,
    budgetId: values[1],
    requestNonce: values[2],
    amount: values[3],
    remaining: values[4],
    expiresAt: values[5],
    stateVersion: values[6],
    domainHashLo: values[7],
    domainHashHi: values[8],
    vaultConfigLo: values[9],
    vaultConfigHi: values[10],
    clientLo: values[11],
    clientHi: values[12],
    budgetGrantLo: values[13],
    budgetGrantHi: values[14],
  };
}

export function decryptArciumWithdrawalGrantView(
  cipher: RescueCipherInstance,
  ciphertexts: readonly ArciumCiphertext[],
  nonce: ArrayLike<number>
): ArciumWithdrawalGrantView {
  const values = decryptArciumScalars(
    cipher,
    ciphertexts,
    nonce,
    ARCIUM_WITHDRAWAL_GRANT_SCALARS
  );
  return {
    approved: values[0] === 1n,
    withdrawalId: values[1],
    amount: values[2],
    expiresAt: values[3],
    stateVersion: values[4],
    domainHashLo: values[5],
    domainHashHi: values[6],
    vaultConfigLo: values[7],
    vaultConfigHi: values[8],
    clientLo: values[9],
    clientHi: values[10],
    withdrawalGrantLo: values[11],
    withdrawalGrantHi: values[12],
    recipientLo: values[13],
    recipientHi: values[14],
  };
}

export async function fetchArciumMxePublicKeyWithRetry(
  provider: Parameters<typeof getMXEPublicKey>[0],
  programId: Parameters<typeof getMXEPublicKey>[1],
  options: FetchMxePublicKeyOptions = {}
): Promise<Uint8Array> {
  const attempts = options.attempts ?? 20;
  const delayMs = options.delayMs ?? 500;

  for (let attempt = 0; attempt < attempts; attempt++) {
    const publicKey = await getMXEPublicKey(provider, programId);
    if (publicKey) {
      return publicKey;
    }
    if (attempt + 1 < attempts) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  throw new Error(
    `Failed to fetch Arcium MXE public key after ${attempts} attempts`
  );
}
