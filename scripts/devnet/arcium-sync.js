#!/usr/bin/env node

const anchor = require("@coral-xyz/anchor");

const {
  loadDefaultEnvFiles,
  loadProgram,
  loadProvider,
  loadState,
} = require("./common");
const {
  computeArciumDomainHashParts,
  fetchArciumMxePublicKeyWithRetry,
  splitU256Le,
} = require("./arcium-utils");

const PublicKey = anchor.web3.PublicKey;
const BUDGET_GRANT_STATUS_READY = 1;
const WITHDRAWAL_GRANT_STATUS_READY = 1;
const ARCIUM_GRANT_MEMCMP_VAULT_OFFSET = 9;

function bytesToHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function decodeFixedBytes(name, value, length = 32) {
  if (!value) {
    throw new Error(`${name} is required`);
  }
  const normalized = String(value).trim();
  const bytes = /^[0-9a-fA-F]{64}$/.test(normalized)
    ? Buffer.from(normalized, "hex")
    : Buffer.from(normalized, "base64");
  if (bytes.length !== length) {
    throw new Error(`${name} must decode to ${length} bytes`);
  }
  return new Uint8Array(bytes);
}

function decodeOptionalFixedBytes(env, names, length = 32) {
  for (const name of names) {
    if (env[name]) {
      return decodeFixedBytes(name, env[name], length);
    }
  }
  return null;
}

function decodeRequiredFixedBytes(env, names, length = 32) {
  const value = decodeOptionalFixedBytes(env, names, length);
  if (!value) {
    throw new Error(`${names.join(" or ")} is required`);
  }
  return value;
}

function numberValue(value) {
  if (typeof value === "number") {
    return value;
  }
  if (value && typeof value.toNumber === "function") {
    return value.toNumber();
  }
  return Number(value);
}

function bigintValue(value, field) {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error(`${field} must be a safe integer`);
    }
    return BigInt(value);
  }
  if (value && typeof value.toString === "function") {
    const stringValue = value.toString();
    if (/^-?[0-9]+$/.test(stringValue)) {
      return BigInt(stringValue);
    }
  }
  if (typeof value === "string" && /^-?[0-9]+$/.test(value)) {
    return BigInt(value);
  }
  throw new Error(`${field} must be an integer`);
}

function publicKeyFrom(value, field) {
  if (value instanceof PublicKey) {
    return value;
  }
  if (value && typeof value.toBase58 === "function") {
    return new PublicKey(value.toBase58());
  }
  try {
    return new PublicKey(value);
  } catch (error) {
    throw new Error(`${field} must be a valid public key`);
  }
}

function pubkeySplit(pubkey) {
  return splitU256Le(publicKeyFrom(pubkey, "pubkey").toBytes());
}

function assertBigintEqual(field, actual, expected) {
  if (actual !== expected) {
    throw new Error(
      `${field} mismatch: decrypted=${actual} account=${expected}`
    );
  }
}

function assertPubkeySplit(field, actualLo, actualHi, expectedPubkey) {
  const expected = pubkeySplit(expectedPubkey);
  if (actualLo !== expected.lo || actualHi !== expected.hi) {
    throw new Error(`${field} split does not match decrypted Arcium grant`);
  }
}

function recordAccount(record) {
  return record.account || record;
}

function recordPublicKey(record, field) {
  if (!record.publicKey) {
    throw new Error(`${field}.publicKey is required`);
  }
  return publicKeyFrom(record.publicKey, `${field}.publicKey`);
}

function byteArray(value, length, field) {
  if (value.length !== length) {
    throw new Error(`${field} must contain ${length} bytes`);
  }
  return Array.from(value, (byte, index) => {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`${field}[${index}] must be a byte`);
    }
    return byte;
  });
}

function ciphertextArrays(ciphertexts, expectedLength, field) {
  if (ciphertexts.length !== expectedLength) {
    throw new Error(`${field} must contain ${expectedLength} ciphertexts`);
  }
  return ciphertexts.map((ciphertext, index) =>
    byteArray(ciphertext, 32, `${field}[${index}]`)
  );
}

function stringifyJsonExact(value) {
  if (value === null) {
    return "null";
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Cannot serialize non-finite number");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stringifyJsonExact(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.entries(value)
      .map(
        ([key, item]) => `${JSON.stringify(key)}:${stringifyJsonExact(item)}`
      )
      .join(",")}}`;
  }
  throw new Error(`Cannot serialize ${typeof value}`);
}

async function postJsonExact(baseUrl, route, body, headers) {
  return fetch(`${baseUrl}${route}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(headers || {}),
    },
    body: stringifyJsonExact(body),
  });
}

function jsonDisplay(value) {
  return JSON.stringify(
    value,
    (_key, item) => (typeof item === "bigint" ? item.toString() : item),
    2
  );
}

function adminHeaders(env = process.env) {
  const token = env.SUBLY402_ADMIN_AUTH_TOKEN;
  if (!token) {
    throw new Error("SUBLY402_ADMIN_AUTH_TOKEN is required for arcium sync");
  }
  return { Authorization: `Bearer ${token}` };
}

function budgetGrantLoadRequestFromAccount(record, options = {}) {
  const budgetGrant = recordPublicKey(record, "BudgetGrant");
  const account = recordAccount(record);
  if (numberValue(account.status) !== BUDGET_GRANT_STATUS_READY) {
    throw new Error(`BudgetGrant ${budgetGrant.toBase58()} is not ready`);
  }
  if (!options.expectedDomainHash) {
    throw new Error("expectedDomainHash is required for budget grants");
  }
  if (!options.teeX25519Pubkey) {
    throw new Error("teeX25519Pubkey is required for budget grants");
  }
  if (!options.mxePublicKey) {
    throw new Error("mxePublicKey is required for budget grants");
  }

  return {
    grantId: budgetGrant.toBase58(),
    vaultConfig: publicKeyFrom(account.vaultConfig, "vaultConfig").toBase58(),
    client: publicKeyFrom(account.client, "client").toBase58(),
    budgetId: bigintValue(account.budgetId, "budgetId"),
    requestNonce: bigintValue(account.requestNonce, "requestNonce"),
    expiresAt: bigintValue(account.expiresAt, "expiresAt"),
    stateVersionAtAuthorization: bigintValue(
      account.stateVersionAtAuthorization,
      "stateVersionAtAuthorization"
    ),
    domainHashLo: options.expectedDomainHash.lo,
    domainHashHi: options.expectedDomainHash.hi,
    teeX25519Pubkey: byteArray(options.teeX25519Pubkey, 32, "teeX25519Pubkey"),
    mxePublicKey: byteArray(options.mxePublicKey, 32, "mxePublicKey"),
    grantCiphertexts: ciphertextArrays(
      account.grantCiphertexts,
      15,
      "grantCiphertexts"
    ),
    grantNonce: byteArray(account.grantNonce, 16, "grantNonce"),
  };
}

function withdrawalGrantLoadRequestFromAccount(record, options = {}) {
  const withdrawalGrant = recordPublicKey(record, "WithdrawalGrant");
  const account = recordAccount(record);
  if (numberValue(account.status) !== WITHDRAWAL_GRANT_STATUS_READY) {
    throw new Error(
      `WithdrawalGrant ${withdrawalGrant.toBase58()} is not ready`
    );
  }
  if (!options.expectedDomainHash) {
    throw new Error("expectedDomainHash is required for withdrawal grants");
  }
  if (!options.teeX25519Pubkey) {
    throw new Error("teeX25519Pubkey is required for withdrawal grants");
  }
  if (!options.mxePublicKey) {
    throw new Error("mxePublicKey is required for withdrawal grants");
  }

  return {
    grantId: withdrawalGrant.toBase58(),
    vaultConfig: publicKeyFrom(account.vaultConfig, "vaultConfig").toBase58(),
    client: publicKeyFrom(account.client, "client").toBase58(),
    withdrawalId: bigintValue(account.withdrawalId, "withdrawalId"),
    recipientAta: publicKeyFrom(
      account.recipientAta,
      "recipientAta"
    ).toBase58(),
    expiresAt: bigintValue(account.expiresAt, "expiresAt"),
    stateVersionAtAuthorization: bigintValue(
      account.stateVersionAtAuthorization,
      "stateVersionAtAuthorization"
    ),
    domainHashLo: options.expectedDomainHash.lo,
    domainHashHi: options.expectedDomainHash.hi,
    teeX25519Pubkey: byteArray(options.teeX25519Pubkey, 32, "teeX25519Pubkey"),
    mxePublicKey: byteArray(options.mxePublicKey, 32, "mxePublicKey"),
    grantCiphertexts: ciphertextArrays(
      account.grantCiphertexts,
      15,
      "grantCiphertexts"
    ),
    grantNonce: byteArray(account.grantNonce, 16, "grantNonce"),
    consumed: false,
  };
}

function grantSkipReason(
  record,
  expectedStatus,
  vaultConfig,
  now,
  includeExpired
) {
  const account = recordAccount(record);
  if (
    publicKeyFrom(account.vaultConfig, "vaultConfig").toBase58() !==
    vaultConfig.toBase58()
  ) {
    return "different-vault";
  }
  if (numberValue(account.status) !== expectedStatus) {
    return `status-${numberValue(account.status)}`;
  }
  const expiresAt = bigintValue(account.expiresAt, "expiresAt");
  if (!includeExpired && expiresAt <= BigInt(now)) {
    return "expired";
  }
  return null;
}

function parseArgs(argv) {
  const options = {
    dryRun: false,
    includeExpired: false,
    budgetOnly: false,
    withdrawalOnly: false,
  };
  for (const arg of argv) {
    if (arg === "--dry-run") {
      options.dryRun = true;
    } else if (arg === "--include-expired") {
      options.includeExpired = true;
    } else if (arg === "--budget-only") {
      options.budgetOnly = true;
    } else if (arg === "--withdrawal-only") {
      options.withdrawalOnly = true;
    } else {
      throw new Error(
        `Unknown argument ${arg}; expected --dry-run, --include-expired, --budget-only, or --withdrawal-only`
      );
    }
  }
  if (options.budgetOnly && options.withdrawalOnly) {
    throw new Error("--budget-only and --withdrawal-only cannot be combined");
  }
  return options;
}

async function loadGrantRecords(program, accountName, vaultConfig) {
  return program.account[accountName].all([
    {
      memcmp: {
        offset: ARCIUM_GRANT_MEMCMP_VAULT_OFFSET,
        bytes: vaultConfig.toBase58(),
      },
    },
  ]);
}

async function resolveMxePublicKey(env, provider, programId) {
  const configured = decodeOptionalFixedBytes(
    env,
    [
      "SUBLY402_ARCIUM_MXE_PUBLIC_KEY_HEX",
      "SUBLY402_ARCIUM_MXE_PUBLIC_KEY_B64",
    ],
    32
  );
  if (configured) {
    return configured;
  }
  return fetchArciumMxePublicKeyWithRetry(provider, programId, {
    attempts: Number(env.SUBLY402_ARCIUM_MXE_FETCH_ATTEMPTS || "20"),
    delayMs: Number(env.SUBLY402_ARCIUM_MXE_FETCH_DELAY_MS || "500"),
  });
}

async function syncRequests({ enclaveUrl, headers, dryRun, route, requests }) {
  const loaded = [];
  for (const request of requests) {
    if (dryRun) {
      loaded.push({ grantId: request.grantId, dryRun: true, request });
      continue;
    }
    const response = await postJsonExact(enclaveUrl, route, request, headers);
    if (!response.ok) {
      throw new Error(
        `${route} failed for ${request.grantId}: ${
          response.status
        } ${await response.text()}`
      );
    }
    loaded.push(await response.json());
  }
  return loaded;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  loadDefaultEnvFiles();

  const state = loadState();
  if (!state?.vaultConfig) {
    throw new Error(
      "data/devnet-state.json with vaultConfig is required. Run devnet:bootstrap first."
    );
  }

  const provider = loadProvider();
  anchor.setProvider(provider);
  const program = loadProgram(provider);
  if (!program.account.budgetGrant || !program.account.withdrawalGrant) {
    throw new Error(
      "Generated IDL is missing Arcium grant accounts. Run anchor build first."
    );
  }

  const vaultConfig = new PublicKey(state.vaultConfig);
  const [arciumConfigPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("arcium_config"), vaultConfig.toBuffer()],
    program.programId
  );
  const [vaultConfigAccount, arciumConfigAccount] = await Promise.all([
    program.account.vaultConfig.fetch(vaultConfig),
    program.account.arciumConfig.fetch(arciumConfigPda),
  ]);

  const mxePublicKey = await resolveMxePublicKey(
    process.env,
    provider,
    program.programId
  );
  const teeX25519Pubkey = byteArray(
    arciumConfigAccount.teeX25519Pubkey,
    32,
    "teeX25519Pubkey"
  );
  const budgetDomainHash = computeArciumDomainHashParts({
    instructionKind: "authorize_budget",
    programId: program.programId,
    vaultConfig,
    vaultConfigAccount,
    arciumConfigAccount,
  });
  const withdrawalDomainHash = computeArciumDomainHashParts({
    instructionKind: "authorize_withdrawal",
    programId: program.programId,
    vaultConfig,
    vaultConfigAccount,
    arciumConfigAccount,
  });
  const now = Math.floor(Date.now() / 1000);

  const [budgetRecords, withdrawalRecords] = await Promise.all([
    options.withdrawalOnly
      ? Promise.resolve([])
      : loadGrantRecords(program, "budgetGrant", vaultConfig),
    options.budgetOnly
      ? Promise.resolve([])
      : loadGrantRecords(program, "withdrawalGrant", vaultConfig),
  ]);

  const budgetRequests = [];
  const withdrawalRequests = [];
  const skipped = [];

  for (const record of budgetRecords) {
    const reason = grantSkipReason(
      record,
      BUDGET_GRANT_STATUS_READY,
      vaultConfig,
      now,
      options.includeExpired
    );
    if (reason) {
      skipped.push({
        type: "budget",
        grantId: record.publicKey.toBase58(),
        reason,
      });
      continue;
    }
    budgetRequests.push(
      budgetGrantLoadRequestFromAccount(record, {
        expectedDomainHash: budgetDomainHash,
        teeX25519Pubkey,
        mxePublicKey,
      })
    );
  }

  for (const record of withdrawalRecords) {
    const reason = grantSkipReason(
      record,
      WITHDRAWAL_GRANT_STATUS_READY,
      vaultConfig,
      now,
      options.includeExpired
    );
    if (reason) {
      skipped.push({
        type: "withdrawal",
        grantId: record.publicKey.toBase58(),
        reason,
      });
      continue;
    }
    withdrawalRequests.push(
      withdrawalGrantLoadRequestFromAccount(record, {
        expectedDomainHash: withdrawalDomainHash,
        teeX25519Pubkey,
        mxePublicKey,
      })
    );
  }

  const enclaveUrl =
    process.env.SUBLY402_TEST_ENCLAVE_URL || "http://127.0.0.1:3100";
  const headers = options.dryRun ? {} : adminHeaders(process.env);
  const [budgetLoaded, withdrawalLoaded] = await Promise.all([
    syncRequests({
      enclaveUrl,
      headers,
      dryRun: options.dryRun,
      route: "/v1/admin/arcium/budget-grant-encrypted",
      requests: budgetRequests,
    }),
    syncRequests({
      enclaveUrl,
      headers,
      dryRun: options.dryRun,
      route: "/v1/admin/arcium/withdrawal-grant-encrypted",
      requests: withdrawalRequests,
    }),
  ]);

  console.log(
    jsonDisplay({
      ok: true,
      dryRun: options.dryRun,
      enclaveUrl,
      vaultConfig: vaultConfig.toBase58(),
      arciumConfig: arciumConfigPda.toBase58(),
      mxePublicKeyHex: bytesToHex(mxePublicKey),
      scanned: {
        budgetGrants: budgetRecords.length,
        withdrawalGrants: withdrawalRecords.length,
      },
      loaded: {
        budgetGrants: budgetLoaded,
        withdrawalGrants: withdrawalLoaded,
      },
      skipped,
    })
  );
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}

module.exports = {
  BUDGET_GRANT_STATUS_READY,
  WITHDRAWAL_GRANT_STATUS_READY,
  adminHeaders,
  bigintValue,
  budgetGrantLoadRequestFromAccount,
  computeArciumDomainHashParts,
  decodeFixedBytes,
  decodeOptionalFixedBytes,
  decodeRequiredFixedBytes,
  grantSkipReason,
  jsonDisplay,
  parseArgs,
  postJsonExact,
  pubkeySplit,
  stringifyJsonExact,
  withdrawalGrantLoadRequestFromAccount,
};
