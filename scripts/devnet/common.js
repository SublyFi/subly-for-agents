const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const anchor = require("@coral-xyz/anchor");
const nacl = require("tweetnacl");
const {
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
} = require("@solana/web3.js");

const ROOT = path.resolve(__dirname, "..", "..");
const LOCAL_ENV_PATH = path.join(ROOT, ".env.devnet.local");
const GENERATED_ENV_PATH = path.join(ROOT, ".env.devnet.generated");
const STATE_PATH = path.join(ROOT, "data", "devnet-state.json");

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function expandEnv(value) {
  return value.replace(
    /\$([A-Z_][A-Z0-9_]*)/g,
    (_match, name) => process.env[name] || ""
  );
}

function parseEnvAssignment(rawValue) {
  const value = rawValue.trim();
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    const quote = value[0];
    const unquoted = value.slice(1, -1);
    return quote === '"' ? expandEnv(unquoted) : unquoted;
  }
  return expandEnv(value);
}

function encodedEnvGroup(key) {
  if (key.endsWith("_HEX") || key.endsWith("_B64")) {
    const base = key.slice(0, -4);
    return [`${base}_HEX`, `${base}_B64`];
  }
  return [key];
}

function envGroupIsProtected(key, protectedKeys) {
  return encodedEnvGroup(key).some((groupKey) => protectedKeys.has(groupKey));
}

function clearAlternativeEncodedEnv(key, protectedKeys = new Set()) {
  const alternative = key.endsWith("_HEX")
    ? `${key.slice(0, -4)}_B64`
    : key.endsWith("_B64")
    ? `${key.slice(0, -4)}_HEX`
    : null;
  if (alternative && !protectedKeys.has(alternative)) {
    delete process.env[alternative];
  }
}

function loadEnvFile(filePath, options = {}) {
  if (!fs.existsSync(filePath)) {
    return;
  }
  const protectedKeys = options.protectedKeys || new Set();
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const match = trimmed.match(/^export\s+([A-Z0-9_]+)=(.*)$/);
    if (!match) {
      continue;
    }
    const [, key, rawValue] = match;
    if (envGroupIsProtected(key, protectedKeys)) {
      continue;
    }
    clearAlternativeEncodedEnv(key, protectedKeys);
    process.env[key] = parseEnvAssignment(rawValue);
  }
}

function loadDefaultEnvFiles() {
  const protectedKeys = new Set(Object.keys(process.env));
  loadEnvFile(GENERATED_ENV_PATH, { protectedKeys });
  loadEnvFile(LOCAL_ENV_PATH, { protectedKeys });
}

function loadKeypairFromFile(filePath) {
  const secretKey = Uint8Array.from(
    JSON.parse(fs.readFileSync(filePath, "utf8"))
  );
  return Keypair.fromSecretKey(secretKey);
}

function loadProvider() {
  const rpcUrl =
    process.env.ANCHOR_PROVIDER_URL || process.env.SUBLY402_SOLANA_RPC_URL;
  if (!rpcUrl) {
    throw new Error(
      "ANCHOR_PROVIDER_URL or SUBLY402_SOLANA_RPC_URL is required"
    );
  }
  const walletPath = requireEnv("ANCHOR_WALLET");
  const walletKeypair = loadKeypairFromFile(walletPath);
  const provider = new anchor.AnchorProvider(
    new anchor.web3.Connection(rpcUrl, {
      commitment: "confirmed",
    }),
    new anchor.Wallet(walletKeypair),
    {
      commitment: "confirmed",
      preflightCommitment: "confirmed",
    }
  );
  return provider;
}

function loadProgram(provider) {
  const idlPath = path.join(ROOT, "target", "idl", "subly402_vault.json");
  const idl = JSON.parse(fs.readFileSync(idlPath, "utf8"));
  return new anchor.Program(idl, provider);
}

function deriveVaultAddresses(governance, vaultId, programId) {
  const vaultIdBn = new anchor.BN(vaultId.toString());
  const [vaultConfigPda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("vault_config"),
      governance.toBuffer(),
      vaultIdBn.toArrayLike(Buffer, "le", 8),
    ],
    programId
  );
  const [vaultTokenAccountPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault_token"), vaultConfigPda.toBuffer()],
    programId
  );
  return { vaultConfigPda, vaultTokenAccountPda, vaultIdBn };
}

function decodeHex32(name, value) {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${name} must be 64 hex chars`);
  }
  return Array.from(Buffer.from(value, "hex"));
}

function randomSeedBase64() {
  return crypto.randomBytes(32).toString("base64");
}

function keypairFromSeedBase64(seedBase64) {
  const seed = Buffer.from(seedBase64, "base64");
  if (seed.length !== 32) {
    throw new Error("seed must decode to 32 bytes");
  }
  return Keypair.fromSeed(seed);
}

function ensureDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function saveState(state) {
  ensureDir(STATE_PATH);
  fs.writeFileSync(STATE_PATH, `${JSON.stringify(state, null, 2)}\n`);
}

function loadState() {
  if (!fs.existsSync(STATE_PATH)) {
    return null;
  }
  return JSON.parse(fs.readFileSync(STATE_PATH, "utf8"));
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\"'\"'`)}'`;
}

function writeGeneratedEnv(vars) {
  const lines = Object.entries(vars).map(([key, value]) => {
    return `export ${key}=${shellQuote(value)}`;
  });
  ensureDir(GENERATED_ENV_PATH);
  fs.writeFileSync(GENERATED_ENV_PATH, `${lines.join("\n")}\n`);
}

function readGeneratedEnvAssignments() {
  if (!fs.existsSync(GENERATED_ENV_PATH)) {
    return {};
  }
  const assignments = {};
  const lines = fs.readFileSync(GENERATED_ENV_PATH, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const match = trimmed.match(/^export\s+([A-Z0-9_]+)=(.*)$/);
    if (!match) {
      continue;
    }
    const [, key, rawValue] = match;
    assignments[key] = parseEnvAssignment(rawValue);
  }
  return assignments;
}

function updateGeneratedEnv(vars) {
  writeGeneratedEnv({
    ...readGeneratedEnvAssignments(),
    ...vars,
  });
}

function requireSdkArcium() {
  const modulePath = path.join(ROOT, "sdk", "dist", "arcium.js");
  const sourcePath = path.join(ROOT, "sdk", "src", "arcium.ts");
  const needsBuild =
    !fs.existsSync(modulePath) ||
    (fs.existsSync(sourcePath) &&
      fs.statSync(sourcePath).mtimeMs > fs.statSync(modulePath).mtimeMs);
  if (needsBuild) {
    const result = spawnSync("npm", ["--prefix", "sdk", "run", "build"], {
      cwd: ROOT,
      stdio: "inherit",
    });
    if (result.status !== 0) {
      throw new Error(
        "Failed to build sdk/dist/arcium.js. Run npm --prefix sdk run build and retry."
      );
    }
  }
  return require(modulePath);
}

async function fundAccount(provider, recipient, lamports) {
  const tx = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: provider.wallet.publicKey,
      toPubkey: recipient,
      lamports,
    })
  );
  await provider.sendAndConfirm(tx, []);
}

async function postJson(baseUrl, route, body, headers) {
  const response = await fetch(`${baseUrl}${route}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(headers || {}),
    },
    body: JSON.stringify(body),
  });
  return response;
}

async function getJson(baseUrl, route, headers) {
  return fetch(`${baseUrl}${route}`, {
    headers: headers || {},
  });
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value).sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0
    );
    return `{${entries
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function computePaymentDetailsHash(details) {
  return sha256hex(canonicalJson(details));
}

function computeRequestHash(
  { method, origin, pathAndQuery, bodySha256 },
  paymentDetailsHash
) {
  const preimage =
    `SUBLY402-SVM-V1-REQ\n` +
    `${method}\n` +
    `${origin}\n` +
    `${pathAndQuery}\n` +
    `${bodySha256}\n` +
    `${paymentDetailsHash}\n`;
  return sha256hex(preimage);
}

function signPaymentPayload(client, fields) {
  const message =
    `SUBLY402-SVM-V1-AUTH\n` +
    `${fields.version}\n` +
    `${fields.scheme}\n` +
    `${fields.paymentId}\n` +
    `${fields.client}\n` +
    `${fields.vault}\n` +
    `${fields.providerId}\n` +
    `${fields.payTo}\n` +
    `${fields.network}\n` +
    `${fields.assetMint}\n` +
    `${fields.amount}\n` +
    `${fields.requestHash}\n` +
    `${fields.paymentDetailsHash}\n` +
    `${fields.expiresAt}\n` +
    `${fields.nonce}\n`;
  return Buffer.from(
    nacl.sign.detached(Buffer.from(message), client.secretKey)
  ).toString("base64");
}

async function waitForEndpoint(label, fn, maxAttempts = 120, delayMs = 1000) {
  let lastError;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const value = await fn();
      if (value) {
        return value;
      }
    } catch (error) {
      lastError = error;
    }
    await sleep(delayMs);
  }
  if (lastError) {
    throw lastError;
  }
  throw new Error(`Timed out waiting for ${label}`);
}

module.exports = {
  GENERATED_ENV_PATH,
  ROOT,
  STATE_PATH,
  computePaymentDetailsHash,
  computeRequestHash,
  decodeHex32,
  deriveVaultAddresses,
  fundAccount,
  getJson,
  keypairFromSeedBase64,
  loadDefaultEnvFiles,
  loadEnvFile,
  loadProgram,
  loadProvider,
  loadState,
  postJson,
  randomSeedBase64,
  requireSdkArcium,
  requireEnv,
  saveState,
  sha256hex,
  signPaymentPayload,
  sleep,
  updateGeneratedEnv,
  waitForEndpoint,
  writeGeneratedEnv,
};
