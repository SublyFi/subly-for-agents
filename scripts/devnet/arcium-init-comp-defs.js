#!/usr/bin/env node

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const anchor = require("@coral-xyz/anchor");
const { AddressLookupTableProgram, SystemProgram } = require("@solana/web3.js");
const {
  getCircuitState,
  getArciumProgram,
  getCompDefAccAddress,
  getLookupTableAddress,
  getMXEAccAddress,
  getRawCircuitAccAddress,
} = require("@arcium-hq/client");

const {
  ROOT,
  loadDefaultEnvFiles,
  loadProgram,
  loadProvider,
} = require("./common");

const COMP_DEFS = [
  ["init_agent_vault", "initInitAgentVaultCompDef"],
  ["apply_deposit", "initApplyDepositCompDef"],
  ["settle_yield", "initSettleYieldCompDef"],
  ["owner_view", "initOwnerViewCompDef"],
  ["authorize_budget", "initAuthorizeBudgetCompDef"],
  ["reconcile_budget", "initReconcileBudgetCompDef"],
  ["authorize_withdrawal", "initAuthorizeWithdrawalCompDef"],
  ["reconcile_withdrawal", "initReconcileWithdrawalCompDef"],
  ["prepare_recovery_claim", "initPrepareRecoveryClaimCompDef"],
];
const MAX_UPLOAD_PER_TX_BYTES = 814;
const MAX_REALLOC_PER_IX = 10_240;
const MAX_EMBIGGEN_IX_PER_TX = 18;

function compDefOffset(name) {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(name))
    .digest()
    .readUInt32LE(0);
}

function selectedCompDefs() {
  const selected = process.env.SUBLY402_ARCIUM_COMP_DEF_NAMES;
  if (!selected) {
    return COMP_DEFS;
  }
  const names = new Set(
    selected
      .split(",")
      .map((name) => name.trim())
      .filter(Boolean)
  );
  return COMP_DEFS.filter(([name]) => names.has(name));
}

function isCompleted(compDef) {
  return getCircuitState(compDef.circuitSource) === "OnchainFinalized";
}

async function fetchCompDef(arciumProgram, compDefAccount) {
  return arciumProgram.account.computationDefinitionAccount.fetchNullable(
    compDefAccount,
    "confirmed"
  );
}

async function sendWithRetry(label, fn) {
  const maxAttempts = Number(
    process.env.SUBLY402_ARCIUM_UPLOAD_ATTEMPTS || "6"
  );
  let lastError;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      const message = error?.message || String(error);
      if (!/429|Too Many Requests|rate limit/i.test(message)) {
        throw error;
      }
      const delayMs = Math.min(30_000, 1000 * 2 ** attempt);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  throw new Error(`${label} failed after retries: ${lastError?.message}`);
}

async function ensureRawCircuitAccount(
  provider,
  arciumProgram,
  compDefAccount,
  compDefOffsetValue,
  mxeProgramId,
  rawCircuitIndex,
  requiredCircuitBytes,
  logging
) {
  const rawCircuitAccount = getRawCircuitAccAddress(
    compDefAccount,
    rawCircuitIndex
  );
  let account = await provider.connection.getAccountInfo(rawCircuitAccount);
  const signatures = [];

  if (!account) {
    const signature = await sendWithRetry("init raw circuit account", () =>
      arciumProgram.methods
        .initRawCircuitAcc(compDefOffsetValue, mxeProgramId, rawCircuitIndex)
        .accounts({ signer: provider.wallet.publicKey })
        .rpc()
    );
    signatures.push(signature);
    if (logging) {
      console.log(`Initiated raw circuit account ${rawCircuitIndex}`);
    }
    account = await provider.connection.getAccountInfo(rawCircuitAccount);
  }

  const requiredAccountSize = requiredCircuitBytes + 9;
  while (account.data.length < requiredAccountSize) {
    const remaining = requiredAccountSize - account.data.length;
    const ixCount = Math.min(
      MAX_EMBIGGEN_IX_PER_TX,
      Math.ceil(remaining / MAX_REALLOC_PER_IX)
    );
    const tx = new anchor.web3.Transaction();
    for (let index = 0; index < ixCount; index += 1) {
      // eslint-disable-next-line no-await-in-loop
      tx.add(
        await arciumProgram.methods
          .embiggenRawCircuitAcc(
            compDefOffsetValue,
            mxeProgramId,
            rawCircuitIndex
          )
          .accounts({ signer: provider.wallet.publicKey })
          .instruction()
      );
    }
    const previousLength = account.data.length;
    const signature = await sendWithRetry("resize raw circuit account", () =>
      provider.sendAndConfirm(tx, [], {
        commitment: "confirmed",
        preflightCommitment: "confirmed",
      })
    );
    signatures.push(signature);
    account = await provider.connection.getAccountInfo(rawCircuitAccount);
    if (logging) {
      console.log(
        `Resized raw circuit account ${rawCircuitIndex}: ${previousLength} -> ${account.data.length}`
      );
    }
  }

  return signatures;
}

async function uploadCircuitResumeSafe(
  provider,
  arciumProgram,
  name,
  mxeProgramId,
  rawCircuit,
  compDefOffsetValue,
  logging,
  chunkSize
) {
  const compDefAccount = getCompDefAccAddress(mxeProgramId, compDefOffsetValue);
  const signatures = await ensureRawCircuitAccount(
    provider,
    arciumProgram,
    compDefAccount,
    compDefOffsetValue,
    mxeProgramId,
    0,
    rawCircuit.length,
    logging
  );

  const txCount = Math.ceil(rawCircuit.length / MAX_UPLOAD_PER_TX_BYTES);
  const delayMs = Number(process.env.SUBLY402_ARCIUM_UPLOAD_DELAY_MS || "0");
  for (let cursor = 0; cursor < txCount; cursor += chunkSize) {
    const currentChunkSize = Math.min(chunkSize, txCount - cursor);
    if (logging) {
      console.log(
        `Uploading ${name} chunk ${cursor / chunkSize + 1} of ${Math.ceil(
          txCount / chunkSize
        )}`
      );
    }
    const promises = [];
    for (let index = 0; index < currentChunkSize; index += 1) {
      const circuitOffset = MAX_UPLOAD_PER_TX_BYTES * (cursor + index);
      const uploadData = Buffer.alloc(MAX_UPLOAD_PER_TX_BYTES);
      rawCircuit.copy(
        uploadData,
        0,
        circuitOffset,
        Math.min(circuitOffset + MAX_UPLOAD_PER_TX_BYTES, rawCircuit.length)
      );
      promises.push(
        sendWithRetry(`upload ${name} at ${circuitOffset}`, () =>
          arciumProgram.methods
            .uploadCircuit(
              compDefOffsetValue,
              mxeProgramId,
              0,
              Array.from(uploadData),
              circuitOffset
            )
            .accounts({ signer: provider.wallet.publicKey })
            .rpc()
        )
      );
    }
    // eslint-disable-next-line no-await-in-loop
    signatures.push(...(await Promise.all(promises)));
    if (delayMs > 0 && cursor + chunkSize < txCount) {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  signatures.push(
    await sendWithRetry(`finalize ${name}`, () =>
      arciumProgram.methods
        .finalizeComputationDefinition(compDefOffsetValue, mxeProgramId)
        .accounts({ signer: provider.wallet.publicKey })
        .rpc()
    )
  );
  return signatures;
}

async function uploadCircuitIfRequested(provider, name, mxeProgramId) {
  if (process.env.SUBLY402_ARCIUM_UPLOAD_CIRCUITS !== "1") {
    return null;
  }
  const circuitPath = path.join(ROOT, "build", `${name}.arcis`);
  if (!fs.existsSync(circuitPath)) {
    throw new Error(`${circuitPath} is missing. Run arcium build first.`);
  }
  const rawCircuit = fs.readFileSync(circuitPath);
  const chunkSize = Number(
    process.env.SUBLY402_ARCIUM_UPLOAD_CHUNK_SIZE || "1"
  );
  const logging = process.env.SUBLY402_ARCIUM_UPLOAD_LOGS === "1";
  const signatures = await uploadCircuitResumeSafe(
    provider,
    getArciumProgram(provider),
    name,
    mxeProgramId,
    rawCircuit,
    compDefOffset(name),
    logging,
    chunkSize
  );
  return {
    circuitPath: path.relative(ROOT, circuitPath),
    bytes: rawCircuit.length,
    signatures: signatures.length,
  };
}

async function main() {
  loadDefaultEnvFiles();

  const provider = loadProvider();
  anchor.setProvider(provider);

  const program = loadProgram(provider);
  const arciumProgram = getArciumProgram(provider);
  const mxeProgramId = program.programId;
  const mxeAccount = getMXEAccAddress(mxeProgramId);
  const mxe = await arciumProgram.account.mxeAccount.fetch(mxeAccount);
  const addressLookupTable = getLookupTableAddress(
    mxeProgramId,
    new anchor.BN(mxe.lutOffsetSlot)
  );
  const commonAccounts = {
    payer: provider.wallet.publicKey,
    mxeAccount,
    addressLookupTable,
    lutProgram: AddressLookupTableProgram.programId,
    arciumProgram: arciumProgram.programId,
    systemProgram: SystemProgram.programId,
  };

  const results = [];
  for (const [name, methodName] of selectedCompDefs()) {
    const offset = compDefOffset(name);
    const compDefAccount = getCompDefAccAddress(mxeProgramId, offset);
    let compDef = await fetchCompDef(arciumProgram, compDefAccount);
    let initializedSignature = null;
    if (!compDef) {
      initializedSignature = await program.methods[methodName]()
        .accountsPartial({
          ...commonAccounts,
          compDefAccount,
        })
        .rpc();
      compDef = await fetchCompDef(arciumProgram, compDefAccount);
    }

    if (isCompleted(compDef)) {
      results.push({
        name,
        offset,
        compDefAccount: compDefAccount.toBase58(),
        status: "completed",
        ...(initializedSignature ? { signature: initializedSignature } : {}),
      });
      continue;
    }

    const upload = await uploadCircuitIfRequested(provider, name, mxeProgramId);
    if (upload) {
      compDef = await fetchCompDef(arciumProgram, compDefAccount);
    }
    results.push({
      name,
      offset,
      compDefAccount: compDefAccount.toBase58(),
      status: isCompleted(compDef) ? "completed" : "pending_upload",
      ...(initializedSignature ? { signature: initializedSignature } : {}),
      ...(upload ? { upload } : {}),
    });
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        mxeAccount: mxeAccount.toBase58(),
        addressLookupTable: addressLookupTable.toBase58(),
        results,
      },
      null,
      2
    )
  );
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}

module.exports = {
  COMP_DEFS,
  compDefOffset,
};
