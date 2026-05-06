#!/usr/bin/env node

const anchor = require("@coral-xyz/anchor");

const {
  loadDefaultEnvFiles,
  loadProgram,
  loadProvider,
  loadState,
  saveState,
  updateGeneratedEnv,
} = require("./common");
const {
  computeArciumDomainHashParts,
  fetchArciumMxePublicKeyWithRetry,
} = require("./arcium-utils");

const ARCIUM_STATUS = {
  disabled: 0,
  mirror: 1,
  enforced: 2,
  paused: 3,
};

const ARCIUM_STATUS_NAME = Object.fromEntries(
  Object.entries(ARCIUM_STATUS).map(([name, value]) => [value, name])
);

function parseStatus(value, defaultStatus = "mirror") {
  const normalized = String(value || defaultStatus)
    .trim()
    .toLowerCase();
  if (/^[0-3]$/.test(normalized)) {
    return Number(normalized);
  }
  if (Object.prototype.hasOwnProperty.call(ARCIUM_STATUS, normalized)) {
    return ARCIUM_STATUS[normalized];
  }
  throw new Error(
    `Invalid SUBLY402_ARCIUM_STATUS ${value}; expected disabled, mirror, enforced, paused, or 0-3`
  );
}

function statusName(status) {
  return ARCIUM_STATUS_NAME[status] || `unknown:${status}`;
}

function parsePublicKey(name, value, fallback) {
  const resolved = value || fallback;
  if (!resolved) {
    throw new Error(`${name} is required`);
  }
  return new anchor.web3.PublicKey(resolved);
}

function parseU16(name, value, fallback) {
  const raw = value ?? fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 10_000) {
    throw new Error(`${name} must be an integer between 0 and 10000`);
  }
  return parsed;
}

function parseU32(name, value, fallback) {
  const raw = value ?? fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 0xffffffff) {
    throw new Error(`${name} must be a u32 integer`);
  }
  return parsed;
}

function parseU64Bn(name, value, fallback) {
  const raw = value ?? fallback;
  if (!/^[0-9]+$/.test(String(raw))) {
    throw new Error(`${name} must be an unsigned integer`);
  }
  return new anchor.BN(String(raw));
}

function decodeX25519PublicKey(value) {
  if (!value) {
    return new Array(32).fill(0);
  }
  const normalized = String(value).trim();
  let bytes;
  if (/^[0-9a-fA-F]{64}$/.test(normalized)) {
    bytes = Buffer.from(normalized, "hex");
  } else {
    bytes = Buffer.from(normalized, "base64");
  }
  if (bytes.length !== 32) {
    throw new Error(
      "SUBLY402_ARCIUM_TEE_X25519_PUBKEY_HEX must be 64 hex chars or SUBLY402_ARCIUM_TEE_X25519_PUBKEY_B64 must decode to 32 bytes"
    );
  }
  return Array.from(bytes);
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

function configuredMxePublicKey(env) {
  if (env.SUBLY402_ARCIUM_MXE_PUBLIC_KEY_HEX) {
    return decodeFixedBytes(
      "SUBLY402_ARCIUM_MXE_PUBLIC_KEY_HEX",
      env.SUBLY402_ARCIUM_MXE_PUBLIC_KEY_HEX
    );
  }
  if (env.SUBLY402_ARCIUM_MXE_PUBLIC_KEY_B64) {
    return decodeFixedBytes(
      "SUBLY402_ARCIUM_MXE_PUBLIC_KEY_B64",
      env.SUBLY402_ARCIUM_MXE_PUBLIC_KEY_B64
    );
  }
  return null;
}

function bytesToHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function pubkeyEquals(left, right) {
  return left.toBase58() === right.toBase58();
}

function bnEquals(left, right) {
  return new anchor.BN(left).eq(new anchor.BN(right));
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

function isDefaultPubkey(value) {
  return pubkeyEquals(value, anchor.web3.PublicKey.default);
}

function assertDeploymentConfigured(config) {
  const pubkeyFields = [
    ["SUBLY402_ARCIUM_PROGRAM_ID", "arciumProgramId"],
    ["SUBLY402_ARCIUM_MXE_ACCOUNT", "mxeAccount"],
    ["SUBLY402_ARCIUM_CLUSTER_ACCOUNT", "clusterAccount"],
    ["SUBLY402_ARCIUM_MEMPOOL_ACCOUNT", "mempoolAccount"],
  ];
  for (const [envName, field] of pubkeyFields) {
    if (isDefaultPubkey(config[field])) {
      throw new Error(
        `${envName} is required and cannot be the default pubkey`
      );
    }
  }
  if (config.teeX25519Pubkey.every((byte) => Number(byte) === 0)) {
    throw new Error(
      "SUBLY402_ARCIUM_TEE_X25519_PUBKEY_HEX or SUBLY402_ARCIUM_TEE_X25519_PUBKEY_B64 is required"
    );
  }
}

function arciumStateFromAccount(account, arciumConfigPda) {
  return {
    status: statusName(numberValue(account.status)),
    statusCode: numberValue(account.status),
    arciumConfig: arciumConfigPda?.toBase58(),
    arciumProgramId: account.arciumProgramId.toBase58(),
    mxeAccount: account.mxeAccount.toBase58(),
    clusterAccount: account.clusterAccount.toBase58(),
    mempoolAccount: account.mempoolAccount.toBase58(),
    compDefVersion: numberValue(account.compDefVersion),
    teeX25519PubkeyHex: bytesToHex(account.teeX25519Pubkey),
    strategyController: account.strategyController.toBase58(),
    minLiquidReserveBps: numberValue(account.minLiquidReserveBps),
    maxStrategyAllocationBps: numberValue(account.maxStrategyAllocationBps),
    settlementBufferAmount: account.settlementBufferAmount.toString(),
    strategyWithdrawalSlaSec: account.strategyWithdrawalSlaSec.toString(),
  };
}

function statusRequiresDeployment(status) {
  return status === ARCIUM_STATUS.mirror || status === ARCIUM_STATUS.enforced;
}

async function resolveMxePublicKey(env, provider, programId) {
  const configured = configuredMxePublicKey(env);
  if (configured) {
    return configured;
  }
  return fetchArciumMxePublicKeyWithRetry(provider, programId, {
    attempts: Number(env.SUBLY402_ARCIUM_MXE_FETCH_ATTEMPTS || "20"),
    delayMs: Number(env.SUBLY402_ARCIUM_MXE_FETCH_DELAY_MS || "500"),
  });
}

function buildDesiredConfig(env, state, status, options = {}) {
  const existing = state.arcium || {};
  const requiresDeployment =
    options.requireDeployment ?? statusRequiresDeployment(status);
  const zeroPubkey = anchor.web3.PublicKey.default.toBase58();
  const arciumProgramId = parsePublicKey(
    "SUBLY402_ARCIUM_PROGRAM_ID",
    env.SUBLY402_ARCIUM_PROGRAM_ID,
    existing.arciumProgramId || (requiresDeployment ? undefined : zeroPubkey)
  );
  const mxeAccount = parsePublicKey(
    "SUBLY402_ARCIUM_MXE_ACCOUNT",
    env.SUBLY402_ARCIUM_MXE_ACCOUNT,
    existing.mxeAccount || (requiresDeployment ? undefined : zeroPubkey)
  );
  const clusterAccount = parsePublicKey(
    "SUBLY402_ARCIUM_CLUSTER_ACCOUNT",
    env.SUBLY402_ARCIUM_CLUSTER_ACCOUNT,
    existing.clusterAccount || (requiresDeployment ? undefined : zeroPubkey)
  );
  const mempoolAccount = parsePublicKey(
    "SUBLY402_ARCIUM_MEMPOOL_ACCOUNT",
    env.SUBLY402_ARCIUM_MEMPOOL_ACCOUNT,
    existing.mempoolAccount || (requiresDeployment ? undefined : zeroPubkey)
  );
  const teeX25519Pubkey = decodeX25519PublicKey(
    env.SUBLY402_ARCIUM_TEE_X25519_PUBKEY_HEX ||
      env.SUBLY402_ARCIUM_TEE_X25519_PUBKEY_B64 ||
      existing.teeX25519PubkeyHex
  );

  const desired = {
    arciumProgramId,
    mxeAccount,
    clusterAccount,
    mempoolAccount,
    compDefVersion: parseU32(
      "SUBLY402_ARCIUM_COMP_DEF_VERSION",
      env.SUBLY402_ARCIUM_COMP_DEF_VERSION,
      existing.compDefVersion ?? "0"
    ),
    teeX25519Pubkey,
    strategyController: parsePublicKey(
      "SUBLY402_ARCIUM_STRATEGY_CONTROLLER",
      env.SUBLY402_ARCIUM_STRATEGY_CONTROLLER,
      existing.strategyController || state.governance
    ),
    minLiquidReserveBps: parseU16(
      "SUBLY402_ARCIUM_MIN_LIQUID_RESERVE_BPS",
      env.SUBLY402_ARCIUM_MIN_LIQUID_RESERVE_BPS,
      existing.minLiquidReserveBps ?? "0"
    ),
    maxStrategyAllocationBps: parseU16(
      "SUBLY402_ARCIUM_MAX_STRATEGY_ALLOCATION_BPS",
      env.SUBLY402_ARCIUM_MAX_STRATEGY_ALLOCATION_BPS,
      existing.maxStrategyAllocationBps ?? "10000"
    ),
    settlementBufferAmount: parseU64Bn(
      "SUBLY402_ARCIUM_SETTLEMENT_BUFFER_AMOUNT",
      env.SUBLY402_ARCIUM_SETTLEMENT_BUFFER_AMOUNT,
      existing.settlementBufferAmount ?? "0"
    ),
    strategyWithdrawalSlaSec: parseU64Bn(
      "SUBLY402_ARCIUM_STRATEGY_WITHDRAWAL_SLA_SEC",
      env.SUBLY402_ARCIUM_STRATEGY_WITHDRAWAL_SLA_SEC,
      existing.strategyWithdrawalSlaSec ?? "3600"
    ),
  };
  if (requiresDeployment) {
    assertDeploymentConfigured(desired);
  }
  return desired;
}

function findConfigMismatches(account, desired) {
  const mismatches = [];
  const comparePubkey = (field, desiredValue) => {
    if (!pubkeyEquals(account[field], desiredValue)) {
      mismatches.push(field);
    }
  };
  comparePubkey("arciumProgramId", desired.arciumProgramId);
  comparePubkey("mxeAccount", desired.mxeAccount);
  comparePubkey("clusterAccount", desired.clusterAccount);
  comparePubkey("mempoolAccount", desired.mempoolAccount);
  comparePubkey("strategyController", desired.strategyController);
  if (numberValue(account.compDefVersion) !== desired.compDefVersion) {
    mismatches.push("compDefVersion");
  }
  if (
    Buffer.from(account.teeX25519Pubkey).compare(
      Buffer.from(desired.teeX25519Pubkey)
    ) !== 0
  ) {
    mismatches.push("teeX25519Pubkey");
  }
  if (
    numberValue(account.minLiquidReserveBps) !== desired.minLiquidReserveBps
  ) {
    mismatches.push("minLiquidReserveBps");
  }
  if (
    numberValue(account.maxStrategyAllocationBps) !==
    desired.maxStrategyAllocationBps
  ) {
    mismatches.push("maxStrategyAllocationBps");
  }
  if (
    !bnEquals(account.settlementBufferAmount, desired.settlementBufferAmount)
  ) {
    mismatches.push("settlementBufferAmount");
  }
  if (
    !bnEquals(
      account.strategyWithdrawalSlaSec,
      desired.strategyWithdrawalSlaSec
    )
  ) {
    mismatches.push("strategyWithdrawalSlaSec");
  }
  return mismatches;
}

async function setArciumStatus(
  program,
  provider,
  vaultConfigPda,
  arciumConfigPda,
  status
) {
  await program.methods
    .setArciumStatus(status)
    .accountsPartial({
      governance: provider.wallet.publicKey,
      vaultConfig: vaultConfigPda,
      arciumConfig: arciumConfigPda,
    })
    .rpc();
}

async function updateArciumDeployment(
  program,
  provider,
  vaultConfigPda,
  arciumConfigPda,
  desired
) {
  if (!program.methods.updateArciumDeployment) {
    throw new Error(
      "Generated IDL is missing updateArciumDeployment. Run anchor build and redeploy before rotating Arcium config."
    );
  }
  await program.methods
    .updateArciumDeployment(
      desired.arciumProgramId,
      desired.mxeAccount,
      desired.clusterAccount,
      desired.mempoolAccount,
      desired.compDefVersion,
      desired.teeX25519Pubkey
    )
    .accountsPartial({
      governance: provider.wallet.publicKey,
      vaultConfig: vaultConfigPda,
      arciumConfig: arciumConfigPda,
    })
    .rpc();
}

async function main() {
  loadDefaultEnvFiles();

  const state = loadState();
  if (!state) {
    throw new Error(
      "data/devnet-state.json is missing. Run devnet:bootstrap first."
    );
  }
  if (!state.vaultConfig) {
    throw new Error(
      "state.vaultConfig is missing. Run devnet:bootstrap first."
    );
  }

  const provider = loadProvider();
  anchor.setProvider(provider);
  const program = loadProgram(provider);
  if (
    !program.methods.initializeArciumConfig ||
    !program.methods.setArciumStatus
  ) {
    throw new Error(
      "Generated IDL is missing Arcium config methods. Run anchor build first."
    );
  }

  const targetStatus = parseStatus(
    process.env.SUBLY402_ARCIUM_STATUS,
    state.arciumStatus || state.arcium?.status || "mirror"
  );

  const vaultConfigPda = new anchor.web3.PublicKey(state.vaultConfig);
  const [arciumConfigPda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("arcium_config"), vaultConfigPda.toBuffer()],
    program.programId
  );
  const accountInfo = await provider.connection.getAccountInfo(arciumConfigPda);
  let existingArciumConfig = null;
  let initialized = false;
  let statusTransitions = [];

  if (accountInfo) {
    existingArciumConfig = await program.account.arciumConfig.fetch(
      arciumConfigPda
    );
  }

  const stateForDesired = existingArciumConfig
    ? {
        ...state,
        arcium: arciumStateFromAccount(existingArciumConfig, arciumConfigPda),
      }
    : state;
  const desired = buildDesiredConfig(
    process.env,
    stateForDesired,
    targetStatus,
    {
      requireDeployment: !accountInfo || statusRequiresDeployment(targetStatus),
    }
  );

  if (!accountInfo) {
    if (
      targetStatus === ARCIUM_STATUS.enforced &&
      process.env.SUBLY402_ARCIUM_ALLOW_ENFORCED !== "1"
    ) {
      throw new Error(
        "Refusing to enter enforced mode without SUBLY402_ARCIUM_ALLOW_ENFORCED=1"
      );
    }
    const initialStatus =
      targetStatus === ARCIUM_STATUS.enforced
        ? ARCIUM_STATUS.mirror
        : targetStatus;
    await program.methods
      .initializeArciumConfig(
        initialStatus,
        desired.arciumProgramId,
        desired.mxeAccount,
        desired.clusterAccount,
        desired.mempoolAccount,
        desired.compDefVersion,
        desired.teeX25519Pubkey,
        desired.strategyController,
        desired.minLiquidReserveBps,
        desired.maxStrategyAllocationBps,
        desired.settlementBufferAmount,
        desired.strategyWithdrawalSlaSec
      )
      .accountsPartial({
        governance: provider.wallet.publicKey,
        vaultConfig: vaultConfigPda,
        arciumConfig: arciumConfigPda,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();
    initialized = true;
    statusTransitions.push(statusName(initialStatus));
  } else {
    if (
      targetStatus === ARCIUM_STATUS.enforced &&
      numberValue(existingArciumConfig.status) !== ARCIUM_STATUS.enforced &&
      process.env.SUBLY402_ARCIUM_ALLOW_ENFORCED !== "1"
    ) {
      throw new Error(
        "Refusing to enter enforced mode without SUBLY402_ARCIUM_ALLOW_ENFORCED=1"
      );
    }
    const mismatches = findConfigMismatches(existingArciumConfig, desired);
    if (mismatches.length > 0) {
      const deploymentFields = new Set([
        "arciumProgramId",
        "mxeAccount",
        "clusterAccount",
        "mempoolAccount",
        "compDefVersion",
        "teeX25519Pubkey",
      ]);
      const canRotateDeployment =
        process.env.SUBLY402_ARCIUM_ALLOW_CONFIG_ROTATION === "1" &&
        mismatches.every((field) => deploymentFields.has(field));
      if (canRotateDeployment) {
        await updateArciumDeployment(
          program,
          provider,
          vaultConfigPda,
          arciumConfigPda,
          desired
        );
        statusTransitions.push("deployment-updated");
        existingArciumConfig = await program.account.arciumConfig.fetch(
          arciumConfigPda
        );
      } else {
        const suffix = mismatches.every((field) => deploymentFields.has(field))
          ? " Set SUBLY402_ARCIUM_ALLOW_CONFIG_ROTATION=1 after redeploying a program that includes updateArciumDeployment."
          : "";
        throw new Error(
          `Existing ArciumConfig differs in immutable fields: ${mismatches.join(
            ", "
          )}. Deploy a new vault or add an explicit config rotation instruction.${suffix}`
        );
      }
    }
    const remainingMismatches = findConfigMismatches(
      existingArciumConfig,
      desired
    );
    if (remainingMismatches.length > 0) {
      throw new Error(
        `Existing ArciumConfig still differs after rotation: ${remainingMismatches.join(
          ", "
        )}.`
      );
    }
  }

  let arciumConfig =
    existingArciumConfig ||
    (await program.account.arciumConfig.fetch(arciumConfigPda));
  if (
    targetStatus === ARCIUM_STATUS.enforced &&
    numberValue(arciumConfig.status) !== ARCIUM_STATUS.enforced &&
    numberValue(arciumConfig.status) !== ARCIUM_STATUS.mirror
  ) {
    await setArciumStatus(
      program,
      provider,
      vaultConfigPda,
      arciumConfigPda,
      ARCIUM_STATUS.mirror
    );
    statusTransitions.push("mirror");
    arciumConfig = await program.account.arciumConfig.fetch(arciumConfigPda);
  }
  if (numberValue(arciumConfig.status) !== targetStatus) {
    await setArciumStatus(
      program,
      provider,
      vaultConfigPda,
      arciumConfigPda,
      targetStatus
    );
    statusTransitions.push(statusName(targetStatus));
    arciumConfig = await program.account.arciumConfig.fetch(arciumConfigPda);
  }

  const mxePublicKey = statusRequiresDeployment(
    numberValue(arciumConfig.status)
  )
    ? await resolveMxePublicKey(process.env, provider, program.programId)
    : null;
  const mxePublicKeyHex = mxePublicKey ? bytesToHex(mxePublicKey) : undefined;
  const vaultConfigAccount = statusRequiresDeployment(
    numberValue(arciumConfig.status)
  )
    ? await program.account.vaultConfig.fetch(vaultConfigPda)
    : null;
  const budgetDomainHash = vaultConfigAccount
    ? computeArciumDomainHashParts({
        instructionKind: "authorize_budget",
        programId: program.programId,
        vaultConfig: vaultConfigPda,
        vaultConfigAccount,
        arciumConfigAccount: arciumConfig,
      })
    : null;
  const withdrawalDomainHash = vaultConfigAccount
    ? computeArciumDomainHashParts({
        instructionKind: "authorize_withdrawal",
        programId: program.programId,
        vaultConfig: vaultConfigPda,
        vaultConfigAccount,
        arciumConfigAccount: arciumConfig,
      })
    : null;
  const nextState = {
    ...state,
    arciumConfig: arciumConfigPda.toBase58(),
    arciumStatus: statusName(numberValue(arciumConfig.status)),
    arcium: {
      ...arciumStateFromAccount(arciumConfig, arciumConfigPda),
      ...(mxePublicKeyHex ? { mxePublicKeyHex } : {}),
      ...(budgetDomainHash
        ? {
            authorizeBudgetDomainHash: {
              lo: budgetDomainHash.lo.toString(),
              hi: budgetDomainHash.hi.toString(),
            },
          }
        : {}),
      ...(withdrawalDomainHash
        ? {
            authorizeWithdrawalDomainHash: {
              lo: withdrawalDomainHash.lo.toString(),
              hi: withdrawalDomainHash.hi.toString(),
            },
          }
        : {}),
    },
  };
  saveState(nextState);
  if (mxePublicKeyHex && budgetDomainHash && withdrawalDomainHash) {
    updateGeneratedEnv({
      SUBLY402_ARCIUM_MXE_PUBLIC_KEY_HEX: mxePublicKeyHex,
      SUBLY402_ARCIUM_AUTHORIZE_BUDGET_DOMAIN_HASH_LO:
        budgetDomainHash.lo.toString(),
      SUBLY402_ARCIUM_AUTHORIZE_BUDGET_DOMAIN_HASH_HI:
        budgetDomainHash.hi.toString(),
      SUBLY402_ARCIUM_AUTHORIZE_WITHDRAWAL_DOMAIN_HASH_LO:
        withdrawalDomainHash.lo.toString(),
      SUBLY402_ARCIUM_AUTHORIZE_WITHDRAWAL_DOMAIN_HASH_HI:
        withdrawalDomainHash.hi.toString(),
    });
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        initialized,
        statusTransitions,
        stateFile: "data/devnet-state.json",
        summary: nextState.arcium,
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
  ARCIUM_STATUS,
  arciumStateFromAccount,
  buildDesiredConfig,
  bytesToHex,
  configuredMxePublicKey,
  decodeFixedBytes,
  decodeX25519PublicKey,
  findConfigMismatches,
  numberValue,
  parseStatus,
  resolveMxePublicKey,
  statusRequiresDeployment,
  statusName,
  updateArciumDeployment,
};
