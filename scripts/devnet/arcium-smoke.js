#!/usr/bin/env node

const crypto = require("crypto");

const anchor = require("@coral-xyz/anchor");
const {
  createAccount,
  mintTo,
  TOKEN_PROGRAM_ID,
} = require("@solana/spl-token");
const { Keypair, PublicKey, SystemProgram } = require("@solana/web3.js");
const {
  awaitComputationFinalization,
  getCircuitState,
  getArciumProgram,
  getClockAccAddress,
  getClusterAccAddress,
  getCompDefAccAddress,
  getComputationAccAddress,
  getExecutingPoolAccAddress,
  getFeePoolAccAddress,
  getMempoolAccAddress,
  getMXEAccAddress,
} = require("@arcium-hq/client");

const {
  fundAccount,
  loadDefaultEnvFiles,
  loadProgram,
  loadProvider,
  loadState,
  requireSdkArcium,
  sleep,
} = require("./common");
const { compDefOffset } = require("./arcium-init-comp-defs");
const {
  computeArciumDomainHashParts,
  fetchArciumMxePublicKeyWithRetry,
} = require("./arcium-utils");

const CLIENT_VAULT_STATUS_IDLE = 0;
const DEPOSIT_CREDIT_STATUS_APPLIED = 1;
const BUDGET_GRANT_STATUS_READY = 1;
const BUDGET_GRANT_STATUS_CANCELLED = 5;
const WITHDRAWAL_GRANT_STATUS_READY = 1;
const WITHDRAWAL_GRANT_STATUS_CANCELLED = 5;

function u64Le(value) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64LE(BigInt(value));
  return buffer;
}

function nextOffsetFactory() {
  let next = BigInt(Date.now()) * 1000n + BigInt(crypto.randomInt(0, 1000));
  return () => {
    next += 1n;
    return new anchor.BN(next.toString());
  };
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

function arrayBytes(value, expectedLength, field) {
  const bytes = Array.from(value);
  if (bytes.length !== expectedLength) {
    throw new Error(`${field} must be ${expectedLength} bytes`);
  }
  return bytes;
}

function deriveSignPda(programId) {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("ArciumSignerAccount")],
    programId
  )[0];
}

function deriveClientVaultState(programId, vaultConfig, client) {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("client_vault_state"),
      vaultConfig.toBuffer(),
      client.toBuffer(),
    ],
    programId
  )[0];
}

function deriveDepositCredit(programId, vaultConfig, client, depositNonce) {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("deposit_credit"),
      vaultConfig.toBuffer(),
      client.toBuffer(),
      u64Le(depositNonce),
    ],
    programId
  )[0];
}

function deriveBudgetGrant(programId, clientVaultState, budgetId) {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("budget_grant"), clientVaultState.toBuffer(), u64Le(budgetId)],
    programId
  )[0];
}

function deriveWithdrawalGrant(programId, clientVaultState, withdrawalId) {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("withdrawal_grant"),
      clientVaultState.toBuffer(),
      u64Le(withdrawalId),
    ],
    programId
  )[0];
}

async function waitForAccount(label, fn, maxAttempts = 120, delayMs = 1000) {
  let last;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    last = await fn();
    if (last?.ok) {
      return last.value;
    }
    await sleep(delayMs);
  }
  throw new Error(
    `Timed out waiting for ${label}${last?.reason ? `: ${last.reason}` : ""}`
  );
}

async function awaitQueuedComputation(provider, programId, offset, timeoutMs) {
  const signature = await awaitComputationFinalization(
    provider,
    offset,
    programId,
    "confirmed",
    timeoutMs
  );
  return signature;
}

function commonArciumAccounts({
  arciumProgram,
  arciumConfig,
  clusterOffset,
  computationOffset,
  compDefName,
  programId,
}) {
  return {
    signPdaAccount: deriveSignPda(programId),
    mxeAccount: arciumConfig.mxeAccount,
    mempoolAccount: arciumConfig.mempoolAccount,
    executingPool: getExecutingPoolAccAddress(clusterOffset),
    computationAccount: getComputationAccAddress(
      clusterOffset,
      computationOffset
    ),
    compDefAccount: getCompDefAccAddress(programId, compDefOffset(compDefName)),
    clusterAccount: arciumConfig.clusterAccount,
    poolAccount: getFeePoolAccAddress(),
    clockAccount: getClockAccAddress(),
    systemProgram: SystemProgram.programId,
    arciumProgram: arciumProgram.programId,
  };
}

async function requireCompletedCompDefs(arciumProgram, programId, names) {
  const incomplete = [];
  for (const name of names) {
    const compDefAccount = getCompDefAccAddress(programId, compDefOffset(name));
    // eslint-disable-next-line no-await-in-loop
    const account =
      await arciumProgram.account.computationDefinitionAccount.fetchNullable(
        compDefAccount,
        "confirmed"
      );
    const status = account ? getCircuitState(account.circuitSource) : "missing";
    if (status !== "OnchainFinalized") {
      incomplete.push({
        name,
        compDefAccount: compDefAccount.toBase58(),
        status,
      });
    }
  }
  if (incomplete.length > 0) {
    const namesCsv = incomplete.map((item) => item.name).join(",");
    throw new Error(
      `Arcium computation definitions are not completed: ${JSON.stringify(
        incomplete
      )}. Upload/finalize them first with SUBLY402_ARCIUM_COMP_DEF_NAMES=${namesCsv} SUBLY402_ARCIUM_UPLOAD_CIRCUITS=1 yarn devnet:arcium-init-comp-defs`
    );
  }
}

async function main() {
  loadDefaultEnvFiles();

  const state = loadState();
  if (!state?.vaultConfig || !state?.vaultTokenAccount || !state?.usdcMint) {
    throw new Error("data/devnet-state.json is missing vault state");
  }

  const provider = loadProvider();
  anchor.setProvider(provider);
  const program = loadProgram(provider);
  const arciumProgram = getArciumProgram(provider);
  const arciumSdk = requireSdkArcium();
  const nextOffset = nextOffsetFactory();
  const computationTimeoutMs = Number(
    process.env.SUBLY402_ARCIUM_SMOKE_COMPUTATION_TIMEOUT_MS || "180000"
  );
  const stepOrder = [
    "init_agent_vault",
    "apply_deposit",
    "authorize_budget",
    "authorize_withdrawal",
  ];
  const smokeUntil =
    process.env.SUBLY402_ARCIUM_SMOKE_UNTIL || "authorize_withdrawal";
  const smokeUntilIndex = stepOrder.indexOf(smokeUntil);
  if (smokeUntilIndex === -1) {
    throw new Error(
      `SUBLY402_ARCIUM_SMOKE_UNTIL must be one of ${stepOrder.join(", ")}`
    );
  }

  const vaultConfig = new PublicKey(state.vaultConfig);
  const vaultTokenAccount = new PublicKey(state.vaultTokenAccount);
  const usdcMint = new PublicKey(state.usdcMint);
  const [arciumConfigPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("arcium_config"), vaultConfig.toBuffer()],
    program.programId
  );
  const [vaultConfigAccount, arciumConfigAccount] = await Promise.all([
    program.account.vaultConfig.fetch(vaultConfig),
    program.account.arciumConfig.fetch(arciumConfigPda),
  ]);

  const mxeAccount = getMXEAccAddress(program.programId);
  if (mxeAccount.toBase58() !== arciumConfigAccount.mxeAccount.toBase58()) {
    throw new Error("ArciumConfig MXE account does not match program MXE PDA");
  }
  const mxe = await arciumProgram.account.mxeAccount.fetch(mxeAccount);
  const clusterOffset = numberValue(mxe.cluster);
  const derivedCluster = getClusterAccAddress(clusterOffset);
  const derivedMempool = getMempoolAccAddress(clusterOffset);
  const derivedExecutingPool = getExecutingPoolAccAddress(clusterOffset);
  const derivedComputationProbe = getComputationAccAddress(
    clusterOffset,
    new anchor.BN(1)
  );
  if (
    arciumConfigAccount.clusterAccount.toBase58() !==
      derivedCluster.toBase58() ||
    arciumConfigAccount.mempoolAccount.toBase58() !== derivedMempool.toBase58()
  ) {
    throw new Error("ArciumConfig cluster/mempool accounts do not match MXE");
  }
  await requireCompletedCompDefs(
    arciumProgram,
    program.programId,
    stepOrder.slice(0, smokeUntilIndex + 1)
  );

  const depositAmount = Number(
    process.env.SUBLY402_ARCIUM_SMOKE_DEPOSIT_AMOUNT || "2000000"
  );
  const budgetAmount = Number(
    process.env.SUBLY402_ARCIUM_SMOKE_BUDGET_AMOUNT || "500000"
  );
  const withdrawalAmount = Number(
    process.env.SUBLY402_ARCIUM_SMOKE_WITHDRAWAL_AMOUNT || "200000"
  );
  if (budgetAmount + withdrawalAmount > depositAmount) {
    throw new Error("Arcium smoke amounts exceed deposit amount");
  }

  const client = Keypair.generate();
  await fundAccount(provider, client.publicKey, 1_000_000_000);

  const clientVaultState = deriveClientVaultState(
    program.programId,
    vaultConfig,
    client.publicKey
  );

  const initOffset = nextOffset();
  await program.methods
    .initAgentVault(initOffset)
    .accountsPartial({
      client: client.publicKey,
      vaultConfig,
      arciumConfig: arciumConfigPda,
      clientVaultState,
      ...commonArciumAccounts({
        arciumProgram,
        arciumConfig: arciumConfigAccount,
        clusterOffset,
        computationOffset: initOffset,
        compDefName: "init_agent_vault",
        programId: program.programId,
      }),
    })
    .signers([client])
    .rpc();
  const initFinalizeSignature = await awaitQueuedComputation(
    provider,
    program.programId,
    initOffset,
    computationTimeoutMs
  );
  const initializedState = await waitForAccount(
    "client vault state init callback",
    async () => {
      const account = await program.account.clientVaultState.fetchNullable(
        clientVaultState
      );
      if (
        account &&
        numberValue(account.status) === CLIENT_VAULT_STATUS_IDLE &&
        numberValue(account.stateVersion) >= 1
      ) {
        return { ok: true, value: account };
      }
      return {
        ok: false,
        reason: account
          ? `status=${numberValue(
              account.status
            )} stateVersion=${account.stateVersion.toString()}`
          : "account missing",
      };
    }
  );
  const baseResult = {
    ok: true,
    smokeUntil,
    client: client.publicKey.toBase58(),
    clientVaultState: clientVaultState.toBase58(),
    clusterOffset,
    arciumConfig: arciumConfigPda.toBase58(),
    mxeAccount: mxeAccount.toBase58(),
    clusterAccount: arciumConfigAccount.clusterAccount.toBase58(),
    mempoolAccount: arciumConfigAccount.mempoolAccount.toBase58(),
    executingPool: derivedExecutingPool.toBase58(),
    computationProbe: derivedComputationProbe.toBase58(),
    initAgentVault: {
      computationOffset: initOffset.toString(),
      finalizeSignature: initFinalizeSignature,
      stateVersion: initializedState.stateVersion.toString(),
    },
  };
  if (smokeUntil === "init_agent_vault") {
    console.log(JSON.stringify(baseResult, null, 2));
    return;
  }

  const clientTokenAccount = await createAccount(
    provider.connection,
    provider.wallet.payer,
    usdcMint,
    client.publicKey
  );
  await mintTo(
    provider.connection,
    provider.wallet.payer,
    usdcMint,
    clientTokenAccount,
    provider.wallet.publicKey,
    depositAmount
  );

  const depositNonce = BigInt(Date.now()) + BigInt(crypto.randomInt(1000));
  const depositCredit = deriveDepositCredit(
    program.programId,
    vaultConfig,
    client.publicKey,
    depositNonce
  );
  await program.methods
    .depositWithCredit(
      new anchor.BN(depositAmount),
      new anchor.BN(depositNonce.toString())
    )
    .accountsPartial({
      client: client.publicKey,
      vaultConfig,
      depositCredit,
      clientTokenAccount,
      vaultTokenAccount,
      systemProgram: SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID,
    })
    .signers([client])
    .rpc();

  const applyDepositOffset = nextOffset();
  await program.methods
    .applyDeposit(applyDepositOffset)
    .accountsPartial({
      client: client.publicKey,
      vaultConfig,
      arciumConfig: arciumConfigPda,
      clientVaultState,
      depositCredit,
      ...commonArciumAccounts({
        arciumProgram,
        arciumConfig: arciumConfigAccount,
        clusterOffset,
        computationOffset: applyDepositOffset,
        compDefName: "apply_deposit",
        programId: program.programId,
      }),
    })
    .signers([client])
    .rpc();
  const applyDepositFinalizeSignature = await awaitQueuedComputation(
    provider,
    program.programId,
    applyDepositOffset,
    computationTimeoutMs
  );
  const appliedDeposit = await waitForAccount(
    "deposit credit applied callback",
    async () => {
      const [vaultState, credit] = await Promise.all([
        program.account.clientVaultState.fetchNullable(clientVaultState),
        program.account.depositCredit.fetchNullable(depositCredit),
      ]);
      if (
        vaultState &&
        credit &&
        numberValue(vaultState.status) === CLIENT_VAULT_STATUS_IDLE &&
        numberValue(vaultState.stateVersion) >=
          numberValue(initializedState.stateVersion) + 1 &&
        numberValue(credit.status) === DEPOSIT_CREDIT_STATUS_APPLIED
      ) {
        return { ok: true, value: { vaultState, credit } };
      }
      return {
        ok: false,
        reason: `vaultStatus=${
          vaultState ? numberValue(vaultState.status) : "missing"
        } creditStatus=${credit ? numberValue(credit.status) : "missing"}`,
      };
    }
  );
  const applyDepositResult = {
    depositCredit: depositCredit.toBase58(),
    amount: depositAmount,
    computationOffset: applyDepositOffset.toString(),
    finalizeSignature: applyDepositFinalizeSignature,
    depositStatus: numberValue(appliedDeposit.credit.status),
    stateVersion: appliedDeposit.vaultState.stateVersion.toString(),
  };
  if (smokeUntil === "apply_deposit") {
    console.log(
      JSON.stringify(
        {
          ...baseResult,
          applyDeposit: applyDepositResult,
        },
        null,
        2
      )
    );
    return;
  }

  const mxePublicKey = await fetchArciumMxePublicKeyWithRetry(
    provider,
    program.programId,
    {
      attempts: Number(process.env.SUBLY402_ARCIUM_MXE_FETCH_ATTEMPTS || "20"),
      delayMs: Number(process.env.SUBLY402_ARCIUM_MXE_FETCH_DELAY_MS || "500"),
    }
  );
  const clientArciumKeys = await arciumSdk.deriveArciumX25519Keypair(
    {
      publicKey: client.publicKey,
      secretKey: client.secretKey,
    },
    {
      programId: program.programId,
      vaultConfig,
      derivationScope: "subly402:devnet-arcium-smoke:v1",
    }
  );
  const clientCipher = arciumSdk.createArciumSharedCipher(
    clientArciumKeys.privateKey,
    mxePublicKey
  );

  const budgetId = BigInt(Date.now()) + BigInt(crypto.randomInt(1000));
  const budgetRequestNonce = budgetId + 1000n;
  const budgetExpiresAt = Math.floor(Date.now() / 1000) + 3600;
  const budgetDomain = computeArciumDomainHashParts({
    instructionKind: "authorize_budget",
    programId: program.programId,
    vaultConfig,
    vaultConfigAccount,
    arciumConfigAccount,
  });
  const encryptedBudget = arciumSdk.encryptArciumBudgetRequest(
    clientCipher,
    clientArciumKeys.publicKey,
    {
      domainHashLo: budgetDomain.lo,
      domainHashHi: budgetDomain.hi,
      budgetId,
      requestNonce: budgetRequestNonce,
      amount: budgetAmount,
      expiresAt: budgetExpiresAt,
    }
  );
  const budgetGrant = deriveBudgetGrant(
    program.programId,
    clientVaultState,
    budgetId
  );
  const authorizeBudgetOffset = nextOffset();
  await program.methods
    .authorizeBudget(
      authorizeBudgetOffset,
      new anchor.BN(budgetId.toString()),
      new anchor.BN(budgetRequestNonce.toString()),
      new anchor.BN(budgetExpiresAt),
      arrayBytes(encryptedBudget.x25519PublicKey, 32, "budget x25519"),
      encryptedBudget.ciphertexts,
      arrayBytes(encryptedBudget.nonce, 16, "budget nonce")
    )
    .accountsPartial({
      client: client.publicKey,
      vaultConfig,
      arciumConfig: arciumConfigPda,
      clientVaultState,
      budgetGrant,
      ...commonArciumAccounts({
        arciumProgram,
        arciumConfig: arciumConfigAccount,
        clusterOffset,
        computationOffset: authorizeBudgetOffset,
        compDefName: "authorize_budget",
        programId: program.programId,
      }),
    })
    .signers([client])
    .rpc();
  const authorizeBudgetFinalizeSignature = await awaitQueuedComputation(
    provider,
    program.programId,
    authorizeBudgetOffset,
    computationTimeoutMs
  );
  const readyBudgetGrant = await waitForAccount(
    "budget grant ready callback",
    async () => {
      const [vaultState, grant] = await Promise.all([
        program.account.clientVaultState.fetchNullable(clientVaultState),
        program.account.budgetGrant.fetchNullable(budgetGrant),
      ]);
      if (
        vaultState &&
        grant &&
        numberValue(vaultState.status) === CLIENT_VAULT_STATUS_IDLE &&
        numberValue(grant.status) === BUDGET_GRANT_STATUS_READY
      ) {
        return { ok: true, value: grant };
      }
      if (
        grant &&
        numberValue(grant.status) === BUDGET_GRANT_STATUS_CANCELLED
      ) {
        throw new Error("Budget grant was cancelled by the Arcium circuit");
      }
      return {
        ok: false,
        reason: `vaultStatus=${
          vaultState ? numberValue(vaultState.status) : "missing"
        } grantStatus=${grant ? numberValue(grant.status) : "missing"}`,
      };
    }
  );
  const authorizeBudgetResult = {
    budgetGrant: budgetGrant.toBase58(),
    amount: budgetAmount,
    computationOffset: authorizeBudgetOffset.toString(),
    finalizeSignature: authorizeBudgetFinalizeSignature,
    status: numberValue(readyBudgetGrant.status),
    stateVersionAtAuthorization:
      readyBudgetGrant.stateVersionAtAuthorization.toString(),
  };
  if (smokeUntil === "authorize_budget") {
    console.log(
      JSON.stringify(
        {
          ...baseResult,
          applyDeposit: applyDepositResult,
          authorizeBudget: authorizeBudgetResult,
        },
        null,
        2
      )
    );
    return;
  }

  const recipient = Keypair.generate();
  const recipientTokenAccount = await createAccount(
    provider.connection,
    provider.wallet.payer,
    usdcMint,
    recipient.publicKey
  );
  const withdrawalId = budgetId + 2000n;
  const withdrawalExpiresAt = Math.floor(Date.now() / 1000) + 3600;
  const withdrawalDomain = computeArciumDomainHashParts({
    instructionKind: "authorize_withdrawal",
    programId: program.programId,
    vaultConfig,
    vaultConfigAccount,
    arciumConfigAccount,
  });
  const encryptedWithdrawal = arciumSdk.encryptArciumWithdrawalRequest(
    clientCipher,
    clientArciumKeys.publicKey,
    {
      domainHashLo: withdrawalDomain.lo,
      domainHashHi: withdrawalDomain.hi,
      withdrawalId,
      amount: withdrawalAmount,
      expiresAt: withdrawalExpiresAt,
    }
  );
  const withdrawalGrant = deriveWithdrawalGrant(
    program.programId,
    clientVaultState,
    withdrawalId
  );
  const authorizeWithdrawalOffset = nextOffset();
  await program.methods
    .authorizeWithdrawal(
      authorizeWithdrawalOffset,
      new anchor.BN(withdrawalId.toString()),
      new anchor.BN(withdrawalExpiresAt),
      recipientTokenAccount,
      arrayBytes(encryptedWithdrawal.x25519PublicKey, 32, "withdrawal x25519"),
      encryptedWithdrawal.ciphertexts,
      arrayBytes(encryptedWithdrawal.nonce, 16, "withdrawal nonce")
    )
    .accountsPartial({
      client: client.publicKey,
      vaultConfig,
      arciumConfig: arciumConfigPda,
      clientVaultState,
      withdrawalGrant,
      ...commonArciumAccounts({
        arciumProgram,
        arciumConfig: arciumConfigAccount,
        clusterOffset,
        computationOffset: authorizeWithdrawalOffset,
        compDefName: "authorize_withdrawal",
        programId: program.programId,
      }),
    })
    .signers([client])
    .rpc();
  const authorizeWithdrawalFinalizeSignature = await awaitQueuedComputation(
    provider,
    program.programId,
    authorizeWithdrawalOffset,
    computationTimeoutMs
  );
  const readyWithdrawalGrant = await waitForAccount(
    "withdrawal grant ready callback",
    async () => {
      const [vaultState, grant] = await Promise.all([
        program.account.clientVaultState.fetchNullable(clientVaultState),
        program.account.withdrawalGrant.fetchNullable(withdrawalGrant),
      ]);
      if (
        vaultState &&
        grant &&
        numberValue(vaultState.status) === CLIENT_VAULT_STATUS_IDLE &&
        numberValue(grant.status) === WITHDRAWAL_GRANT_STATUS_READY
      ) {
        return { ok: true, value: grant };
      }
      if (
        grant &&
        numberValue(grant.status) === WITHDRAWAL_GRANT_STATUS_CANCELLED
      ) {
        throw new Error("Withdrawal grant was cancelled by the Arcium circuit");
      }
      return {
        ok: false,
        reason: `vaultStatus=${
          vaultState ? numberValue(vaultState.status) : "missing"
        } grantStatus=${grant ? numberValue(grant.status) : "missing"}`,
      };
    }
  );
  const authorizeWithdrawalResult = {
    withdrawalGrant: withdrawalGrant.toBase58(),
    recipientTokenAccount: recipientTokenAccount.toBase58(),
    amount: withdrawalAmount,
    computationOffset: authorizeWithdrawalOffset.toString(),
    finalizeSignature: authorizeWithdrawalFinalizeSignature,
    status: numberValue(readyWithdrawalGrant.status),
    stateVersionAtAuthorization:
      readyWithdrawalGrant.stateVersionAtAuthorization.toString(),
  };

  console.log(
    JSON.stringify(
      {
        ...baseResult,
        applyDeposit: applyDepositResult,
        authorizeBudget: authorizeBudgetResult,
        authorizeWithdrawal: authorizeWithdrawalResult,
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
