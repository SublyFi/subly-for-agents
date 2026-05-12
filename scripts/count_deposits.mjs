import { Connection, PublicKey } from '@solana/web3.js';
import bs58 from 'bs58';

const RPC = 'https://devnet.helius-rpc.com/?api-key=d4f302b4-c9aa-4632-a08c-dba50524db17';
const PROGRAM_ID = '3iusaL6ys79DsbpweDwGhHvtjdnhAhtpyczPtMbu5Mbe';
const VAULTS = [
  '3bR3ViL4aFHda95cfL2kKBrup1L2fUgbEfW6yw1BSrfc',
  '6i5SyF8Hx2u5MZW2JgWGhdg5CJsAKeF7UaRAd9bERDDL',
];

// First-8-byte Anchor discriminators (hex)
const DISCRIMINATORS = {
  deposit:              'f223c68952e1f2b6',
  deposit_with_credit:  'fb2f7578fc2c23a3',
  apply_deposit:        '2fd1ddd6590a7e47',
};

const conn = new Connection(RPC, 'confirmed');

async function getAllSignatures(addr) {
  const pk = new PublicKey(addr);
  const all = [];
  let before = undefined;
  while (true) {
    const batch = await conn.getSignaturesForAddress(pk, { before, limit: 1000 });
    if (batch.length === 0) break;
    all.push(...batch);
    if (batch.length < 1000) break;
    before = batch[batch.length - 1].signature;
  }
  return all;
}

function classify(tx) {
  if (!tx) return null;
  const msg = tx.transaction.message;
  const keys = msg.staticAccountKeys
    ? msg.staticAccountKeys.map(k => k.toBase58())
    : msg.accountKeys.map(k => (typeof k === 'string' ? k : k.toBase58()));
  const ixs = msg.compiledInstructions ?? msg.instructions;
  const found = new Set();
  for (const ix of ixs) {
    const programId = keys[ix.programIdIndex];
    if (programId !== PROGRAM_ID) continue;
    const data = ix.data;
    let bytes;
    if (data instanceof Uint8Array) bytes = data;
    else if (typeof data === 'string') bytes = bs58.decode(data);
    else continue;
    if (bytes.length < 8) continue;
    const disc = Buffer.from(bytes.slice(0, 8)).toString('hex');
    for (const [name, hex] of Object.entries(DISCRIMINATORS)) {
      if (disc === hex) found.add(name);
    }
  }
  // Also check inner instructions (CPI) for completeness — apply_deposit may CPI from arcium queue, but for vault address as signer-of-account it should appear in top-level too. Keep top-level only.
  return found;
}

async function processVault(addr) {
  console.log(`\n==== ${addr} ====`);
  const sigs = await getAllSignatures(addr);
  console.log(`total signatures: ${sigs.length}`);
  const counts = { deposit: 0, deposit_with_credit: 0, apply_deposit: 0, other: 0, failed: 0 };
  const depositSigs = [];
  // Fetch transactions in batches
  const BATCH = 25;
  for (let i = 0; i < sigs.length; i += BATCH) {
    const slice = sigs.slice(i, i + BATCH);
    const txs = await Promise.all(slice.map(s =>
      conn.getTransaction(s.signature, { maxSupportedTransactionVersion: 0, commitment: 'confirmed' })
        .catch(() => null)
    ));
    for (let j = 0; j < slice.length; j++) {
      const sigInfo = slice[j];
      const tx = txs[j];
      if (!tx) { counts.failed++; continue; }
      const types = classify(tx);
      let matched = false;
      for (const t of types) { counts[t]++; matched = true; }
      if (matched) depositSigs.push({ sig: sigInfo.signature, slot: sigInfo.slot, blockTime: sigInfo.blockTime, types: [...types], err: !!sigInfo.err });
      else counts.other++;
    }
    process.stderr.write(`  processed ${Math.min(i + BATCH, sigs.length)}/${sigs.length}\r`);
  }
  console.error('');
  console.log('counts:', counts);
  console.log(`deposit-like txs: ${depositSigs.length} (success: ${depositSigs.filter(s=>!s.err).length}, failed: ${depositSigs.filter(s=>s.err).length})`);
  // Print first 5 and last 5
  const sorted = [...depositSigs].sort((a,b) => (a.blockTime||0)-(b.blockTime||0));
  console.log('earliest 3:');
  for (const s of sorted.slice(0,3)) console.log(' ', new Date((s.blockTime||0)*1000).toISOString(), s.types.join(','), s.sig);
  console.log('latest 3:');
  for (const s of sorted.slice(-3)) console.log(' ', new Date((s.blockTime||0)*1000).toISOString(), s.types.join(','), s.sig);
  return { addr, total: sigs.length, counts, depositSigs };
}

const results = [];
for (const v of VAULTS) {
  results.push(await processVault(v));
}

console.log('\n==== SUMMARY ====');
for (const r of results) {
  const c = r.counts;
  const totalDeposits = c.deposit + c.deposit_with_credit + c.apply_deposit;
  console.log(`${r.addr}: total_sigs=${r.total}, deposits(all)=${totalDeposits}  [deposit=${c.deposit}, deposit_with_credit=${c.deposit_with_credit}, apply_deposit=${c.apply_deposit}]`);
}
