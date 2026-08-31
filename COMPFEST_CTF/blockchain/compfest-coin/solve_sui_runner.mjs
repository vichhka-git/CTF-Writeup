import { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import { Transaction } from '@mysten/sui/transactions';
import fs from 'fs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const info = JSON.parse(fs.readFileSync('/tmp/sui_launch_info.json', 'utf8'));

const rpcUrl = info.rpc_url;
const client = new SuiJsonRpcClient({ url: rpcUrl });

const privKey = info.privkey;
const decoded = decodeSuiPrivateKey(privKey);
const keypair = Ed25519Keypair.fromSecretKey(decoded.secretKey);
const address = keypair.toSuiAddress();

const PACKAGE_ID = info.package_id;
const SETUP_ID = info.setup_id;
const REGISTRY = info.registry;
const VAULT = info.vault;
const ACCOUNT = info.account;
const CONFIG = info.config;
const ORACLE = info.oracle;

const USDC = `${PACKAGE_ID}::assets::USDC`;
const SUIX = `${PACKAGE_ID}::assets::SUIX`;
const CFX = `${PACKAGE_ID}::assets::CFX`;

async function main() {
  console.log('[*] Step 1: Create route pool <USDC, SUIX>');
  const tx1 = new Transaction();
  tx1.setSender(address);
  tx1.setGasBudget(100_000_000);

  tx1.moveCall({
    target: `${PACKAGE_ID}::pool::create_route_pool`,
    typeArguments: [USDC, SUIX],
    arguments: [
      tx1.object(REGISTRY),
      tx1.object(CONFIG),
      tx1.pure.u64(1),         // reserve_base: 1
      tx1.pure.u64(2_000_000), // reserve_quote: 2_000_000
    ],
  });

  const res1 = await client.signAndExecuteTransaction({
    signer: keypair,
    transaction: tx1,
    options: { showEffects: true, showEvents: true },
  });

  let poolId = null;
  if (res1.events) {
    for (const ev of res1.events) {
      if (ev.type.includes('RoutePoolCreated')) {
        poolId = ev.parsedJson.pool;
      }
    }
  }
  if (!poolId && res1.effects?.created) {
    for (const c of res1.effects.created) {
      if (c.owner?.Shared) poolId = c.reference.objectId;
    }
  }
  console.log('[+] Pool created:', poolId);
  console.log('[*] Waiting 3s for node indexing...');
  await sleep(3000);

  console.log('[*] Step 2: Open position and register strategy');
  const tx2 = new Transaction();
  tx2.setSender(address);
  tx2.setGasBudget(100_000_000);

  tx2.moveCall({
    target: `${PACKAGE_ID}::pool::open_position`,
    typeArguments: [USDC, SUIX],
    arguments: [tx2.object(poolId)],
  });

  tx2.moveCall({
    target: `${PACKAGE_ID}::registry::register_route_strategy`,
    typeArguments: [USDC, SUIX, 'u64'],
    arguments: [tx2.object(REGISTRY), tx2.pure.u64(0)],
  });

  const res2 = await client.signAndExecuteTransaction({
    signer: keypair,
    transaction: tx2,
    options: { showEffects: true },
  });

  let positionId = null;
  let strategyId = null;

  for (const c of res2.effects.created) {
    const objId = c.reference.objectId;
    for (let retry = 0; retry < 5; retry++) {
      try {
        const obj = await client.getObject({ id: objId, options: { showType: true } });
        if (obj.data?.type?.includes('RoutePosition')) {
          positionId = objId;
          break;
        } else if (obj.data?.type?.includes('RouteStrategy')) {
          strategyId = objId;
          break;
        }
      } catch (e) {
        await sleep(500);
      }
    }
  }
  console.log('[+] Position:', positionId);
  console.log('[+] Strategy:', strategyId);
  console.log('[*] Waiting 3s for node indexing...');
  await sleep(3000);

  console.log('[*] Step 3: Add liquidity, claim incentives, solve');
  const tx3 = new Transaction();
  tx3.setSender(address);
  tx3.setGasBudget(100_000_000);

  tx3.moveCall({
    target: `${PACKAGE_ID}::pool::add_liquidity`,
    typeArguments: [USDC, SUIX],
    arguments: [
      tx3.object(poolId),
      tx3.object(positionId),
      tx3.pure.u64(1000),
      tx3.object(CONFIG),
    ],
  });

  tx3.moveCall({
    target: `${PACKAGE_ID}::vault::claim_route_incentives`,
    typeArguments: [USDC, SUIX, 'u64'],
    arguments: [
      tx3.object(VAULT),
      tx3.object(poolId),
      tx3.object(strategyId),
      tx3.object(positionId),
      tx3.object(ACCOUNT),
      tx3.object(ORACLE),
      tx3.object(CONFIG),
    ],
  });

  tx3.moveCall({
    target: `${PACKAGE_ID}::setup::solve`,
    typeArguments: [],
    arguments: [
      tx3.object(SETUP_ID),
      tx3.object(ACCOUNT),
      tx3.object(CONFIG),
    ],
  });

  const res3 = await client.signAndExecuteTransaction({
    signer: keypair,
    transaction: tx3,
    options: { showEffects: true },
  });
  console.log('[+] Solve Tx status:', res3.effects?.status);

  await sleep(2000);
  const setupObj = await client.getObject({ id: SETUP_ID, options: { showContent: true } });
  console.log('[+] Setup isSolved:', setupObj.data?.content?.fields?.solved);
}

main().catch(console.error);
