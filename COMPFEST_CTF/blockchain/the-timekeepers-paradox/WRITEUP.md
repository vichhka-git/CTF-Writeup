# The Timekeeper's Paradox — Writeup

## Challenge Summary
- **Category:** Blockchain / Smart Contracts
- **Points:** 331 / 244
- **Flag:** `COMPFEST18{t1m3k33p3r_pr1c3_0r4cl3_m4n1p_v14_st0r4g3_c0ll1s10n_le4k3dddddd_n0000000}`

## Vulnerability & Mechanism
1. **Proxy Storage Collision with Implementation:**
   - `TimekeeperProxy` defines:
     - Slot 0: `admin`
     - Slot 1: `implementation`
     - Slot 2: `pendingAdmin`
     - Slot 3: `validImplementations`
   - `TimekeeperOracle` defines:
     - Slot 0: `admin`
     - Slot 1: `reporter`
     - Slot 2: `latestPrice`
     - Slot 3: `observations`
   - When `TimekeeperLending` queries oracle price via `oracle.staticcall(abi.encodeWithSignature("getLatestPrice()"))`, the proxy delegatecalls `TimekeeperOracle.getLatestPrice()`.
   - In the proxy's storage context, Slot 2 is `pendingAdmin`. Therefore, `getLatestPrice()` returns `uint256(uint160(proxy.pendingAdmin))`.

2. **Privilege Escalation via Multicall:**
   - `TimekeeperProxy.setPendingAdmin(address)` requires `msg.sender == address(this)`.
   - `TimekeeperProxy.multicall(bytes[])` executes `address(this).call(data[i])`.
   - Calling `multicall` with `setPendingAdmin(address(1))` passes the check and sets `pendingAdmin = address(1)`.
   - This sets Slot 2 of the proxy to `1`.

3. **Oracle Price Collapse & Pool Draining:**
   - `lending.getOraclePrice()` now returns `1` (1 wei of TKG per 1 ETH).
   - The user deposits 10,000 TKG tokens ($10,000 \times 10^{18}$ wei).
   - Collateral value calculation: $\text{valueInETH} = \frac{10000 \times 10^{18} \times 10^{18}}{1} = 10^{40}$ ETH.
   - Calling `lending.borrowETH(50 ether)` borrows all 50 ETH in the pool.
   - `lending.balance` drops to 0, satisfying `Setup.isSolved()`.

## Reproducible Solver
Run [`solve.py`](./solve.py):
```bash
python3 solve.py
```
