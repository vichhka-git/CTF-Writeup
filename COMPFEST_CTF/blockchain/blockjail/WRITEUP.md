# BlockJail — Writeup

## Setup

`BlockJail.enter()` accepts an "Agent" contract as `msg.sender` only if its runtime bytecode passes
`_validateAgentRuntime`: at most `MAX_AGENT_SIZE=36` bytes, opcodes restricted to a small allow-list, exactly
one `DELEGATECALL` (`0xf4`), and a pushed operand `<= type(uint144).max` (i.e. an address with the top 2 bytes
zero) that has code — a "vanity implementation" check. This is the standard minimal-clone / ERC-1167-style
constrained-bytecode CTF pattern: build a tiny delegatecall proxy pointing at a CREATE2-grindable
"vanity" (2-leading-zero-byte) address.

- Runtime (36 bytes): copies calldata, `DELEGATECALL`s the 18-byte-embedded vanity address, returns/reverts
  the result.
- `enter()` sets `agent = msg.sender` (the proxy) and `beneficiary = tx.origin`.
- `openPath()`, `stealHeart()`, `infiltrate(bytes)` are `onlyAgent`.
- `stealHeart()` sends BlockJail's entire ETH balance to `beneficiary` (our EOA).
- `infiltrate(card)` requires `pathOpened` and forwards `card` to
  `PALACE.beginInfiltration(bytes)` (a separate `PalaceVault` contract, source not provided in the challenge
  attachments — only its deployed bytecode is reachable on-chain).

## PalaceVault (reverse engineered from bytecode)

The distributed files omitted `PalaceVault.sol`, so its deployed EVM bytecode was pulled live via `eth_getCode`
and disassembled (`pyevmasm` doesn't support `PUSH0`/Prague-era opcodes, so a small custom disassembler was
written to handle the `0x5f` `PUSH0` opcode used throughout since the contract is compiled for `evm_version =
"prague"`).

`beginInfiltration(bytes calldata card)`:
- requires `msg.sender == TARGET` (the BlockJail contract address, embedded as an immutable) and
  `card.length == 5 && <reentrancy-guard slot> == 0`.
- copies `card[0..4]` into five storage slots (slot4..slot8), i.e. **the raw bytes of `card` become
  attacker-chosen storage values**.
- iterates a local `function()[4] memory` array of **internal function pointers** ("guards"). Three are
  explicitly assigned; the 4th (index 0) is left at Solidity's built-in *uninitialized-function-pointer* trap
  (`Panic(0x51)`) — a red herring that reverts if ever reached.
- one guard performs `SSTORE(card[0], card[1])` — an **arbitrary storage-slot write**, using two attacker
  bytes as `(slot, value)`. With `card[0]=0`, this sets storage **slot 0 = card[1]**, which is exactly the
  packed boolean "cracked/open" flag (`flagA`) PalaceVault's own `isSolved()` requires to be non-zero.
- another guard, gated on `flagA != 0`, zeroes `mapping(address => uint256)[TARGET]` (also required `==0` by
  `isSolved()`) and, on its **first** pass while `flagA` was still false, transfers PalaceVault's *entire ETH
  balance* to `tx.origin` — draining the second half of the `Setup` funding to us as a side effect.
- `isSolved() == flagA && mapping[TARGET]==0 && address(this).balance==0`.

Rather than fully hand-decode the loop's guard-selection/ordering logic, the tiny remaining search space
(`card[0]=0`, `card[1]=1` required by two other gates; `card[2..4]` each bounded to `0..3` by a third gate) —
**64 candidates** — was brute-forced with cheap, state-free `eth_call`s (spoofing `from=TARGET`, valid since
`eth_call` doesn't authenticate the sender) against the live chain. `card = [0,1,3,0,1]` was the unique
combination that didn't revert.

## Exploit

1. Deploy a `Factory` (plain `CREATE2` deployer) and an `Implementation` contract whose `attack(address)` calls
   `enter()`, `openPath()`, `infiltrate(hex"0001030001")`, `stealHeart()` in sequence.
2. Grind a `CREATE2` salt so `Implementation`'s address has 2 leading zero bytes (`<= uint144.max`).
3. Deploy the 36-byte Agent proxy (initcode: `CODECOPY` the runtime, `RETURN` it) delegatecalling to that
   vanity address.
4. Call `Agent.attack(TARGET)`. This becomes `BlockJail`'s privileged `agent`, opens the path, submits the
   correct card (arbitrary-write primitive) to flip PalaceVault's solved flag and drain its balance, then
   drains BlockJail's own balance via `stealHeart()`.
5. `Setup.isSolved()` → `true` (`pathOpened`, `BlockJail.balance==0`, `PalaceVault.isSolved()==true`).

## Flag

`COMPFEST18{I_guess_bro_here_is_relatively_secure_mirror_flag_you_have_searched_for_0f95fd47}`

## Notes

- Solidity source for `PalaceVault.sol` was not provided; the exploit's `card` value was derived by reverse
  engineering the deployed bytecode plus a small (64-candidate) `eth_call` brute force, not from source.
- The connection endpoint fronts a Next.js "Blockchain Launcher" behind a `pwn.red` proof-of-work gate and a
  Cloudflare managed challenge; a real browser (DrissionPage/Brave) was used to clear both and to retrieve the
  per-instance RPC URL / private key / `Setup` address (which the UI visually truncates but which appear in
  full in the `/launch` endpoint's JSON response), and to click the UI's "Flag" button — bound to the launch
  session's cookie — once `isSolved()` was confirmed on-chain.
