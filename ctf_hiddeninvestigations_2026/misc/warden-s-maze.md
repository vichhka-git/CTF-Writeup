# Warden's Maze

Warden's Maze was a 57 point misc challenge (371 solves in the local record). It is a small terminal arcade game served on one TCP connection. The maze holds a vault sealed on every side, and the only way in is a genuine bug in the engine's visibility pass, which writes an explored tile to a wrongly computed index. The provided binary is the same one the live service runs.

## What you are given

- `maze-breach.zip` with `maze` (459,488 bytes, ELF64 x86-64, static PIE, stripped, Rust, build-id `fed17c6fe344cbb43196e1904e4057492b08a98b`) and `README.txt`.
- The README documents the controls (one letter plus Enter: `w` up, `s` down, `a` left, `d` right, `q` quit), says the whole maze is redrawn after every move, and says the token is minted per instance and only appears on a genuine win.
- The portal supplies `<challenge-host>` and `<port>`. The hosted endpoint is TLS with SNI routing, so a plain `nc` will not reach the game.

## Reproduction

1. Run the binary locally first, where there is no TLS in the way. `docker run --platform linux/amd64 -p <local-port>:<game-port> -v "$PWD":/w -w /w debian:trixie-slim ./maze` publishes the game's own listener (the port is in `README.txt`) on a port of your choosing, and you connect to that local port. You get the initial board, the footer `move: w/a/s/d   quit: q`, and a fresh redraw after every command. Each redraw starts with `ESC[2J ESC[H`, so parse full frames rather than assuming one TCP chunk is one board.

2. Map the data model from the binary. The source maze is 21 rows of 24 characters at file offset 0x5e664. At runtime each cell is one byte, `tilecode | 0x40`, where bit 6 is the explored marker, and the index is `y*24 + x`. The low six bits select the tile: 1 is `#`, 2 is `.`, 3 is `%` (the vault wall), 4 is floor, 5 is `$` (the prize). The renderer masks with 0x3f and looks the code up in the four character table `#.% $` at 0x60d20, falling back to a space.

3. Read the collision rule at 0x6941. It masks the cell with 0x3f and tests a bitmask of 0x35, so codes 0, 2, 4 and 5 are walkable and codes 1 and 3 are walls. The explored bit alone cannot make a wall walkable; the type bits have to change.

4. Read the visibility pass at 0x9680. It walks a radius 6 disk around the player, Bresenham steps a ray from the player to each target, stops the ray at an opaque tile, and marks the target explored when the ray arrives. The target index at 0x985e is computed correctly with a bounds checked helper at 0xa199. The store index is not:

   ```
   0x989d  ecx += i * width        ; 32 bit, width = 24
   0x98a1  movsbq %cl,%rcx         ; sign extends only the low byte
   0x98a5  rcx += player_index
   0x98cb  movb %al,(%map,%rcx)    ; al = target_code & 0x3f | 0x40
   ```

   The write lands at `player + (int8)((i*24 + j) & 0xff)` while the value written is the target tile's code. At `i = 6`, `6*24 = 144`, which does not fit a signed byte; narrowed to int8 it is -112. The up ray is processed before the down ray, so the last store is the one that matters.

5. Turn that into a usable alias. A delta of -112 in a 24 wide grid is 5 rows up and 8 columns right. So standing at (4,14), the target cell 6 rows below is (4,20), and if the downward ray is clear the store lands at (14-5, 4+8) = (12,9), which is a `%` cell of the vault's top wall. The value written is the target's code, 4 for floor, so the vault wall becomes floor. All other radius 6 offsets satisfy `|i*24 + j| < 128` and write back to their own cell, so only the two vertical rays change collision types.

6. Check the geometry against the board. Row 14 column 4 is a corridor cell, and column 4 is clear from row 15 to row 20. Cell (12,9) is part of the vault's top wall in the rendered map. Nothing else has to be true; the breach happens on the move that leaves you standing at (4,14).

7. Walk there and trigger it. From the spawn at (12,1) the recorded route to the breach and then to the prize is 45 moves of one letter each, sent one per line:

   ```
   saaaasssaasssaaaasssdsssd
   awwwwddddwwdddddsssa
   ```

   The breach fires on the 25th character, the `d` that ends the first line at (4,14). The second line goes up and around, through the hole at (12,9), then (12,10), then across to the prize at (11,11).

   An offline breadth first search over the real transitions (map mutation, warden patrol, turn parity) found a different 45 move route and a 60 move route that avoids `w`. Both reach the same cell. Use whichever you prefer; the 45 move version above is the one that was driven against the live instance.

8. Connect to the hosted endpoint. TLS with SNI is enforced by the platform:

   ```
   openssl s_client -quiet -connect <challenge-host>:<port> -servername <challenge-host>
   ```

   Or bridge it locally with `socat TCP-LISTEN:<local-port>,reuseaddr,fork OPENSSL-CONNECT:<challenge-host>:<port>,snihost=<challenge-host>` and point a plain client at the local port. Type the letters one per line and watch the redraws.

9. Win. When the player steps onto the `$`, the controller prints `The vault is open. You take the prize.` and then the token. The live run produced `hiCTF{maze-warden-vault-seed-2026_a6dea3e7e1}`. A local run of the same binary produced a different string, `hiCTF{warden_vault_cleared_845f9b65}`, which matches the README's statement that the token is minted per instance. Submit the token your instance prints.

The local notes record the bug offset, the arithmetic, the cell coordinates and the exact move strings. They do not record a full room by room trace of the 45 moves, only the command sequence and the resulting token.

## Why it works

The engine stores the map as one byte per cell and computes every index as `y*width + x`. The visibility pass needs two indices, one to read the target tile and one to write the explored marker, and the author computed the second one by hand instead of reusing the first. That hand rolled index is built in a 32 bit register and then sign extended from only its low byte at 0x98a1, which is the classic half widened index bug. For almost every offset in the radius 6 disk the truncation is invisible because the value fits in a signed byte. The vertical extremes are the exception: `6*24` is 144, the truncation turns it into -112, and the store lands inside the map rather than out of bounds.

Because the stored value is the target tile's code and not a constant, the stray write copies a walkable floor code onto whatever cell the bad index points at. Here that cell is a vault wall, so the seal becomes ordinary floor and the game's own collision check then lets the player walk in. The vault was never protected by a special rule; it was protected by the assumption that the visibility pass only marks tiles the player can already see.

## Flag

```
hiCTF{maze-warden-vault-seed-2026_a6dea3e7e1}
```
