# Two Worlds, One Heart — Reverse Engineering (Easy)

**Flag:** `pwnsec{h3_5p34k5_32_5h3_5p34k5_64_l0v3!}`

## Decisive clue
Three response tiers, not two: `[-]` "didn't even try to listen", `[~]` "I heard your
words... but you still don't understand my heart", `[+]` granted. A *partial* tier means
one input is validated twice, by two different things. The binary is named
**portal33.exe**, and `main` refuses to do anything unless `IsWow64Process` is true —
`0x33` is the WOW64 64-bit code-segment selector.

## Mechanism: Heaven's Gate over one shared byte range
`main` (0x408CB0) reads one 128-byte line, trims it, then:

```
if (strlen(input) == 40 && sub_401600())   // else "[-]"
    if (sub_4016B3(input, sub_401600))     // else "[~]"
        -> "[+] Access Granted"
```

`sub_4016B3` is a classic Heaven's Gate stub:

```
push 33h ; call $+5 ; add [esp],5 ; retf   ; far-return into CS=0x33 (64-bit)
mov esi,esi / mov ebx,ebx                  ; zero-extend to rsi/rbx
call ebx                                   ; ebx = 0x401600  <-- the SAME function
... push 23h ; retf                        ; back to 32-bit
```

So **the bytes at 0x401600 are executed twice — once as x86-32, once as x86-64.**
The selector is a single instruction:

| bytes | 32-bit decode | 64-bit decode |
|---|---|---|
| `31 C0` | `xor eax,eax` | `xor eax,eax` |
| `48 85 C0` | `dec eax` + `test eax,eax` → **NZ, fall through** | `test rax,rax` → **Z, jump taken** |

Falling through validates `input[0:20]`; the taken branch validates `input[20:40]`.
"The exact same words mean one thing to him, and something completely different to her."

Both halves are the same invertible chained construction, `rol(word ^ prev) == const`,
where each step's key is the previous step's expected value:

* **32-bit world** — 5 dwords, `rol 11`, keys/targets `0x1337C0DE → 0xCDBD7302 →
  0x30833D2E → 0xB310EA05 → 0xDEF1B433 → 0x1C3B640E` ⇒ `pwnsec{h3_5p34k5_32_`
* **64-bit world** — qword @+0x14 (`rol 0x13`), qword @+0x1C (`rol 0x1D`), dword @+0x24
  (`rol 0xD`) ⇒ `5h3_5p34k5_64_l0v3!}`

Inverting with `ror` recovers all 40 bytes directly — no search.

## Verification
```
$ printf 'pwnsec{h3_5p34k5_32_5h3_5p34k5_64_l0v3!}\n\n' | wine files/portal33.exe
[+] "You didn't just listen to my words... you stayed until you understood my heart."
[+] Access Granted! Flag verified.
```

## Paths not taken
`sub_401730` renders the large ANSI truecolor portal artwork from `.rdata` into a
`.bss` buffer. It is decoration; it was named as the loop risk up front and never
reversed. IDA's `JUMPOUT(0x41837B)` for `sub_4016B3` is a misread of the `retf` — there
is no runtime-generated code in `.bss`.

## Lesson
A *partial*-credit response tier is a structural tell: it localises the check count
before any decompilation. And when a PE gates itself on `IsWow64Process`, read the
same code at two bitnesses before assuming the second checker lives elsewhere.
