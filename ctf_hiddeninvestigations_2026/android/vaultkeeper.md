# VaultKeeper

Android, 57 points, 378 solves. The APK is a vault app whose single button is supposed to return the master key. Behind that button sits a native pipeline: hash the bundled vault blob into a cell array, mix it in Kotlin, unseal a 2048-byte bytecode program, mix again, run the program in a small VM, and XOR two tables plus the VM output into a 51-byte message that a SHA-256 gate accepts. The message never reaches the screen, so the gate is the only oracle.

## What you are given

`VaultKeeper.zip` contains `VaultKeeper.apk`. Unpacking gives `assets/vault.bin` (8192 bytes) and `libvaultnative.so` for `arm64-v8a` and `x86_64`. No device and no live service are involved.

The app layer is small: `com.hictf.vaultkeeper.claim.ClaimOrchestrator`, `claim.CellMixer`, `claim.BlobSource`, `jni.NativeBridge`, `security.EnvAudit`, `security.FlagRepository` and the two activities. The native library exports `nv_seed`, `nv_unseal`, `nv_exec`, `nv_final` and their JNI wrappers.

## Reproduction

1. Read the orchestration. `ClaimOrchestrator.runClaim` is a state machine: SEEDING calls `NativeBridge.nvSeed(vault, token)`, MIXING1 calls `CellMixer.k1(cells)`, UNSEALING calls `nvUnseal(cells, token)`, MIXING2 calls `CellMixer.k2(prog, cells)`, EXECUTING calls `nvExec(prog, cells, token)`, FINALIZING calls `nvFinal(token)`, then COMMITTED. `EnvAudit.fullPass` runs first, before the state machine touches any native code. The token is a 16-byte array produced by `ui.GestureArmer`; any 16 bytes will do for analysis.

2. Reimplement `CellMixer` exactly, including int32 wraparound. `k1` runs seven rounds. In round `i` it walks the 128-entry array forward when `i` is even and backward when odd:

```
c[k] = rotl32((c[k] + rotl32(c[k-1], 11) + rotr32(c[k+1], 5)) * MUL_C, (i % 3) + 13)
```

jadx prints `MUL_C` as `-2048144789`, which is `0x85EBCA6B` unsigned. `k2` builds a 256-byte block from the cells, XORs it over the program, and repeats per block; the block index shifts the cell stride by 13 and the constant by 31.

3. Map the native entry points. In the x86_64 slice, `nv_seed` is at `0x40c0`, `nv_unseal` at `0x4310`, `nv_exec` at `0x4440`, `nv_final` at `0x46e0`, and the bytecode interpreter is `0x4b20`.

4. Reconstruct `nv_seed`. It hashes the vault blob together with the 10-byte constant at file offset `0xf46`, which reads `VK-SEED-v1`, then expands that digest over the 128-entry int32 array, eight words per digest:

```
d = SHA256(vault.bin || "VK-SEED-v1")
cells[8*i : 8*i+8] = SHA256(d || u32le(i))        for i = 0..15
```

The token is not part of this hash, so the cells do not depend on it.

5. Reconstruct `nv_unseal` and the round key. The output length is `0x800`. `KS` is 51 bytes, built from a 4096-byte rodata region and a label that sits at file offset `0x3220`:

```
KS    = SHA256(SHA256(rodata[0x2220:0x3220]) || "VK-SELFMIX-v1")
KS    = KS || SHA256(KS)[:19]
out[i] = ((cells[(7 + 31*i) & 127] >> ((8*i) & 0x18)) & 0xff) ^ KS[i % 51] ^ rodata[0xf60 + i] ^ 0xa5
```

`k2` then XORs its block keystream over those 2048 bytes to produce the program.

6. Run the program. `nv_exec` passes the buffer to the interpreter at `0x4b20`, which writes a 64-byte result into static storage at vaddr `0x8cb0` (`.bss + 0x240`). The interpreter does not need to be reimplemented: the x86_64 slice of the library runs on a desktop Linux once three Android shims are in place.

7. Build the shims. The library needs `__strrchr_chk` (glibc's checked `strrchr`), four stub shared objects named `liblog`, `libdl`, `libc` and `libm` that carry a `LIBC` version node, and a patched copy of the library with `.gnu.version` rewritten to all-GLOBAL and `DT_VERNEEDNUM` set to 0.

```
LIBC { global: *; };                      # version script for each stub
char *__strrchr_chk(const char *s, int c, size_t n) { return strrchr(s, c); }
```

A short C harness can then `dlopen` the patched copy, `dlsym` the three plain symbols, call them in the order the Kotlin code does, and read `base + 0x8cb0` afterwards. The workspace keeps that harness and the patched library.

8. Compute the message. `nv_final` has an honest branch that assembles 51 bytes, which is exactly the flag length, from two rodata tables, the VM output and `KS`:

```
payload[i] = rodata[0x1770+i] ^ rodata[0x17b0+i] ^ vmout[i] ^ KS[i]    for i = 0..50
gate       = SHA256("VK-TAG-2026" || payload)[:16]
accept     = gate == rodata[0x17f0:0x1800]      # 62672db15a0b6a4793b351292f29a0b3
```

With the VM output from step 7 the gate matches, and the payload is the flag.

9. Do not look for the message in the app. The honest branch copies its 51 bytes into a 16-byte rotating buffer and wipes it. There is no log call, no file write and no UI path for it, which is why the author embedded the truncated hash: it lets a solver confirm a recomputation without ever exposing the plaintext to the device.

What the local notes do not keep is the harness stdout, meaning the 64 VM bytes and the fault word. Those are regenerated by rerunning step 7. The formulas, the offsets, the key material and the gate hash are all recorded.

## Why it works

The flag is not stored. It is assembled from constants and VM output by a function that throws its result away, and the only way to know the assembly is correct is a truncated SHA-256 comparison written for that purpose. Everything else is obfuscation without secrecy: the vault blob is a fixed asset, the token is not hashed into the cells, the hash chain uses no salt or secret input, and the bytecode program is executed by the analyst's own CPU the moment the library loads.

The binary agrees with that reading. It exports a never-called `getFlag` at `0x5e00`, carries a logcat-only flag string, and has two fault-path taunts keyed on a debug bit in the fault word. All four are decoys and none is the answer. The honest path is the one whose XOR output the embedded hash accepts.

## Flag

```
hiCTF{!!I_10v3_4ndr0!d_m4n_m4k!ng_th3m_f331_g0Od!!}
```
