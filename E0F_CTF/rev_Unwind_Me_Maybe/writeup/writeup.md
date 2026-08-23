# Unwind Me Maybe - Reverse Engineering Writeup

## Summary
- **Category:** rev
- **Points:** 378
- **Binary:** unwind-me-maybe.exe (64-bit Windows PE compiled with Rust and MSVC)
- **Flag:** `e0f{p4n1c_0wn5_th3_l4st_b0rr0w3d_byt3!!}`

## Analysis
1. The binary is a 64-bit PE executable written in Rust and compiled with MSVC exception handling.
2. In `main` (0x1400013c0), the program sets a custom panic hook to suppress console output and enters a `try` block catching C++ / Rust panics.
3. It calls function `0x140001840` recursively starting with index 29 (0x1d).
4. Each frame in `0x140001840` registers a C++ unwind destructor (`0x1400018b0`) in the x64 SEH / `.pdata` / `.xdata` FuncInfo exception handler tables, referencing a 4-byte entry in a static lookup table at RVA 0x164d2.
5. When the recursion reaches the terminal entry (where `next == 0`), it deliberately triggers a panic/exception via `0x140014dc0`.
6. During the exception unwinding process, the runtime unwinds the 40 stack frames in LIFO (reverse) order. For each frame, destructor `0x1400018b0` calls `0x1400019b0`, which executes one of four byte operations specified in the table entry:
   - Op 0: `arg1 ^ arg2`
   - Op 1: `(arg1 - arg2) & 0xff`
   - Op 2: `ror8(arg1, arg2)`
   - Op 3: `(rol8(arg1, 4) ^ arg2) & 0xff`
   The resulting byte is appended to an internal buffer.
7. Once unwinding returns to the catch block in `main`, the 40 decoded bytes form the flag string `e0f{p4n1c_0wn5_th3_l4st_b0rr0w3d_byt3!!}`.
