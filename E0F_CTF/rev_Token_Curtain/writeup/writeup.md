# Token Curtain - Writeup

## Summary
- **Category:** Reverse Engineering
- **Challenge:** Token Curtain
- **Flag:** `e0f{t0k3n5_d4nc3_b3h1nd_th3_curt41n_l0l}`

## Mechanism & Analysis
1. The binary `Token.Curtain.dll` is a .NET 10.0 assembly.
2. In `Main`, an interface map of `IPlaybill` implemented on `Ensemble` is inspected.
3. For each method `C00` through `C19`, the method has a `[Cue(Source, Mask, Rotate, Salt)]` custom attribute.
4. Each method calls generic `Fold<T>(Props[cue.Source], cue.Mask, cue.Rotate, cue.Salt)` where `T` is one of the cast classes `M00`..`M19` encoded in `MethodSpec` instantiations.
5. In `Fold<T>`, `typeof(T).MetadataToken` is obtained (which evaluates to `0x02000000 | TypeDef_Row_Index`).
6. `Fold<T>` calculates:
   - `loc0 = ((token * 17881) + salt) & 0xFFFF`
   - `v = (arg0 ^ mask) & 0xFFFF`
   - `v_rot = ror16(v, rot)`
   - `result = (v_rot - loc0) & 0xFFFF`
7. The output 16-bit integers are written little-endian into a 40-byte stackalloc span.
8. The binary hashes this span with SHA-256, prints the first 6 bytes as `Applause: <hex>`, then immediately zero-memories the buffer (`The audience remembers none`).
9. Emulating this transformation in Python over the 20 `Props` ushorts directly reconstructs the 40-byte flag: `e0f{t0k3n5_d4nc3_b3h1nd_th3_curt41n_l0l}`.
