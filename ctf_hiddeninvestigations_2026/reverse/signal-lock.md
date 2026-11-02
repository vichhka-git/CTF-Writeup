# Signal Lock

Reverse, 57 points, 382 solves. The anti-cheat module is a single stripped Erlang BEAM file,
shipped gzipped, with no source and no `abstract_code` chunk. Its entry point validates an
8-byte session token by running it through a 64-bit bijection and comparing against a
constant. The accepted token drives a SHA-256 keystream that decrypts a 48-byte literal into
the flag.

## What you are given

`signal-lock.zip` is 1,345 bytes and holds one member, `signal_lock.beam`, 1,215 bytes, which
`file` reports as gzip. Gunzipping gives a 1,624-byte IFF container: `FOR1`, a big-endian
total size, `BEAM`, then the chunks `Line` (86 bytes), `Type` (72), `AtU8` (278), `Code`
(731), `StrT` (0), `ImpT` (184), `ExpT` (40), `LitT` (115) and `Meta` (28). The README says
Erlang/OTP 26 or newer and suggests loading the module and calling `signal_lock:verify/1`.
The team's submission log records the recovered token as accepted (`goodFlag`, 31 October
2026).

## Reproduction

1. Unpack the module and confirm there is no source inside. There is no `abstract_code`
   chunk, so the only route is the `Code` chunk and `beam_disasm`.

   ```sh
   file signal_lock.beam              # gzip compressed data, original size 1624
   gunzip -c signal_lock.beam > unpacked.beam
   head -c 12 unpacked.beam | xxd     # 464f5231 ... 4245414d
   ```

2. Read the atom table from `AtU8` before disassembling anything. It contains `verify`,
   `transform`, `unlock`, `keystream`, `cipher`, `sha256`, `crypto`, `hash`, `rotl`, `bsl`,
   `bsr`, `bor`, `bxor`, `binary:part/3`, `lists:zip/2`, `list_to_binary` and
   `binary_to_list`. That is enough to predict the shape: a rotate, a hash-based stream, a
   binary compare and a zip/XOR loop.

3. Inflate `LitT`. It holds three terms only: `{error,locked}`, `{error,bad_token}`, and one
   48-byte binary. There is no token literal anywhere, so the accepted token has to be
   computed rather than found. The 48-byte binary is the ciphertext.

4. Disassemble on a matching runtime. OTP 29 disassembled the module unchanged, so the
   README's OTP 26 note only matters for loading it.

   ```erlang
   erl -noshell -eval 'io:format("~p~n",[beam_disasm:file("signal_lock")]),halt().'
   ```

   The exported function is `verify/1`. Guarded clauses are `is_binary(Token),
   byte_size(Token) =:= 8`, then `<<X:64>> = Token`, then `case transform(X) of
   12675316763487955908 -> {ok, unlock(X)}`. Any other 8-byte value returns
   `{error,locked}` and anything that is not 8 bytes returns `{error,bad_token}`.

5. Write down the transform constants. `transform/1` is a straight-line sequence:

   ```
   A = X bxor 0xA5A5A5A55A5A5A5A
   B = (A * 0x9E3779B97F4A7C15) band 0xFFFFFFFFFFFFFFFF
   C = rotl(B, 29)                       % ((B bsl 29) bor (B bsr 35)) band 2^64-1
   return (C + 0x0123456789ABCDEF) band 0xFFFFFFFFFFFFFFFF
   ```

   The target is `12675316763487955908`, which is `0xAFE7C5708F40EBC4`.

6. Invert the chain instead of searching it. Every step is invertible: xor, multiplication
   by an odd constant (invertible modulo `2^64`), a rotation, and an addition. Reverse order
   with `C3 = 0x0123456789ABCDEF`, `C2 = 0x9E3779B97F4A7C15` and
   `C1 = 0xA5A5A5A55A5A5A5A`:

   ```
   t = (12675316763487955908 - C3) mod 2^64
   b = rotr(t, 29)
   a = b * inverse(C2) mod 2^64
   X = a xor C1
   ```

   That gives `X = 0x67346D3330763372`, whose 8 bytes are `67 34 6d 33 30 76 33 72`, the
   ASCII string `g4m30v3r`.

7. Follow the success branch. `unlock/1` fetches the 48-byte literal and builds
   `keystream(Seed, Len)` as `crypto:hash(sha256, <<Seed:64, I:32>>)` for `I = 0, 1, ...`,
   concatenated and cut to 48 bytes. Both fields are big-endian, so the counter starts at
   `00000000`. The flag is the literal XOR that stream.

8. Confirm against the real module, which is the only check that matters:

   ```sh
   erl -pa . -noshell -eval 'Tok = <<16#67,16#34,16#6d,16#33,16#30,16#76,16#33,16#72>>,
     io:format("~p~n",[signal_lock:verify(Tok)]), halt().'
   ```

   It returns `{ok,<<"hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}">>}`. Two control
   cases separate the two failure paths: `verify(<<0:64>>)` returns `{error,locked}` and
   `verify(<<1,2,3>>)` returns `{error,bad_token}`.

9. What the notes do not record: which OTP release the author compiled with, beyond the
   README's "26 or newer". The challenge has no live service, so there is no server-side
   transcript either; the module call in step 8 is the whole interaction.

## Why it works

The validator is a bijection built from invertible operations, so the accepted token is fully
determined and recoverable by running the chain backwards. A brute-force search over 2^64
values is unnecessary, and the literal table offers no shortcut because it never contains the
token. The same structure makes the flag recoverable: the input token is the only secret in
the keystream, and the success branch returns the XOR result directly.

## Flag

```
hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}
```
