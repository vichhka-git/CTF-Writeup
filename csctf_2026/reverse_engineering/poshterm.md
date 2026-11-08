# PoshTerm

**Category:** Reverse Engineering · **Points:** 120 · **Flag:** `CSCTF{4_G00D_P0W3RSH3LL_DO35_N0T_C4LL_W1K1P3D14}`

## What the handout gives you

The handout arrives as an archive containing a Windows terminal emulator executable and a brief user manual.

- `chall.7z` — a 63 MB 7-Zip compressed archive containing the challenge files.
- `PoshTerm.exe` — an 85 MB 64-bit Windows portable executable extracted from the archive.
- `documentation.txt` — a plain text file describing the custom terminal commands and basic usage.

## Walkthrough

1. **Identify the bundle type.** Running `file PoshTerm.exe` identifies a 64-bit PE32+ executable. Strings inspection reveals standard .NET runtime hosting exports and embedded assembly bundle markers (`BSJB`). The binary is a self-contained single-file .NET 6 application bundle that packages the CLR runtime alongside the target assemblies.

2. **Extract embedded managed assemblies.** Single-file .NET extractors or decompiler bundles recover the packed managed modules directly from the host PE file. The bundle contains multiple runtime dependencies (`System.Private.CoreLib.dll`, `System.Net.Http.dll`) and the application logic inside `PoshTerm.dll`.

3. **Locate the command dispatch logic.** Opening `PoshTerm.dll` in a .NET decompiler exposes the main terminal processing loop. The switch table evaluates user input strings against typical utility commands such as `help`, `clear`, `connect`, and `exit`. Alongside these entries lies an undocumented command keyword: `_sc`, which is also aliased to `service_code`.

4. **Decompile the hidden service handler.** The handler method for `_sc` sets an airframe parameter string `"Cessna 421 Golden Eagle"` and forwards it as an argument to an asynchronous internal method designated `A()`.

5. **Reconstruct the dynamic key generation.** Method `A()` performs two successive external web API transactions to construct a decryption key:
   - It sends an HTTP GET request to the Wikipedia search API (`https://en.wikipedia.org/w/api.php?action=query&list=search&format=json&srlimit=1&srsearch=Cessna+421+Golden+Eagle`) to resolve the canonical article title. It then fetches the HTML content of the article and evaluates a regular expression across the text near the `first_flight` attribute. The regex matches `October 14, 1965`, which the code converts into the ISO format string `1965-10-14`.
   - It submits this formatted date string as a query parameter to the NASA JPL Solar System Dynamics calendar API endpoint (`https://ssd-api.jpl.nasa.gov/jd_cal.api?format=jd.7&cd=1965-10-14`). The API response returns a JSON object containing the astronomical Julian Date field `jd`: `"2439047.5000000"`.

6. **Identify the stream cipher.** Function `j()` initializes a 256-byte state array `l` with sequential values from 0 through 255. It executes a Key Scheduling Algorithm (KSA) loop that permutes the state using the key bytes. A second loop implements the Pseudo-Random Generation Algorithm (PRGA) to XOR input bytes with keystream values. This structure matches standard RC4 stream cipher decryption.

7. **Decrypt the stored ciphertext.** Method `A()` defines a static 48-byte hex array: `37f1f43867e61d207c0b78ca4385ee14f67d98e0c0cdbe6e5027ff506e302cb66b8c8c5ad07d726c0e24e9f13bbcdfa9`. Decrypting this byte array with RC4 using the exact ASCII key string `"2439047.5000000"` yields the plaintext flag string.

## Answer

The decrypted payload produces the flag string:

`CSCTF{4_G00D_P0W3RSH3LL_DO35_N0T_C4LL_W1K1P3D14}`

## Notes

The key requires the full string `"2439047.5000000"` including all seven decimal places. Parsing the value as a floating-point number and re-stringifying it without fixed formatting drops the trailing zeroes and breaks decryption.

