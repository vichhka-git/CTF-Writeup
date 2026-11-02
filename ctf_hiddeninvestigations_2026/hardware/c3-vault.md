# C3 Vault

Hardware, 59 points, 312 solves. The handout is a laboratory acquisition from a retired ESP32-C3 gateway: a 4 MiB SPI flash image and a 336-byte dump of the eFuse read-register window. The gateway still knows how to authenticate to a remote vault, and the flag lives only on a host-side verifier. The work is to peel two encryption layers off the flash, read the enrollment credentials out of NVS, rebuild the response the gateway firmware would produce, and send it to the live verifier.

## What you are given

`c3_vault.zip` contains `flash_image.bin` (4 MiB, physical offsets preserved), `efuse_read.bin` (336 bytes), `recovery.txt`, `ATTRIBUTION.txt`, `SHA256SUMS` and `diagram.png`. There is no login material and no board. The portal supplies the verifier `<challenge-host>` and `<port>` for your team's instance; the hostname changes with each lease.

`recovery.txt` explains the eFuse format: 336 bytes read from registers `0x6000882c..0x6000897b` in ascending address order, each register little endian, BLOCK0 and BLOCK1 with six words each, BLOCK2 through BLOCK10 with eight. It also states that the flag is not in the evidence and that a stale enrollment namespace may survive a credential migration.

If the `efuse_read.bin` in your working copy is several kilobytes of ASCII (`EFUSE_NAME (Block)...`), it is an `espefuse summary` that overwrote the acquisition. Re-extract it from the archive member: 336 bytes, SHA-256 `18d261669c0a3d86c06a454357c59438553ba44a55f8de40dac1a14ad2418104`. The flash image is 4,194,304 bytes, SHA-256 `b1795449ab157d3713900cfcabc2bc9b8f475340ae618c3268f4e1573eb583ac`.

## Reproduction

1. Locate the key block in the eFuse dump. Using the word layout from `recovery.txt`, BLOCK4 occupies bytes `0x70..0x90`. Decode BLOCK0 as well and you get `WR_DIS = 0x00800100`, which write-protects `KEY_PURPOSE_0` and `BLOCK_KEY0`, `SPI_BOOT_CRYPT_CNT = 1` (flash encryption on), and `KEY_PURPOSE_0 = 4`, which is `XTS_AES_128_KEY`. So the 32 bytes at `0x70` are the flash encryption key, and it can no longer be changed. That is why the evidence is enough: the key is burned and readable.

2. Reverse the key. `espefuse` burns XTS keys in reverse byte order, so the effective key is the full reversal of the 32 bytes:

   ```
   7f4d6513a54df7f727c12ffd0fdc61e88292d86a653ddf9c2a2712e7f7110ea6
   ```

   We tested the raw order and a per-word byte reversal against the partition table. Only the full reversal produced `aa50` entries with coherent offsets and sizes, so the ordering is verified by the artifact, not assumed.

3. Decrypt the partition table at physical offset `0x8000`. ESP32 flash encryption is AES-XTS in 128-byte units with the physical address as tweak, and `espsecure` carries it as a private helper (we had 4.7.0 installed):

   ```python
   import io, espsecure
   out = io.BytesIO()
   espsecure._flash_encryption_operation_aes_xts(
       out, io.BytesIO(flash[0x8000:0x8100]), 0x8000, io.BytesIO(key), True)
   ```

   The decrypted table reads `nvs` at `0x9000` size `0x6000`, `nvs_keys` at `0xf000` size `0x1000`, `factory` at `0x10000` size `0x100000`.

4. Decrypt `nvs_keys` at `0xf000` with the same routine. The first 64 bytes are the NVS encryption and tweak keys; bytes 64 to 67 are `57 fb 65 ba`, which read little endian is `0xba65fb57`. That equals `zlib.crc32(first64, 0xffffffff)`, so the 64 bytes are the right ones.

5. Do not decrypt the NVS data partition. Its page headers are already plaintext (`fcffffff00000000feff...` at `0x9000`); only the entries are encrypted. Applying the flash key to `0x9000..0xf000` rewrites the headers and the whole namespace parse fails. Decrypt the app at `0x10000` and the `nvs_keys` page at `0xf000`, nothing else.

6. Parse the secure NVS entries. Each entry is AES-XTS with the 64-byte key and a tweak equal to the entry's offset inside its 4096-byte page, little endian in 16 bytes:

   ```python
   Cipher(algorithms.AES(nvs_keys[:64]),
          modes.XTS(offset_in_page.to_bytes(16, "little"))).decryptor()
   ```

   The namespace table declares `gateway = 1`, `vault_v1 = 2`, `vault_v2 = 3`. Decrypted values are `gateway/hostname = "c3-vault-gw"`, `gateway/device_id` (16 bytes beginning `ee0315f3953aad29...`), `gateway/generation = 7`, a `vault_v1/seed` beginning `d857200f87a1728b...` and a `vault_v2/seed` beginning `826e4e9e65c0ce89...`. Both keys are 32-byte blobs. The full seed bytes are deliberately not transcribed here; they come straight out of the NVS parse and the same parse reproduces them.

7. Decide which namespace is live. `vault_v1` is the stale record left behind by the migration that `recovery.txt` warns about. The decrypted application carries `device_id` at `0x13458`, `vault_v2` at `0x134d4` and `c3-vault/device-key/v2` at `0x135b4`, so v2 plus the gateway generation is the current enrollment. One more detail: `generation` is stored as an NVS `U16` while the firmware calls `nvs_get_u32`. The value is still 7.

8. Read the two HMAC stages out of the decrypted factory image (ESP image magic `e9`, five segments). `app_main` sits at `0x420048f0`. The derivation is:

   ```
   device_key = HMAC_SHA256(seed_v2, "c3-vault/device-key/v2\0" || device_id || le32(generation))
   response   = HMAC_SHA256(device_key, "C3VAULT-AUTH-V2\0" || challenge || device_id)
   ```

   Both domain strings are 16-byte rodata copies, so their length is set by the memcpy and not by the C string. `C3VAULT-AUTH-V2` is 15 characters plus one NUL; the byte after it belongs to the neighbouring `nvs_keys` string. The device-key domain is 22 characters plus one NUL, 23 bytes. The second prefix lives at image offset `0x33a4` (DROM `0x3c0233a4`), which is the offset to check your extraction against.

   The natural misreading, 14 characters plus two NULs, still produces a well-formed HMAC and the live service answers `DENIED`. We ran roughly ninety variants over wrong key and message layouts before the byte-exact firmware layout was the one that authenticated.

9. Authenticate to the live verifier. It greets with a `DEVICE` line and a `CHALLENGE` line carrying 64 hex characters, then expects a single line:

   ```
   auth <response hex>
   ```

   The recorded session at 2026-10-30T16:52:50Z used challenge `55114bf4f801ffe920671d225ae85d91a106b15c3a8cf7e497d260e026258e1c`, produced response `65d7e57812f2c573617838ca03797f28f9b632ea6be7179545225055a0f95d1f`, and the service answered `VAULT OPENED` followed by the flag. A wrong response returns `DENIED`.

   The local notes do not reproduce the verifier's exact banner text beyond the `DEVICE` and `CHALLENGE` fields, and they do not record the framing beyond "line oriented, one `auth` line in". The transcript preserved only the challenge, the response and the final two lines. The working client wraps the socket in TLS without certificate verification, but nothing else about the transport is recorded.

10. Watch the flag spelling when transcribing. Our first submission carried `efus3_cl4r_jt4g...`, one character short in the second word, and the portal rejected it with `badFlag`. The accepted string has `efus3_cl34r`.

## Why it works

The design assumes that flash encryption protects everything at rest because the key lives in eFuse and cannot be read back. The evidence hands over the read-register window instead, and the eFuse layout tells you which 32 bytes are the XTS key and that it is burned in reverse. Once that key is available, both layers fall: the application and the `nvs_keys` partition decrypt with it directly, and the NVS entry key that protects the credentials is the first 64 bytes of `nvs_keys`. The NVS encryption is therefore not an independent barrier, it is a second use of one compromised secret.

Two smaller traps sit on top of that. The `vault_v1` namespace is a valid, decryptable, plausible-looking seed from before the migration, and a solver who takes the first seed they see derives an HMAC that the live service rejects. And the 16-byte domain prefixes make the HMAC input length-sensitive in a way the disassembly does not shout about, because the trailing NULs come from neighbouring rodata rather than from a string length.

## Flag

```
hiCTF{efus3_cl34r_jt4g_0p3n_nv5_47127e7145}
```
