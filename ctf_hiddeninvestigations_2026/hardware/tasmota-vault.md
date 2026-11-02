# Tasmota Vault

Hardware, 56 points, 428 solves. A farm gateway was retired during a vault-key rotation. Its ESP32 flash is preserved along with a short broker capture. The gateway runs official Tasmota firmware with a custom Berry agent, and the agent holds the logic that unwraps a sealed record. The task is entirely offline: read the flash, recover the agent and its data from the filesystem, work out the key derivation from the agent's own bytecode, pick the rotation epoch the gateway could authenticate, and open the sealed record.

## What you are given

`tasmota_vault.zip` contains:

```
flash.bin      4 MiB ESP32 flash image, physical offsets preserved
mqtt.pcap      30 packets, Ethernet/IPv4/TCP/MQTT 3.1.1
recovery.txt   acquisition notes and format assumptions
ATTRIBUTION.txt
```

`recovery.txt` sets the ground rules: classic ESP32, 4 MiB flash, LittleFS disk format 2.0 with 4096-byte erase blocks, Berry bytecode v4, and a warning that the ESP32 partition label and subtype follow upstream naming rather than the actual on-flash format. It also says the capture includes historical state and a TCP retransmission, and that the factory NVS is unprovisioned. `ATTRIBUTION.txt` pins Tasmota v15.6.0 and states plainly that the files in LittleFS belong to the challenge application and are not Tasmota settings, so `decode-config` is the wrong tool.

There is no instance, no broker and no login material. Nothing in this challenge touches the network.

## Reproduction

1. Read the partition table at `0x8000`:

   ```
   type=1 sub=2   off=0x9000    size=0x5000    nvs
   type=1 sub=0   off=0xe000    size=0x2000    otadata
   type=0 sub=0   off=0x10000   size=0xd0000   safeboot
   type=0 sub=16  off=0xe0000   size=0x2d0000  app0
   type=1 sub=130 off=0x3b0000  size=0x50000   spiffs
   ```

   The last partition is labelled `spiffs` and is not SPIFFS. `recovery.txt` warns about exactly this. Carve `0x3b0000..0x400000` out to `lfs.img` and check the superblock: ASCII `littlefs` appears at offset `0x8` and the version word reads `0x00020000`, so it is LittleFS 2.0.

2. Mount it with block size 4096 and list the tree:

   ```
   /autoexec.be          18 B    load("vault.bec")
   /vault.bec          1464 B    Berry bytecode v4, magic BE CD FE 04
   /vault/device.id      16 B
   /vault/keyring.bin   108 B    three entries of <u32 LE epoch><32-byte key>
   /vault/sealed.bin     74 B    12-byte GCM IV | 46-byte ciphertext | 16-byte tag
   ```

   The keyring entries are epochs 6, 7 and 8. The sealed record is 74 bytes, and since AES-GCM does not pad, the plaintext is 46 bytes.

3. Do not reverse `vault.bec` by hand. The workspace ships a Python port of the Berry interpreter (`src/berry_port`) with the v4 bytecode loader, so load the file with that module and walk the proto tree, printing constants and opcodes. That is what makes the next step trustworthy: the semantics come from the same bytecode format the device ran.

4. Read the recovered constants. They name the whole protocol without ambiguity:

   ```
   crypto  json  mqtt  read_blob  unseal  vault_message  subscribe
   farm/gw-01/cmnd/VaultRotate
   vault/device.id   vault/keyring.bin   vault/sealed.bin
   tasmota-vault/unwrap/v2   '00'
   HMAC_SHA256   AES_GCM   tag   nonce   epoch   device   rotation
   authentication tag
   ```

5. Read the `unseal()` logic (the second proto, 151 instructions). In order: parse the request as JSON; read `vault/device.id` and require the request's `device` to equal it, otherwise raise `device`; require `epoch` to be an int of at least 1 and `nonce` to be 32 bytes, otherwise raise `rotation`; read `vault/keyring.bin` and require its size to be a multiple of 36; select the 32-byte key from the entry whose epoch matches; build the transcript; derive; then decrypt and check the tag, raising `authentication tag` on mismatch.

   ```
   rk = bytes.fromstring("tasmota-vault/unwrap/v2")   # raw ASCII
      + bytes("00")                                  # hex -> one 0x00 byte
      + dev + add(epoch, 4) + nonce
   k  = HMAC_SHA256(keyring[epoch]).update(rk).out()
   iv = sealed[0:12] ; ct = sealed[12:-16]
   pt = AES_GCM(k, iv).decrypt(ct), tag checked against sealed[-16:]
   ```

   The split between `bytes(str)` and `bytes.fromstring(str)` is load bearing. `bytes(str)` parses hex, so `"00"` becomes a single `0x00` separator byte; `bytes.fromstring(str)` takes raw ASCII, which is why the domain string is written that way. Getting this backwards produces a key that fails the GCM tag, and nothing in the agent labels the difference; only the bytecode shows which constructor is used where.

6. Read the broker capture. It is small enough to walk by hand: TCP to the broker on the MQTT port, CONNECT with client id `farm-gw-01` and a lab read-only login (the credentials are in the capture; treat them as fixture values), SUBSCRIBE to `farm/gw-01/cmnd/VaultRotate` at qos1, then two PUBLISH packets to the gateway on that topic. The second publish is the TCP retransmission of the first.

   The first publish names the device, `epoch` 7 and a nonce. The second names the same device, `epoch` 8 and a different nonce:

   ```
   epoch 7 nonce 9bb1ebe2f5663269d3be1348ee57dc7dbce22b373243aebd67897581cf6f65f0
   epoch 8 nonce 1a3dfb1382455e073f25450c8c8cee24ba89b0a924f86b7103a732ab902a2606
   ```

   `recovery.txt` already said the capture contains historical state, so one of these two is a past rotation rather than the current one.

7. Run the derivation for both epochs, using the keyring key for that epoch:

   ```python
   msg = b"tasmota-vault/unwrap/v2" + b"\x00" + dev + struct.pack("<I", epoch) + nonce
   key = hmac.new(keyring[epoch], msg, hashlib.sha256).digest()
   pt  = AESGCM(key).decrypt(sealed[:12], sealed[12:], None)
   ```

   Epoch 7 fails the GCM tag. Epoch 8 authenticates and returns the flag. The tag is the oracle: the historical epoch is rejected by cryptographic verification rather than by inspection.

8. Record the dead ends that cost time, because they all look plausible at first:

   - `decode-config` on the flash. `ATTRIBUTION.txt` says the LittleFS files are the challenge application, and the factory NVS is unprovisioned, so there are no settings to decode.
   - Treating the `spiffs` partition as SPIFFS. The label lies and the magic is `littlefs`.
   - AES-256-CBC or AES-CTR using a keyring key directly. Those calls do not exist in the bytecode; the keyring key is only an HMAC input.
   - Searching the NVS partition for credentials. It is the unprovisioned factory NVS.

## Why it works

The rotation protocol protects the sealed record with a key derived from three inputs: a per-epoch keyring entry, the device identifier, and a 32-byte nonce delivered over MQTT. Every one of those inputs is on the retired gateway or in the captured session. The keyring sits in the same LittleFS as the sealed record, the device identifier is a file next to it, and the nonce came over a broker connection that was captured. The only remaining work is to reproduce the transcript layout exactly, and the agent's own bytecode documents that, including the awkward hex-versus-ASCII constructor split.

The design flaw is that rotation is treated as a confidentiality boundary when it is only an ordering. All three epochs of key material are retained in the same keyring file, so an old epoch cannot protect anything; the only thing separating `epoch 7` from `epoch 8` is which nonce the broker last sent, and the capture contains both. The GCM tag then decides, which is why the challenge is solvable without brute force and why the wrong epoch fails cleanly instead of producing a plausible-looking plaintext.

The local notes do not record the packet timestamps or the broker address from the pcap, and they keep the device identifier and the keyring bytes out of the prose. Those come straight out of the LittleFS mount.

## Flag

```
hiCTF{b3rry_r0t4t10n_c94934d76344ab1151e03afd}
```
