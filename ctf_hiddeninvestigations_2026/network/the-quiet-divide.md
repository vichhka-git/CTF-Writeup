# The Quiet Divide

Network, 73 points, 133 solves. One 150 MB capture from a 98 second window on an Asterion Dynamics
network. Nothing in it is protected by a secret that cannot be recovered: the TLS keylog for the
QUIC session is split into two escrow shares that XOR back together, and the archive key is derived
from data the capture itself carries. The work is deciding which of the replicated records is
authoritative, and only one transaction in three mirrored SQLite archives satisfies every identity
check.

## What you are given

`the-quiet-divide.zip` expands to one file, `the-quiet-divide.pcap`: 152,240,093 bytes, 110,248
packets, 98.8 seconds from 2026-11-01 14:18:45 UTC, snaplen 262,144, Ethernet, SHA-256
`20745719c71667df455e3bd68cd948d4dffbe3c68ac925dc991e2040411bdddc`. There is no instance and no
login material.

The traffic is 109,997 TCP frames (the bulk of the bytes), 370 HTTP frames, 23 QUIC frames, 56 DNS
and 168 ARP. The service roles, read from URIs and user agents, are: an archive vault that stores
and serves `/api/v2/archive/ops-17/<md5>` blobs, a case and custody service (`/v8/events`,
`/v8/audit`, `/v8/policy`, `/v10/finalize-batch`, `/v10/sdk`, `/v10/interop`), a committee roster,
a device enrollment and attestation service, two firmware distribution endpoints (7.7.0 and 7.7.1),
a pulse frame endpoint, an independent witness checkpoint (`/v9/checkpoint`, `/v9/trust`), a replica
ingest, and NOC monitoring noise. The addresses and service ports are visible in the capture and are
not reproduced here.

## Reproduction

1. Confirm the shape before carving anything.

   ```sh
   capinfos the-quiet-divide.pcap
   tshark -r the-quiet-divide.pcap -q -z io,phs
   ```

   The protocol hierarchy shows the HTTP frames carrying 132 KB of JSON and the TCP bulk carrying
   the archives. Nothing exotic is hiding in the byte count.

2. Carve the HTTP objects.

   ```sh
   tshark -r the-quiet-divide.pcap --export-objects http,objects
   ```

   215 objects, 142,291,118 bytes: 171 JSON, 27 binary, 2 ELF, 15 text. Three of the binary objects
   are 4,861,987 bytes and start with `AVLT10\0`; each has a matching `archive-write-receipt/2`
   JSON. Six larger objects start with `AVLT2` and are not part of this path.

3. Read the SDK and interop objects. They describe the envelope: `AVLT10\0`, a 12-byte nonce, then
   AES-256-GCM over an SQLite corpus, keys from HKDF-SHA256, Ed25519 signatures, and canonical JSON
   with sorted keys, compact separators and ASCII only. The info strings are
   `MIRRORBREAK/10/RECORD-VAULT` for the archive and `MIRRORBREAK/10/PRODUCTION-CASE` for the final
   seal.

4. Recover the keylog from the escrow shares. There are eight escrow objects: four share records
   carrying `batch_id`, `slot`, `share_b64`, `linked_observation_sha256` and `keylog_sha256`, and
   four write receipts. Two batches have two slots each, and every share is 760 bytes after base64
   decoding. XOR the two slots of a batch:

   ```python
   a = b64decode(obj['share_b64']); b = b64decode(obj2['share_b64'])
   len(a), len(b)          # (760, 760)
   keylog = bytes(x ^ y for x, y in zip(a, b))
   ```

   Batch `84e2f6dce89de72d37fe90f1` gives 760 printable bytes whose SHA-256 is
   `fbe54727d9b4e9fda0797486cb933d1f06c6db3790394e4e1a6b1630e4f202c4`, exactly the
   `keylog_sha256` recorded in the object. Batch `fe3785612f9ddb7cd02844ec` behaves the same way
   (`b52d5cda69ce3bee3f9c784e3485dd8d3cd80f9c33f731cb9920f8ef583232d8`). The XOR is an NSS keylog:
   four lines, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_HANDSHAKE_TRAFFIC_SECRET`,
   `SERVER_TRAFFIC_SECRET_0` and `CLIENT_TRAFFIC_SECRET_0`, each a label, a 64-hex client random and
   a 96-hex secret.

5. Decrypt the QUIC session with that keylog.

   ```sh
   tshark -r the-quiet-divide.pcap -o tls.keylog_file:84e2f6dce89de72d37fe90f1_xor.bin \
     -Y "quic" -T fields -e frame.number -e quic.stream_data
   ```

   The handshake is frames 10641 and 10644. Frame 10668 is a 403-byte `mb-quic-observation/3`
   record signed by ARCH-14: `device_id ARCH-14`, `epoch_ms 1793517535155`, `firmware_sha256
   0835dfce...`, `load_pct 8`, `queue_depth 31`, `sequence 848971`, `shard IDX-S9`, signature
   `798fa204...`. Frame 10672 is an `mb-quic-ack/3` whose `signed_sha256` is `60369e7f...`, the
   observation hash the custody events reference. A second QUIC handshake near the end of the
   capture (frames 110137 and 110138) is a different session and was not needed.

6. Verify the custody chain. Each `audit` object holds `events` and a `seal`; each event carries
   `event` and `signatures` keyed by committee member. The committee object gives five Ed25519
   public keys, `threshold 3`, chairs C0 and C1, and a `signature_domain` whose last two characters
   are a literal backslash and a zero. The five signatures verify over that string with those two
   characters replaced by a single 0x00 byte, not over the literal text. Canonicalisation is
   `mb-cjson-ascii-v1`: sorted keys, compact separators, ASCII.

   ```
   732 ROOT   parent 0000...  hash 8c3c3046...
   733 PREP   parent 8c3c3046  hash 4999e542
   733 COMMIT parent 4999e542  hash f61ce4fe
   734 PREP   parent f61ce4fe  hash 9a5e1332
   734 COMMIT parent 9a5e1332  hash b34dc728
   ```

   All five verify with the NUL form of the domain and three signers, and the checkpoint object
   freezes epoch 734 COMMIT with `terminal_event_sha256 b34dc728...`, signed by W0, whose delegation
   from C0 is the `trust` object. Policy fixes the terminal at 734/COMMIT and states that a recovery
   credential (authority class `standby-diagnostics`, domain `dr-ops`) cannot finalize production,
   which rejects the 735 branch that also appears in the ingest and log objects.

7. Pick the firmware. Two distributions are present: 7.7.0 with SHA-256 `0835dfce...` and 7.7.1 with
   `7f2081d3...`. The release ticket approves 7f2081d3, but policy says qualification is not
   installation, and every custody event plus the attestation names `0835dfce...`. Each ELF arrives
   as four HTTP fragments; concatenating `pulse-codec_7.7.0_amd64.elf` with `(1)`, `(2)` and `(3)`
   gives 14,528 bytes whose SHA-256 is `0835dfce...`.

8. Decode the PLS2 frame. Five `PLS2` magic hits exist in the capture; the real one is at file
   offset 40620, 32 bytes, and its SHA-256 `10da1fc0...` equals the `frame_sha256` in the
   attestation body, which is how it is identified. The frame is checked with CRC32 over the first
   28 bytes and with a state witness `seq ^ (queue << 8) ^ load ^ 0x5AA5A55A`. The fields decode as:

   ```
   sequence = ror(be32(frame[8:12]), 7) ^ 0xC0FFEE21                    -> 10450910
   queue    = be16(frame[20:22]) ^ ((seq * 73) & 0xffff)                -> 23
   load     = be16(frame[22:24]) ^ ((seq*173 + queue*7) & 0xffff)       -> 71
   epoch_ms = (be64(frame[12:20]) - (seq << 13)) ^ 0xA96D4E0B7C2296F1   -> 1793517529318
   ```

   Then `codec = sha256("MB10/CODEC/STATE\0" + canonical({sequence, scheduler_queue, load,
   epoch_ms}) + frame)` is `c358a8d65550291f281fb21927a04e3462d0d33e0063eb6594b21a79181007c9`, the
   `observed_state` the authoritative record has to carry.

9. Derive the archive key.

   ```
   chain    = sha256(canonical(audit["events"]))                 -> 7a7a01d9...
   fw       = HMAC(key=chain, "MB10/FULL/ELF\0" + firmware)      -> 772264c1...
   evidence = chain || fw || attestation_sig || observation_sig || codec   (224 bytes)
   key      = HKDF-SHA256(evidence, salt=seal.archive_salt_hex,
                          info="MIRRORBREAK/10/RECORD-VAULT")
   ```

   `archive_salt_hex` is `6d562eb7d1e5ef0b993548337b8a2b9b` and the derived key is `a62a8156...`.
   Decrypt each candidate with `AESGCM(key).decrypt(blob[7:19], blob[19:], aad)`, where the AAD is
   `canonical({"schema":"mb-corpus/10","commit":"b34dc728..."})`. All three decrypt to a
   4,861,952-byte `SQLite format 3` database, so the GCM tag does not choose between them.

10. Open the databases. Each has four tables: `transfers` (7 rows: `tx_id`, `case_commit`,
    `device_nonce`, `counter`, `origin`, `version`, `release_checkpoint`), `receipts` (7 rows:
    `observed_state`, `disposition`, `fragment_commit`), `fragments` (28 rows, four per transaction)
    and `operations` (10,000 rows of noise).

11. Decide which transaction is the production record. A row qualifies only if every identity field
    agrees with the evidence and its fragment commit recomputes:

    ```
    identity: case_commit == b34dc728...        (terminal event)
              device_nonce == 12060f75d51d36eb9db836f46f49f575
              counter == 10450910               (frame sequence)
              origin == "OPS-17", version == 10
              release_checkpoint == 5e4f78ad... (witness checkpoint)
              observed_state == c358a8d6...     (codec)
              disposition == "accepted"

    fragments: pad_i  = HMAC(codec, "MB10/FRAGMENT\0" + tx_id + be32(ord))
               material = concat(payload_i XOR pad_i)              (32 bytes)
               commit   = sha256(material + terminal + tx_id + codec) == receipt.fragment_commit
    ```

    Across all three archives exactly one row passes both: `6dd9ec588c9914ca95df44b2` in
    `archive_plain_5a2c8adef3c0846a2d0fb62d00844c64.sqlite`. Other rows match the case commit and
    the nonce but fail the fragment commit, or match the fragments and carry a different nonce or
    counter. The recorded output ends `validated_transactions=1`.

12. Open the final seal. The seal lives in `audit["seal"]` and is an `mb-final-seal/10` body with
    `salt_hex ded3d12c395ca229af8ed23e9268ab99`, `nonce_hex 0de2e11f0e0d47651a0c1b45`,
    `archive_batch_sha256 672e46f7...` and `checkpoint_sha256 5e4f78ad...`:

    ```
    final_key = HKDF-SHA256(material || evidence || checkpoint_signature,
                            salt=seal.salt_hex,
                            info="MIRRORBREAK/10/PRODUCTION-CASE")
    aad       = canonical({schema, terminal_event_sha256, attestation_sha256,
                           observation_sha256, firmware_sha256,
                           archive_batch_sha256, checkpoint_sha256})
    plaintext = AESGCM(final_key).decrypt(seal.nonce_hex, seal.ciphertext_b64, aad)
    ```

    The plaintext is 47 bytes, SHA-256 `197ba28c...`, and it is the flag.

13. What the notes do not record: the chain hash, firmware HMAC, evidence hash and archive key are
    printed during the recorded run but are not stored in the artifacts. The values above
    were recomputed from the same objects and reproduce the recorded codec and all three archive
    decryptions. The `AVLT2` family and the escrow-linked 735 branch were not needed. The local
    `RESULT.md` is intake-only and still says pending; the accepted record is the submission log
    entry from 1 November 2026 and the local scripts and outputs.

## Why it works

The capture is self-authenticating but not self-selecting. Everything needed to derive the archive
key is in the clear: the custody events, the deployed firmware ELF, the attestation signature, the
observation signature and the codec state. The only hidden piece is the TLS session key, and it was
split across two escrow records that XOR back into a keylog, so the transport secret and the
application evidence sit in the same capture and one opens the other.

The selection is the real puzzle. Three archives are valid corpora under the same key, and the
witness checkpoint, the attestation nonce, the frame sequence and the codec state are what separate
the production record from the decoys. Trusting the checkpoint alone still fails, because several
rows carry it; the fragment commit is what binds the recovered material to the case, and only one
row satisfies both halves.

## Flag

```
hiCTF{c8c46fdbd6e5e4eacabfba53a156ff9ab10567f2}
```
