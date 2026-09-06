# Huddle — TFC CTF 2026 (web)

**Flag:** `BHFlagY{d24705608f579187678933a0e757e1b8}`

Two gates, exactly as the description advertises: "work your way into the owner's
seat, then turn the workspace's own tooling into a window onto the server."

## Recon

`/bundle.js` (webpack, minified but readable) gives the whole API surface:

```
POST /api/register            POST /api/files/upload      (raw octet-stream)
POST /api/login               POST /api/files/thumbnail   {file_id}
GET  /api/me                  GET  /api/channels/:id/messages
GET  /api/workspace           POST /api/channels/:id/messages
POST /api/workspace/settings  GET  /api/invite  ->  {token, sig}
POST /api/join                {token, sig}
```

Directed enumeration confirmed there is nothing else under `/api`.

## Gate 1 — secret-prefix MAC on the invite link (SHA-256 length extension)

`GET /api/invite` returns:

```json
{"token":"dGVhbT1tYWluJmVtYWlsPXUyODA3OTQ3NzBAbWFpbC5jb20mcm9sZT1tZW1iZXI",
 "sig":"70cbbf97d9403ad305f85f82a3f0494f50fbaa37f37f410ccb7ac29c01e43e6e"}
```

The token is base64url of `team=main&email=<you>&role=member`, and `sig` is 64 hex
characters. Replaying the issued `sig` with a hand-edited `role=owner` is rejected,
so the signature really covers the body — but the interesting question is *how*.

`sig = SHA256(secret || plaintext)` is a secret-prefix MAC, not HMAC, so it is
vulnerable to **length extension**: knowing the digest and the message length is
enough to compute the digest of `message || glue-padding || suffix` without the key.
The suffix is `&role=owner`, and the server's query-string parser keeps the **last**
value for a repeated key — so the appended `role` wins.

Sweeping the unknown secret length 1..64 (the only unknown) lands on **24**:

```
24 200 {"ok":true,"email":"u280794770@mail.com","role":"owner"}
```

The glue padding is raw binary, which survives base64url transport intact.

`POST /api/workspace/settings {"video_messages": true}` is now accepted.

## Gate 2 — FFmpeg `-enable_drefs` arbitrary file read through the thumbnailer

`POST /api/files/upload` stores raw bytes; `POST /api/files/thumbnail {file_id}`
returns `/thumbnails/<rand>.jpg`.

Two facts narrow the surface hard:

* The JPEG carries the comment **`Lavc59.37.100`** → FFmpeg 5.1, and the thumbnail
  keeps the source resolution (no rescale).
* Only `mp4`/`mov` (ISO-BMFF `ftyp`) with a video stream is accepted. PNG, JPEG,
  GIF, MKV, AVI, SVG and audio-only MP4 all fail. HLS playlists, `ffconcat`, and
  the classic AVI+m3u8+XBIN generator are all rejected before FFmpeg sees them.

Being pushed *into the mov demuxer* is the clue. The only external-data mechanism
that demuxer has is the **data reference (`dref`)**: a track may declare that its
sample bytes live in a *different file*. FFmpeg 5.1 `mov_read_dref()` only parses
the `alis` (Macintosh alias) form, and `mov_read_trak()` honours it only when the
`enable_drefs` option is set. `/proc/self/cmdline` later confirmed the app does
exactly that:

```
ffmpeg -y -loglevel error -enable_drefs 1 -use_absolute_path 1 \
       -i /tmp/huddle/uploads/F00000037 -frames:v 1 -q:v 2 \
       /tmp/huddle/thumbs/3cce29bd482f066f.jpg
```

`mov_open_dref()` builds the path as
`dirname(input) + "../" * (nlvl_from - 1) + tail(path, nlvl_to)`, so the alias's
`nlvl_from` / `nlvl_to` counters are a directory-traversal primitive. With uploads
in `/tmp/huddle/uploads/`, `nlvl_from = 4` reaches `/`.

### Making the read *legible*

The referenced file becomes the track's raw sample data, so the trick is to pick a
sample description under which arbitrary bytes decode to something recoverable.
A hand-built `.mov` with a `raw ` sample entry of **depth 1** gives 1-bit-per-pixel
(MONOWHITE-style, palettised) video: every input byte is 8 black/white pixels.

* `stsz` = `W*H/8` (one sample), `stco` = byte offset *inside the referenced file*
* `stsd` width/height = `W`/`H`, depth = 1
* `dref` = one `alis` entry whose TLV type 2 carries the absolute target path

Because the image is bilevel, FFmpeg's lossy `-q:v 2` JPEG still thresholds back to
the exact bits — the recovered bytes are byte-for-byte correct, not approximate.
A grayscale (depth 8/40) variant would have been mangled by JPEG quantisation.

Reading `/etc/passwd` at 64x64 (512 bytes) confirms the primitive:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

And then:

```
$ python3 readfile.py /flag.txt 256
BHFlagY{d24705608f579187678933a0e757e1b8}
```

Verified through three independent reads (64x64, 32x16, and offset 8 at
`nlvl_from=6`) that all agree.

## Why the rejected paths failed

| Path | Outcome |
| --- | --- |
| Replay issued `sig` with edited `role` | Signature covers the body; rejected |
| HLS `#EXTM3U` with `file://` segments | `hls_probe` refuses non-`.m3u8` names/mimetypes; also blocked by the `ftyp` whitelist |
| neex `gen_xbin_avi.py` (AVI+m3u8+XBIN) | Same HLS probe guard, and AVI is not whitelisted |
| `ffconcat` demuxer | Not whitelisted; `safe` mode blocks absolute paths anyway |
| Extra JSON params on `/api/files/thumbnail` (`vf`, `ss`, `size`, …) | All ignored — no ffmpeg argument injection |
| Metadata (`title`) shell injection | No delay from `$(sleep 8)`; args are not shelled |
| Prototype pollution on `/api/workspace/settings` | Only `video_messages` is read |
| Path traversal in `file_id` / `/thumbnails/` | `file_id` is a registry lookup; static route normalises |

## Lesson

When a media pipeline narrows the accepted containers, the whitelist itself is the
hint: it tells you which demuxer the author wants you inside. For QuickTime/MP4 the
external-data primitive is `dref`/`alis`, gated by `-enable_drefs`. And when a file
read comes back as *pixels*, pick a 1-bit sample format — bilevel data survives lossy
JPEG intact, while 8-bit grayscale does not.

## Reproduce

`solve.py` runs the whole chain (register → length extension → enable video →
build the alias `.mov` → decode the JPEG back to bytes):

```
python3 solve.py http://<instance> /flag.txt
```

Note: the instance for this account was retired after the flag was accepted, so a
fresh spawn is required to re-run it end to end.
