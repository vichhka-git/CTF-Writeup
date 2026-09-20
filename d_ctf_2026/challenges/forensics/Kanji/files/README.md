# Kanji handout

The original `small.zip` handout is split into five numbered pieces because the source archive is larger than GitHub's regular-file limit.

From the `d_ctf_2026` directory, reassemble it with:

```bash
./scripts/join-parts.sh \
  challenges/forensics/Kanji/files/small.zip. \
  challenges/forensics/Kanji/files/small.zip
```

The resulting file is the original challenge archive.
