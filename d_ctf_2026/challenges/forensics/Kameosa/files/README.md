# Kameosa handout

The original `toc.7z` handout is stored as a regular ZIP stream split into 189 numbered pieces so that no GitHub object exceeds 100 MiB.

From the `d_ctf_2026` directory, reassemble and extract it with:

```bash
./scripts/join-parts.sh \
  challenges/forensics/Kameosa/files/toc.7z.zip. \
  challenges/forensics/Kameosa/files/toc.7z.zip
unzip challenges/forensics/Kameosa/files/toc.7z.zip toc.7z \
  -d challenges/forensics/Kameosa/files
```
