# solstice-9 handout

The original `solstice9-firmware.img` is stored inside a stored ZIP stream split into 43 numbered pieces so that no GitHub object exceeds 100 MiB.

From the `d_ctf_2026` directory, reassemble and extract it with:

```bash
./scripts/join-parts.sh \
  challenges/misc/solstice-9/files/solstice9-firmware.zip. \
  challenges/misc/solstice-9/files/solstice9-firmware.zip
unzip challenges/misc/solstice-9/files/solstice9-firmware.zip \
  -d challenges/misc/solstice-9/files
```
