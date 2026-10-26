# Hack.lu CTF 2026 (flu.xxx) — writeups

Writeups for 21 challenges solved during Hack.lu CTF 2026. Every writeup here is
for a challenge that was actually solved and produced the real flag; the flag at
the bottom of each page is the one the service returned.

Each directory is self-contained:

* `README.md` — challenge description, analysis, and a step-by-step reproduction
  with the commands and outputs that were actually used.
* `solve.py` / `exploit.py` / `keygen.py` / `solve.mjs` — the working scripts,
  cleaned up so they run from the directory with a fresh instance. Usage is in
  the script docstring and in the README.

Points and solve counts are from the final scoreboard snapshot. Handouts are not
redistributed here; download them from the challenge page or use the file names
listed in each writeup's `Files` table.

## Challenges

| # | Challenge | Category | Pts | Solves | Writeup |
|---|---|---|---|---|---|
| 2 | kurl | misc (k8s) | 72 | 140 | [2-kurl](2-kurl/README.md) — tokenless `kubectl` in a side pod, service proxy, mass-assigned `is_admin` |
| 3 | CEOnnect Four | misc | 113 | 55 | [3-ceonnect-four](3-ceonnect-four/README.md) — OOB format string, OOB function pointer, bit-packed stack write |
| 6 | uushell | misc | 106 | 61 | [6-uushell](6-uushell/README.md) — uuencode-filtered bash jail, `M()(...)` subshell body + `$IFS` |
| 7 | Every 7x7 Nonoflag | rev | 78 | 113 | [7-every-7x7-nonoflag](7-every-7x7-nonoflag/README.md) — wasm nonogram generator, one solvable card in 2,427,000 |
| 8 | doppelflip | misc | 119 | 50 | [8-doppelflip](8-doppelflip/README.md) — two root-owned bit flips: `-c`→`-s`, `je`→`jne` in `pam_rootok` |
| 9 | turbo-malloc | pwn | 73 | 135 | [9-turbo-malloc](9-turbo-malloc/README.md) — `turbo_realloc` shrink bug, forged chunk, `notes[]` window, `memcpy@got`→`system` |
| 10 | LinkedInspirator | crypto | 78 | 113 | [10-linkedinspirator](10-linkedinspirator/README.md) — CBC padding oracle, CBC-R, 2^-16 username grind for the tag |
| 11 | IL2FLAG | rev | 80 | 106 | [11-il2flag](11-il2flag/README.md) — stripped IL2CPP metadata, static per-stage string resolution |
| 13 | M&A | active directory | 114 | 54 | [13-ma](13-ma/README.md) — Kerberoast → gMSA → NTDS → child golden ticket → ExtraSids to parent EA |
| 14 | Lauschangriff | crypto | 77 | 117 | [14-lauschangriff](14-lauschangriff/README.md) — 96-bit ARX CRNG, z3 state recovery, X25519 + ML-KEM, TLS 1.3 decrypt |
| 17 | Declassifier | pwn | 75 | 126 | [17-declassifier](17-declassifier/README.md) — `redact()` length bug, 318-byte stack shift, `.text`-only ROP |
| 19 | CHIP | pwn | 84 | 96 | [19-chip](19-chip/README.md) — unchecked `Fx55`/`Fx65`, 64 KiB OOB over the VM state, ROP |
| 20 | Vaulty | rev | 74 | 129 | [20-vaulty](20-vaulty/README.md) — `strlen`-truncated KDF, 2-byte effective password, 16-bit brute |
| 22 | Challenge Deployment | misc (k8s) | 80 | 106 | [22-challenge-deployment](22-challenge-deployment/README.md) — `pods/portforward` without `resourceNames`, last-applied-configuration leak |
| 25 | VeryMildHidden | rev | 63 | 215 | [25-verymildhidden](25-verymildhidden/README.md) — 4-byte-instruction VM, 55 independent byte checks |
| 28 | Selene.Protocol.v1.1-LNR | rev | 82 | 101 | [28-selene-protocol](28-selene-protocol/README.md) — sabotaged FNV key, LNR1 archive, inverted ARX license check |
| 29 | Remote DJ | misc | 95 | 74 | [29-remote-dj](29-remote-dj/README.md) — cmus safe mode: `pl-export` + `status_display_program` → RCE |
| 30 | flag_check_appliance_v2_FINAL.raw | rev | 77 | 118 | [30-flag-check-appliance](30-flag-check-appliance/README.md) — 7914 systemd units as a bit-test DAG, GF(2) solve |
| 31 | LIcense Validation Suite | rev | 65 | 197 | [31-license-validation-suite](31-license-validation-suite/README.md) — seed-table key, ptrace-dependent constant |
| 32 | v67 | pwn | 86 | 91 | [32-v67](32-v67/README.md) — JIT fuel prologue drifts `jit_entry`, second call lands on a `CONST` immediate |
| 35 | Challenge Deployment 2 | misc (k8s) | 98 | 70 | [35-challenge-deployment-2](35-challenge-deployment-2/README.md) — `services/proxy` only, unquoted `flagRef=.` → unmasked `SecretList` |

## Flags

<details>
<summary>Spoilers — 21 flags</summary>

```
 2  flag{kubectl_1s_just_curl_w1th_3xtr4_st3ps}
 3  flag{W0w_c0ngr47z_f0r_pu5h1ng_70_pr0d_y0u_34rn3d_y0ur_fl4g:e07e8d319d8cf772ab91166b1d0eaba2}
 6  flag{youu_are_the_uundispuuted_champion_of_uushell}
 7  flag{c0ngrats_my_fri3nd_y0u_are_the_r3al_puzzle_m4ster}
 8  flag{the_odds_of_this_happening_due_to_cosmic_rays_are_small_but_not_zero}
 9  flag{4gile_and_f4st_n0t3s_what_m0re_c0uld_you_want_f4437659304736eb7a71404b68bcd201}
10  flag{nothing_good_in_life_comes_easy_e625b47a565c370dcebe48891f1ef0ae}
11  flag{im_thinking_miku_miku_ooeeoo}
13  flag{m0v3_f4st_br34k_th3_f0r3st_89a71f9g}
14  flag{26c1f32464d9fae836e9a1fbc9040d22}
17  flag{00p5-57r1ng_r3pl4c3m3n7_w17h0u7_4dju571ng_57r1ng_l3ng7h_15_4_b4d_1d34:14dd5335c3eaa0f7644923c41883bf31}
19  flag{w0w_1t_3ven_h4s_a_d1spl4y_cbecfad06b5b6f7ac3b84e5776c36c63}
20  flag{f4ulty_v4ulty_str1ng_l3ngth}
22  flag{1ts_alw4ys_DNS_4lso_1n_K8s}
25  flag{M4yb3_w3_c4n_74k3_0n_3v3n_70ugh3r_ch4113ng3$_n0w?}
28  flag{n0_m0r3_nuk3z_th15_0n3_1z_pr0p3r}
29  flag{0hhhh,_th4t5_why_th3y_call_th1s_1ns3cure!!!}
30  flag{https://github.com/systemd/systemd/commit/294446dcb98eaa1ced5839da674c2065b1367a3a}
31  flag{GDB_Runtime_Insights}
32  flag{6b35552d2cdda443a67b56060bbe9532}
35  flag{n0w_y0u_n33d3d_t0_d0_th3_DNS_tr1ck}
```

</details>

## Conventions

Where a flag's wording hints at a different intended path, the writeup documents
the path that actually produced the flag.

The writeups assume the challenge handout is extracted in the current directory.
Where a challenge is instance-based, the commands use a generic `<host> <port>`
or the public challenge hostname; replace it with your own instance. Kubernetes
writeups use `kubectl --kubeconfig ./kubeconfig.yaml`, with the kubeconfig the
instance page provides.
