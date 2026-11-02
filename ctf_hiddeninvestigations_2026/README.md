# hiCTF 2026 (Hidden Investigations): solved challenge writeups

This folder collects reproduction writeups for the 61 challenges the team solved at hiCTF 2026 (Hidden Investigations). Each file is written for a person who has the handout and wants to walk the solve by hand: it lists what to inspect, what to run, what the intermediate values mean, and where the flag comes from. The writeups do not rely on the team solver scripts.

Live-service challenges use `<challenge-host>` and `<port>` placeholders. The event portal supplies the real values for your own instance, and they are deliberately not recorded here. The collection also leaves out account names, tokens, and event submission identifiers.

The flags are the accepted values from the event. A few challenges were solved from the portal before the submission gate existed, and those writeups say so rather than pretending a transcript exists.

## Contents

| Category | Writeups |
|---|---:|
| [android](#android) | 2 |
| [blockchain](#blockchain) | 5 |
| [cryptography](#cryptography) | 7 |
| [forensics](#forensics) | 7 |
| [hardware](#hardware) | 5 |
| [misc](#misc) | 6 |
| [network](#network) | 1 |
| [osint](#osint) | 2 |
| [pwn](#pwn) | 4 |
| [reverse](#reverse) | 10 |
| [steg](#steg) | 6 |
| [web](#web) | 6 |
| **Total** | **61** |

## android

| Challenge | Points | Flag | Writeup |
|---|---:|---|---|
| Cipher | 61 | `hiCTF{cryptography_should_be_implemnetd_properly}` | [android/cipher.md](android/cipher.md) |
| VaultKeeper | 57 | `hiCTF{!!I_10v3_4ndr0!d_m4n_m4k!ng_th3m_f331_g0Od!!}` | [android/vaultkeeper.md](android/vaultkeeper.md) |

## blockchain

| Challenge | Points | Flag | Writeup |
|---|---:|---|---|
| Dormant Signer | 58 | `hiCTF{layout_undead_borrowed_betrays}` | [blockchain/dormant-signer.md](blockchain/dormant-signer.md) |
| Hollow Reserve | 63 | `hiCTF{th1n_p00l_was_the_r3al_0racle}` | [blockchain/hollow-reserve.md](blockchain/hollow-reserve.md) |
| Pruned Ledger | 61 | `hiCTF{pruned_storage_calldata_never_forgets}` | [blockchain/pruned-ledger.md](blockchain/pruned-ledger.md) |
| Quiet Upgrade | 64 | `hiCTF{sl0t0_c0llision_then_a_qu1et_upgrade_88af2caaf5}` | [blockchain/quiet-upgrade.md](blockchain/quiet-upgrade.md) |
| Standing Order | 70 | `hiCTF{one_sig_two_paths_then_the_l00p_5383acb880}` | [blockchain/standing-order.md](blockchain/standing-order.md) |

## cryptography

| Challenge | Points | Flag | Writeup |
|---|---:|---|---|
| Cairn | 76 | `hiCTF{w41k_th3_sup3rs1n9u14r_l46yr1ntH}` | [cryptography/cairn.md](cryptography/cairn.md) |
| ChronoGrind | 58 | `hiCTF{n1c3_w0rk_n0w_t4k3_s0m3_r3$t}` | [cryptography/chronogrind.md](cryptography/chronogrind.md) |
| Cipher Cascade | 53 | `hiCTF{l4y3r_by_l4y3r_unw1nd}` | [cryptography/cipher-cascade.md](cryptography/cipher-cascade.md) |
| Just Give Me The Flag Man | 60 | `hiCTF{sh1ft1ng_7hr0ugh_7h3_b4s3s}` | [cryptography/just-give-me-the-flag-man.md](cryptography/just-give-me-the-flag-man.md) |
| Log Jam | 57 | `hiCTF{W0W1_y0u_4ctu4a11y_s01v3d_1t_ju$t_L1k3_tH4t}` | [cryptography/log-jam.md](cryptography/log-jam.md) |
| Rocinate | 60 | `hiCTF{lmaoooo_w0t???y0u_d1d_17_??435p37++}` | [cryptography/rocinate.md](cryptography/rocinate.md) |
| Tyco | 56 | `hiCTF{your_ai_slop_bores_me}` | [cryptography/tyco.md](cryptography/tyco.md) |

## forensics

| Challenge | Points | Flag | Writeup |
|---|---:|---|---|
| Broken Signals | 53 | `hiCTF{h34d3r_r3p41r_m4st3r}` | [forensics/broken-signals.md](forensics/broken-signals.md) |
| Ghost in RAM | 64 | `hiCTF{gh0st_pr0c3ss_rng_pwn3d}` | [forensics/ghost-in-ram.md](forensics/ghost-in-ram.md) |
| Ghost in the Wire | 53 | `hiCTF{1cmp_3xf1l_d3t3ct3d}` | [forensics/ghost-in-the-wire.md](forensics/ghost-in-the-wire.md) |
| Memory Liar | 54 | `hiCTF{dk0m_unl1nk_3pr0c3ss_l1st_cr0ss_ch3ck_7c3a9f}` | [forensics/memory-liar.md](forensics/memory-liar.md) |
| RESURRECTION (Operation Eclipse Void) | 59 | `hiCTF{p3_0v3rl4y_71m3d473574mp_k3y_n7f5_runl157_cl5_g30m37ry_7r4ns4c710n_n4n0_f1l371m3_3v7x_b1n4ry_xml_70k3n5_b17m4p_orph4n_v01d_r35urr3c710n}` | [forensics/resurrection-operation-eclipse-void.md](forensics/resurrection-operation-eclipse-void.md) |
| TESSERA | 62 | `hiCTF{alpc_p0rt_c0lloquy_s35s10n_z3r0_syst3npr0f1l3_r3p4r53_buff3r_vort3x}` | [forensics/tessera.md](forensics/tessera.md) |
| The Miner That Mined The Victim | 97 | `hiCTF{c4r3ful_4b0ut_cr4ck3d_t001s_e315a23532}` | [forensics/the-miner-that-mined-the-victim.md](forensics/the-miner-that-mined-the-victim.md) |

## hardware

| Challenge | Points | Flag | Writeup |
|---|---:|---|---|
| C3 Vault | 59 | `hiCTF{efus3_cl34r_jt4g_0p3n_nv5_47127e7145}` | [hardware/c3-vault.md](hardware/c3-vault.md) |
| Cold Chain | 69 | `hiCTF{cold_chain_restored_defrost_cleared_7dbe44e9ca}` | [hardware/cold-chain.md](hardware/cold-chain.md) |
| GhostBus | 58 | `hiCTF{gh0st_bu5_uart_n0nc3_r3v3al_9c3f12}` | [hardware/ghostbus.md](hardware/ghostbus.md) |
| Ground Station | 69 | `hiCTF{ground_station_fueling_test_nominal_a21a9de2dc}` | [hardware/ground-station.md](hardware/ground-station.md) |
| Tasmota Vault | 56 | `hiCTF{b3rry_r0t4t10n_c94934d76344ab1151e03afd}` | [hardware/tasmota-vault.md](hardware/tasmota-vault.md) |

## misc

| Challenge | Points | Flag | Writeup |
|---|---:|---|---|
| Dead Air | 60 | `hiCTF{s1l3nc3_w4s_th3_m3ss4g3_6r3v}` | [misc/dead-air.md](misc/dead-air.md) |
| Forgotten Secrets | 54 | `hiCTF{m3m0ry_dump_d1g_d33p}` | [misc/forgotten-secrets.md](misc/forgotten-secrets.md) |
| Labyrinth | 72 | `hiCTF{l34rn3d_th3_t0ngu3_w4lk3d_th3_l4byr1nth_1f41175172}` | [misc/labyrinth.md](misc/labyrinth.md) |
| The Collector's Trail | 66 | `hiCTF{marble_sparrow_9eb44602eedb764aac082a3816b7d7cb}` | [misc/the-collector-s-trail.md](misc/the-collector-s-trail.md) |
| The Foxglove Trace | 54 | `hiCTF{FoxgloveCoffee_Guest}` | [misc/the-foxglove-trace.md](misc/the-foxglove-trace.md) |
| Warden’s Maze | 57 | `hiCTF{maze-warden-vault-seed-2026_a6dea3e7e1}` | [misc/warden-s-maze.md](misc/warden-s-maze.md) |

## network

| Challenge | Points | Flag | Writeup |
|---|---:|---|---|
| The Quiet Divide | 73 | `hiCTF{c8c46fdbd6e5e4eacabfba53a156ff9ab10567f2}` | [network/the-quiet-divide.md](network/the-quiet-divide.md) |

## osint

| Challenge | Points | Flag | Writeup |
|---|---:|---|---|
| Low Tide Ledger | 69 | `hiCTF{Eko-Atlantic-City_Lagos_Nigeria_Nairahomes-Realty_3C}` | [osint/low-tide-ledger.md](osint/low-tide-ledger.md) |
| Shadow Identity | 53 | `hiCTF{jihan_mohin_dimack}` | [osint/shadow-identity.md](osint/shadow-identity.md) |

## pwn

| Challenge | Points | Flag | Writeup |
|---|---:|---|---|
| Apex Engine | 55 | `hiCTF{t0ct0u_mult1thr34d_r4c3_c0nd1t10n_w1n_8d3f_73d9174dc9}` | [pwn/apex-engine.md](pwn/apex-engine.md) |
| LetMeOut | 60 | `hiCTF{__^_^__n0rm4l1z3_b3f0r3_y0u_tru5t__>_<___4e323a9e48}` | [pwn/letmeout.md](pwn/letmeout.md) |
| Project Mangoo | 64 | `hiCTF{n0_g4dg3ts_n0_sh3llc0d3_jusT_p1v0t_d33p3r_5dd4aae270}` | [pwn/project-mangoo.md](pwn/project-mangoo.md) |
| Titan Relay | 66 | `hiCTF{ru5t_vm_g4te_and_h4ndler_ch41n_2d6eec5715}` | [pwn/titan-relay.md](pwn/titan-relay.md) |

## reverse

| Challenge | Points | Flag | Writeup |
|---|---:|---|---|
| Cold Beacon | 54 | `hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}` | [reverse/cold-beacon.md](reverse/cold-beacon.md) |
| Cold Circuit | 68 | `hiCTF{6e305f6a7461675f6e65656465642121}` | [reverse/cold-circuit.md](reverse/cold-circuit.md) |
| Entitlement | 59 | `hiCTF{>o<_C0ngrats_Her3_1s_Y0ur_HI4_Subscript1on_^_^}` | [reverse/entitlement.md](reverse/entitlement.md) |
| Epsilon Drift | 54 | `hiCTF{1eee754_s1gn3d_z3r0_1u1p_dr1ft_eps!}` | [reverse/epsilon-drift.md](reverse/epsilon-drift.md) |
| Last Execution | 56 | `hiCTF{3x3c_9_r3m3mb3rs_4ll_but_th3_l4st_h4lt_l13s}` | [reverse/last-execution.md](reverse/last-execution.md) |
| Night Batch | 56 | `hiCTF{c0b0l_p4ck3d_d3c1mal_n1ghtly_b4tch!}` | [reverse/night-batch.md](reverse/night-batch.md) |
| Obfuscated Flow | 55 | `hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}` | [reverse/obfuscated-flow.md](reverse/obfuscated-flow.md) |
| Signal Lock | 57 | `hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}` | [reverse/signal-lock.md](reverse/signal-lock.md) |
| Snapfile | 59 | `hiCTF{r3c0nstruct3d_th3_sn4pf1l3_by73_by_by73}` | [reverse/snapfile.md](reverse/snapfile.md) |
| The Inner Engine | 57 | `hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}` | [reverse/the-inner-engine.md](reverse/the-inner-engine.md) |

## steg

| Challenge | Points | Flag | Writeup |
|---|---:|---|---|
| Echoes of a Forgotten Canvas | 59 | `hiCTF{mu1t!14y3r3d_st3g0o_ju5t_l0v333}` | [steg/echoes-of-a-forgotten-canvas.md](steg/echoes-of-a-forgotten-canvas.md) |
| Hall of Mirrors | 92 | `hiCTF{h1dd3n_numb3r_l4ttice_le4k}` | [steg/hall-of-mirrors.md](steg/hall-of-mirrors.md) |
| Paper Trail | 60 | `hiCTF{n3w_ar34_fOr_hid!ng_d4t4_n4m3d_TJ}` | [steg/paper-trail.md](steg/paper-trail.md) |
| Roof of Africa | 53 | `hiCTF{h4kun4_m4t4t4_m34ns_n0_w0rr13s}` | [steg/roof-of-africa.md](steg/roof-of-africa.md) |
| Whispers in the Margin | 55 | `hiCTF{573g4n0gr4phy_!5_fun}` | [steg/whispers-in-the-margin.md](steg/whispers-in-the-margin.md) |
| Zanzibar Whisper | 53 | `hiCTF{sp1c3_1sl4nd_s3cr3ts}` | [steg/zanzibar-whisper.md](steg/zanzibar-whisper.md) |

## web

| Challenge | Points | Flag | Writeup |
|---|---:|---|---|
| File Viewer | 68 | `hiCTF{E45Y_5yml1Nk_8b91346d2f}` | [web/file-viewer.md](web/file-viewer.md) |
| Orphaned Context | 61 | `hiCTF{local_dev_fixture_not_a_real_flag_d7ac89d7f4}` | [web/orphaned-context.md](web/orphaned-context.md) |
| Ouroboros | 79 | `hiCTF{pr0to_pollution_to_cust0m_new_Function_gadget_rce_50bad32d63}` | [web/ouroboros.md](web/ouroboros.md) |
| Overgrowth | 73 | `hiCTF{graphql_al1as_batch1ng_brute_f0rces_the_0tp_bb17f07f98}` | [web/overgrowth.md](web/overgrowth.md) |
| Stillwell Estates | 74 | `hiCTF{s1l3nt_l4n73rn_3573735_abd3e034f8}` | [web/stillwell-estates.md](web/stillwell-estates.md) |
| Whisper | 58 | `hiCTF{bl1nd_regex_3xfil_then_f0rge_the_cust0m_s1gner_9510c3c74e}` | [web/whisper.md](web/whisper.md) |

## Notes on evidence

Each writeup is based on the local challenge files and the team record: handout descriptions, shipped source, solution notes, live session logs, and submission results. Where the local record does not preserve an intermediate value, the writeup says so instead of filling the gap. That is most visible in VaultKeeper, Standing Order, Whispers in the Margin, and Echoes of a Forgotten Canvas.

The writeups avoid full solve scripts. Short commands are included where a reader needs to reproduce a check, but the reasoning and the values are written out so the steps can be followed manually.
