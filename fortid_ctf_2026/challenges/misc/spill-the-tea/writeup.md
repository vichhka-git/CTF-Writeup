# FortID CTF 2026 Writeup: Spill the Tea

- **Category:** Misc
- **Challenge author:** ipaljak, laragrr
- **Points / Solves:** 299 pts / 13 solves
- **Flag:** `FortID{1_Sw3ar_70_Sp1ll_7h3_T3a_Th3_Wh0l3_Te3_4nd_N0thin6_Bu7_7h3_T34}`

---

## Challenge

> Oh no! Our recent hire spilled some tea over flag. Hope you can still read
> it...

---

## Summary

The photo contains a version 6 QR code partly covered by tea. I used its QR Reed–Solomon parity to recover the obscured payload bits, then checked the reconstructed symbol against independent image maps and an OpenCV decode.

## Recon and mechanism

`flag.jpg` contains a 41×41 QR symbol (version 6). Tea obscures the format cells and much of the center, so ordinary thresholding does not read the payload. The fixed function patterns establish the grid; the known FortID prefix and the byte-mode framing identify the strongest candidate as ECC-Q, mask 3, count 70.

Version 6-Q has four RS blocks with 19 data bytes and 24 parity bytes each. QR divides the original data into consecutive blocks, then interleaves the encoded codewords for transmission. After deinterleaving, the message data is therefore `block0 || block1 || block2 || block3`.

The solution ranks uncertain module bits, fixes the known QR framing and prefix bits, and solves each block's binary parity equations over GF(2). The recovered candidate has zero RS syndromes in all four blocks and 11 surplus parity equations in the least-constrained block. Its post-message filler differs from the usual EC/11 sequence, but the discrepancy begins after the 70-byte payload and terminator. Keeping the recovered tail produces a matrix that agrees with the high-support image samples and decodes to the same payload.

## Solution

Run the complete local reconstruction with the CTF virtual environment:

```sh
python3 solve.py
```

The calibrated homography and exact block anchors are stored with the analysis artifacts. `solve.py` retrains the per-module classifier, runs the ranked bit solver for Q/mask 3/count 70, and checks the two anchor blocks. It then rebuilds the QR using the recovered block tails, compares it with the high-support HSV and subcell maps, and confirms the payload with OpenCV.

The first two data blocks recover the byte-mode header, count 70, and this prefix:

```text
FortID{1_Sw3ar_70_Sp1ll_7h3_T3a_Th3_??????????????????????????????????
```

The final matrix agrees with all 491 supported data modules in `hsv_median.npz` and 509 of 510 supported modules in `subcell_map.npz`. A synthetic rendering decodes with OpenCV 5.0.0 to the same payload. The run prints:

```text
hsv_median.npz: 491/491 high-support data modules agree
subcell_map.npz: 509/510 high-support data modules agree
synthetic QR decode: FortID{1_Sw3ar_70_Sp1ll_7h3_T3a_Th3_Wh0l3_Te3_4nd_N0thin6_Bu7_7h3_T34}
```

The complete solver is in [solve.py](solve.py). Run it from the event root with `python3 solve.py`.

## Flag

```text
FortID{1_Sw3ar_70_Sp1ll_7h3_T3a_Th3_Wh0l3_Te3_4nd_N0thin6_Bu7_7h3_T34}
```

## Tools

Python in the solver environment, qrcode 8.2, reedsolo 1.7.0, NumPy 2.5.3, scikit-learn 1.9.1, and OpenCV 5.0.0.

## Lessons

- Keep original data-block order distinct from the interleaved RS codeword stream; mixing them corrupts the QR header and length.
- Use parity and image evidence together. A readable candidate alone is weak; the recovered bits must satisfy every RS block and match independently derived visible modules.
