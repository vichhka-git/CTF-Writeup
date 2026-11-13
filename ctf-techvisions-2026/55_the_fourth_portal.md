## 55 — the fourth portal (Crypto)

1. Extract `the_fourth_portal.zip`. Each world file contains 16 beacon readings `(X, Z)`. Up to four readings per world are forged.
2. For each world, fit a degree-7 polynomial modulo 257. Use RANSAC: sample seven points, solve for the coefficients, count inliers, and keep the model with 12 of 16 inliers.
3. The recovered coefficients are: overworld `8ef4c2485c80028a`, Nether `936cb351a406eae6`, End `c93a0bb1ab9d7b0a`; the Echo core is `6e11c3619fee00c4`.
4. Interleave the four values per row to form a 32-byte input keying material.
5. Run HKDF-SHA256 with salt `4a06df8e10e1cb1e5c5fd2373f125dda` and info `TVX:fourth-portal:v1` to derive a 32-byte AES key.
6. Decrypt `vault.json` with AES-256-GCM using nonce `59cea0d35d9d3b98d04739da` and AAD `echo-vault-v1`.

`TVX{th3_3ch0_b1nds_th3_f0ur_w0rlds}`
