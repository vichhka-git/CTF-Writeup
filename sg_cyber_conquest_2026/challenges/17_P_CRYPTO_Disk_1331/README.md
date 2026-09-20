# P_CRYPTO, Disk 1331

## Solution
The challenge asks us to recover the "token" from the intercepts `C1` and `C2` (XMIT.A and XMIT.B). The developer's comments in the Javascript (`content.md` step 12) describe a convoluted manual process for decrypting the token from the ciphertext ("halve it, feed the low nibbles back..."). 

However, the comment also notes:
"Go through the frame yourself if you would rather verify it."

This indicates that the token is actually baked into the `FRAME` variable, which serves as the background template for the C64 screen. 

By dumping the `FRAME` variable array and translating the C64 screen codes (adding 128 for inverse characters), we can read the raw text of the screen directly:

```
Row 1:         DIRECTORATE NIGHT FRAME         
Row 2:                                         
Row 3:                        FLAG: PAINTTHESCR
Row 4: EEN                                     
Row 5:                                         
Row 6:                       PROCEED TO ONBOARD
Row 7: ING          
```

The flag is clearly visible in the `FRAME` variable without needing to perform any crypto attacks on the stream cipher or the intercepts.

**Flag:** `flag{PAINTTHESCREEN}`
