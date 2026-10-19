# It But A Wee Bit Reverse

- **Category:** Reverse Engineering
- **Points:** 15
- **Flag:** `deadface{x0r_1s_not_encryption}`

## Challenge

We pulled this binary off a DEADFACE member's machine. It's guarding something, and it wants a password. Strings won't save you this time, they were just clever enough to not leave it lying in plaintext. Figure out what it wants, and it'll give up its secret. Submit the flag as `deadface{flag-text}`. [DownloadBinary](https://tinyurl.com/2fupr6sm)(16KB) SHA256: `fa76583b6f4c9f6414fb79c3ffe717709ba3d74ce62ce7043d59807e8ca538f8`

## Solution

main: strlen==10 gate, input[i]^0x42==pw_enc[i] (.data 0x4010), then prints 31 bytes of flag_enc (.data 0x4020) xor pw[i%10]; pw_enc^0x42=sunshine42; flag_enc^pw = flag; verified statically AND by unshare -rn run of scratch copy printing 'Access granted!' + same flag
