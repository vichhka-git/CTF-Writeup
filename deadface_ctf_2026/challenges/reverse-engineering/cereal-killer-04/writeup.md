# Cereal Killer 04

- **Category:** Reverse Engineering
- **Points:** 250
- **Flag:** `deadface{Before_Consenting_to_Med_Exam_Ascertain_Destination_of_Finger!}`

## Challenge

We have a new set of Spooky Cereals this year, in honor of our New Visitors, who have traveled so long and far to come visit us and to share their other-worldly wisdom with us! Finally, we have the Greys. Everyone is very familiar with them, primarily because of Hollywood. Big eyes, big bulbous heads with skinny bodies... tiny little mouths and long, spindly fingers. You get the picture. Unlike the rest of our Far-Flung Friends, the Greys communicate with each other using "Assembly Codes". This has led some to speculate that they are actually biologic meat-puppets that are remotely piloted. Ly

## Solution

Outer PE is a managed loader containing a 6,656-byte payload. Main uses a visible 01 01 XOR key, but that output is not a PE; the repeating 41 33 mask is derived from the embedded MZ header and independently validated by PE32/CLR parsing. The recovered DLL checks MD5(ASCII(password)); offline wordlist recovery gives password booberry. On match it forms Trim(password)+Trim(password), derives 32 bytes with PBKDF2-HMAC-SHA1 using ASCII thegreysarecomin as both salt and IV for 1,000 rounds, then AES-256-CBC/PKCS7 decrypts the 80-byte ciphertext into the candidate. Plaintext SHA-256: e0a09e58c386bbe9733883d660e616199912cf068d4c422436169989da350c6b.
