from Crypto.Cipher import AES
import os
import signal

signal.alarm(300)
keys = [os.urandom(16), os.urandom(16)]
for r in [0, 1]:
    for ch in input("> ")[:6]:
        cipher = AES.new(keys[0], AES.MODE_GCM, nonce=keys[1])
        cipher.encrypt(f"{ch}|encrypted by {keys[0].hex()}".encode())
        print(cipher.hexdigest()[r::2])
    assert input(f"keys[{r}]> ") == keys[r].hex()
print(os.environ.get("DYN_FLAG", "BHFlagY{0000000000000000}"))
