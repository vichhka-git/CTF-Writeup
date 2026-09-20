from sage.all import Matrix, ZZ
import sys

# Read pubkey
with open("files/pubkey.txt") as f:
    pubkey = [int(line.strip()) for line in f if line.strip() and not line.startswith("#")]

# Read ciphertexts
with open("files/ciphertext.txt") as f:
    cts = [int(line.strip()) for line in f if line.strip() and not line.startswith("#")]

# Active indices: bit 0 of each byte is 0 for standard ASCII
active_indices = [i for i in range(72) if i % 8 != 0]
a = [pubkey[i] for i in active_indices]
m = len(a) # 63

def solve_block(block_idx, c, block_size=20, N=100):
    print(f"[*] Solving block {block_idx}...")
    B = Matrix(ZZ, m + 1, m + 2)
    for i in range(m):
        B[i, i] = 2
        B[i, m+1] = N * a[i]
    for i in range(m):
        B[m, i] = 1
    B[m, m] = 1
    B[m, m+1] = N * c

    # BKZ reduction
    L = B.BKZ(block_size=block_size)

    for r in L:
        if r[m+1] == 0 and abs(r[m]) == 1:
            entries = list(r[:m])
            for sign in [r[m], -r[m]]:
                sub_x = [(1 - sign * entries[i]) // 2 for i in range(m)]
                if all(val in (0, 1) for val in sub_x) and sum(sub_x[i] * a[i] for i in range(m)) == c:
                    full_x = [0] * 72
                    for idx, val in zip(active_indices, sub_x):
                        full_x[idx] = val
                    bs = bytearray()
                    for k in range(0, 72, 8):
                        byte = 0
                        for bit in full_x[k:k+8]:
                            byte = (byte << 1) | bit
                        bs.append(byte)
                    print(f"[+] Block {block_idx} solved: {bytes(bs)}")
                    return bytes(bs)
    return None

full_flag = b""
for idx, c in enumerate(cts):
    res = solve_block(idx, c, block_size=20)
    if not res:
        print(f"[*] Trying block_size=25 for block {idx}...")
        res = solve_block(idx, c, block_size=25)
    if not res:
        print(f"[-] Failed to solve block {idx}")
        sys.exit(1)
    full_flag += res

flag_str = full_flag.decode("utf-8", errors="replace").rstrip("\x00")
print("=" * 60)
print(f"[+] FULL FLAG: {flag_str}")
print("=" * 60)

with open("flag.txt", "w") as f:
    f.write(flag_str + "\n")
