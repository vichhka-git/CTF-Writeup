def permutation(n):
    seed = 12648430
    order = list(range(n))
    def step():
        nonlocal seed
        seed = (seed * 1103515245 + 12345) & 4294967295
        return seed
    for i in range(n - 1, 0, -1):
        j = step() % (i + 1)
        order[i], order[j] = order[j], order[i]
    return order

def reverse_bits(x):
    return int(f'{x:08b}'[::-1], 2)

TARGET = (49, 49, 32, 215, 114, 107, 87, 252, 85, 169, 44, 91, 123, 198, 227, 27, 147, 217, 25, 87, 122, 187, 205, 104, 219, 17, 173)
n = len(TARGET)
perm = permutation(n)

flag = [0] * n

for j, i in enumerate(perm):
    out = TARGET[j]
    key = (93 + j * 29 + i * 11) & 255
    c = 0
    
    if (j & 3) == 0:
        # left rotate by 1
        # out = ((c + key) << 1 | (c + key) >> 7) & 255
        # (c + key) & 255 = right rotate by 1 of out
        c_plus_key = ((out >> 1) | (out << 7)) & 255
        c = (c_plus_key - key) & 255
    elif (j & 3) == 1:
        # out = c ^ key ^ i
        c = out ^ key ^ i
    elif (j & 3) == 2:
        # out = (c * 7 + key) & 255
        # c * 7 = (out - key) mod 256
        # inverse of 7 mod 256 is 183 (since 7 * 183 = 1281 = 5 * 256 + 1)
        c = ((out - key) * 183) & 255
    elif (j & 3) == 3:
        # out = reverse_bits(c) ^ key
        # reverse_bits(c) = out ^ key
        c = reverse_bits(out ^ key)
        
    flag[i] = chr(c)

print("".join(flag))
