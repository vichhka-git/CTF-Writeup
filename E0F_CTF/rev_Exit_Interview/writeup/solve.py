import pefile

pe = pefile.PE("exit-interview.exe")
image_base = 0x140000000

chunks = [
    0x140017430,
    0x140017438,
    0x140017440,
    0x140017448,
    0x140017450
]

chunk_bytes = []
for vaddr in chunks:
    rva = vaddr - image_base
    data = pe.get_data(rva, 8)
    chunk_bytes.append(data)
    print(f"Chunk {vaddr:x}: {data.hex()}")

# Now run the decode logic
flag = [0] * 40

for initial_rcx in range(5):
    r11b = (initial_rcx * 7 + 0x5a) & 0xff
    for r10 in range(8):
        r9 = initial_rcx + r10 * 5
        edx = r9 % 7
        
        B = chunk_bytes[initial_rcx][r10]
        
        # ROR by (edx + 1)
        shift = (edx + 1)
        ror = ((B >> shift) | (B << (8 - shift))) & 0xff
        
        cl = (r9 * 13 + r11b) & 0xff
        dec = ror ^ cl
        
        flag[r9] = dec

print("Flag:", bytes(flag))

