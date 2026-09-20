#!/usr/bin/env python3
"""
Solve Notice 10 - The Palette That Did Not Change.
"""

import struct, zlib

def read_pcx_palette(filename):
    """Read the 16-color palette from a PCX header (offset 16, 48 bytes)."""
    with open(filename, 'rb') as f:
        data = f.read()
    palette = []
    for i in range(16):
        r = data[16 + i*3]
        g = data[16 + i*3 + 1]
        b = data[16 + i*3 + 2]
        palette.append((r, g, b))
    return palette

# Read palettes
pal_current = read_pcx_palette("NOTICE10.PCX")
pal_prior = read_pcx_palette("NOTICE10.BAK")

print("Current (PCX):", pal_current)
print("Prior   (BAK):", pal_prior)

# Build permutation: for each position i in current, find where that color is in prior
cur_to_prior = []
for i in range(16):
    color = pal_current[i]
    for j in range(16):
        if pal_prior[j] == color:
            cur_to_prior.append(j)
            break

# And the reverse
prior_to_cur = []
for i in range(16):
    color = pal_prior[i]
    for j in range(16):
        if pal_current[j] == color:
            prior_to_cur.append(j)
            break

print(f"\ncur_to_prior (current[i] is at prior[?]): {cur_to_prior}")
print(f"prior_to_cur (prior[i] is at current[?]): {prior_to_cur}")

# Read paragraph text
with open("NOTICE10.TXT", "r") as f:
    lines = f.read().replace('\r', '').strip().split('\n')

para_bodies = []
for line in lines:
    line = line.strip()
    if len(line) >= 2 and line[:2].isdigit():
        num = int(line[:2])
        if 1 <= num <= 16:
            body = line[3:]  # skip "NN "
            para_bodies.append(body)

print(f"\nParagraph bodies ({len(para_bodies)} paragraphs):")
for i, body in enumerate(para_bodies):
    print(f"  P{i+1:02d}: '{body}'")

# Try extracting designation using different table interpretations
target_crc = 0x34887E5B

def extract_designation(station_numbers):
    designation = ""
    for i in range(16):
        col = station_numbers[i]
        body = para_bodies[i]
        if col < len(body):
            designation += body[col]
        else:
            designation += "?"
    return designation

# The paragraph body starts with a 16-char code like "DSRILOA3T68N9OUT"
# followed by spaces and descriptive text.
# "A station number is read as a column of this paragraph"
# Since station numbers are 0-15 and the codes are 16 chars, the columns
# should index into the 16-char code prefix.

tables_to_try = {
    "cur_to_prior": cur_to_prior,
    "prior_to_cur": prior_to_cur,
}

print(f"\nTarget CRC: {target_crc:08X}")
for name, table in tables_to_try.items():
    desig = extract_designation(table)
    crc = zlib.crc32(desig.encode('ascii')) & 0xFFFFFFFF
    match = "MATCH!" if crc == target_crc else ""
    print(f"  {name}: '{desig}' CRC={crc:08X} {match}")
    
    desig_upper = desig.upper()
    crc_upper = zlib.crc32(desig_upper.encode('ascii')) & 0xFFFFFFFF
    match_upper = "MATCH!" if crc_upper == target_crc else ""
    print(f"  {name} (upper): '{desig_upper}' CRC={crc_upper:08X} {match_upper}")

# If direct permutation doesn't work, maybe the "edit order table" is something else.
# Let me think about PALSWAP's description:
# "Entries are stored in EDIT ORDER: the entry most recently written by an editing 
#  station is filed first."
# "Recovering the table for a notice therefore requires BOTH revisions"
# 
# So in the current copy, the palette is in the order entries were last edited.
# In the prior copy, the palette is in the order entries were edited before that.
# 
# The difference tells us which entries moved and where they ended up.
# The station number for each palette slot = the index in the current palette
# where that color appears.
# 
# But actually, I think the station numbers ARE the permutation values themselves.
# Let me try: for each palette index 0-15, the "station number" assigned to that
# position is determined by where the entry moved between prior and current.

# Another interpretation: the edit order in the CURRENT file gives us the table directly.
# Position 0 in current = most recently edited = has some station number.
# That station number might just be the original position in the prior copy.

# So table[i] = cur_to_prior[i] means: the entry at position i in the current file
# originally came from position cur_to_prior[i] in the prior file.
# That prior position IS the station number.

# This is what we already tried. Let me also try reading from different parts of the text.

# Wait - let me re-read the text format more carefully:
# "01 DSRILOA3T68N9OUT  CONTINUITY STANDING NOTICE..."
# Column 0 of the body (after "01 ") is 'D'
# The 16-char code at the start has columns 0-15

# But maybe the station numbers should be used differently:
# "A station number is read as a column of this paragraph"
# Maybe: for paragraph i (0-indexed), read column station_number from it.
# And the 16 station numbers come from comparing the palettes.
# But which 16? One per paragraph... 

# Actually I think the table maps position -> station, and we have 16 positions
# corresponding to 16 paragraphs. For position/paragraph i, station_number[i]
# gives the column to read from that paragraph.

# So the question is just what the correct permutation is. Let me try all possibilities
# more carefully, including the identity permutation.

# Actually, maybe I need to look at pixel data too. The PCX pixel data uses palette
# indices, and the same image data with a different palette ordering would produce
# different index values. The difference in indices between the two files could encode
# the station numbers.

# But the challenge says "The artwork is identical in both" and "Do not open the images
# in an editor" - the VISUAL appearance is the same but the indices are different.

# Let me decode the PCX pixel data and compare index values.

def decode_pcx_pixels(filename):
    """Decode PCX RLE pixel data."""
    with open(filename, 'rb') as f:
        data = f.read()
    
    # PCX header
    manufacturer = data[0]
    version = data[1]
    encoding = data[2]
    bpp = data[3]
    xmin = struct.unpack('<H', data[4:6])[0]
    ymin = struct.unpack('<H', data[6:8])[0]
    xmax = struct.unpack('<H', data[8:10])[0]
    ymax = struct.unpack('<H', data[10:12])[0]
    nplanes = data[65]
    bpl = struct.unpack('<H', data[66:68])[0]
    
    width = xmax - xmin + 1
    height = ymax - ymin + 1
    
    print(f"\n  PCX {filename}: {width}x{height}, {bpp}bpp, {nplanes} planes, {bpl} bytes/line")
    
    # Decode RLE
    pixels = []
    pos = 128  # pixel data starts after header
    total_bytes = bpl * nplanes * height
    
    while len(pixels) < total_bytes and pos < len(data):
        byte = data[pos]
        pos += 1
        if byte >= 0xC0:
            count = byte & 0x3F
            if pos < len(data):
                value = data[pos]
                pos += 1
            else:
                break
            pixels.extend([value] * count)
        else:
            pixels.append(byte)
    
    return pixels, width, height, nplanes, bpl, bpp

pix_current, w, h, nplanes, bpl, bpp = decode_pcx_pixels("NOTICE10.PCX")
pix_prior, _, _, _, _, _ = decode_pcx_pixels("NOTICE10.BAK")

print(f"\n  Current pixel count: {len(pix_current)}")
print(f"  Prior pixel count: {len(pix_prior)}")

# For a 16-color image with 4 planes, each pixel's color is determined
# by the corresponding bit in each plane.
# But if bpp=1 and nplanes=4, each pixel is 4 bits (index 0-15).
# If bpp=4 and nplanes=1, each byte has 2 pixels.
# If bpp=8, each byte is one pixel index.

# Let's check the actual format
print(f"\n  bpp={bpp}, nplanes={nplanes}")

# With bpp=4, nplanes=1: each byte = 2 pixels (high nibble, low nibble)
# With bpp=1, nplanes=4: planar format
# With bpp=8, nplanes=1: 1 byte per pixel

if bpp == 8 and nplanes == 1:
    # Direct pixel indices
    print("  Direct 8-bit pixel indices")
    # Compare first few pixels
    diffs = [(i, pix_current[i], pix_prior[i]) for i in range(min(len(pix_current), len(pix_prior))) if pix_current[i] != pix_prior[i]]
    print(f"  Differing pixels: {len(diffs)} out of {min(len(pix_current), len(pix_prior))}")
    if diffs:
        for i, c, p in diffs[:20]:
            print(f"    pixel {i}: current={c} prior={p}")

elif bpp == 1 and nplanes == 4:
    print("  Planar 4-bit format (1bpp x 4 planes)")
    # Each scanline has nplanes * bpl bytes
    # Plane 0 bits, then plane 1 bits, etc.
    # Need to reconstruct pixel indices from planes
    
    def planar_to_indices(pixels, width, height, bpl):
        indices = []
        row_bytes = 4 * bpl  # 4 planes * bytes_per_line
        for y in range(height):
            row_start = y * row_bytes
            for x in range(width):
                byte_idx = x // 8
                bit_idx = 7 - (x % 8)
                idx = 0
                for plane in range(4):
                    plane_start = row_start + plane * bpl
                    b = pixels[plane_start + byte_idx]
                    idx |= ((b >> bit_idx) & 1) << plane
                indices.append(idx)
        return indices
    
    idx_current = planar_to_indices(pix_current, w, h, bpl)
    idx_prior = planar_to_indices(pix_prior, w, h, bpl)
    
    print(f"  Reconstructed {len(idx_current)} pixel indices (current)")
    print(f"  Reconstructed {len(idx_prior)} pixel indices (prior)")
    
    # Now compare: for each pixel, current index and prior index should map
    # through respective palettes to the same color
    # So: pal_current[idx_current[i]] == pal_prior[idx_prior[i]]
    
    # The mapping between indices tells us the permutation
    # idx_current[i] maps to idx_prior[i] for the same visual pixel
    
    # Build the permutation from index mapping
    index_map = {}  # current_index -> prior_index
    for i in range(min(len(idx_current), len(idx_prior))):
        ci = idx_current[i]
        pi = idx_prior[i]
        if ci not in index_map:
            index_map[ci] = pi
        elif index_map[ci] != pi:
            print(f"  WARNING: inconsistent mapping at pixel {i}: current[{ci}] maps to both {index_map[ci]} and {pi}")
    
    print(f"\n  Index mapping (current -> prior):")
    for k in sorted(index_map.keys()):
        print(f"    current idx {k:2d} -> prior idx {index_map[k]:2d}")
    
    # This mapping should be consistent with the palette permutation
    # pal_current[ci] == pal_prior[pi]
    print(f"\n  Verification:")
    for ci in sorted(index_map.keys()):
        pi = index_map[ci]
        match = "OK" if pal_current[ci] == pal_prior[pi] else "MISMATCH"
        print(f"    pal_current[{ci:2d}]={pal_current[ci]} == pal_prior[{pi:2d}]={pal_prior[pi]} {match}")
    
    # Now try using THIS mapping as the station numbers
    # The table: for position i (0-15), station_number = index_map[i] or inverse
    table_a = [index_map.get(i, i) for i in range(16)]
    table_b = [0]*16
    for ci, pi in index_map.items():
        if ci < 16:
            table_b[pi] = ci
    
    print(f"\n  table_a (cur->prior): {table_a}")
    print(f"  table_b (prior->cur): {table_b}")
    
    for name, table in [("idx cur->prior", table_a), ("idx prior->cur", table_b),
                        ("pal cur->prior", cur_to_prior), ("pal prior->cur", prior_to_cur)]:
        desig = extract_designation(table)
        crc = zlib.crc32(desig.encode('ascii')) & 0xFFFFFFFF
        match = "MATCH!" if crc == target_crc else ""
        print(f"  {name}: '{desig}' CRC={crc:08X} {match}")

elif bpp == 4 and nplanes == 1:
    print("  Packed 4-bit format (2 pixels per byte)")

print("\n=== Sealed clearance block ===")
sealed_hex = "35 25 2D 22 35 3A 64 31 63 2E 7A 11 35 7F 5D 67 61 78 78 23 78 65 64 27 61 29 34"
sealed = bytes(int(x, 16) for x in sealed_hex.split())
print(f"Sealed block ({len(sealed)} bytes): {sealed.hex()}")

block_crc_target = 0xE2021920

# Try XOR decryption with each candidate designation
for name, table in tables_to_try.items():
    for upper in [False, True]:
        desig = extract_designation(table)
        if upper:
            desig = desig.upper()
        key = desig.encode('ascii')
        decrypted = bytes(sealed[i] ^ key[i % len(key)] for i in range(len(sealed)))
        crc = zlib.crc32(decrypted) & 0xFFFFFFFF
        match = "MATCH!" if crc == block_crc_target else ""
        try:
            text = decrypted.decode('ascii')
        except:
            text = repr(decrypted)
        print(f"  {name}{'(U)' if upper else ''}: desig='{desig}' -> '{text}' CRC={crc:08X} {match}")
        if match:
            print(f"\n  *** FLAG: {text} ***")
            with open("flag.txt", "w") as f:
                f.write(text.strip() + "\n")
