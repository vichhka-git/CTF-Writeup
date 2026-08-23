#!/usr/bin/env python3
import pefile
import os

def solve():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Handle being called from agent_workspace or agent_result
    if os.path.exists(os.path.join(script_dir, '..', 'gopher-carousel.exe')):
        exe_path = os.path.join(script_dir, '..', 'gopher-carousel.exe')
    else:
        exe_path = '/home/john/Desktop/E0F_CTF/rev_Gopher_Carousel/gopher-carousel.exe'
    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    with open(exe_path, 'rb') as f:
        data = f.read()

    def get_bytes_va(va, length):
        rva = va - image_base
        for s in pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                offset = s.PointerToRawData + (rva - s.VirtualAddress)
                return data[offset : offset + length]
        return None

    table = get_bytes_va(0x140188d80, 4 * 36)

    def splitmix64(x):
        x = (x + 0x9e3779b97f4a7c15) & 0xffffffffffffffff
        z = x
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9 & 0xffffffffffffffff
        z = (z ^ (z >> 27)) * 0x94d049bb133111eb & 0xffffffffffffffff
        z = (z ^ (z >> 31)) & 0xffffffffffffffff
        return x, z

    def q7(rax):
        out = bytearray(36)
        for c in range(36):
            state = ((rax + 1) * 0x9e3779b97f4a7c15) & 0xffffffffffffffff
            state ^= 0x6c617a795f677269
            r9 = 0
            for s in range(c + 1):
                state, r9 = splitmix64(state)
            byte_val = (r9 >> ((c & 7) * 8)) & 0xff
            tbl_byte = table[rax * 36 + c]
            out[c] = tbl_byte ^ byte_val
        return bytearray(out)

    def q2():
        state = 0x726f746174655f36
        steps = []
        for _ in range(52):
            state, z = splitmix64(state)
            op = z % 7
            p1 = (z >> 9) % 6
            p2 = (z >> 21) % 6
            p3 = ((z >> 37) % 11) + 1
            steps.append((op, p1, p2, p3))
        return steps

    def ring_cells(r):
        cells = []
        for c in range(r, 6 - r):
            cells.append(r * 6 + c)
        for row in range(r + 1, 6 - r):
            cells.append(row * 6 + (5 - r))
        for c in range(5 - r - 1, r - 1, -1):
            cells.append((5 - r) * 6 + c)
        for row in range(5 - r - 1, r, -1):
            cells.append(row * 6 + r)
        return cells

    def rol8(val, shift):
        shift %= 8
        return ((val << shift) | (val >> (8 - shift))) & 0xff

    def step(grid, op, p1, p2, p3, is_inverse):
        shift = -p3 if is_inverse else p3
        if op == 0: # rotateRow
            s = (shift % 6 + 6) % 6
            row = p1
            temp = [grid[row * 6 + i] for i in range(6)]
            for i in range(6):
                grid[row * 6 + (i + s) % 6] = temp[i]
        elif op == 1: # rotateCol
            s = (shift % 6 + 6) % 6
            col = p1
            temp = [grid[i * 6 + col] for i in range(6)]
            for i in range(6):
                grid[((i + s) % 6) * 6 + col] = temp[i]
        elif op == 2: # swapRows
            r1, r2 = p1, p2
            for col in range(6):
                grid[r1 * 6 + col], grid[r2 * 6 + col] = grid[r2 * 6 + col], grid[r1 * 6 + col]
        elif op == 3: # swapCols
            c1, c2 = p1, p2
            for row in range(6):
                grid[row * 6 + c1], grid[row * 6 + c2] = grid[row * 6 + c2], grid[row * 6 + c1]
        elif op == 4: # xor
            for i in range(6):
                mask_base = (i * 17 + p2 + 93) & 0xff
                rot1 = (i + p1) % 8
                k1 = rol8(mask_base, rot1)
                grid[p1 * 6 + i] ^= k1
                rot2 = (rot1 + 3) % 8
                k2 = rol8(mask_base, rot2)
                grid[i * 6 + p2] ^= k2
        elif op == 5: # transpose
            for r in range(6):
                for c in range(r + 1, 6):
                    grid[r * 6 + c], grid[c * 6 + r] = grid[c * 6 + r], grid[r * 6 + c]
        elif op == 6: # rotateRing
            ring_idx = p1 % 3
            cells = ring_cells(ring_idx)
            L = len(cells)
            s = (shift % L + L) % L
            temp = [grid[cells[i]] for i in range(L)]
            for i in range(L):
                grid[cells[(i + s) % L]] = temp[i]

    # Target grid for rax = 2
    target = q7(2)

    # Inverse q3: apply 52 steps in reverse order with is_inverse=True
    steps = q2()
    grid = bytearray(target)
    for op, p1, p2, p3 in reversed(steps):
        step(grid, op, p1, p2, p3, is_inverse=True)

    # Invert q4 initial permutation and XOR
    state = 0x7369785f62795f36
    payload = bytearray(36)
    for i in range(36):
        dst_idx = (i * 5 + 7) % 36
        state, z = splitmix64(state)
        k = (z >> 56) & 0xff
        payload[i] = grid[dst_idx] ^ k

    flag = 'e0f{' + payload.decode('latin1') + '}'
    print(flag)
    return flag

if __name__ == '__main__':
    solve()
