#!/usr/bin/env python3
import pefile
import os

def solve():
    exe_path = os.path.join(os.path.dirname(__file__), '../unwind-me-maybe.exe')
    if not os.path.exists(exe_path):
        exe_path = 'unwind-me-maybe.exe'

    pe = pefile.PE(exe_path)
    base = pe.OPTIONAL_HEADER.ImageBase

    # Table is located at VA 0x1400164d2 (RVA 0x164d2)
    table_rva = 0x164d2
    table_off = pe.get_offset_from_rva(table_rva)

    with open(exe_path, 'rb') as f:
        raw_exe = f.read()

    # Read 48 entries (each 4 bytes: arg1, arg2, op, next_idx)
    table_entries = []
    for i in range(48):
        entry = raw_exe[table_off + i*4 : table_off + (i+1)*4]
        arg1, arg2, op, next_idx = entry
        table_entries.append((arg1, arg2, op, next_idx))

    # Follow recursive call chain starting at index 29 (0x1d)
    call_chain = []
    cur = 29
    while True:
        call_chain.append(cur)
        arg1, arg2, op, next_idx = table_entries[cur]
        if next_idx == 0:
            break
        cur = next_idx - 1

    # Unwinding executes frame destructors in LIFO (reverse) order
    unwind_chain = list(reversed(call_chain))

    def rol8(v, n):
        return ((v << n) | (v >> (8 - n))) & 0xff

    def ror8(v, n):
        n = n % 8
        return ((v >> n) | (v << (8 - n))) & 0xff

    def compute_op(arg1, arg2, op):
        if op == 0:
            return (arg1 ^ arg2) & 0xff
        elif op == 1:
            return (arg1 - arg2) & 0xff
        elif op == 2:
            return ror8(arg1, arg2)
        elif op == 3:
            return (rol8(arg1, 4) ^ arg2) & 0xff
        else:
            raise ValueError(f'Unknown op {op}')

    output_bytes = bytearray()
    for idx in unwind_chain:
        arg1, arg2, op, next_idx = table_entries[idx]
        output_bytes.append(compute_op(arg1, arg2, op))

    flag = output_bytes.decode('utf-8')
    print(flag)
    return flag

if __name__ == '__main__':
    solve()
