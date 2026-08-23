#!/usr/bin/env python3
import os
import struct
import hashlib
import dnfile

def ror16(val, r):
    r = r % 16
    return ((val >> r) | (val << (16 - r))) & 0xFFFF

def fold(arg0, mask, rot, salt, token):
    loc0 = ((token * 17881) + salt) & 0xFFFF
    v = (arg0 ^ mask) & 0xFFFF
    v_rot = ror16(v, rot)
    return (v_rot - loc0) & 0xFFFF

def solve():
    dll_path = os.path.join(os.path.dirname(__file__), '..', 'Token.Curtain.dll')
    if not os.path.exists(dll_path):
        dll_path = 'Token.Curtain.dll'
    pe = dnfile.dnPE(dll_path)
    
    # 1. Read Props from FieldRVA
    field_rva = pe.net.mdtables.FieldRva[0].Rva
    props_raw = pe.get_data(field_rva, 40)
    props = struct.unpack('<20H', props_raw)
    
    # 2. Extract cues from CustomAttributes on IPlaybill.C00..C19 methods
    cues = []
    for i in range(23, 43):
        ca = pe.net.mdtables.CustomAttribute[i]
        prolog, src, mask, rot, salt, num_named = struct.unpack('<HiiiiH', ca.Value.value)
        cues.append((src, mask, rot, salt))
        
    # 3. Extract generic TypeDef tokens from MethodSpecs 1..20
    tokens = []
    for i in range(20):
        ms = pe.net.mdtables.MethodSpec[i]
        b = ms.Instantiation.value
        enc_tok = b[3]
        row_idx = enc_tok >> 2
        # TypeDef token in CLI is 0x02000000 | row_index
        token = 0x02000000 | row_idx
        tokens.append(token)
        
    # 4. Simulate Main loop
    span = bytearray(40)
    for i in range(20):
        src, mask, rot, salt = cues[i]
        tok = tokens[i]
        in_val = props[src]
        out_val = fold(in_val, mask, rot, salt, tok)
        span[i * 2] = out_val & 0xFF
        span[i * 2 + 1] = (out_val >> 8) & 0xFF
        
    flag = span.decode('ascii')
    print('Flag:', flag)
    
    # Verify applause hash
    h = hashlib.sha256(span).hexdigest()
    print('Applause SHA256 (first 6 bytes hex):', h[:12])
    return flag

if __name__ == '__main__':
    solve()
