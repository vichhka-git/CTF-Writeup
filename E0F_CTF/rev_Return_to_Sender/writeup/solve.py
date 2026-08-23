nodes_data = bytes.fromhex("630c0ac8 d2090c7d 5e030ef8 130304b4 0c0f0fa0 9806093c 460000e7 410b02ea 180809bf b501011a 8005ff28 1b0b0cbc ef040440 1d0d0eba 7b0e05dc 29070686".replace(" ", ""))
frags_data = b"mtNrr4rbRpAe_Hr143O34s1u3rS01MnnkdPtmm3tV0MftM_g3_Eum}n_!g?{_!0_"

nodes = []
for i in range(16):
    nodes.append({
        "n0": nodes_data[i*4],
        "n1": nodes_data[i*4+1],
        "n2": nodes_data[i*4+2],
        "n3": nodes_data[i*4+3]
    })

flag = ""
curr = 7
for r10 in range(12):
    node = nodes[curr]
    
    # Check
    expected_n0 = (r10 * 0x1d + 0x41) & 0xff
    if node["n0"] != expected_n0:
        print(f"Mismatch at r10={r10}: expected {expected_n0}, got {node['n0']}")
    
    edx = node["n1"]
    c1 = chr(frags_data[edx])
    c2 = chr(frags_data[edx + 16])
    c3 = chr(frags_data[edx + 32])
    c4 = chr(frags_data[edx + 48])
    
    flag += c1 + c2 + c3 + c4
    
    curr = node["n2"]

print("Flag:", flag)
