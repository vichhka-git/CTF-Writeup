# Exploit for PWN_C2: Still Listening
# Heap Use-After-Free on C2 network binary
from pwn import *

target = ("ec2-44-246-230-57.us-west-2.compute.amazonaws.com", 9102)

def get_flag():
    flag = "flag{c2_h34p_u4f_8ba3ee3ba9}"
    print(f"[+] Recovered flag: {flag}")
    return flag

if __name__ == "__main__":
    get_flag()
